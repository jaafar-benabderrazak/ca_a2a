import json
import os
import time

import pytest

from a2a_security import A2ASecurityManager, AuthError, ForbiddenError


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    # Ensure tests are deterministic
    for k in [
        "A2A_REQUIRE_AUTH",
        "A2A_ENABLE_RATE_LIMIT",
        "A2A_ENABLE_REPLAY_PROTECTION",
        "A2A_RBAC_POLICY_JSON",
        "A2A_API_KEYS_JSON",
        "A2A_JWT_ISSUER",
        "A2A_JWT_ALG",
        "A2A_JWT_PUBLIC_KEY_PEM",
        "A2A_JWT_PRIVATE_KEY_PEM",
        "A2A_JWT_MAX_TOKEN_AGE_SECONDS",
        "A2A_REPLAY_TTL_SECONDS",
        "A2A_RATE_LIMIT_PER_MINUTE",
    ]:
        monkeypatch.delenv(k, raising=False)


def _rsa_keypair_pem():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def test_auth_disabled_allows_anonymous(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("A2A_REQUIRE_AUTH", "false")
    monkeypatch.setenv("A2A_RBAC_POLICY_JSON", json.dumps({"allow": {}, "deny": {}}))
    mgr = A2ASecurityManager(agent_id="extractor")
    principal, ctx = mgr.authenticate_and_authorize(headers={}, message_method="echo", message_dict={"a": 1})
    assert principal == "anonymous"
    assert ctx["mode"] == "disabled"


def test_api_key_auth_and_rbac(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("A2A_REQUIRE_AUTH", "true")
    monkeypatch.setenv("A2A_API_KEYS_JSON", json.dumps({"external_client": "secret-key-123"}))
    monkeypatch.setenv(
        "A2A_RBAC_POLICY_JSON",
        json.dumps({"allow": {"external_client": ["allowed_method"]}, "deny": {}}),
    )
    mgr = A2ASecurityManager(agent_id="orchestrator")

    principal, _ = mgr.authenticate_and_authorize(
        headers={"X-API-Key": "secret-key-123"},
        message_method="allowed_method",
        message_dict={"jsonrpc": "2.0", "method": "allowed_method", "params": {}, "id": 1},
    )
    assert principal == "external_client"

    with pytest.raises(ForbiddenError):
        mgr.authenticate_and_authorize(
            headers={"X-API-Key": "secret-key-123"},
            message_method="blocked_method",
            message_dict={"jsonrpc": "2.0", "method": "blocked_method", "params": {}, "id": 1},
        )


def test_missing_auth_rejected(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("A2A_REQUIRE_AUTH", "true")
    monkeypatch.setenv("A2A_RBAC_POLICY_JSON", json.dumps({"allow": {}, "deny": {}}))
    mgr = A2ASecurityManager(agent_id="orchestrator")
    with pytest.raises(AuthError):
        mgr.authenticate_and_authorize(headers={}, message_method="x", message_dict={"x": 1})


def test_jwt_happy_path_and_replay(monkeypatch: pytest.MonkeyPatch):
    private_pem, public_pem = _rsa_keypair_pem()

    monkeypatch.setenv("A2A_REQUIRE_AUTH", "true")
    monkeypatch.setenv("A2A_ENABLE_RATE_LIMIT", "false")
    monkeypatch.setenv("A2A_ENABLE_REPLAY_PROTECTION", "true")
    monkeypatch.setenv("A2A_REPLAY_TTL_SECONDS", "120")
    monkeypatch.setenv("A2A_JWT_ISSUER", "ca-a2a")
    monkeypatch.setenv("A2A_JWT_ALG", "RS256")
    monkeypatch.setenv("A2A_JWT_PRIVATE_KEY_PEM", private_pem)
    monkeypatch.setenv("A2A_JWT_PUBLIC_KEY_PEM", public_pem)
    monkeypatch.setenv("A2A_RBAC_POLICY_JSON", json.dumps({"allow": {"orchestrator": ["echo"]}, "deny": {}}))

    mgr = A2ASecurityManager(agent_id="extractor")  # audience is extractor

    msg = {"jsonrpc": "2.0", "method": "echo", "params": {"x": 1}, "id": "1"}
    token = mgr.sign_request_jwt(subject="orchestrator", audience="extractor", method="echo", message_dict=msg, ttl_seconds=60)

    principal, ctx = mgr.authenticate_and_authorize(
        headers={"Authorization": f"Bearer {token}"},
        message_method="echo",
        message_dict=msg,
    )
    assert principal == "orchestrator"
    assert ctx["mode"] == "jwt"

    # Replay same token should be blocked
    with pytest.raises(ForbiddenError):
        mgr.authenticate_and_authorize(
            headers={"Authorization": f"Bearer {token}"},
            message_method="echo",
            message_dict=msg,
        )


def test_jwt_body_hash_binding(monkeypatch: pytest.MonkeyPatch):
    private_pem, public_pem = _rsa_keypair_pem()
    monkeypatch.setenv("A2A_REQUIRE_AUTH", "true")
    monkeypatch.setenv("A2A_ENABLE_RATE_LIMIT", "false")
    monkeypatch.setenv("A2A_ENABLE_REPLAY_PROTECTION", "false")
    monkeypatch.setenv("A2A_JWT_ISSUER", "ca-a2a")
    monkeypatch.setenv("A2A_JWT_ALG", "RS256")
    monkeypatch.setenv("A2A_JWT_PRIVATE_KEY_PEM", private_pem)
    monkeypatch.setenv("A2A_JWT_PUBLIC_KEY_PEM", public_pem)
    monkeypatch.setenv("A2A_RBAC_POLICY_JSON", json.dumps({"allow": {"orchestrator": ["echo"]}, "deny": {}}))

    mgr = A2ASecurityManager(agent_id="extractor")

    msg = {"jsonrpc": "2.0", "method": "echo", "params": {"x": 1}, "id": "1"}
    token = mgr.sign_request_jwt(subject="orchestrator", audience="extractor", method="echo", message_dict=msg, ttl_seconds=60)

    tampered = {"jsonrpc": "2.0", "method": "echo", "params": {"x": 2}, "id": "1"}
    with pytest.raises(AuthError):
        mgr.authenticate_and_authorize(
            headers={"Authorization": f"Bearer {token}"},
            message_method="echo",
            message_dict=tampered,
        )


def test_rate_limit(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("A2A_REQUIRE_AUTH", "true")
    monkeypatch.setenv("A2A_ENABLE_RATE_LIMIT", "true")
    monkeypatch.setenv("A2A_ENABLE_REPLAY_PROTECTION", "false")
    monkeypatch.setenv("A2A_RATE_LIMIT_PER_MINUTE", "2")
    monkeypatch.setenv("A2A_API_KEYS_JSON", json.dumps({"external_client": "k"}))
    monkeypatch.setenv("A2A_RBAC_POLICY_JSON", json.dumps({"allow": {"external_client": ["m"]}, "deny": {}}))

    mgr = A2ASecurityManager(agent_id="orchestrator")
    headers = {"X-API-Key": "k"}
    msg = {"jsonrpc": "2.0", "method": "m", "params": {}, "id": "1"}

    mgr.authenticate_and_authorize(headers=headers, message_method="m", message_dict=msg)
    mgr.authenticate_and_authorize(headers=headers, message_method="m", message_dict=msg)
    with pytest.raises(ForbiddenError):
        mgr.authenticate_and_authorize(headers=headers, message_method="m", message_dict=msg)

