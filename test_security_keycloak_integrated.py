"""
Integrated Security Test Suite for Keycloak-Based A2A Security

Tests all security features in a deployed environment:
1. Keycloak JWT authentication
2. RBAC authorization via Keycloak roles
3. Rate limiting
4. Replay protection
5. JSON Schema validation
6. End-to-end security flow

Based on: "Securing Agent-to-Agent (A2A) Communications Across Domains"

Usage:
    # Unit tests (mocked Keycloak)
    pytest test_security_keycloak_integrated.py -v

    # Integration tests (requires Keycloak)
    pytest test_security_keycloak_integrated.py -v -m integration

    # All tests with real Keycloak
    KEYCLOAK_URL=http://keycloak:8080 pytest test_security_keycloak_integrated.py -v
"""

import pytest
import asyncio
import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock
import hashlib


# ============================================================================
# FIXTURES AND HELPERS
# ============================================================================

def generate_mock_jwt_claims(
    username: str = "test-user",
    roles: list = None,
    client_id: str = "ca-a2a-agents",
    issuer: str = "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
    expires_in: int = 300
) -> Dict[str, Any]:
    """Generate mock Keycloak JWT claims"""
    now = int(time.time())
    roles = roles or ["document-processor"]
    
    return {
        "sub": f"user-{username}-{now}",
        "preferred_username": username,
        "name": f"Test User {username}",
        "email": f"{username}@ca-a2a.local",
        "realm_access": {
            "roles": roles
        },
        "resource_access": {
            client_id: {
                "roles": roles
            }
        },
        "aud": client_id,
        "iss": issuer,
        "iat": now,
        "exp": now + expires_in,
        "jti": hashlib.sha256(f"{username}:{now}".encode()).hexdigest()[:32],
        "azp": client_id,
        "scope": "openid profile email"
    }


class MockKeycloakValidator:
    """Mock Keycloak validator for unit testing"""
    
    def __init__(self, users: Dict[str, Dict] = None):
        """
        Initialize mock validator with predefined users.
        
        Args:
            users: Dict mapping tokens to (username, roles, claims)
        """
        self.users = users or {}
        self._verified_tokens = []
    
    def add_user(self, token: str, username: str, roles: list, custom_claims: Dict = None):
        """Add a mock user token"""
        claims = generate_mock_jwt_claims(username, roles)
        if custom_claims:
            claims.update(custom_claims)
        self.users[token] = (username, roles, claims)
    
    def verify_token(self, token: str) -> Tuple[str, list, Dict]:
        """Mock token verification"""
        self._verified_tokens.append(token)
        
        if token in self.users:
            return self.users[token]
        
        if token.startswith("valid_"):
            # Auto-generate for valid_ prefixed tokens
            username = token.replace("valid_", "")
            roles = ["document-processor"]
            claims = generate_mock_jwt_claims(username, roles)
            return username, roles, claims
        
        raise ValueError(f"Invalid token: {token}")


@pytest.fixture
def mock_keycloak():
    """Create mock Keycloak validator with predefined users"""
    validator = MockKeycloakValidator()
    
    # Add test users with different roles
    validator.add_user(
        "admin_token",
        "admin-user",
        ["admin", "user"]
    )
    validator.add_user(
        "lambda_token",
        "lambda-service",
        ["lambda"]
    )
    validator.add_user(
        "orchestrator_token",
        "orchestrator-service",
        ["orchestrator"]
    )
    validator.add_user(
        "document_processor_token",
        "doc-processor",
        ["document-processor"]
    )
    validator.add_user(
        "viewer_token",
        "viewer-user",
        ["viewer"]
    )
    validator.add_user(
        "unknown_role_token",
        "unknown-user",
        ["unknown-role"]
    )
    
    return validator


@pytest.fixture
def mock_rbac_mapper():
    """Create RBAC mapper"""
    from keycloak_auth import KeycloakRBACMapper
    return KeycloakRBACMapper()


# ============================================================================
# TEST 1: KEYCLOAK JWT AUTHENTICATION
# ============================================================================

class TestKeycloakAuthentication:
    """Test Keycloak JWT authentication"""
    
    def test_valid_token_verification(self, mock_keycloak, mock_rbac_mapper):
        """Test successful JWT verification"""
        principal, roles, claims = mock_keycloak.verify_token("admin_token")
        
        assert principal == "admin-user"
        assert "admin" in roles
        assert claims["preferred_username"] == "admin-user"
        assert "jti" in claims
        assert "exp" in claims
    
    def test_invalid_token_rejection(self, mock_keycloak):
        """Test rejection of invalid tokens"""
        with pytest.raises(ValueError) as exc_info:
            mock_keycloak.verify_token("invalid_token_xyz")
        
        assert "Invalid token" in str(exc_info.value)
    
    def test_token_expiration_claim(self, mock_keycloak):
        """Test that tokens have proper expiration claims"""
        _, _, claims = mock_keycloak.verify_token("lambda_token")
        
        assert "exp" in claims
        assert "iat" in claims
        assert claims["exp"] > claims["iat"]
        assert claims["exp"] > int(time.time())  # Not yet expired
    
    def test_jti_claim_uniqueness(self, mock_keycloak):
        """Test that JTI claims are present for replay protection"""
        _, _, claims1 = mock_keycloak.verify_token("admin_token")
        _, _, claims2 = mock_keycloak.verify_token("lambda_token")
        
        assert "jti" in claims1
        assert "jti" in claims2
        assert claims1["jti"] != claims2["jti"]  # Unique per token
    
    def test_audience_claim_validation(self, mock_keycloak):
        """Test audience claim is properly set"""
        _, _, claims = mock_keycloak.verify_token("orchestrator_token")
        
        assert "aud" in claims
        assert claims["aud"] == "ca-a2a-agents"


# ============================================================================
# TEST 2: RBAC AUTHORIZATION VIA KEYCLOAK ROLES
# ============================================================================

class TestRBACAuthorization:
    """Test RBAC authorization based on Keycloak roles"""
    
    def test_admin_role_full_access(self, mock_rbac_mapper):
        """Test admin role gets wildcard permissions"""
        principal, methods = mock_rbac_mapper.map_roles_to_principal(["admin"])
        
        assert principal == "admin"
        assert methods == ["*"]
    
    def test_lambda_role_full_access(self, mock_rbac_mapper):
        """Test lambda role gets wildcard permissions"""
        principal, methods = mock_rbac_mapper.map_roles_to_principal(["lambda"])
        
        assert principal == "lambda"
        assert methods == ["*"]
    
    def test_orchestrator_role_limited_access(self, mock_rbac_mapper):
        """Test orchestrator role gets specific method access"""
        principal, methods = mock_rbac_mapper.map_roles_to_principal(["orchestrator"])
        
        assert principal == "orchestrator"
        assert "extract_document" in methods
        assert "validate_document" in methods
        assert "archive_document" in methods
        assert "list_skills" in methods
        assert "get_health" in methods
        # Should NOT have full access
        assert "*" not in methods
    
    def test_document_processor_role(self, mock_rbac_mapper):
        """Test document-processor role permissions"""
        principal, methods = mock_rbac_mapper.map_roles_to_principal(["document-processor"])
        
        assert principal == "document-processor"
        assert "process_document" in methods
        assert "extract_document" in methods
        assert "validate_document" in methods
        assert "archive_document" in methods
    
    def test_viewer_role_read_only(self, mock_rbac_mapper):
        """Test viewer role gets read-only access"""
        principal, methods = mock_rbac_mapper.map_roles_to_principal(["viewer"])
        
        assert principal == "viewer"
        assert "list_skills" in methods
        assert "get_health" in methods
        # Should NOT have write access
        assert "process_document" not in methods
        assert "extract_document" not in methods
    
    def test_unknown_role_no_access(self, mock_rbac_mapper):
        """Test unknown role gets no permissions"""
        principal, methods = mock_rbac_mapper.map_roles_to_principal(["unknown-role"])
        
        assert principal == "unknown"
        assert len(methods) == 0
    
    def test_multiple_roles_priority(self, mock_rbac_mapper):
        """Test multiple roles use highest priority"""
        # Admin takes precedence
        principal, methods = mock_rbac_mapper.map_roles_to_principal(["viewer", "admin"])
        assert principal == "admin"
        assert methods == ["*"]
        
        # Lambda takes precedence over orchestrator
        principal, methods = mock_rbac_mapper.map_roles_to_principal(["orchestrator", "lambda"])
        assert principal == "lambda"
        assert methods == ["*"]
    
    def test_method_authorization_check(self, mock_keycloak, mock_rbac_mapper):
        """Test full authorization flow: token -> roles -> method check"""
        # Get viewer token
        principal_name, roles, claims = mock_keycloak.verify_token("viewer_token")
        rbac_principal, allowed_methods = mock_rbac_mapper.map_roles_to_principal(roles)
        
        # Viewer can access list_skills
        assert "list_skills" in allowed_methods or "*" in allowed_methods
        
        # Viewer cannot access process_document
        assert "process_document" not in allowed_methods and "*" not in allowed_methods
        
        # Get lambda token - should have full access
        principal_name, roles, claims = mock_keycloak.verify_token("lambda_token")
        rbac_principal, allowed_methods = mock_rbac_mapper.map_roles_to_principal(roles)
        
        assert "*" in allowed_methods


# ============================================================================
# TEST 3: RATE LIMITING
# ============================================================================

class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def test_rate_limit_allows_within_limit(self):
        """Test requests within rate limit are allowed"""
        from a2a_security import SlidingWindowRateLimiter
        
        limiter = SlidingWindowRateLimiter(limit=5, window_seconds=60)
        
        # First 5 requests should be allowed
        for i in range(5):
            allowed, meta = limiter.allow("test-user")
            assert allowed is True, f"Request {i+1} should be allowed"
            assert meta["remaining"] == 5 - (i + 1)
    
    def test_rate_limit_blocks_excess(self):
        """Test requests exceeding rate limit are blocked"""
        from a2a_security import SlidingWindowRateLimiter
        
        limiter = SlidingWindowRateLimiter(limit=3, window_seconds=60)
        
        # First 3 requests should be allowed
        for _ in range(3):
            allowed, _ = limiter.allow("test-user")
            assert allowed is True
        
        # 4th request should be blocked
        allowed, meta = limiter.allow("test-user")
        assert allowed is False
        assert meta["remaining"] == 0
    
    def test_rate_limit_per_principal(self):
        """Test rate limits are applied per principal"""
        from a2a_security import SlidingWindowRateLimiter
        
        limiter = SlidingWindowRateLimiter(limit=2, window_seconds=60)
        
        # User A makes 2 requests
        limiter.allow("user-a")
        limiter.allow("user-a")
        
        # User A is now blocked
        allowed, _ = limiter.allow("user-a")
        assert allowed is False
        
        # User B can still make requests
        allowed, _ = limiter.allow("user-b")
        assert allowed is True
    
    def test_rate_limit_metadata(self):
        """Test rate limit metadata is correct"""
        from a2a_security import SlidingWindowRateLimiter
        
        limiter = SlidingWindowRateLimiter(limit=10, window_seconds=60)
        
        _, meta = limiter.allow("test-user")
        
        assert "limit" in meta
        assert "remaining" in meta
        assert "window_seconds" in meta
        assert "reset_in_seconds" in meta
        assert meta["limit"] == 10
        assert meta["window_seconds"] == 60


# ============================================================================
# TEST 4: REPLAY PROTECTION
# ============================================================================

class TestReplayProtection:
    """Test replay protection functionality"""
    
    def test_first_use_allowed(self):
        """Test first use of nonce is allowed"""
        from a2a_security import ReplayProtector
        
        protector = ReplayProtector(ttl_seconds=120)
        
        now = int(time.time())
        exp = now + 60
        
        result = protector.check_and_store("unique-nonce-123", exp)
        assert result is True
    
    def test_replay_blocked(self):
        """Test replay of same nonce is blocked"""
        from a2a_security import ReplayProtector
        
        protector = ReplayProtector(ttl_seconds=120)
        
        now = int(time.time())
        exp = now + 60
        nonce = "replay-test-nonce"
        
        # First use - allowed
        result = protector.check_and_store(nonce, exp)
        assert result is True
        
        # Replay attempt - blocked
        result = protector.check_and_store(nonce, exp)
        assert result is False
    
    def test_different_nonces_allowed(self):
        """Test different nonces are each allowed once"""
        from a2a_security import ReplayProtector
        
        protector = ReplayProtector(ttl_seconds=120)
        
        now = int(time.time())
        exp = now + 60
        
        # Different nonces should all be allowed
        assert protector.check_and_store("nonce-1", exp) is True
        assert protector.check_and_store("nonce-2", exp) is True
        assert protector.check_and_store("nonce-3", exp) is True
        
        # But replaying any should fail
        assert protector.check_and_store("nonce-1", exp) is False
        assert protector.check_and_store("nonce-2", exp) is False
    
    def test_empty_nonce_rejected(self):
        """Test empty nonce is rejected"""
        from a2a_security import ReplayProtector
        
        protector = ReplayProtector(ttl_seconds=120)
        
        result = protector.check_and_store("", int(time.time()) + 60)
        assert result is False


# ============================================================================
# TEST 5: JSON SCHEMA VALIDATION
# ============================================================================

class TestJSONSchemaValidation:
    """Test JSON Schema validation for method parameters"""
    
    @pytest.fixture
    def validator(self):
        from a2a_security_enhanced import JSONSchemaValidator
        return JSONSchemaValidator()
    
    def test_valid_process_document(self, validator):
        """Test valid process_document parameters"""
        if not validator.enabled:
            pytest.skip("jsonschema not installed")
        
        params = {
            "s3_key": "invoices/2026/01/invoice.pdf",
            "priority": "normal"
        }
        is_valid, error = validator.validate("process_document", params)
        
        assert is_valid is True
        assert error is None
    
    def test_path_traversal_rejected(self, validator):
        """Test path traversal attempt is rejected"""
        if not validator.enabled:
            pytest.skip("jsonschema not installed")
        
        params = {
            "s3_key": "../../../etc/passwd",
            "priority": "normal"
        }
        is_valid, error = validator.validate("process_document", params)
        
        assert is_valid is False
        # Error should mention pattern or path traversal
        assert error is not None
    
    def test_missing_required_field_rejected(self, validator):
        """Test missing required field is rejected"""
        if not validator.enabled:
            pytest.skip("jsonschema not installed")
        
        params = {
            "priority": "normal"
            # Missing required 's3_key'
        }
        is_valid, error = validator.validate("process_document", params)
        
        assert is_valid is False
        assert "s3_key" in error.lower() or "required" in error.lower()
    
    def test_invalid_enum_rejected(self, validator):
        """Test invalid enum value is rejected"""
        if not validator.enabled:
            pytest.skip("jsonschema not installed")
        
        params = {
            "s3_key": "test.pdf",
            "priority": "urgent"  # Not in ["low", "normal", "high"]
        }
        is_valid, error = validator.validate("process_document", params)
        
        assert is_valid is False
    
    def test_additional_properties_rejected(self, validator):
        """Test additional properties are rejected"""
        if not validator.enabled:
            pytest.skip("jsonschema not installed")
        
        params = {
            "s3_key": "test.pdf",
            "priority": "normal",
            "malicious_injection": "<script>alert('xss')</script>"
        }
        is_valid, error = validator.validate("process_document", params)
        
        assert is_valid is False
        assert "additional" in error.lower()
    
    def test_extract_document_valid(self, validator):
        """Test valid extract_document parameters"""
        if not validator.enabled:
            pytest.skip("jsonschema not installed")
        
        params = {
            "s3_key": "documents/invoice.pdf"
        }
        is_valid, error = validator.validate("extract_document", params)
        
        assert is_valid is True
    
    def test_validate_document_valid(self, validator):
        """Test valid validate_document parameters"""
        if not validator.enabled:
            pytest.skip("jsonschema not installed")
        
        params = {
            "extracted_data": {"pages": 1, "text": "Invoice content"},
            "s3_key": "test.pdf"
        }
        is_valid, error = validator.validate("validate_document", params)
        
        assert is_valid is True
    
    def test_archive_document_valid(self, validator):
        """Test valid archive_document parameters"""
        if not validator.enabled:
            pytest.skip("jsonschema not installed")
        
        params = {
            "s3_key": "test.pdf",
            "extracted_data": {"pages": 1},
            "validation_result": {"score": 100, "valid": True}
        }
        is_valid, error = validator.validate("archive_document", params)
        
        assert is_valid is True
    
    def test_unknown_method_allowed(self, validator):
        """Test unknown method is allowed (no schema defined)"""
        if not validator.enabled:
            pytest.skip("jsonschema not installed")
        
        params = {
            "any_field": "any_value"
        }
        is_valid, error = validator.validate("custom_method", params)
        
        assert is_valid is True  # No schema = allow


# ============================================================================
# TEST 6: INTEGRATED SECURITY FLOW
# ============================================================================

class TestIntegratedSecurityFlow:
    """Test complete security flow with all components"""
    
    @pytest.fixture
    def security_manager(self, monkeypatch):
        """Create A2A Security Manager with mocked Keycloak"""
        # Set required environment variables
        monkeypatch.setenv("A2A_REQUIRE_AUTH", "true")
        monkeypatch.setenv("A2A_USE_KEYCLOAK", "false")  # Use local JWT
        monkeypatch.setenv("A2A_ENABLE_RATE_LIMIT", "true")
        monkeypatch.setenv("A2A_RATE_LIMIT_PER_MINUTE", "100")
        monkeypatch.setenv("A2A_ENABLE_REPLAY_PROTECTION", "true")
        monkeypatch.setenv("A2A_RBAC_POLICY_JSON", json.dumps({
            "allow": {
                "admin": ["*"],
                "lambda": ["*"],
                "orchestrator": ["extract_document", "validate_document", "archive_document"],
                "viewer": ["list_skills", "get_health"]
            },
            "deny": {}
        }))
        monkeypatch.setenv("A2A_API_KEYS_JSON", json.dumps({
            "admin": "admin-api-key-secret",
            "lambda": "lambda-api-key-secret",
            "orchestrator": "orchestrator-api-key-secret",
            "viewer": "viewer-api-key-secret"
        }))
        
        from a2a_security import A2ASecurityManager
        return A2ASecurityManager(agent_id="test-agent")
    
    def test_api_key_auth_allowed_method(self, security_manager):
        """Test API key authentication with allowed method"""
        principal, ctx = security_manager.authenticate_and_authorize(
            headers={"X-API-Key": "admin-api-key-secret"},
            message_method="process_document",
            message_dict={"jsonrpc": "2.0", "method": "process_document", "params": {}, "id": "1"}
        )
        
        assert principal == "admin"
        assert ctx["mode"] == "api_key"
    
    def test_api_key_auth_denied_method(self, security_manager):
        """Test API key authentication with denied method"""
        from a2a_security import ForbiddenError
        
        # Viewer tries to call process_document (not allowed)
        with pytest.raises(ForbiddenError):
            security_manager.authenticate_and_authorize(
                headers={"X-API-Key": "viewer-api-key-secret"},
                message_method="process_document",
                message_dict={"jsonrpc": "2.0", "method": "process_document", "params": {}, "id": "1"}
            )
    
    def test_rate_limiting_in_auth_flow(self, security_manager, monkeypatch):
        """Test rate limiting is enforced in auth flow"""
        from a2a_security import ForbiddenError
        
        # Set very low rate limit for testing
        monkeypatch.setenv("A2A_RATE_LIMIT_PER_MINUTE", "3")
        
        # Recreate security manager with new rate limit
        from a2a_security import A2ASecurityManager
        security_manager = A2ASecurityManager(agent_id="test-agent")
        
        headers = {"X-API-Key": "admin-api-key-secret"}
        message = {"jsonrpc": "2.0", "method": "list_skills", "params": {}, "id": "1"}
        
        # First 3 requests should succeed
        for i in range(3):
            principal, ctx = security_manager.authenticate_and_authorize(
                headers=headers,
                message_method="list_skills",
                message_dict=message
            )
            assert principal == "admin"
        
        # 4th request should be rate limited
        with pytest.raises(ForbiddenError) as exc_info:
            security_manager.authenticate_and_authorize(
                headers=headers,
                message_method="list_skills",
                message_dict=message
            )
        
        assert "Rate limit" in str(exc_info.value)
    
    def test_missing_auth_rejected(self, security_manager):
        """Test missing authentication is rejected"""
        from a2a_security import AuthError
        
        with pytest.raises(AuthError):
            security_manager.authenticate_and_authorize(
                headers={},
                message_method="list_skills",
                message_dict={"jsonrpc": "2.0", "method": "list_skills", "params": {}, "id": "1"}
            )


# ============================================================================
# TEST 7: TOKEN REVOCATION
# ============================================================================

class TestTokenRevocation:
    """Test JWT token revocation functionality"""
    
    @pytest.fixture
    def revocation_list(self):
        from a2a_security_enhanced import TokenRevocationList
        return TokenRevocationList(db_pool=None)  # In-memory only
    
    @pytest.mark.asyncio
    async def test_revoke_token(self, revocation_list):
        """Test token revocation"""
        jti = "test-token-jti-123"
        reason = "Compromised credentials"
        revoked_by = "admin"
        
        success = await revocation_list.revoke_token(jti, reason, revoked_by)
        assert success is True
        
        # Check if revoked
        is_revoked = await revocation_list.is_revoked(jti)
        assert is_revoked is True
    
    @pytest.mark.asyncio
    async def test_non_revoked_token_allowed(self, revocation_list):
        """Test non-revoked token is allowed"""
        jti = "valid-token-jti-456"
        
        is_revoked = await revocation_list.is_revoked(jti)
        assert is_revoked is False
    
    @pytest.mark.asyncio
    async def test_expired_revocation_cleaned(self, revocation_list):
        """Test expired revocations are cleaned up"""
        jti = "expired-revoked-token"
        
        # Revoke with past expiry
        expires_at = datetime.utcnow() - timedelta(hours=1)
        await revocation_list.revoke_token(jti, "test", "admin", expires_at)
        
        # Should not be revoked (expired)
        is_revoked = await revocation_list.is_revoked(jti)
        assert is_revoked is False


# ============================================================================
# TEST 8: HMAC REQUEST SIGNING
# ============================================================================

class TestHMACRequestSigning:
    """Test HMAC request signing for message integrity"""
    
    @pytest.fixture
    def signer(self):
        from a2a_security_enhanced import RequestSigner, generate_signature_secret
        secret = generate_signature_secret(64)
        return RequestSigner(secret)
    
    def test_sign_and_verify(self, signer):
        """Test successful signing and verification"""
        method = "POST"
        path = "/message"
        body = b'{"jsonrpc":"2.0","method":"process_document","params":{},"id":"1"}'
        
        signature = signer.sign_request(method, path, body)
        assert signature is not None
        assert ":" in signature  # Format: timestamp:signature
        
        is_valid, error = signer.verify_signature(signature, method, path, body)
        assert is_valid is True
        assert error is None
    
    def test_tampered_body_rejected(self, signer):
        """Test tampering with body is detected"""
        method = "POST"
        path = "/message"
        body = b'{"jsonrpc":"2.0","method":"process_document","params":{},"id":"1"}'
        
        signature = signer.sign_request(method, path, body)
        
        # Tamper with body
        tampered_body = b'{"jsonrpc":"2.0","method":"evil_method","params":{},"id":"1"}'
        
        is_valid, error = signer.verify_signature(signature, method, path, tampered_body)
        assert is_valid is False
        assert "Invalid signature" in error
    
    def test_tampered_path_rejected(self, signer):
        """Test tampering with path is detected"""
        method = "POST"
        path = "/message"
        body = b'{"jsonrpc":"2.0","method":"test","params":{},"id":"1"}'
        
        signature = signer.sign_request(method, path, body)
        
        # Tamper with path
        is_valid, error = signer.verify_signature(signature, method, "/admin", body)
        assert is_valid is False
    
    def test_expired_signature_rejected(self, signer):
        """Test expired signature is rejected"""
        method = "POST"
        path = "/message"
        body = b'{"jsonrpc":"2.0","method":"test","params":{},"id":"1"}'
        
        # Sign with old timestamp
        old_timestamp = int(time.time()) - 400
        signature = signer.sign_request(method, path, body, timestamp=old_timestamp)
        
        is_valid, error = signer.verify_signature(signature, method, path, body, max_age_seconds=300)
        assert is_valid is False
        assert "too old" in error.lower()


# ============================================================================
# INTEGRATION TESTS (Require Real Keycloak)
# ============================================================================

@pytest.mark.integration
class TestKeycloakIntegration:
    """Integration tests requiring actual Keycloak server"""
    
    @pytest.fixture
    def keycloak_url(self):
        url = os.getenv("KEYCLOAK_URL")
        if not url:
            pytest.skip("KEYCLOAK_URL environment variable not set")
        return url
    
    @pytest.fixture
    def keycloak_realm(self):
        return os.getenv("KEYCLOAK_REALM", "ca-a2a")
    
    @pytest.fixture
    def keycloak_client_id(self):
        return os.getenv("KEYCLOAK_CLIENT_ID", "ca-a2a-agents")
    
    def test_keycloak_server_reachable(self, keycloak_url, keycloak_realm):
        """Test Keycloak server is reachable"""
        import requests
        
        well_known_url = f"{keycloak_url}/realms/{keycloak_realm}/.well-known/openid-configuration"
        
        response = requests.get(well_known_url, timeout=10)
        assert response.status_code == 200
        
        config = response.json()
        assert "issuer" in config
        assert "token_endpoint" in config
        assert "jwks_uri" in config
    
    def test_keycloak_jwks_endpoint(self, keycloak_url, keycloak_realm):
        """Test JWKS endpoint is accessible"""
        import requests
        
        jwks_url = f"{keycloak_url}/realms/{keycloak_realm}/protocol/openid-connect/certs"
        
        response = requests.get(jwks_url, timeout=10)
        assert response.status_code == 200
        
        jwks = response.json()
        assert "keys" in jwks
        assert len(jwks["keys"]) > 0
    
    @pytest.mark.skip(reason="Requires valid credentials")
    def test_full_keycloak_auth_flow(
        self, 
        keycloak_url, 
        keycloak_realm, 
        keycloak_client_id
    ):
        """Test full authentication flow with Keycloak"""
        from keycloak_auth import KeycloakAuthClient, KeycloakJWTValidator
        
        # Get credentials from environment
        username = os.getenv("KEYCLOAK_TEST_USERNAME")
        password = os.getenv("KEYCLOAK_TEST_PASSWORD")
        client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET")
        
        if not username or not password:
            pytest.skip("Test credentials not configured")
        
        # Authenticate
        auth_client = KeycloakAuthClient(
            keycloak_url=keycloak_url,
            realm=keycloak_realm,
            client_id=keycloak_client_id,
            client_secret=client_secret
        )
        
        access_token, refresh_token, expires_in = auth_client.authenticate_password(
            username=username,
            password=password
        )
        
        assert access_token is not None
        assert expires_in > 0
        
        # Verify token
        validator = KeycloakJWTValidator(
            keycloak_url=keycloak_url,
            realm=keycloak_realm,
            client_id=keycloak_client_id
        )
        
        principal, roles, claims = validator.verify_token(access_token)
        
        assert principal is not None
        assert len(roles) > 0


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

class TestSecurityPerformance:
    """Test performance impact of security features"""
    
    def test_rate_limiter_performance(self):
        """Test rate limiter performance (should be < 0.1ms per check)"""
        from a2a_security import SlidingWindowRateLimiter
        
        limiter = SlidingWindowRateLimiter(limit=1000, window_seconds=60)
        
        start = time.perf_counter()
        iterations = 1000
        
        for i in range(iterations):
            limiter.allow(f"user-{i % 10}")
        
        elapsed = time.perf_counter() - start
        avg_time = elapsed / iterations
        
        assert avg_time < 0.0001  # Less than 0.1ms per check
        print(f"Average rate limiter check time: {avg_time*1000:.4f}ms")
    
    def test_replay_protector_performance(self):
        """Test replay protector performance"""
        from a2a_security import ReplayProtector
        
        protector = ReplayProtector(ttl_seconds=120)
        
        now = int(time.time())
        start = time.perf_counter()
        iterations = 1000
        
        for i in range(iterations):
            protector.check_and_store(f"nonce-{i}", now + 60)
        
        elapsed = time.perf_counter() - start
        avg_time = elapsed / iterations
        
        assert avg_time < 0.0001  # Less than 0.1ms per check
        print(f"Average replay check time: {avg_time*1000:.4f}ms")
    
    def test_schema_validation_performance(self):
        """Test schema validation performance"""
        from a2a_security_enhanced import JSONSchemaValidator
        
        validator = JSONSchemaValidator()
        if not validator.enabled:
            pytest.skip("jsonschema not installed")
        
        params = {
            "s3_key": "invoices/2026/01/test.pdf",
            "priority": "normal"
        }
        
        start = time.perf_counter()
        iterations = 100
        
        for _ in range(iterations):
            validator.validate("process_document", params)
        
        elapsed = time.perf_counter() - start
        avg_time = elapsed / iterations
        
        assert avg_time < 0.005  # Less than 5ms per validation
        print(f"Average schema validation time: {avg_time*1000:.3f}ms")


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])

