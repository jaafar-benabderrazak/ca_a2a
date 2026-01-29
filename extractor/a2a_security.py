"""
A2A Security Utilities

Implements:
- JWT-based authentication (RS256 recommended) for agent-to-agent traffic
- API-key authentication (useful for external client -> orchestrator)
- RBAC authorization (caller -> allowed JSON-RPC methods)
- Replay protection (JWT jti / nonce cache with TTL)
- Rate limiting (sliding window, in-memory)

Notes:
- In production, move replay + rate limit state to Redis/DynamoDB.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import logging

logger = logging.getLogger(__name__)

# Optional Keycloak integration
try:
    from keycloak_auth import KeycloakJWTValidator, KeycloakRBACMapper
    KEYCLOAK_AVAILABLE = True
except ImportError:
    KEYCLOAK_AVAILABLE = False
    logger.debug("Keycloak integration not available (keycloak_auth.py not found)")


class AuthError(Exception):
    pass


class ForbiddenError(Exception):
    pass


def _now() -> int:
    return int(time.time())


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_agent_id(value: str) -> str:
    return (value or "").strip().lower()


def _parse_json_env(name: str, default: Any) -> Any:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception as e:
        logger.warning("Failed to parse %s as JSON: %s", name, str(e))
        return default


class SlidingWindowRateLimiter:
    """
    Simple in-memory sliding window rate limiter.
    """

    def __init__(self, limit: int, window_seconds: int, ttl_seconds: Optional[int] = None):
        self.limit = int(limit)
        self.window_seconds = int(window_seconds)
        self.ttl_seconds = int(ttl_seconds or max(window_seconds * 2, 120))
        self._events: Dict[str, list[int]] = {}

    def allow(self, key: str) -> Tuple[bool, Dict[str, Any]]:
        now = _now()
        window_start = now - self.window_seconds
        ev = self._events.get(key, [])
        ev = [t for t in ev if t >= window_start]

        allowed = len(ev) < self.limit
        if allowed:
            ev.append(now)

        self._events[key] = ev

        # Opportunistic cleanup (cheap)
        self._cleanup(now)

        reset_in = (ev[0] + self.window_seconds - now) if ev else self.window_seconds
        meta = {
            "limit": self.limit,
            "remaining": max(0, self.limit - len(ev)),
            "window_seconds": self.window_seconds,
            "reset_in_seconds": max(0, int(reset_in)),
        }
        return allowed, meta

    def _cleanup(self, now: int):
        cutoff = now - self.ttl_seconds
        dead = [k for k, ev in self._events.items() if not ev or ev[-1] < cutoff]
        for k in dead:
            self._events.pop(k, None)


class ReplayProtector:
    """
    Tracks seen nonces (JWT jti) for a limited time to block replays.
    """

    def __init__(self, ttl_seconds: int = 120):
        self.ttl_seconds = int(ttl_seconds)
        self._seen: Dict[str, int] = {}  # nonce -> exp_timestamp

    def check_and_store(self, nonce: str, exp: int) -> bool:
        now = _now()
        self._cleanup(now)
        if not nonce:
            return False
        if nonce in self._seen and self._seen[nonce] >= now:
            return False
        # Store until exp (bounded by ttl)
        self._seen[nonce] = min(exp, now + self.ttl_seconds)
        return True

    def _cleanup(self, now: int):
        dead = [k for k, v in self._seen.items() if v < now]
        for k in dead:
            self._seen.pop(k, None)


@dataclass(frozen=True)
class JwtAuthConfig:
    issuer: str
    audience: Optional[str]
    public_key_pem: Optional[str]
    private_key_pem: Optional[str]
    algorithm: str = "RS256"
    max_skew_seconds: int = 30
    max_token_age_seconds: int = 120


class A2ASecurityManager:
    """
    One place to enforce A2A security decisions.
    """

    def __init__(self, agent_id: str):
        self.agent_id = _normalize_agent_id(agent_id)

        # Feature flags / defaults
        # Default is OFF to keep local/dev flows working unless explicitly enabled.
        self.require_auth = os.getenv("A2A_REQUIRE_AUTH", "false").lower() == "true"
        self.enable_rate_limit = os.getenv("A2A_ENABLE_RATE_LIMIT", "true").lower() == "true"
        self.enable_replay_protection = os.getenv("A2A_ENABLE_REPLAY_PROTECTION", "true").lower() == "true"

        # Keycloak OAuth2/OIDC integration
        self.use_keycloak = os.getenv("A2A_USE_KEYCLOAK", "false").lower() == "true"
        self.keycloak_validator = None
        self.keycloak_rbac_mapper = None
        
        if self.use_keycloak:
            if not KEYCLOAK_AVAILABLE:
                raise RuntimeError("Keycloak authentication enabled but keycloak_auth module not available")
            
            keycloak_url = os.getenv("KEYCLOAK_URL")
            keycloak_realm = os.getenv("KEYCLOAK_REALM", "ca-a2a")
            keycloak_client_id = os.getenv("KEYCLOAK_CLIENT_ID", "ca-a2a-agents")
            
            if not keycloak_url:
                raise ValueError("KEYCLOAK_URL environment variable required when A2A_USE_KEYCLOAK=true")
            
            self.keycloak_validator = KeycloakJWTValidator(
                keycloak_url=keycloak_url,
                realm=keycloak_realm,
                client_id=keycloak_client_id,
                cache_ttl=int(os.getenv("KEYCLOAK_CACHE_TTL", "3600"))
            )
            
            self.keycloak_rbac_mapper = KeycloakRBACMapper()
            logger.info(f"Keycloak authentication enabled for realm: {keycloak_realm}")

        # RBAC policy: {"allow": {"caller": ["method1","method2","*"]}, "deny": {...}}
        self.rbac_policy = _parse_json_env("A2A_RBAC_POLICY_JSON", default={"allow": {}, "deny": {}})

        # API keys: {"principal": "plaintext-api-key", ...}
        self.api_keys = _parse_json_env("A2A_API_KEYS_JSON", default={})
        self._api_key_hashes = {
            principal: _sha256_hex(key.encode("utf-8"))
            for principal, key in self.api_keys.items()
            if isinstance(key, str) and key
        }

        # JWT configuration (prefer RS256 with distributed public key)
        self.jwt = JwtAuthConfig(
            issuer=os.getenv("A2A_JWT_ISSUER", "ca-a2a"),
            audience=self.agent_id,
            public_key_pem=os.getenv("A2A_JWT_PUBLIC_KEY_PEM"),
            private_key_pem=os.getenv("A2A_JWT_PRIVATE_KEY_PEM"),
            algorithm=os.getenv("A2A_JWT_ALG", "RS256"),
            max_skew_seconds=int(os.getenv("A2A_JWT_MAX_SKEW_SECONDS", "30")),
            max_token_age_seconds=int(os.getenv("A2A_JWT_MAX_TOKEN_AGE_SECONDS", "120")),
        )

        # Controls
        self.rate_limiter = SlidingWindowRateLimiter(
            limit=int(os.getenv("A2A_RATE_LIMIT_PER_MINUTE", "300")),
            window_seconds=60,
        )
        self.replay = ReplayProtector(ttl_seconds=int(os.getenv("A2A_REPLAY_TTL_SECONDS", "120")))

    def body_hash(self, message_dict: Dict[str, Any]) -> str:
        # Stable JSON serialization for hash binding
        raw = json.dumps(message_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return _sha256_hex(raw)

    def authenticate_and_authorize(
        self,
        *,
        headers: Dict[str, str],
        message_method: Optional[str],
        message_dict: Dict[str, Any],
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Returns (principal, auth_context).
        Raises AuthError / ForbiddenError.
        """
        method = message_method or ""

        if not self.require_auth:
            return "anonymous", {"mode": "disabled"}

        principal, ctx = self._authenticate(headers=headers, method=method, message_dict=message_dict)

        if self.enable_rate_limit:
            allowed, meta = self.rate_limiter.allow(principal)
            if not allowed:
                raise ForbiddenError(f"Rate limit exceeded (limit={meta['limit']}/min)")
            ctx["rate_limit"] = meta

        if method:
            # Check if we have Keycloak dynamic RBAC override
            if ctx.get("dynamic_rbac") and ctx.get("methods_override"):
                allowed_methods = ctx["methods_override"]
                if "*" not in allowed_methods and method not in allowed_methods:
                    raise ForbiddenError(f"Keycloak role does not permit method '{method}' (allowed: {allowed_methods})")
            else:
                # Use traditional RBAC policy
                if not self._is_allowed(principal, method):
                    raise ForbiddenError(f"Caller '{principal}' not allowed to call '{method}'")

        return principal, ctx

    def authenticate(
        self,
        *,
        headers: Dict[str, str],
        method: str = "",
        message_dict: Optional[Dict[str, Any]] = None,
        allow_anonymous: bool = False,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Authenticate only (no RBAC/rate-limit checks by default).

        Useful for non-JSON-RPC endpoints like GET /card and GET /skills where we only
        need identity to decide what to disclose.

        - If A2A_REQUIRE_AUTH=false => returns ("anonymous", {"mode":"disabled"})
        - If A2A_REQUIRE_AUTH=true and allow_anonymous=true => returns ("anonymous", {"mode":"anonymous"}) on missing/invalid credentials
        - Otherwise raises AuthError / ForbiddenError
        """
        if not self.require_auth:
            return "anonymous", {"mode": "disabled"}

        try:
            return self._authenticate(
                headers=headers,
                method=method or "",
                message_dict=message_dict or {},
            )
        except (AuthError, ForbiddenError):
            if allow_anonymous:
                return "anonymous", {"mode": "anonymous"}
            raise

    def is_allowed(self, principal: str, method: str) -> bool:
        """Public wrapper to reuse RBAC allow/deny rules elsewhere."""
        return self._is_allowed(principal, method)

    def filter_visible_methods(self, principal: str, methods: list[str]) -> list[str]:
        """
        Return the subset of `methods` visible/allowed for `principal` based on RBAC.
        """
        allow = (self.rbac_policy or {}).get("allow", {}) or {}
        allowed_methods = allow.get(principal, []) if isinstance(allow, dict) else []
        if "*" in allowed_methods:
            return list(methods)
        return [m for m in methods if self._is_allowed(principal, m)]

    def _authenticate(self, *, headers: Dict[str, str], method: str, message_dict: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        auth_header = headers.get("Authorization", "") or ""
        api_key_header = headers.get("X-API-Key", "") or ""

        # 1) JWT (preferred)
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()
            principal, ctx = self._verify_jwt(token=token, method=method, message_dict=message_dict)
            return principal, ctx

        # 2) API key (fallback, usually for external client -> orchestrator)
        candidate = ""
        if auth_header.lower().startswith("apikey "):
            candidate = auth_header.split(" ", 1)[1].strip()
        elif api_key_header:
            candidate = api_key_header.strip()

        if candidate:
            principal = self._verify_api_key(candidate)
            return principal, {"mode": "api_key"}

        raise AuthError("Missing Authorization (expected Bearer JWT or API key)")

    def _verify_api_key(self, api_key: str) -> str:
        if not self._api_key_hashes:
            raise AuthError("API key auth not configured")
        digest = _sha256_hex(api_key.encode("utf-8"))
        for principal, expected in self._api_key_hashes.items():
            if hmac.compare_digest(digest, expected):
                return principal
        raise AuthError("Invalid API key")

    def _verify_jwt(self, *, token: str, method: str, message_dict: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        # If Keycloak is enabled, use Keycloak JWT validation
        if self.use_keycloak and self.keycloak_validator:
            return self._verify_keycloak_jwt(token=token, method=method, message_dict=message_dict)
        
        # Otherwise use traditional JWT validation
        if not self.jwt.public_key_pem:
            raise AuthError("JWT public key not configured (A2A_JWT_PUBLIC_KEY_PEM)")

        try:
            import jwt  # PyJWT
        except Exception:
            raise AuthError("PyJWT not installed")

        # Verify signature + standard claims
        try:
            claims = jwt.decode(
                token,
                key=self.jwt.public_key_pem,
                algorithms=[self.jwt.algorithm],
                audience=self.jwt.audience,
                issuer=self.jwt.issuer,
                options={
                    "require": ["exp", "iat", "iss", "sub", "aud", "jti"],
                },
                leeway=self.jwt.max_skew_seconds,
            )
        except Exception as e:
            raise AuthError(f"Invalid JWT: {str(e)}")

        sub = _normalize_agent_id(str(claims.get("sub", "")))
        if not sub:
            raise AuthError("JWT missing sub")

        # Bind token to the request content/method to prevent token reuse across requests
        if method:
            token_method = str(claims.get("m", ""))
            if token_method and token_method != method:
                raise AuthError("JWT method binding mismatch")

        expected_bh = str(claims.get("bh", ""))
        if expected_bh:
            actual_bh = self.body_hash(message_dict)
            if expected_bh != actual_bh:
                raise AuthError("JWT body hash binding mismatch")

        # Freshness (defense-in-depth beyond exp)
        now = _now()
        iat = int(claims.get("iat", 0))
        if iat and (now - iat) > self.jwt.max_token_age_seconds:
            raise AuthError("JWT too old")

        # Replay protection on jti
        jti = str(claims.get("jti", "") or "")
        exp = int(claims.get("exp", 0) or 0)
        if self.enable_replay_protection:
            ok = self.replay.check_and_store(f"{sub}:{jti}", exp=exp or (now + self.replay.ttl_seconds))
            if not ok:
                raise ForbiddenError("Replay detected")

        return sub, {"mode": "jwt", "claims": {"sub": sub, "aud": claims.get("aud"), "jti": jti}}

    def _is_allowed(self, principal: str, method: str) -> bool:
        allow = (self.rbac_policy or {}).get("allow", {}) or {}
        deny = (self.rbac_policy or {}).get("deny", {}) or {}

        # Explicit deny wins
        denied_methods = deny.get(principal, []) if isinstance(deny, dict) else []
        if "*" in denied_methods or method in denied_methods:
            return False

        allowed_methods = allow.get(principal, []) if isinstance(allow, dict) else []
        if "*" in allowed_methods or method in allowed_methods:
            return True

        return False

    def can_sign_jwt(self) -> bool:
        return bool(self.jwt.private_key_pem)

    def sign_request_jwt(
        self,
        *,
        subject: str,
        audience: str,
        method: str,
        message_dict: Dict[str, Any],
        ttl_seconds: int = 60,
    ) -> str:
        """
        Create a short-lived request-bound JWT.
        """
        if not self.jwt.private_key_pem:
            raise AuthError("JWT private key not configured (A2A_JWT_PRIVATE_KEY_PEM)")

        try:
            import jwt  # PyJWT
        except Exception:
            raise AuthError("PyJWT not installed")

        now = _now()
        jti = _sha256_hex(f"{subject}:{audience}:{now}:{os.urandom(16).hex()}".encode("utf-8"))[:32]
        claims = {
            "iss": self.jwt.issuer,
            "sub": _normalize_agent_id(subject),
            "aud": _normalize_agent_id(audience),
            "iat": now,
            "exp": now + int(ttl_seconds),
            "jti": jti,
            # Bind to request content
            "m": method,
            "bh": self.body_hash(message_dict),
        }
        token = jwt.encode(claims, key=self.jwt.private_key_pem, algorithm=self.jwt.algorithm)
        return token

    def _verify_keycloak_jwt(self, *, token: str, method: str, message_dict: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """
        Verify JWT token issued by Keycloak.
        
        Returns:
            Tuple of (principal, auth_context)
        
        Raises:
            AuthError: If token is invalid
        """
        if not self.keycloak_validator:
            raise AuthError("Keycloak validator not initialized")
        
        try:
            # Verify token with Keycloak
            username, keycloak_roles, claims = self.keycloak_validator.verify_token(token)
            
            # Map Keycloak roles to A2A RBAC principal and permissions
            if self.keycloak_rbac_mapper:
                principal, allowed_methods = self.keycloak_rbac_mapper.map_roles_to_principal(keycloak_roles)
            else:
                principal = username
                allowed_methods = []
            
            # Build auth context
            ctx = {
                "mode": "keycloak_jwt",
                "username": username,
                "keycloak_roles": keycloak_roles,
                "rbac_principal": principal,
                "allowed_methods": allowed_methods,
                "token_exp": claims.get("exp"),
                "token_iat": claims.get("iat"),
                "token_sub": claims.get("sub"),
            }
            
            # Note: Replay protection with Keycloak tokens
            # Keycloak tokens have 'jti' claim which can be used for replay protection
            if self.enable_replay_protection:
                jti = claims.get("jti")
                exp = claims.get("exp", _now() + 300)
                if jti:
                    if not self.replay.check_and_store(jti, exp):
                        raise AuthError("Token replay detected (jti already seen)")
                    ctx["replay_protected"] = True
            
            # Update RBAC policy dynamically based on Keycloak roles
            # This allows Keycloak to be the source of truth for permissions
            if principal and allowed_methods:
                # Temporarily override RBAC for this request
                ctx["dynamic_rbac"] = True
                ctx["principal_override"] = principal
                ctx["methods_override"] = allowed_methods
            
            logger.info(f"Keycloak JWT verified: principal={principal}, roles={keycloak_roles}")
            
            return principal, ctx
            
        except Exception as e:
            logger.warning(f"Keycloak JWT verification failed: {e}")
            raise AuthError(f"Invalid Keycloak JWT: {str(e)}")

