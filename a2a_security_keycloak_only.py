"""
A2A Security Utilities - Keycloak OAuth2 Only

Modern OAuth2/OIDC authentication with Keycloak.

Implements:
- Keycloak JWT validation (RS256) via JWKS endpoint
- Dynamic RBAC from Keycloak roles
- Replay protection (JWT jti / nonce cache with TTL)
- Rate limiting (sliding window, in-memory)

Removed (legacy):
- API Key authentication
- Legacy JWT (HS256) with shared secrets

Notes:
- In production, move replay + rate limit state to Redis/DynamoDB.
- All users must authenticate via Keycloak OAuth2/OIDC
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import logging

logger = logging.getLogger(__name__)

# Keycloak integration (required)
try:
    from keycloak_auth import KeycloakJWTValidator, KeycloakRBACMapper
    KEYCLOAK_AVAILABLE = True
except ImportError:
    KEYCLOAK_AVAILABLE = False
    logger.error("CRITICAL: keycloak_auth module not found. Keycloak is required for authentication.")
    raise RuntimeError("Keycloak authentication module (keycloak_auth.py) is required but not available")


class AuthError(Exception):
    """Authentication failed"""
    pass


class ForbiddenError(Exception):
    """Authorization failed"""
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


class A2ASecurityManager:
    """
    OAuth2/OIDC security manager using Keycloak.
    
    All authentication is handled via Keycloak JWT tokens.
    Dynamic RBAC from Keycloak roles.
    """

    def __init__(self, agent_id: str):
        self.agent_id = _normalize_agent_id(agent_id)

        # Feature flags
        self.enable_rate_limit = os.getenv("A2A_ENABLE_RATE_LIMIT", "true").lower() == "true"
        self.enable_replay_protection = os.getenv("A2A_ENABLE_REPLAY_PROTECTION", "true").lower() == "true"

        # Keycloak OAuth2/OIDC (REQUIRED)
        keycloak_url = os.getenv("KEYCLOAK_URL")
        keycloak_realm = os.getenv("KEYCLOAK_REALM", "ca-a2a")
        keycloak_client_id = os.getenv("KEYCLOAK_CLIENT_ID", "ca-a2a-agents")
        
        if not keycloak_url:
            raise ValueError("KEYCLOAK_URL environment variable is required")
        
        self.keycloak_validator = KeycloakJWTValidator(
            keycloak_url=keycloak_url,
            realm=keycloak_realm,
            client_id=keycloak_client_id,
            cache_ttl=int(os.getenv("KEYCLOAK_CACHE_TTL", "3600"))
        )
        
        self.keycloak_rbac_mapper = KeycloakRBACMapper()
        logger.info(f"Keycloak OAuth2 authentication initialized for realm: {keycloak_realm}")

        # Rate limiter
        self.rate_limiter = SlidingWindowRateLimiter(
            limit=int(os.getenv("A2A_RATE_LIMIT_PER_MINUTE", "300")),
            window_seconds=60,
        )
        
        # Replay protection
        self.replay = ReplayProtector(ttl_seconds=int(os.getenv("A2A_REPLAY_TTL_SECONDS", "120")))

    def body_hash(self, message_dict: Dict[str, Any]) -> str:
        """Stable JSON serialization for hash binding"""
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
        Authenticate via Keycloak JWT and authorize method access.
        
        Returns: (principal, auth_context)
        Raises: AuthError / ForbiddenError
        """
        method = message_method or ""

        # Authenticate via Keycloak JWT
        principal, ctx = self._authenticate_keycloak(headers=headers, method=method, message_dict=message_dict)

        # Rate limiting
        if self.enable_rate_limit:
            allowed, meta = self.rate_limiter.allow(principal)
            if not allowed:
                raise ForbiddenError(f"Rate limit exceeded (limit={meta['limit']}/min)")
            ctx["rate_limit"] = meta

        # RBAC authorization (from Keycloak roles)
        if method:
            allowed_methods = ctx.get("allowed_methods", [])
            if "*" not in allowed_methods and method not in allowed_methods:
                raise ForbiddenError(
                    f"User '{ctx.get('username')}' with role(s) {ctx.get('keycloak_roles')} "
                    f"not permitted to call method '{method}'. Allowed: {allowed_methods}"
                )

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
        
        Useful for non-JSON-RPC endpoints like GET /card and GET /skills.
        
        - If allow_anonymous=True => returns ("anonymous", {"mode":"anonymous"}) on missing/invalid credentials
        - Otherwise raises AuthError
        """
        try:
            return self._authenticate_keycloak(
                headers=headers,
                method=method or "",
                message_dict=message_dict or {},
            )
        except (AuthError, ForbiddenError):
            if allow_anonymous:
                return "anonymous", {"mode": "anonymous"}
            raise

    def is_allowed(self, principal: str, method: str, auth_context: Dict[str, Any]) -> bool:
        """Check if principal is allowed to call method based on Keycloak roles"""
        allowed_methods = auth_context.get("allowed_methods", [])
        return "*" in allowed_methods or method in allowed_methods

    def filter_visible_methods(self, principal: str, methods: list[str], auth_context: Dict[str, Any]) -> list[str]:
        """
        Return the subset of `methods` visible/allowed for `principal` based on Keycloak RBAC.
        """
        allowed_methods = auth_context.get("allowed_methods", [])
        if "*" in allowed_methods:
            return list(methods)
        return [m for m in methods if m in allowed_methods]

    def _authenticate_keycloak(
        self, 
        *, 
        headers: Dict[str, str], 
        method: str, 
        message_dict: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Authenticate using Keycloak JWT token.
        
        Returns: (principal, auth_context)
        Raises: AuthError
        """
        auth_header = headers.get("Authorization", "") or headers.get("authorization", "")

        if not auth_header.lower().startswith("bearer "):
            raise AuthError("Missing Authorization header. Expected: Bearer <keycloak-jwt-token>")

        token = auth_header.split(" ", 1)[1].strip()

        # Validate JWT via Keycloak JWKS
        try:
            username, keycloak_roles, claims = self.keycloak_validator.verify_token(token)
        except Exception as e:
            raise AuthError(f"Invalid Keycloak JWT: {e}")

        # Replay protection (check jti claim)
        if self.enable_replay_protection:
            jti = claims.get("jti")
            exp = claims.get("exp", _now() + 300)
            if not jti or not self.replay.check_and_store(jti, exp):
                raise AuthError("Token replay detected or missing jti")

        # Map Keycloak roles to A2A RBAC principal and allowed methods
        principal, allowed_methods = self.keycloak_rbac_mapper.map_roles_to_principal(keycloak_roles)

        # Build auth context
        auth_context = {
            "mode": "keycloak_oauth2",
            "username": username,
            "keycloak_roles": keycloak_roles,
            "rbac_principal": principal,
            "allowed_methods": allowed_methods,
            "token_claims": claims,
            "subject": claims.get("sub"),
            "issuer": claims.get("iss"),
            "audience": claims.get("aud"),
            "expires_at": claims.get("exp"),
            "issued_at": claims.get("iat"),
        }

        logger.info(
            f"Keycloak authentication successful: user={username}, roles={keycloak_roles}, "
            f"principal={principal}, allowed_methods={allowed_methods}"
        )

        return principal, auth_context


# Backwards compatibility alias (will be removed in future versions)
KeycloakSecurityManager = A2ASecurityManager
