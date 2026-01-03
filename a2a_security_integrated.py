"""
Extended A2A Security Manager with Enhanced Features

Integrates:
- HMAC request signing
- JSON Schema validation  
- Token revocation
- mTLS authentication

This extends the base A2ASecurityManager with additional security features.
"""

import os
import logging
from typing import Dict, Any, Optional, Tuple

from a2a_security import A2ASecurityManager, AuthError, ForbiddenError
from a2a_security_enhanced import (
    RequestSigner,
    JSONSchemaValidator,
    TokenRevocationList,
    MTLSAuthenticator,
)

logger = logging.getLogger(__name__)


class EnhancedA2ASecurityManager(A2ASecurityManager):
    """
    Enhanced security manager with additional features from research paper.
    """
    
    def __init__(self, agent_id: str, db_pool=None):
        # Initialize base security manager
        super().__init__(agent_id)
        
        # Enhanced features configuration
        self.enable_hmac = os.getenv("A2A_ENABLE_HMAC_SIGNING", "false").lower() == "true"
        self.enable_schema_validation = os.getenv("A2A_ENABLE_SCHEMA_VALIDATION", "true").lower() == "true"
        self.enable_token_revocation = os.getenv("A2A_ENABLE_TOKEN_REVOCATION", "true").lower() == "true"
        self.enable_mtls = os.getenv("A2A_ENABLE_MTLS", "false").lower() == "true"
        
        # Initialize HMAC signer
        hmac_secret = os.getenv("A2A_HMAC_SECRET_KEY")
        if self.enable_hmac and hmac_secret:
            try:
                self.hmac_signer = RequestSigner(hmac_secret)
                logger.info("HMAC request signing enabled")
            except Exception as e:
                logger.error(f"Failed to initialize HMAC signer: {e}")
                self.hmac_signer = None
                self.enable_hmac = False
        else:
            self.hmac_signer = None
            if self.enable_hmac:
                logger.warning("HMAC enabled but no secret key configured (A2A_HMAC_SECRET_KEY)")
                self.enable_hmac = False
        
        # Initialize JSON Schema validator
        if self.enable_schema_validation:
            try:
                self.schema_validator = JSONSchemaValidator()
                if self.schema_validator.enabled:
                    logger.info("JSON Schema validation enabled")
                else:
                    logger.warning("JSON Schema validation requested but jsonschema not installed")
                    self.enable_schema_validation = False
            except Exception as e:
                logger.error(f"Failed to initialize schema validator: {e}")
                self.schema_validator = None
                self.enable_schema_validation = False
        else:
            self.schema_validator = None
        
        # Initialize token revocation list
        if self.enable_token_revocation:
            try:
                self.revocation_list = TokenRevocationList(db_pool=db_pool)
                logger.info(f"Token revocation enabled (db_pool={'configured' if db_pool else 'not configured'})")
            except Exception as e:
                logger.error(f"Failed to initialize revocation list: {e}")
                self.revocation_list = None
                self.enable_token_revocation = False
        else:
            self.revocation_list = None
        
        # Initialize mTLS authenticator
        if self.enable_mtls:
            ca_cert_path = os.getenv("A2A_MTLS_CA_CERT_PATH")
            if ca_cert_path:
                try:
                    self.mtls_auth = MTLSAuthenticator(ca_cert_path)
                    if self.mtls_auth.enabled:
                        logger.info("mTLS certificate authentication enabled")
                    else:
                        logger.warning("mTLS enabled but CA certificate not loaded")
                        self.enable_mtls = False
                except Exception as e:
                    logger.error(f"Failed to initialize mTLS authenticator: {e}")
                    self.mtls_auth = None
                    self.enable_mtls = False
            else:
                logger.warning("mTLS enabled but no CA certificate path configured (A2A_MTLS_CA_CERT_PATH)")
                self.mtls_auth = None
                self.enable_mtls = False
        else:
            self.mtls_auth = None
        
        # Log enabled features
        features = []
        if self.require_auth:
            features.append("Authentication")
        if self.enable_rate_limit:
            features.append("Rate Limiting")
        if self.enable_replay_protection:
            features.append("Replay Protection")
        if self.enable_hmac:
            features.append("HMAC Signing")
        if self.enable_schema_validation:
            features.append("Schema Validation")
        if self.enable_token_revocation:
            features.append("Token Revocation")
        if self.enable_mtls:
            features.append("mTLS")
        
        logger.info(f"Security features enabled for {agent_id}: {', '.join(features) if features else 'None'}")
    
    async def authenticate_and_authorize_enhanced(
        self,
        *,
        headers: Dict[str, str],
        message_method: Optional[str],
        message_dict: Dict[str, Any],
        raw_body: bytes,
        request_path: str = "/message"
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Extended authentication with HMAC, schema validation, and revocation checks.
        
        Returns: (principal, auth_context)
        Raises: AuthError / ForbiddenError
        """
        
        # 1. HMAC signature verification (if enabled)
        if self.enable_hmac and self.hmac_signer:
            signature = headers.get("X-Signature", "") or headers.get("X-HMAC-Signature", "")
            if not signature:
                raise AuthError("HMAC signature required but not provided (X-Signature header)")
            
            method = "POST"  # A2A always uses POST
            is_valid, error = self.hmac_signer.verify_signature(
                signature,
                method,
                request_path,
                raw_body,
                max_age_seconds=int(os.getenv("A2A_HMAC_MAX_AGE_SECONDS", "300"))
            )
            if not is_valid:
                raise AuthError(f"HMAC signature verification failed: {error}")
            
            logger.debug("HMAC signature verified")
        
        # 2. Standard authentication (JWT/API key/mTLS)
        principal, auth_context = await self._authenticate_with_mtls(
            headers=headers,
            message_method=message_method,
            message_dict=message_dict
        )
        
        # 3. Token revocation check (for JWT)
        if self.enable_token_revocation and self.revocation_list and auth_context.get("mode") == "jwt":
            jti = auth_context.get("jti")
            if jti:
                is_revoked = await self.revocation_list.is_revoked(jti)
                if is_revoked:
                    raise ForbiddenError(f"Token has been revoked (jti={jti})")
                logger.debug(f"Token revocation check passed for jti={jti}")
        
        # 4. Rate limiting (from base class)
        if self.enable_rate_limit:
            allowed, meta = self.rate_limiter.allow(principal)
            if not allowed:
                raise ForbiddenError(f"Rate limit exceeded (limit={meta['limit']}/min)")
            auth_context["rate_limit"] = meta
        
        # 5. JSON Schema validation (if method params provided)
        if self.enable_schema_validation and self.schema_validator and message_method:
            params = message_dict.get("params", {})
            if params:
                is_valid, error = self.schema_validator.validate(message_method, params)
                if not is_valid:
                    raise ForbiddenError(f"Schema validation failed: {error}")
                logger.debug(f"Schema validation passed for method: {message_method}")
        
        # 6. RBAC authorization (from base class)
        if message_method:
            if not self._is_allowed(principal, message_method):
                raise ForbiddenError(f"Caller '{principal}' not allowed to call '{message_method}'")
        
        # Add enhanced security context
        auth_context["enhanced_security"] = {
            "hmac_verified": self.enable_hmac,
            "schema_validated": self.enable_schema_validation,
            "revocation_checked": self.enable_token_revocation,
            "mtls_enabled": self.enable_mtls
        }
        
        return principal, auth_context
    
    async def _authenticate_with_mtls(
        self,
        *,
        headers: Dict[str, str],
        message_method: str,
        message_dict: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Authenticate with mTLS support.
        """
        
        # Try mTLS first if enabled
        if self.enable_mtls and self.mtls_auth:
            cert_pem = headers.get("X-Client-Certificate", "").encode('utf-8')
            if cert_pem:
                is_valid, cert_info, error = self.mtls_auth.verify_certificate(cert_pem)
                if is_valid and cert_info:
                    principal = self.mtls_auth.extract_principal_from_cert(cert_info)
                    logger.info(f"mTLS authentication successful: {principal}")
                    return principal, {
                        "mode": "mtls",
                        "certificate": {
                            "subject": cert_info.subject,
                            "issuer": cert_info.issuer,
                            "fingerprint": cert_info.fingerprint,
                            "not_after": cert_info.not_after.isoformat()
                        }
                    }
                else:
                    logger.warning(f"mTLS authentication failed: {error}")
                    # Fall through to JWT/API key
        
        # Fall back to standard authentication (JWT or API key)
        return self.authenticate_and_authorize(
            headers=headers,
            message_method=message_method,
            message_dict=message_dict
        )
    
    async def revoke_token(self, jti: str, reason: str, revoked_by: str) -> bool:
        """
        Revoke a JWT token.
        
        Returns: True if successful
        """
        if not self.enable_token_revocation or not self.revocation_list:
            logger.warning("Token revocation not enabled")
            return False
        
        return await self.revocation_list.revoke_token(jti, reason, revoked_by)
    
    async def get_revoked_tokens(self, limit: int = 100):
        """Get list of revoked tokens (for admin)"""
        if not self.enable_token_revocation or not self.revocation_list:
            return []
        
        return await self.revocation_list.get_revoked_tokens(limit)
    
    def sign_outgoing_request(
        self,
        method: str,
        path: str,
        body: bytes
    ) -> Optional[str]:
        """
        Generate HMAC signature for outgoing request.
        
        Returns: Signature string to include in X-Signature header, or None if HMAC disabled
        """
        if not self.enable_hmac or not self.hmac_signer:
            return None
        
        try:
            signature = self.hmac_signer.sign_request(method, path, body)
            return signature
        except Exception as e:
            logger.error(f"Failed to sign outgoing request: {e}")
            return None


__all__ = ['EnhancedA2ASecurityManager']

