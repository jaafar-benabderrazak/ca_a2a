"""
Enhanced A2A Security Features

Implements additional security mechanisms from research paper:
1. HMAC request signing for message integrity
2. JSON Schema validation for input validation
3. Token revocation system
4. mTLS certificate authentication support

Based on: "Securing Agent-to-Agent (A2A) Communications Across Domains"
"""

from __future__ import annotations

import hmac
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Tuple
from datetime import datetime, timedelta

import logging

logger = logging.getLogger(__name__)


# ============================================================================
# 1. HMAC REQUEST SIGNING
# ============================================================================

class RequestSigner:
    """
    HMAC-based request signing for message integrity protection.
    Prevents tampering and MITM attacks.
    """
    
    def __init__(self, secret_key: str):
        if not secret_key or len(secret_key) < 32:
            raise ValueError("Secret key must be at least 32 characters")
        self.secret_key = secret_key.encode('utf-8')
    
    def sign_request(
        self,
        method: str,
        path: str,
        body: bytes,
        timestamp: Optional[int] = None
    ) -> str:
        """
        Generate HMAC signature for a request.
        
        Signature includes:
        - HTTP method
        - Request path
        - Request body
        - Timestamp (for replay protection)
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        # Construct signing string
        signing_parts = [
            method.upper(),
            path,
            str(timestamp),
            body.decode('utf-8') if isinstance(body, bytes) else body
        ]
        signing_string = '\n'.join(signing_parts)
        
        # Generate HMAC-SHA256 signature
        signature = hmac.new(
            self.secret_key,
            signing_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return f"{timestamp}:{signature}"
    
    def verify_signature(
        self,
        signature_header: str,
        method: str,
        path: str,
        body: bytes,
        max_age_seconds: int = 300
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify HMAC signature.
        
        Returns: (is_valid, error_message)
        """
        try:
            # Parse signature header
            if ':' not in signature_header:
                return False, "Invalid signature format (expected timestamp:signature)"
            
            timestamp_str, provided_signature = signature_header.split(':', 1)
            timestamp = int(timestamp_str)
            
            # Check timestamp freshness (replay protection)
            now = int(time.time())
            age = now - timestamp
            if age > max_age_seconds:
                return False, f"Signature too old ({age}s > {max_age_seconds}s)"
            if age < -30:  # Allow 30s clock skew
                return False, "Signature from future (clock skew)"
            
            # Compute expected signature
            signing_parts = [
                method.upper(),
                path,
                str(timestamp),
                body.decode('utf-8') if isinstance(body, bytes) else body
            ]
            signing_string = '\n'.join(signing_parts)
            
            expected_signature = hmac.new(
                self.secret_key,
                signing_string.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            # Constant-time comparison
            if not hmac.compare_digest(provided_signature, expected_signature):
                return False, "Invalid signature"
            
            return True, None
            
        except Exception as e:
            logger.warning(f"Signature verification error: {e}")
            return False, f"Signature verification failed: {str(e)}"


# ============================================================================
# 2. JSON SCHEMA VALIDATION
# ============================================================================

class JSONSchemaValidator:
    """
    Validates JSON-RPC method parameters against predefined schemas.
    Prevents injection attacks and malformed data.
    """
    
    # Define schemas for all agent methods
    SCHEMAS = {
        "process_document": {
            "type": "object",
            "properties": {
                "s3_key": {
                    "type": "string",
                    "pattern": "^[a-zA-Z0-9/_-][a-zA-Z0-9/_.-]*$",  # Must not start with dot, no path traversal
                    "not": {"pattern": "\\.\\."},  # Reject ../ patterns
                    "minLength": 1,
                    "maxLength": 1024
                },
                "priority": {
                    "type": "string",
                    "enum": ["low", "normal", "high"]
                },
                "correlation_id": {
                    "type": "string",
                    "pattern": "^[a-zA-Z0-9-]+$",
                    "maxLength": 128
                }
            },
            "required": ["s3_key"],
            "additionalProperties": False
        },
        
        "extract_document": {
            "type": "object",
            "properties": {
                "s3_key": {
                    "type": "string",
                    "pattern": "^[a-zA-Z0-9/_-][a-zA-Z0-9/_.-]*$",
                    "not": {"pattern": "\\.\\."},
                    "minLength": 1,
                    "maxLength": 1024
                },
                "correlation_id": {
                    "type": "string",
                    "maxLength": 128
                }
            },
            "required": ["s3_key"],
            "additionalProperties": False
        },
        
        "validate_document": {
            "type": "object",
            "properties": {
                "extracted_data": {
                    "type": "object"
                },
                "s3_key": {
                    "type": "string",
                    "maxLength": 1024
                },
                "correlation_id": {
                    "type": "string",
                    "maxLength": 128
                }
            },
            "required": ["extracted_data"],
            "additionalProperties": False
        },
        
        "archive_document": {
            "type": "object",
            "properties": {
                "s3_key": {
                    "type": "string",
                    "maxLength": 1024
                },
                "extracted_data": {
                    "type": "object"
                },
                "validation_result": {
                    "type": "object"
                },
                "correlation_id": {
                    "type": "string",
                    "maxLength": 128
                }
            },
            "required": ["s3_key", "extracted_data", "validation_result"],
            "additionalProperties": False
        },
        
        "get_document": {
            "type": "object",
            "properties": {
                "document_id": {
                    "type": "integer",
                    "minimum": 1
                }
            },
            "required": ["document_id"],
            "additionalProperties": False
        }
    }
    
    def __init__(self):
        try:
            import jsonschema
            self.validator = jsonschema
            self.enabled = True
        except ImportError:
            logger.warning("jsonschema not installed, validation disabled")
            self.enabled = False
    
    def validate(self, method: str, params: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Validate method parameters against schema.
        
        Returns: (is_valid, error_message)
        """
        if not self.enabled:
            return True, None
        
        schema = self.SCHEMAS.get(method)
        if not schema:
            # No schema defined = allow (backwards compatibility)
            return True, None
        
        try:
            self.validator.validate(instance=params, schema=schema)
            return True, None
        except self.validator.ValidationError as e:
            error_msg = f"Schema validation failed: {e.message}"
            logger.warning(f"Method {method} validation error: {error_msg}")
            return False, error_msg
        except Exception as e:
            logger.error(f"Unexpected validation error: {e}")
            return False, f"Validation error: {str(e)}"


# ============================================================================
# 3. TOKEN REVOCATION SYSTEM
# ============================================================================

@dataclass
class RevokedToken:
    """Represents a revoked JWT token"""
    jti: str
    revoked_at: datetime
    revoked_by: str
    reason: str
    expires_at: datetime


class TokenRevocationList:
    """
    Manages revoked JWT tokens.
    
    Supports both in-memory (dev) and database-backed (prod) storage.
    """
    
    def __init__(self, db_pool=None):
        self.db_pool = db_pool
        self._memory_cache: Dict[str, RevokedToken] = {}
        self._last_cleanup = time.time()
    
    async def revoke_token(
        self,
        jti: str,
        reason: str,
        revoked_by: str,
        expires_at: Optional[datetime] = None
    ) -> bool:
        """
        Add token to revocation list.
        
        Args:
            jti: JWT ID (jti claim)
            reason: Reason for revocation
            revoked_by: Who revoked the token
            expires_at: When the token expires (for cleanup)
        """
        if expires_at is None:
            expires_at = datetime.utcnow() + timedelta(days=30)
        
        revoked = RevokedToken(
            jti=jti,
            revoked_at=datetime.utcnow(),
            revoked_by=revoked_by,
            reason=reason,
            expires_at=expires_at
        )
        
        # Store in memory cache
        self._memory_cache[jti] = revoked
        
        # Store in database if available
        if self.db_pool:
            try:
                async with self.db_pool.acquire() as conn:
                    await conn.execute('''
                        INSERT INTO revoked_tokens (jti, revoked_at, revoked_by, reason, expires_at)
                        VALUES ($1, $2, $3, $4, $5)
                        ON CONFLICT (jti) DO UPDATE
                        SET revoked_at = EXCLUDED.revoked_at,
                            reason = EXCLUDED.reason
                    ''', jti, revoked.revoked_at, revoked_by, reason, expires_at)
                logger.info(f"Token {jti} revoked in database: {reason}")
                return True
            except Exception as e:
                logger.error(f"Failed to revoke token in database: {e}")
                # Continue with memory cache
        
        logger.info(f"Token {jti} revoked in memory cache: {reason}")
        return True
    
    async def is_revoked(self, jti: str) -> bool:
        """
        Check if token is revoked.
        """
        # Check memory cache first (fast)
        if jti in self._memory_cache:
            revoked = self._memory_cache[jti]
            if revoked.expires_at > datetime.utcnow():
                return True
            else:
                # Expired, remove from cache
                del self._memory_cache[jti]
        
        # Check database if available
        if self.db_pool:
            try:
                async with self.db_pool.acquire() as conn:
                    result = await conn.fetchrow('''
                        SELECT jti, expires_at FROM revoked_tokens
                        WHERE jti = $1 AND expires_at > NOW()
                    ''', jti)
                    if result:
                        # Cache for future checks
                        self._memory_cache[jti] = RevokedToken(
                            jti=result['jti'],
                            revoked_at=datetime.utcnow(),
                            revoked_by="db",
                            reason="cached from db",
                            expires_at=result['expires_at']
                        )
                        return True
            except Exception as e:
                logger.error(f"Failed to check revocation in database: {e}")
        
        # Periodic cleanup
        self._cleanup_expired()
        
        return False
    
    def _cleanup_expired(self):
        """Remove expired tokens from memory cache"""
        now = time.time()
        if now - self._last_cleanup < 300:  # Cleanup every 5 minutes
            return
        
        self._last_cleanup = now
        now_dt = datetime.utcnow()
        expired = [jti for jti, rev in self._memory_cache.items() if rev.expires_at <= now_dt]
        for jti in expired:
            del self._memory_cache[jti]
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired revoked tokens from cache")
    
    async def get_revoked_tokens(self, limit: int = 100) -> List[RevokedToken]:
        """Get list of currently revoked tokens (for admin UI)"""
        tokens = []
        
        # Get from database if available
        if self.db_pool:
            try:
                async with self.db_pool.acquire() as conn:
                    rows = await conn.fetch('''
                        SELECT jti, revoked_at, revoked_by, reason, expires_at
                        FROM revoked_tokens
                        WHERE expires_at > NOW()
                        ORDER BY revoked_at DESC
                        LIMIT $1
                    ''', limit)
                    tokens = [RevokedToken(**dict(row)) for row in rows]
            except Exception as e:
                logger.error(f"Failed to fetch revoked tokens: {e}")
        
        # Merge with memory cache
        memory_tokens = [
            rev for rev in self._memory_cache.values()
            if rev.expires_at > datetime.utcnow()
        ]
        
        # Combine and deduplicate
        all_tokens = {t.jti: t for t in (tokens + memory_tokens)}
        return sorted(all_tokens.values(), key=lambda t: t.revoked_at, reverse=True)[:limit]


# ============================================================================
# 4. mTLS CERTIFICATE AUTHENTICATION
# ============================================================================

@dataclass
class CertificateInfo:
    """Parsed certificate information"""
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    fingerprint: str


class MTLSAuthenticator:
    """
    Mutual TLS certificate-based authentication.
    
    Validates client certificates and extracts identity information.
    """
    
    def __init__(self, ca_cert_path: Optional[str] = None):
        self.ca_cert_path = ca_cert_path
        self.enabled = bool(ca_cert_path and os.path.exists(ca_cert_path))
        
        if self.enabled:
            try:
                from OpenSSL import crypto, SSL
                self.crypto = crypto
                self.SSL = SSL
                
                # Load CA certificate
                with open(ca_cert_path, 'rb') as f:
                    ca_cert_data = f.read()
                self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert_data)
                logger.info(f"mTLS enabled with CA: {ca_cert_path}")
            except ImportError:
                logger.warning("pyOpenSSL not installed, mTLS disabled")
                self.enabled = False
            except Exception as e:
                logger.error(f"Failed to load CA certificate: {e}")
                self.enabled = False
        else:
            logger.info("mTLS disabled (no CA certificate configured)")
    
    def verify_certificate(self, cert_pem: bytes) -> Tuple[bool, Optional[CertificateInfo], Optional[str]]:
        """
        Verify client certificate against CA.
        
        Returns: (is_valid, cert_info, error_message)
        """
        if not self.enabled:
            return False, None, "mTLS not enabled"
        
        try:
            # Parse certificate
            cert = self.crypto.load_certificate(self.crypto.FILETYPE_PEM, cert_pem)
            
            # Create certificate store with CA
            store = self.crypto.X509Store()
            store.add_cert(self.ca_cert)
            
            # Verify certificate
            store_ctx = self.crypto.X509StoreContext(store, cert)
            try:
                store_ctx.verify_certificate()
            except Exception as e:
                return False, None, f"Certificate verification failed: {str(e)}"
            
            # Check validity period
            now = datetime.utcnow()
            not_before = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
            not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
            
            if now < not_before:
                return False, None, "Certificate not yet valid"
            if now > not_after:
                return False, None, "Certificate expired"
            
            # Extract certificate information
            subject = cert.get_subject()
            issuer = cert.get_issuer()
            
            cert_info = CertificateInfo(
                subject=f"{subject.CN}" if hasattr(subject, 'CN') else str(subject),
                issuer=f"{issuer.CN}" if hasattr(issuer, 'CN') else str(issuer),
                serial_number=str(cert.get_serial_number()),
                not_before=not_before,
                not_after=not_after,
                fingerprint=cert.digest('sha256').decode('ascii')
            )
            
            logger.info(f"Certificate verified: {cert_info.subject}")
            return True, cert_info, None
            
        except Exception as e:
            logger.error(f"Certificate verification error: {e}")
            return False, None, f"Certificate verification error: {str(e)}"
    
    def extract_principal_from_cert(self, cert_info: CertificateInfo) -> str:
        """
        Extract principal/agent ID from certificate subject.
        
        Expected format: CN=agent-name or CN=orchestrator
        """
        subject = cert_info.subject
        if subject.startswith("CN="):
            return subject[3:].lower()
        return subject.lower()


# ============================================================================
# DATABASE SCHEMA FOR TOKEN REVOCATION
# ============================================================================

SQL_SCHEMA_REVOCATION = """
-- Table for revoked JWT tokens
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti VARCHAR(255) PRIMARY KEY,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_by VARCHAR(100) NOT NULL,
    reason TEXT,
    expires_at TIMESTAMP NOT NULL
);

-- Index for efficient expiration cleanup
CREATE INDEX IF NOT EXISTS idx_revoked_expires ON revoked_tokens(expires_at);

-- Index for lookup by revoked_by
CREATE INDEX IF NOT EXISTS idx_revoked_by ON revoked_tokens(revoked_by);
"""


async def init_revocation_schema(db_pool):
    """Initialize database schema for token revocation"""
    try:
        async with db_pool.acquire() as conn:
            await conn.execute(SQL_SCHEMA_REVOCATION)
        logger.info("Token revocation schema initialized")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize revocation schema: {e}")
        return False


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def generate_signature_secret(length: int = 64) -> str:
    """Generate a random secret for HMAC signing"""
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_test_certificate(
    common_name: str,
    output_dir: str = "certs",
    validity_days: int = 365
) -> Tuple[str, str]:
    """
    Generate self-signed certificate for testing.
    
    Returns: (cert_path, key_path)
    """
    try:
        from OpenSSL import crypto
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate key pair
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        
        # Generate certificate
        cert = crypto.X509()
        cert.get_subject().CN = common_name
        cert.get_subject().O = "CA-A2A Test"
        cert.set_serial_number(int(time.time()))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(validity_days * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')
        
        # Write files
        cert_path = os.path.join(output_dir, f"{common_name}-cert.pem")
        key_path = os.path.join(output_dir, f"{common_name}-key.pem")
        
        with open(cert_path, 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        
        with open(key_path, 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        
        logger.info(f"Generated certificate: {cert_path}")
        return cert_path, key_path
        
    except ImportError:
        raise ImportError("pyOpenSSL required for certificate generation")
    except Exception as e:
        raise Exception(f"Failed to generate certificate: {e}")


__all__ = [
    'RequestSigner',
    'JSONSchemaValidator',
    'TokenRevocationList',
    'MTLSAuthenticator',
    'RevokedToken',
    'CertificateInfo',
    'init_revocation_schema',
    'generate_signature_secret',
    'generate_test_certificate',
]
