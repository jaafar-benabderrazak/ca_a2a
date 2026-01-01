"""
Security Module for Agent-to-Agent Communication
Implements JWT authentication, API key validation, rate limiting, and audit logging
"""
import os
import jwt
import hmac
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict
from enum import Enum
import asyncpg


logger = logging.getLogger(__name__)


class AuthMethod(Enum):
    """Authentication methods"""
    JWT = "jwt"
    API_KEY = "api_key"
    MUTUAL_TLS = "mtls"
    NONE = "none"


@dataclass
class AuthContext:
    """Authentication context for requests"""
    agent_id: str
    auth_method: AuthMethod
    permissions: list[str]
    metadata: Dict[str, Any]
    expires_at: Optional[datetime] = None
    
    def is_expired(self) -> bool:
        """Check if auth context is expired"""
        if self.expires_at:
            return datetime.utcnow() > self.expires_at
        return False
    
    def has_permission(self, permission: str) -> bool:
        """Check if context has specific permission"""
        return permission in self.permissions or '*' in self.permissions


class JWTManager:
    """Manages JWT token generation and verification"""
    
    def __init__(self, secret_key: str, algorithm: str = 'HS256'):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.issuer = 'ca-a2a-system'
        self.audience = 'ca-a2a-agents'
    
    def generate_token(
        self,
        agent_id: str,
        permissions: list[str],
        expires_hours: int = 24,
        metadata: Dict[str, Any] = None
    ) -> str:
        """
        Generate JWT token for agent
        
        Args:
            agent_id: Unique agent identifier
            permissions: List of allowed operations/methods
            expires_hours: Token expiration time in hours
            metadata: Additional claims
        
        Returns:
            JWT token string
        """
        now = datetime.utcnow()
        payload = {
            'agent_id': agent_id,
            'permissions': permissions,
            'iat': now,  # issued at
            'exp': now + timedelta(hours=expires_hours),
            'iss': self.issuer,
            'aud': self.audience,
            'metadata': metadata or {}
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        logger.info(f"Generated JWT token for agent: {agent_id}")
        return token
    
    def verify_token(self, token: str) -> Tuple[bool, Optional[AuthContext], Optional[str]]:
        """
        Verify JWT token and return auth context
        
        Returns:
            Tuple of (success, auth_context, error_message)
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer
            )
            
            auth_context = AuthContext(
                agent_id=payload['agent_id'],
                auth_method=AuthMethod.JWT,
                permissions=payload.get('permissions', []),
                metadata=payload.get('metadata', {}),
                expires_at=datetime.fromtimestamp(payload['exp'])
            )
            
            return True, auth_context, None
            
        except jwt.ExpiredSignatureError:
            return False, None, "Token expired"
        except jwt.InvalidTokenError as e:
            return False, None, f"Invalid token: {str(e)}"
        except Exception as e:
            logger.error(f"Error verifying JWT token: {str(e)}")
            return False, None, f"Token verification failed: {str(e)}"


class APIKeyManager:
    """Manages API key validation and storage"""
    
    def __init__(self, db_pool: Optional[asyncpg.Pool] = None):
        self.db_pool = db_pool
        # In-memory cache for development (use database in production)
        self._api_keys_cache: Dict[str, Dict[str, Any]] = {}
    
    def register_api_key(
        self,
        api_key: str,
        agent_id: str,
        permissions: list[str],
        metadata: Dict[str, Any] = None
    ):
        """Register an API key (for development/testing)"""
        self._api_keys_cache[api_key] = {
            'agent_id': agent_id,
            'permissions': permissions,
            'metadata': metadata or {},
            'created_at': datetime.utcnow(),
            'last_used': None
        }
        logger.info(f"Registered API key for agent: {agent_id}")
    
    async def verify_api_key(self, api_key: str) -> Tuple[bool, Optional[AuthContext], Optional[str]]:
        """
        Verify API key and return auth context
        
        Returns:
            Tuple of (success, auth_context, error_message)
        """
        # Try in-memory cache first
        if api_key in self._api_keys_cache:
            key_data = self._api_keys_cache[api_key]
            key_data['last_used'] = datetime.utcnow()
            
            auth_context = AuthContext(
                agent_id=key_data['agent_id'],
                auth_method=AuthMethod.API_KEY,
                permissions=key_data['permissions'],
                metadata=key_data['metadata']
            )
            
            return True, auth_context, None
        
        # Try database if available
        if self.db_pool:
            try:
                async with self.db_pool.acquire() as conn:
                    row = await conn.fetchrow(
                        """
                        SELECT agent_id, permissions, metadata, is_active
                        FROM api_keys
                        WHERE key_hash = $1 AND is_active = true
                        """,
                        hashlib.sha256(api_key.encode()).hexdigest()
                    )
                    
                    if row:
                        # Update last used timestamp
                        await conn.execute(
                            "UPDATE api_keys SET last_used = NOW() WHERE key_hash = $1",
                            hashlib.sha256(api_key.encode()).hexdigest()
                        )
                        
                        auth_context = AuthContext(
                            agent_id=row['agent_id'],
                            auth_method=AuthMethod.API_KEY,
                            permissions=row['permissions'],
                            metadata=row['metadata'] or {}
                        )
                        
                        return True, auth_context, None
            except Exception as e:
                logger.error(f"Error verifying API key from database: {str(e)}")
        
        return False, None, "Invalid API key"


class RateLimiter:
    """Rate limiting for API requests"""
    
    def __init__(self, requests_per_minute: int = 60, requests_per_hour: int = 1000):
        self.rpm_limit = requests_per_minute
        self.rph_limit = requests_per_hour
        self.requests_minute: Dict[str, list] = defaultdict(list)
        self.requests_hour: Dict[str, list] = defaultdict(list)
    
    def check_rate_limit(self, agent_id: str) -> Tuple[bool, Optional[str]]:
        """
        Check if agent is within rate limits
        
        Returns:
            Tuple of (allowed, error_message)
        """
        now = datetime.utcnow()
        minute_ago = now - timedelta(minutes=1)
        hour_ago = now - timedelta(hours=1)
        
        # Clean old requests
        self.requests_minute[agent_id] = [
            req_time for req_time in self.requests_minute[agent_id]
            if req_time > minute_ago
        ]
        self.requests_hour[agent_id] = [
            req_time for req_time in self.requests_hour[agent_id]
            if req_time > hour_ago
        ]
        
        # Check minute limit
        if len(self.requests_minute[agent_id]) >= self.rpm_limit:
            return False, f"Rate limit exceeded: {self.rpm_limit} requests per minute"
        
        # Check hour limit
        if len(self.requests_hour[agent_id]) >= self.rph_limit:
            return False, f"Rate limit exceeded: {self.rph_limit} requests per hour"
        
        # Record request
        self.requests_minute[agent_id].append(now)
        self.requests_hour[agent_id].append(now)
        
        return True, None
    
    def get_usage_stats(self, agent_id: str) -> Dict[str, int]:
        """Get current usage statistics for agent"""
        return {
            'requests_last_minute': len(self.requests_minute.get(agent_id, [])),
            'requests_last_hour': len(self.requests_hour.get(agent_id, [])),
            'rpm_limit': self.rpm_limit,
            'rph_limit': self.rph_limit
        }


class RequestSigner:
    """Signs and verifies requests using HMAC"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
    
    def sign_request(
        self,
        method: str,
        url: str,
        body: str,
        timestamp: Optional[str] = None
    ) -> str:
        """
        Sign request with HMAC-SHA256
        
        Returns:
            Signature in format: timestamp|signature
        """
        if not timestamp:
            timestamp = datetime.utcnow().isoformat()
        
        message = f"{method}|{url}|{timestamp}|{body}"
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{timestamp}|{signature}"
    
    def verify_signature(
        self,
        signature_header: str,
        method: str,
        url: str,
        body: str,
        max_age_seconds: int = 300
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify request signature
        
        Args:
            signature_header: Signature from X-Signature header
            method: HTTP method
            url: Request URL
            body: Request body
            max_age_seconds: Maximum age of signature (prevents replay attacks)
        
        Returns:
            Tuple of (valid, error_message)
        """
        try:
            timestamp, signature = signature_header.split('|')
            
            # Check timestamp is recent
            req_time = datetime.fromisoformat(timestamp)
            age_seconds = (datetime.utcnow() - req_time).total_seconds()
            
            if age_seconds > max_age_seconds:
                return False, f"Signature expired (age: {age_seconds}s)"
            
            # Verify signature
            expected_sig = self.sign_request(method, url, body, timestamp).split('|')[1]
            
            if not hmac.compare_digest(signature, expected_sig):
                return False, "Invalid signature"
            
            return True, None
            
        except Exception as e:
            return False, f"Signature verification failed: {str(e)}"


class SecurityAuditor:
    """Audit logging for security events"""
    
    def __init__(self, db_pool: Optional[asyncpg.Pool] = None):
        self.db_pool = db_pool
        self.logger = logging.getLogger(f"{__name__}.SecurityAuditor")
    
    def log_auth_attempt(
        self,
        agent_id: str,
        auth_method: str,
        success: bool,
        reason: Optional[str] = None,
        source_ip: Optional[str] = None,
        metadata: Dict[str, Any] = None
    ):
        """Log authentication attempt"""
        log_data = {
            'event': 'authentication_attempt',
            'agent_id': agent_id,
            'auth_method': auth_method,
            'success': success,
            'reason': reason,
            'source_ip': source_ip,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {}
        }
        
        if success:
            self.logger.info(f"Auth success: {agent_id} via {auth_method}")
        else:
            self.logger.warning(f"Auth failed: {agent_id} via {auth_method} - {reason}")
        
        # Store in database if available
        if self.db_pool:
            # Async operation - fire and forget
            try:
                import asyncio
                asyncio.create_task(self._store_audit_log(log_data))
            except:
                pass
    
    def log_authorization_failure(
        self,
        agent_id: str,
        method: str,
        required_permission: str,
        metadata: Dict[str, Any] = None
    ):
        """Log authorization failure"""
        log_data = {
            'event': 'authorization_failure',
            'agent_id': agent_id,
            'method': method,
            'required_permission': required_permission,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {}
        }
        
        self.logger.warning(
            f"Authorization denied: {agent_id} attempted {method} "
            f"(requires: {required_permission})"
        )
        
        if self.db_pool:
            try:
                import asyncio
                asyncio.create_task(self._store_audit_log(log_data))
            except:
                pass
    
    def log_rate_limit_exceeded(self, agent_id: str, limit_type: str):
        """Log rate limit violation"""
        log_data = {
            'event': 'rate_limit_exceeded',
            'agent_id': agent_id,
            'limit_type': limit_type,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.warning(f"Rate limit exceeded: {agent_id} - {limit_type}")
        
        if self.db_pool:
            try:
                import asyncio
                asyncio.create_task(self._store_audit_log(log_data))
            except:
                pass
    
    async def _store_audit_log(self, log_data: Dict[str, Any]):
        """Store audit log in database"""
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO security_audit_logs (event_type, agent_id, details, timestamp)
                    VALUES ($1, $2, $3, $4)
                    """,
                    log_data['event'],
                    log_data.get('agent_id'),
                    log_data,
                    datetime.utcnow()
                )
        except Exception as e:
            self.logger.error(f"Failed to store audit log: {str(e)}")


class SecurityManager:
    """
    Main security manager coordinating all security components
    """
    
    def __init__(
        self,
        jwt_secret: Optional[str] = None,
        enable_jwt: bool = True,
        enable_api_keys: bool = True,
        enable_rate_limiting: bool = True,
        enable_signatures: bool = False,
        db_pool: Optional[asyncpg.Pool] = None
    ):
        # Get secrets from environment
        self.jwt_secret = jwt_secret or os.getenv('JWT_SECRET_KEY', 'dev-secret-change-in-production')
        self.signature_secret = os.getenv('SIGNATURE_SECRET_KEY', 'dev-signature-secret')
        
        # Initialize components
        self.jwt_manager = JWTManager(self.jwt_secret) if enable_jwt else None
        self.api_key_manager = APIKeyManager(db_pool) if enable_api_keys else None
        self.rate_limiter = RateLimiter() if enable_rate_limiting else None
        self.request_signer = RequestSigner(self.signature_secret) if enable_signatures else None
        self.auditor = SecurityAuditor(db_pool)
        
        self.enable_jwt = enable_jwt
        self.enable_api_keys = enable_api_keys
        self.enable_rate_limiting = enable_rate_limiting
        self.enable_signatures = enable_signatures
        
        logger.info(
            f"SecurityManager initialized: JWT={enable_jwt}, "
            f"API_Keys={enable_api_keys}, RateLimit={enable_rate_limiting}, "
            f"Signatures={enable_signatures}"
        )
    
    async def authenticate_request(
        self,
        headers: Dict[str, str],
        source_ip: Optional[str] = None
    ) -> Tuple[bool, Optional[AuthContext], Optional[str]]:
        """
        Authenticate request using available methods
        
        Returns:
            Tuple of (success, auth_context, error_message)
        """
        # Try JWT first
        if self.enable_jwt:
            auth_header = headers.get('authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
                success, auth_context, error = self.jwt_manager.verify_token(token)
                
                self.auditor.log_auth_attempt(
                    agent_id=auth_context.agent_id if auth_context else 'unknown',
                    auth_method='jwt',
                    success=success,
                    reason=error,
                    source_ip=source_ip
                )
                
                if success:
                    return True, auth_context, None
        
        # Try API Key
        if self.enable_api_keys:
            api_key = headers.get('x-api-key')
            if api_key:
                success, auth_context, error = await self.api_key_manager.verify_api_key(api_key)
                
                self.auditor.log_auth_attempt(
                    agent_id=auth_context.agent_id if auth_context else 'unknown',
                    auth_method='api_key',
                    success=success,
                    reason=error,
                    source_ip=source_ip
                )
                
                if success:
                    return True, auth_context, None
        
        return False, None, "No valid authentication credentials provided"
    
    def check_rate_limit(self, agent_id: str) -> Tuple[bool, Optional[str]]:
        """Check if agent is within rate limits"""
        if not self.enable_rate_limiting:
            return True, None
        
        allowed, error = self.rate_limiter.check_rate_limit(agent_id)
        
        if not allowed:
            self.auditor.log_rate_limit_exceeded(agent_id, error)
        
        return allowed, error
    
    def check_permission(self, auth_context: AuthContext, method: str) -> bool:
        """Check if auth context has permission for method"""
        # Allow wildcard permission
        if '*' in auth_context.permissions:
            return True
        
        # Check specific method permission
        if method in auth_context.permissions:
            return True
        
        # Log authorization failure
        self.auditor.log_authorization_failure(
            agent_id=auth_context.agent_id,
            method=method,
            required_permission=method
        )
        
        return False
    
    def generate_agent_token(
        self,
        agent_id: str,
        permissions: list[str] = None,
        expires_hours: int = 24
    ) -> str:
        """Generate JWT token for agent"""
        if not self.jwt_manager:
            raise ValueError("JWT authentication not enabled")
        
        if permissions is None:
            permissions = ['*']  # Full permissions
        
        return self.jwt_manager.generate_token(agent_id, permissions, expires_hours)
    
    def register_api_key(
        self,
        api_key: str,
        agent_id: str,
        permissions: list[str]
    ):
        """Register an API key"""
        if not self.api_key_manager:
            raise ValueError("API key authentication not enabled")
        
        self.api_key_manager.register_api_key(api_key, agent_id, permissions)


# Database schema for security tables
SECURITY_SCHEMA_SQL = """
-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    key_hash VARCHAR(64) UNIQUE NOT NULL,
    agent_id VARCHAR(100) NOT NULL,
    permissions TEXT[] NOT NULL,
    metadata JSONB,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_agent ON api_keys(agent_id);

-- Security audit logs table
CREATE TABLE IF NOT EXISTS security_audit_logs (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    agent_id VARCHAR(100),
    details JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_event ON security_audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_agent ON security_audit_logs(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON security_audit_logs(timestamp);
"""
