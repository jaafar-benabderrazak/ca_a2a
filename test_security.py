"""
Test Security Implementation
Automated tests for authentication, authorization, rate limiting, and audit logging
"""
import pytest
import asyncio
import os
from datetime import datetime, timedelta

from security import (
    SecurityManager,
    JWTManager,
    APIKeyManager,
    RateLimiter,
    SecurityAuditor,
    RequestSigner,
    AuthContext,
    AuthMethod
)


class TestJWTManager:
    """Test JWT token generation and verification"""
    
    def setup_method(self):
        self.jwt_manager = JWTManager(secret_key='test-secret-key')
    
    def test_generate_token(self):
        """Test JWT token generation"""
        token = self.jwt_manager.generate_token(
            agent_id='test-agent',
            permissions=['extract_document', 'validate_document'],
            expires_hours=1
        )
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 50  # JWT tokens are long
    
    def test_verify_valid_token(self):
        """Test verification of valid token"""
        token = self.jwt_manager.generate_token(
            agent_id='test-agent',
            permissions=['extract_document'],
            expires_hours=1
        )
        
        success, auth_context, error = self.jwt_manager.verify_token(token)
        
        assert success is True
        assert auth_context is not None
        assert auth_context.agent_id == 'test-agent'
        assert 'extract_document' in auth_context.permissions
        assert error is None
    
    def test_verify_expired_token(self):
        """Test verification of expired token"""
        # Generate token that expires immediately
        token = self.jwt_manager.generate_token(
            agent_id='test-agent',
            permissions=['*'],
            expires_hours=0  # Expires immediately
        )
        
        # Wait a moment
        import time
        time.sleep(1)
        
        success, auth_context, error = self.jwt_manager.verify_token(token)
        
        assert success is False
        assert auth_context is None
        assert 'expired' in error.lower()
    
    def test_verify_invalid_token(self):
        """Test verification of invalid token"""
        success, auth_context, error = self.jwt_manager.verify_token('invalid-token')
        
        assert success is False
        assert auth_context is None
        assert error is not None


class TestAPIKeyManager:
    """Test API key registration and verification"""
    
    def setup_method(self):
        self.api_key_manager = APIKeyManager()
    
    @pytest.mark.asyncio
    async def test_register_and_verify_api_key(self):
        """Test API key registration and verification"""
        api_key = 'test-key-12345'
        
        self.api_key_manager.register_api_key(
            api_key=api_key,
            agent_id='test-agent',
            permissions=['extract_document', 'validate_document']
        )
        
        success, auth_context, error = await self.api_key_manager.verify_api_key(api_key)
        
        assert success is True
        assert auth_context is not None
        assert auth_context.agent_id == 'test-agent'
        assert 'extract_document' in auth_context.permissions
        assert error is None
    
    @pytest.mark.asyncio
    async def test_verify_invalid_api_key(self):
        """Test verification of invalid API key"""
        success, auth_context, error = await self.api_key_manager.verify_api_key('invalid-key')
        
        assert success is False
        assert auth_context is None
        assert 'invalid' in error.lower()


class TestRateLimiter:
    """Test rate limiting functionality"""
    
    def setup_method(self):
        self.rate_limiter = RateLimiter(
            requests_per_minute=5,
            requests_per_hour=10
        )
    
    def test_allow_within_limit(self):
        """Test requests within rate limit"""
        agent_id = 'test-agent'
        
        # Should allow first 5 requests
        for i in range(5):
            allowed, error = self.rate_limiter.check_rate_limit(agent_id)
            assert allowed is True
            assert error is None
    
    def test_block_over_limit(self):
        """Test blocking requests over rate limit"""
        agent_id = 'test-agent'
        
        # Make 5 requests (at limit)
        for i in range(5):
            self.rate_limiter.check_rate_limit(agent_id)
        
        # 6th request should be blocked
        allowed, error = self.rate_limiter.check_rate_limit(agent_id)
        
        assert allowed is False
        assert error is not None
        assert 'rate limit' in error.lower()
    
    def test_get_usage_stats(self):
        """Test getting usage statistics"""
        agent_id = 'test-agent'
        
        # Make 3 requests
        for i in range(3):
            self.rate_limiter.check_rate_limit(agent_id)
        
        stats = self.rate_limiter.get_usage_stats(agent_id)
        
        assert stats['requests_last_minute'] == 3
        assert stats['requests_last_hour'] == 3
        assert stats['rpm_limit'] == 5
        assert stats['rph_limit'] == 10


class TestRequestSigner:
    """Test HMAC request signing"""
    
    def setup_method(self):
        self.signer = RequestSigner(secret_key='test-signature-secret')
    
    def test_sign_and_verify_request(self):
        """Test signing and verifying a request"""
        method = 'POST'
        url = '/message'
        body = '{"jsonrpc":"2.0","method":"test"}'
        
        signature = self.signer.sign_request(method, url, body)
        
        assert signature is not None
        assert '|' in signature  # Format: timestamp|signature
        
        # Verify signature
        valid, error = self.signer.verify_signature(signature, method, url, body)
        
        assert valid is True
        assert error is None
    
    def test_verify_invalid_signature(self):
        """Test verification of invalid signature"""
        valid, error = self.signer.verify_signature(
            'invalid|signature',
            'POST',
            '/message',
            '{"test":true}'
        )
        
        assert valid is False
        assert error is not None
    
    def test_verify_expired_signature(self):
        """Test verification of expired signature"""
        # Create signature with old timestamp
        old_timestamp = (datetime.utcnow() - timedelta(minutes=10)).isoformat()
        signature = self.signer.sign_request('POST', '/message', '{}', old_timestamp)
        
        valid, error = self.signer.verify_signature(
            signature,
            'POST',
            '/message',
            '{}',
            max_age_seconds=300  # 5 minutes
        )
        
        assert valid is False
        assert 'expired' in error.lower()


class TestSecurityManager:
    """Test integrated security manager"""
    
    def setup_method(self):
        self.security_manager = SecurityManager(
            enable_jwt=True,
            enable_api_keys=True,
            enable_rate_limiting=True
        )
    
    @pytest.mark.asyncio
    async def test_authenticate_with_jwt(self):
        """Test authentication with JWT token"""
        # Generate token
        token = self.security_manager.generate_agent_token(
            agent_id='test-agent',
            permissions=['extract_document']
        )
        
        # Authenticate
        headers = {
            'authorization': f'Bearer {token}'
        }
        
        success, auth_context, error = await self.security_manager.authenticate_request(headers)
        
        assert success is True
        assert auth_context is not None
        assert auth_context.agent_id == 'test-agent'
    
    @pytest.mark.asyncio
    async def test_authenticate_with_api_key(self):
        """Test authentication with API key"""
        api_key = 'test-key-12345'
        
        # Register API key
        self.security_manager.register_api_key(
            api_key=api_key,
            agent_id='test-agent',
            permissions=['extract_document']
        )
        
        # Authenticate
        headers = {
            'x-api-key': api_key
        }
        
        success, auth_context, error = await self.security_manager.authenticate_request(headers)
        
        assert success is True
        assert auth_context is not None
        assert auth_context.agent_id == 'test-agent'
    
    def test_check_permission_allowed(self):
        """Test permission check for allowed method"""
        auth_context = AuthContext(
            agent_id='test-agent',
            auth_method=AuthMethod.JWT,
            permissions=['extract_document', 'validate_document'],
            metadata={}
        )
        
        allowed = self.security_manager.check_permission(auth_context, 'extract_document')
        
        assert allowed is True
    
    def test_check_permission_denied(self):
        """Test permission check for denied method"""
        auth_context = AuthContext(
            agent_id='test-agent',
            auth_method=AuthMethod.JWT,
            permissions=['extract_document'],
            metadata={}
        )
        
        allowed = self.security_manager.check_permission(auth_context, 'delete_document')
        
        assert allowed is False
    
    def test_check_permission_wildcard(self):
        """Test permission check with wildcard permission"""
        auth_context = AuthContext(
            agent_id='test-agent',
            auth_method=AuthMethod.JWT,
            permissions=['*'],
            metadata={}
        )
        
        # Should allow any method
        allowed = self.security_manager.check_permission(auth_context, 'any_method')
        
        assert allowed is True


class TestSecurityAuditor:
    """Test security audit logging"""
    
    def setup_method(self):
        self.auditor = SecurityAuditor()
    
    def test_log_auth_attempt_success(self):
        """Test logging successful authentication attempt"""
        # Should not raise exception
        self.auditor.log_auth_attempt(
            agent_id='test-agent',
            auth_method='jwt',
            success=True,
            source_ip='127.0.0.1'
        )
    
    def test_log_auth_attempt_failure(self):
        """Test logging failed authentication attempt"""
        # Should not raise exception
        self.auditor.log_auth_attempt(
            agent_id='unknown-agent',
            auth_method='api_key',
            success=False,
            reason='Invalid API key',
            source_ip='192.168.1.100'
        )
    
    def test_log_authorization_failure(self):
        """Test logging authorization failure"""
        # Should not raise exception
        self.auditor.log_authorization_failure(
            agent_id='test-agent',
            method='delete_document',
            required_permission='delete_document'
        )
    
    def test_log_rate_limit_exceeded(self):
        """Test logging rate limit violation"""
        # Should not raise exception
        self.auditor.log_rate_limit_exceeded(
            agent_id='test-agent',
            limit_type='60 requests per minute'
        )


if __name__ == '__main__':
    # Run tests
    pytest.main([__file__, '-v', '--tb=short'])
