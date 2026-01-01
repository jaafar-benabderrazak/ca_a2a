"""
Tests for Enhanced A2A Security Implementation
Tests TLS/mTLS, message integrity, zero-trust, and anomaly detection
"""
import pytest
import asyncio
import json
import ssl
from datetime import datetime, timedelta

# Import enhanced security components
from a2a_security_enhanced import (
    TLSConfigManager,
    MessageIntegrityVerifier,
    ZeroTrustEnforcer,
    AnomalyDetector,
    EnhancedSecurityManager
)
from security import SecurityManager, AuthContext, AuthMethod


class TestTLSConfiguration:
    """Test TLS/mTLS configuration"""
    
    def test_tls_config_creation(self):
        """Test creating TLS configuration"""
        config = TLSConfigManager(
            cert_path="test-cert.pem",
            key_path="test-key.pem",
            ca_cert_path="test-ca.pem",
            require_client_cert=False
        )
        
        assert config.cert_path == "test-cert.pem"
        assert config.key_path == "test-key.pem"
        assert config.ca_cert_path == "test-ca.pem"
        assert config.require_client_cert is False
    
    def test_ssl_context_without_certs(self):
        """Test SSL context returns None without certificates"""
        config = TLSConfigManager()
        context = config.create_server_ssl_context()
        
        # Should return None if certs not available
        assert context is None
    
    def test_client_ssl_context_creation(self):
        """Test creating client SSL context"""
        config = TLSConfigManager()
        context = config.create_client_ssl_context()
        
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True


class TestMessageIntegrity:
    """Test HMAC message integrity verification"""
    
    def test_sign_message(self):
        """Test signing a message with HMAC"""
        verifier = MessageIntegrityVerifier("test-secret-key")
        
        message = {
            "jsonrpc": "2.0",
            "id": "test-123",
            "method": "test_method",
            "params": {"key": "value"}
        }
        
        integrity = verifier.sign_message(message)
        
        assert integrity.message_id == "test-123"
        assert integrity.hmac_signature
        assert integrity.algorithm == "sha256"
        assert integrity.timestamp
    
    def test_verify_valid_message(self):
        """Test verifying a valid message"""
        verifier = MessageIntegrityVerifier("test-secret-key")
        
        message = {
            "jsonrpc": "2.0",
            "method": "test",
            "params": {}
        }
        
        integrity = verifier.sign_message(message)
        valid, error = verifier.verify_message(message, integrity)
        
        assert valid is True
        assert error is None
    
    def test_detect_tampered_message(self):
        """Test detecting a tampered message"""
        verifier = MessageIntegrityVerifier("test-secret-key")
        
        message = {
            "jsonrpc": "2.0",
            "method": "test",
            "params": {"amount": 100}
        }
        
        integrity = verifier.sign_message(message)
        
        # Tamper with message
        message["params"]["amount"] = 1000
        
        valid, error = verifier.verify_message(message, integrity)
        
        assert valid is False
        assert "HMAC verification failed" in error
    
    def test_reject_old_message(self):
        """Test rejecting messages that are too old (replay protection)"""
        verifier = MessageIntegrityVerifier("test-secret-key")
        
        message = {"jsonrpc": "2.0", "method": "test"}
        
        # Create integrity with old timestamp
        integrity = verifier.sign_message(message)
        old_timestamp = (datetime.utcnow() - timedelta(minutes=10)).isoformat()
        integrity.timestamp = old_timestamp
        
        valid, error = verifier.verify_message(message, integrity, max_age_seconds=300)
        
        assert valid is False
        assert "Message too old" in error
    
    def test_attach_and_verify_headers(self):
        """Test attaching integrity headers and verification"""
        verifier = MessageIntegrityVerifier("test-secret-key")
        
        message = {"jsonrpc": "2.0", "method": "process"}
        
        # Attach headers
        headers = verifier.attach_integrity_headers(message)
        
        assert 'X-Message-HMAC' in headers
        assert 'X-Message-Timestamp' in headers
        assert 'X-Message-HMAC-Algorithm' in headers
        
        # Verify from headers
        valid, error = verifier.verify_from_headers(message, headers)
        
        assert valid is True
        assert error is None


class TestZeroTrustEnforcement:
    """Test zero-trust security enforcement"""
    
    @pytest.mark.asyncio
    async def test_successful_verification(self):
        """Test successful zero-trust verification"""
        # Setup
        security_manager = SecurityManager()
        
        # Register test API key
        security_manager.register_api_key(
            "test-api-key-123",
            "test-agent",
            ["process_document", "validate"]
        )
        
        zero_trust = ZeroTrustEnforcer(security_manager)
        
        # Verify request
        headers = {'x-api-key': 'test-api-key-123'}
        message = {'method': 'process_document', 'params': {}}
        
        allowed, auth_context, violations = await zero_trust.verify_request(
            headers, message, source_ip="127.0.0.1"
        )
        
        assert allowed is True
        assert auth_context is not None
        assert auth_context.agent_id == "test-agent"
        assert len(violations) == 0
    
    @pytest.mark.asyncio
    async def test_authentication_failure(self):
        """Test zero-trust with authentication failure"""
        security_manager = SecurityManager()
        zero_trust = ZeroTrustEnforcer(security_manager)
        
        # No valid credentials
        headers = {}
        message = {'method': 'test'}
        
        allowed, auth_context, violations = await zero_trust.verify_request(
            headers, message
        )
        
        assert allowed is False
        assert auth_context is None
        assert len(violations) > 0
        assert "Authentication failed" in violations[0]
    
    @pytest.mark.asyncio
    async def test_authorization_failure(self):
        """Test zero-trust with insufficient permissions"""
        security_manager = SecurityManager()
        security_manager.register_api_key(
            "limited-key",
            "limited-agent",
            ["read_only"]  # Limited permissions
        )
        
        zero_trust = ZeroTrustEnforcer(security_manager)
        
        headers = {'x-api-key': 'limited-key'}
        message = {'method': 'delete_document'}  # Requires different permission
        
        allowed, auth_context, violations = await zero_trust.verify_request(
            headers, message
        )
        
        assert allowed is False
        assert "Insufficient permissions" in violations[0]
    
    def test_trust_metrics(self):
        """Test trust level calculation"""
        security_manager = SecurityManager()
        zero_trust = ZeroTrustEnforcer(security_manager)
        
        # New agent
        metrics = zero_trust.get_trust_metrics("new-agent")
        assert metrics['trust_level'] == "new"
        
        # Simulate successful verifications
        for _ in range(50):
            zero_trust.trust_decisions["trusted-agent"] += 1
        
        metrics = zero_trust.get_trust_metrics("trusted-agent")
        assert metrics['trust_level'] == "trusted"
        
        # Established agent
        for _ in range(100):
            zero_trust.trust_decisions["established-agent"] += 1
        
        metrics = zero_trust.get_trust_metrics("established-agent")
        assert metrics['trust_level'] == "established"


class TestAnomalyDetection:
    """Test anomaly detection for agent behavior"""
    
    def test_detect_high_error_rate(self):
        """Test detecting high error rates"""
        detector = AnomalyDetector(window_size=10)
        
        # Record mostly failed requests
        for i in range(10):
            detector.record_request(
                "agent-1",
                "test_method",
                success=(i < 3),  # 70% error rate
                response_time=0.1
            )
        
        anomalies = detector.detect_anomalies("agent-1")
        
        # Should detect high error rate
        assert len(anomalies) > 0
        error_anomaly = [a for a in anomalies if a['type'] == 'high_error_rate']
        assert len(error_anomaly) > 0
        assert error_anomaly[0]['severity'] in ['medium', 'high']
    
    def test_no_anomaly_for_normal_behavior(self):
        """Test no anomalies for normal behavior"""
        detector = AnomalyDetector(window_size=20)
        
        # Record normal requests with varied methods
        for i in range(20):
            method = f"method_{i % 5}"  # Use 5 different methods
            detector.record_request(
                "agent-2",
                method,
                success=True,
                response_time=0.1
            )
        
        anomalies = detector.detect_anomalies("agent-2")
        
        # Should not detect error-based anomalies
        error_anomalies = [a for a in anomalies if a['type'] == 'high_error_rate']
        assert len(error_anomalies) == 0
    
    def test_detect_method_concentration(self):
        """Test detecting unusual method usage patterns"""
        detector = AnomalyDetector(window_size=30)
        
        # Agent uses one method 90% of time
        for i in range(30):
            method = "dominant_method" if i < 27 else "other_method"
            detector.record_request(
                "agent-3",
                method,
                success=True,
                response_time=0.1
            )
        
        anomalies = detector.detect_anomalies("agent-3")
        
        # Should detect method concentration
        method_anomaly = [a for a in anomalies if a['type'] == 'method_concentration']
        assert len(method_anomaly) > 0
    
    def test_error_rate_calculation(self):
        """Test error rate calculation"""
        detector = AnomalyDetector(window_size=10)
        
        # 5 success, 5 failures
        for i in range(10):
            detector.record_request(
                "agent-4",
                "test",
                success=(i % 2 == 0),
                response_time=0.1
            )
        
        error_rate = detector._calculate_error_rate("agent-4")
        assert error_rate == 0.5  # 50% error rate


class TestEnhancedSecurityIntegration:
    """Test complete enhanced security manager"""
    
    @pytest.mark.asyncio
    async def test_full_security_verification(self):
        """Test complete security verification flow"""
        # Setup base security
        base_security = SecurityManager()
        base_security.register_api_key(
            "test-key",
            "test-agent",
            ["*"]  # Full permissions
        )
        
        # Create enhanced security
        enhanced = EnhancedSecurityManager(
            base_security=base_security,
            enable_tls=False,  # Skip TLS for unit test
            enable_message_integrity=True,
            enable_zero_trust=True,
            enable_anomaly_detection=True
        )
        
        # Create message
        message = {
            "jsonrpc": "2.0",
            "method": "test",
            "params": {}
        }
        
        # Sign message
        integrity_headers = enhanced.sign_outgoing_message(message)
        
        # Add auth header
        headers = {
            'x-api-key': 'test-key',
            **integrity_headers
        }
        
        # Verify
        allowed, auth_context, violations = await enhanced.verify_secure_request(
            headers, message, source_ip="127.0.0.1"
        )
        
        assert allowed is True
        assert auth_context is not None
        assert len(violations) == 0
    
    @pytest.mark.asyncio
    async def test_reject_tampered_message(self):
        """Test rejecting tampered messages"""
        base_security = SecurityManager()
        base_security.register_api_key("test-key", "test-agent", ["*"])
        
        enhanced = EnhancedSecurityManager(
            base_security=base_security,
            enable_tls=False,
            enable_message_integrity=True,
            enable_zero_trust=True
        )
        
        message = {"jsonrpc": "2.0", "method": "test", "params": {"value": 100}}
        
        # Sign original message
        integrity_headers = enhanced.sign_outgoing_message(message)
        headers = {'x-api-key': 'test-key', **integrity_headers}
        
        # Tamper with message
        message["params"]["value"] = 999
        
        # Verify (should fail)
        allowed, auth_context, violations = await enhanced.verify_secure_request(
            headers, message
        )
        
        assert allowed is False
        assert "Message integrity" in violations[0]
    
    def test_anomaly_recording(self):
        """Test recording requests for anomaly detection"""
        base_security = SecurityManager()
        enhanced = EnhancedSecurityManager(
            base_security=base_security,
            enable_anomaly_detection=True
        )
        
        # Record requests with varied methods
        for i in range(15):
            method = f"method_{i % 3}"  # Use 3 different methods
            enhanced.record_request_for_anomaly_detection(
                agent_id="test-agent",
                method=method,
                success=True,
                response_time=0.1
            )
        
        # Check anomalies (should not detect error anomalies)
        anomalies = enhanced.check_for_anomalies("test-agent")
        error_anomalies = [a for a in anomalies if a['type'] == 'high_error_rate']
        assert len(error_anomalies) == 0


class TestSecurityBestPractices:
    """Test implementation of security best practices from PDF"""
    
    def test_replay_attack_prevention(self):
        """Test replay attack prevention with timestamps"""
        verifier = MessageIntegrityVerifier("secret")
        
        message = {"jsonrpc": "2.0", "method": "transfer", "params": {"amount": 1000}}
        
        # Sign message
        integrity = verifier.sign_message(message)
        
        # First verification succeeds
        valid1, _ = verifier.verify_message(message, integrity, max_age_seconds=300)
        assert valid1 is True
        
        # Wait and try to replay (simulate old message)
        integrity.timestamp = (datetime.utcnow() - timedelta(minutes=10)).isoformat()
        valid2, error = verifier.verify_message(message, integrity, max_age_seconds=300)
        
        assert valid2 is False
        assert "Message too old" in error
    
    def test_defense_in_depth(self):
        """Test multiple security layers (defense in depth)"""
        # Layer 1: Authentication
        # Layer 2: Rate limiting
        # Layer 3: Authorization
        # Layer 4: Message integrity
        
        base_security = SecurityManager(
            enable_jwt=True,
            enable_api_keys=True,
            enable_rate_limiting=True
        )
        
        enhanced = EnhancedSecurityManager(
            base_security=base_security,
            enable_message_integrity=True,
            enable_zero_trust=True
        )
        
        # All layers should be active
        assert base_security.enable_jwt is True
        assert base_security.enable_rate_limiting is True
        assert enhanced.integrity_verifier is not None
        assert enhanced.zero_trust is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

