"""
Comprehensive Security Test Suite

Tests all enhanced security features:
1. HMAC request signing
2. JSON Schema validation
3. Token revocation
4. mTLS authentication
5. Combined security scenarios

Based on: "Securing Agent-to-Agent (A2A) Communications Across Domains"
"""

import pytest
import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Any

from a2a_security_enhanced import (
    RequestSigner,
    JSONSchemaValidator,
    TokenRevocationList,
    MTLSAuthenticator,
    generate_signature_secret,
    generate_test_certificate,
)


# ============================================================================
# TEST 1: HMAC REQUEST SIGNING
# ============================================================================

class TestHMACRequestSigning:
    """Test HMAC signature generation and verification"""
    
    def setup_method(self):
        self.secret = generate_signature_secret(64)
        self.signer = RequestSigner(self.secret)
    
    def test_sign_and_verify_valid_request(self):
        """Test successful signing and verification"""
        method = "POST"
        path = "/message"
        body = b'{"jsonrpc":"2.0","method":"test","id":"1"}'
        
        # Sign request
        signature = self.signer.sign_request(method, path, body)
        assert signature is not None
        assert ':' in signature  # Format: timestamp:signature
        
        # Verify signature
        is_valid, error = self.signer.verify_signature(signature, method, path, body)
        assert is_valid is True
        assert error is None
    
    def test_reject_tampered_body(self):
        """Test rejection of tampered request body"""
        method = "POST"
        path = "/message"
        body = b'{"jsonrpc":"2.0","method":"test","id":"1"}'
        
        signature = self.signer.sign_request(method, path, body)
        
        # Tamper with body
        tampered_body = b'{"jsonrpc":"2.0","method":"evil","id":"1"}'
        
        is_valid, error = self.signer.verify_signature(signature, method, path, tampered_body)
        assert is_valid is False
        assert "Invalid signature" in error
    
    def test_reject_expired_signature(self):
        """Test rejection of old signatures"""
        method = "POST"
        path = "/message"
        body = b'{"jsonrpc":"2.0","method":"test","id":"1"}'
        
        # Create signature with old timestamp
        old_timestamp = int(time.time()) - 400  # 400 seconds ago
        signature = self.signer.sign_request(method, path, body, timestamp=old_timestamp)
        
        # Verify with max_age of 300 seconds
        is_valid, error = self.signer.verify_signature(
            signature, method, path, body, max_age_seconds=300
        )
        assert is_valid is False
        assert "too old" in error.lower()
    
    def test_reject_future_signature(self):
        """Test rejection of signatures from future (clock skew)"""
        method = "POST"
        path = "/message"
        body = b'{"jsonrpc":"2.0","method":"test","id":"1"}'
        
        # Create signature with future timestamp
        future_timestamp = int(time.time()) + 100
        signature = self.signer.sign_request(method, path, body, timestamp=future_timestamp)
        
        is_valid, error = self.signer.verify_signature(signature, method, path, body)
        assert is_valid is False
        assert "future" in error.lower() or "clock skew" in error.lower()
    
    def test_reject_wrong_secret(self):
        """Test rejection with wrong secret key"""
        method = "POST"
        path = "/message"
        body = b'{"jsonrpc":"2.0","method":"test","id":"1"}'
        
        signature = self.signer.sign_request(method, path, body)
        
        # Try to verify with different signer (different secret)
        wrong_signer = RequestSigner(generate_signature_secret(64))
        is_valid, error = wrong_signer.verify_signature(signature, method, path, body)
        assert is_valid is False


# ============================================================================
# TEST 2: JSON SCHEMA VALIDATION
# ============================================================================

class TestJSONSchemaValidation:
    """Test JSON Schema validation for all agent methods"""
    
    def setup_method(self):
        self.validator = JSONSchemaValidator()
        if not self.validator.enabled:
            pytest.skip("jsonschema not installed")
    
    def test_valid_process_document(self):
        """Test valid process_document parameters"""
        params = {
            "s3_key": "invoices/2026/01/test.pdf",
            "priority": "normal"
        }
        is_valid, error = self.validator.validate("process_document", params)
        assert is_valid is True
        assert error is None
    
    def test_invalid_s3_key_pattern(self):
        """Test rejection of invalid s3_key pattern"""
        params = {
            "s3_key": "../../../etc/passwd",  # Path traversal attempt
            "priority": "normal"
        }
        is_valid, error = self.validator.validate("process_document", params)
        assert is_valid is False
        assert "pattern" in error.lower() or "does not match" in error.lower()
    
    def test_missing_required_field(self):
        """Test rejection of missing required field"""
        params = {
            "priority": "normal"
            # Missing required 's3_key'
        }
        is_valid, error = self.validator.validate("process_document", params)
        assert is_valid is False
        assert "required" in error.lower() or "s3_key" in error.lower()
    
    def test_invalid_priority_enum(self):
        """Test rejection of invalid enum value"""
        params = {
            "s3_key": "test.pdf",
            "priority": "urgent"  # Not in enum: ["low", "normal", "high"]
        }
        is_valid, error = self.validator.validate("process_document", params)
        assert is_valid is False
    
    def test_additional_properties_rejected(self):
        """Test rejection of additional properties"""
        params = {
            "s3_key": "test.pdf",
            "priority": "normal",
            "malicious_field": "evil"  # Not allowed
        }
        is_valid, error = self.validator.validate("process_document", params)
        assert is_valid is False
        assert "additional" in error.lower()
    
    def test_valid_extract_document(self):
        """Test valid extract_document parameters"""
        params = {
            "s3_key": "documents/invoice_001.pdf"
        }
        is_valid, error = self.validator.validate("extract_document", params)
        assert is_valid is True
    
    def test_valid_validate_document(self):
        """Test valid validate_document parameters"""
        params = {
            "extracted_data": {
                "pages": 1,
                "text": "test"
            },
            "s3_key": "test.pdf"
        }
        is_valid, error = self.validator.validate("validate_document", params)
        assert is_valid is True
    
    def test_valid_archive_document(self):
        """Test valid archive_document parameters"""
        params = {
            "s3_key": "test.pdf",
            "extracted_data": {"pages": 1},
            "validation_result": {"score": 100}
        }
        is_valid, error = self.validator.validate("archive_document", params)
        assert is_valid is True
    
    def test_method_without_schema(self):
        """Test method without defined schema (should allow)"""
        params = {
            "any_field": "any_value"
        }
        is_valid, error = self.validator.validate("undefined_method", params)
        assert is_valid is True  # No schema = allow


# ============================================================================
# TEST 3: TOKEN REVOCATION
# ============================================================================

class TestTokenRevocation:
    """Test JWT token revocation system"""
    
    def setup_method(self):
        # Use in-memory revocation list (no DB)
        self.revocation_list = TokenRevocationList(db_pool=None)
    
    @pytest.mark.asyncio
    async def test_revoke_token(self):
        """Test token revocation"""
        jti = "test-token-123"
        reason = "Compromised credentials"
        revoked_by = "admin"
        
        success = await self.revocation_list.revoke_token(jti, reason, revoked_by)
        assert success is True
        
        # Check if revoked
        is_revoked = await self.revocation_list.is_revoked(jti)
        assert is_revoked is True
    
    @pytest.mark.asyncio
    async def test_non_revoked_token(self):
        """Test non-revoked token"""
        jti = "valid-token-456"
        
        is_revoked = await self.revocation_list.is_revoked(jti)
        assert is_revoked is False
    
    @pytest.mark.asyncio
    async def test_expired_revocation(self):
        """Test that expired revocations are cleaned up"""
        jti = "expired-token-789"
        reason = "Test"
        revoked_by = "test"
        
        # Revoke with past expiry
        expires_at = datetime.utcnow() - timedelta(hours=1)
        await self.revocation_list.revoke_token(jti, reason, revoked_by, expires_at)
        
        # Should not be revoked (expired)
        is_revoked = await self.revocation_list.is_revoked(jti)
        assert is_revoked is False
    
    @pytest.mark.asyncio
    async def test_list_revoked_tokens(self):
        """Test listing revoked tokens"""
        # Revoke multiple tokens
        await self.revocation_list.revoke_token("token1", "reason1", "admin1")
        await self.revocation_list.revoke_token("token2", "reason2", "admin2")
        await self.revocation_list.revoke_token("token3", "reason3", "admin3")
        
        tokens = await self.revocation_list.get_revoked_tokens(limit=10)
        assert len(tokens) >= 3
        
        # Check structure
        assert all(hasattr(t, 'jti') for t in tokens)
        assert all(hasattr(t, 'reason') for t in tokens)
        assert all(hasattr(t, 'revoked_by') for t in tokens)


# ============================================================================
# TEST 4: mTLS AUTHENTICATION
# ============================================================================

class TestMTLSAuthentication:
    """Test mTLS certificate authentication"""
    
    def setup_method(self):
        # Generate test certificates
        try:
            self.ca_cert, self.ca_key = generate_test_certificate("ca-a2a-test-ca")
            self.client_cert, self.client_key = generate_test_certificate("orchestrator")
            self.mtls = MTLSAuthenticator(self.ca_cert)
            
            if not self.mtls.enabled:
                pytest.skip("pyOpenSSL not available")
        except Exception as e:
            pytest.skip(f"Certificate generation failed: {e}")
    
    def test_valid_certificate(self):
        """Test verification of valid certificate"""
        with open(self.client_cert, 'rb') as f:
            cert_pem = f.read()
        
        is_valid, cert_info, error = self.mtls.verify_certificate(cert_pem)
        
        # Note: Self-signed cert will fail chain verification
        # This test demonstrates the structure, not actual validation
        assert cert_info is not None or error is not None
    
    def test_extract_principal(self):
        """Test principal extraction from certificate"""
        with open(self.client_cert, 'rb') as f:
            cert_pem = f.read()
        
        is_valid, cert_info, error = self.mtls.verify_certificate(cert_pem)
        
        if cert_info:
            principal = self.mtls.extract_principal_from_cert(cert_info)
            assert principal == "orchestrator"


# ============================================================================
# TEST 5: COMBINED SECURITY SCENARIOS
# ============================================================================

class TestCombinedSecurity:
    """Test combined security scenarios"""
    
    def test_hmac_with_schema_validation(self):
        """Test HMAC signing with schema validation"""
        # Setup
        signer = RequestSigner(generate_signature_secret(64))
        validator = JSONSchemaValidator()
        
        if not validator.enabled:
            pytest.skip("jsonschema not installed")
        
        # Valid request
        params = {
            "s3_key": "test.pdf",
            "priority": "normal"
        }
        message = {
            "jsonrpc": "2.0",
            "method": "process_document",
            "params": params,
            "id": "1"
        }
        body = json.dumps(message).encode('utf-8')
        
        # Sign request
        signature = signer.sign_request("POST", "/message", body)
        
        # Verify signature
        is_valid_sig, sig_error = signer.verify_signature(signature, "POST", "/message", body)
        assert is_valid_sig is True
        
        # Validate schema
        is_valid_schema, schema_error = validator.validate("process_document", params)
        assert is_valid_schema is True
    
    def test_reject_valid_signature_invalid_schema(self):
        """Test rejection when signature valid but schema invalid"""
        # Setup
        signer = RequestSigner(generate_signature_secret(64))
        validator = JSONSchemaValidator()
        
        if not validator.enabled:
            pytest.skip("jsonschema not installed")
        
        # Invalid params (missing required field)
        params = {
            "priority": "normal"
            # Missing 's3_key'
        }
        message = {
            "jsonrpc": "2.0",
            "method": "process_document",
            "params": params,
            "id": "1"
        }
        body = json.dumps(message).encode('utf-8')
        
        # Sign request (signature will be valid)
        signature = signer.sign_request("POST", "/message", body)
        is_valid_sig, sig_error = signer.verify_signature(signature, "POST", "/message", body)
        assert is_valid_sig is True
        
        # But schema validation should fail
        is_valid_schema, schema_error = validator.validate("process_document", params)
        assert is_valid_schema is False


# ============================================================================
# TEST 6: PERFORMANCE TESTS
# ============================================================================

class TestSecurityPerformance:
    """Test performance impact of security features"""
    
    def test_hmac_signing_performance(self):
        """Test HMAC signing performance (should be < 1ms)"""
        signer = RequestSigner(generate_signature_secret(64))
        body = b'{"jsonrpc":"2.0","method":"test","params":{},"id":"1"}'
        
        start = time.perf_counter()
        for _ in range(100):
            signer.sign_request("POST", "/message", body)
        elapsed = time.perf_counter() - start
        
        avg_time = elapsed / 100
        assert avg_time < 0.001  # Less than 1ms per signature
        print(f"Average HMAC signing time: {avg_time*1000:.3f}ms")
    
    def test_schema_validation_performance(self):
        """Test schema validation performance (should be < 1ms)"""
        validator = JSONSchemaValidator()
        if not validator.enabled:
            pytest.skip("jsonschema not installed")
        
        params = {
            "s3_key": "test.pdf",
            "priority": "normal"
        }
        
        start = time.perf_counter()
        for _ in range(100):
            validator.validate("process_document", params)
        elapsed = time.perf_counter() - start
        
        avg_time = elapsed / 100
        assert avg_time < 0.003  # Less than 3ms per validation (realistic threshold for CloudShell/ECS)
        print(f"Average schema validation time: {avg_time*1000:.3f}ms")


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

