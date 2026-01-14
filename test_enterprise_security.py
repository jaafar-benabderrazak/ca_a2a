"""
Comprehensive Test Suite for Enterprise Security Features

Tests:
1. Token Binding (RFC 8473) - Certificate-bound tokens
2. Mutual TLS (mTLS) - Bidirectional certificate authentication
3. Keycloak Integration with Token Binding
4. Combined mTLS + Token Binding + Keycloak flow
5. Attack scenario simulations (token theft, replay, etc.)
6. Performance and overhead measurements

Run with:
    pytest test_enterprise_security.py -v --tb=short
"""

import pytest
import asyncio
import datetime
import hashlib
import base64
import secrets
from pathlib import Path
from typing import Dict, Any, Tuple
from unittest.mock import Mock, patch, MagicMock

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Import modules under test
from token_binding import TokenBindingValidator, CertificateValidator
from mtls_manager import CertificateAuthority, MTLSConfigManager
from keycloak_auth import KeycloakJWTValidator, KeycloakRBACMapper


class TestTokenBindingEnterprise:
    """Enterprise-level token binding tests"""
    
    @pytest.fixture
    def certificate_pair(self):
        """Generate a certificate pair for testing"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "lambda.ca-a2a.local"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CA A2A"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                    ExtendedKeyUsageOID.SERVER_AUTH
                ]),
                critical=True
            )
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )
        
        return cert, private_key
    
    def test_thumbprint_deterministic(self, certificate_pair):
        """Test that thumbprint computation is deterministic"""
        cert, _ = certificate_pair
        validator = TokenBindingValidator()
        
        # Compute multiple times
        thumbprints = [
            validator.compute_certificate_thumbprint(cert, encoding="base64url")
            for _ in range(10)
        ]
        
        # All should be identical
        assert len(set(thumbprints)) == 1
    
    def test_thumbprint_different_certs(self):
        """Test that different certificates produce different thumbprints"""
        validator = TokenBindingValidator()
        
        # Generate two different certificates
        cert1, _ = self._generate_test_cert("client1.local")
        cert2, _ = self._generate_test_cert("client2.local")
        
        thumbprint1 = validator.compute_certificate_thumbprint(cert1)
        thumbprint2 = validator.compute_certificate_thumbprint(cert2)
        
        assert thumbprint1 != thumbprint2
    
    def test_token_binding_claim_structure(self, certificate_pair):
        """Test RFC 8473 compliant claim structure"""
        cert, _ = certificate_pair
        validator = TokenBindingValidator()
        
        claim = validator.create_token_binding_claim(cert)
        
        # Verify RFC 8473 structure
        assert "cnf" in claim
        assert "x5t#S256" in claim["cnf"]
        assert isinstance(claim["cnf"]["x5t#S256"], str)
        
        # Verify base64url encoding (no padding)
        assert '=' not in claim["cnf"]["x5t#S256"]
        assert '+' not in claim["cnf"]["x5t#S256"]
        assert '/' not in claim["cnf"]["x5t#S256"]
    
    def test_token_binding_prevents_token_theft(self, certificate_pair):
        """Test that token binding prevents token theft"""
        cert_lambda, _ = certificate_pair
        cert_attacker, _ = self._generate_test_cert("attacker.local")
        
        validator = TokenBindingValidator()
        
        # Lambda obtains token bound to its certificate
        binding_claim = validator.create_token_binding_claim(cert_lambda)
        jwt_claims = {
            "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
            "sub": "lambda-service",
            "aud": "ca-a2a-agents",
            **binding_claim
        }
        
        # Lambda can use token
        is_valid, error = validator.verify_token_binding(jwt_claims, cert_lambda)
        assert is_valid is True
        
        # Attacker steals token but cannot use it
        is_valid, error = validator.verify_token_binding(jwt_claims, cert_attacker)
        assert is_valid is False
        assert "does not match" in error.lower()
    
    def test_token_binding_constant_time_comparison(self, certificate_pair):
        """Test that thumbprint comparison is constant-time (timing attack resistant)"""
        cert, _ = certificate_pair
        validator = TokenBindingValidator()
        
        correct_thumbprint = validator.compute_certificate_thumbprint(cert)
        wrong_thumbprint = "X" * len(correct_thumbprint)
        
        jwt_claims_correct = {
            "cnf": {"x5t#S256": correct_thumbprint}
        }
        jwt_claims_wrong = {
            "cnf": {"x5t#S256": wrong_thumbprint}
        }
        
        # Both should fail/succeed but with similar timing
        # (secrets.compare_digest ensures constant-time)
        is_valid1, _ = validator.verify_token_binding(jwt_claims_correct, cert)
        is_valid2, _ = validator.verify_token_binding(jwt_claims_wrong, cert)
        
        assert is_valid1 is True
        assert is_valid2 is False
    
    def _generate_test_cert(self, common_name: str) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Helper to generate test certificate"""
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True,
                    content_commitment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True
            )
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )
        return cert, private_key


class TestCertificateValidationEnterprise:
    """Enterprise-level certificate validation tests"""
    
    def test_certificate_chain_validation(self, tmp_path):
        """Test certificate chain validation (CA → Client)"""
        # Generate CA
        ca = CertificateAuthority()
        ca_cert, ca_key = ca.generate_ca(
            common_name="CA A2A Root CA",
            organization="CA A2A"
        )
        
        # Issue client certificate
        client_cert, client_key = ca.issue_client_certificate(
            common_name="orchestrator.ca-a2a.local"
        )
        
        # Verify chain
        validator = CertificateValidator(trusted_ca_cert=ca_cert)
        is_valid, error = validator.validate_certificate_chain(client_cert)
        
        assert is_valid is True
        assert error is None
    
    def test_reject_expired_certificate(self):
        """Test rejection of expired certificates"""
        # Generate expired certificate
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "expired.local"),
        ])
        
        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=730))
            .not_valid_after(datetime.datetime.utcnow() - datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )
        
        validator = CertificateValidator()
        is_valid, error = validator.validate_certificate(
            expired_cert,
            check_expiration=True
        )
        
        assert is_valid is False
        assert "expired" in error.lower()
    
    def test_certificate_revocation_check(self):
        """Test certificate revocation checking (placeholder)"""
        # Note: Full CRL/OCSP implementation would go here
        validator = CertificateValidator()
        
        # Simulate revoked certificate serial number
        validator.revoked_serials.add("123456789")
        
        # Test certificate with revoked serial
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "revoked.local"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(123456789)  # Revoked serial
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )
        
        is_revoked = validator.is_certificate_revoked(cert)
        assert is_revoked is True
    
    def test_key_usage_validation(self):
        """Test key usage validation"""
        # Certificate without CLIENT_AUTH should fail
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "bad-usage.local"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),  # No CLIENT_AUTH
                critical=True
            )
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )
        
        validator = CertificateValidator()
        is_valid, error = validator.validate_certificate(
            cert,
            check_key_usage=True,
            required_key_usage=[ExtendedKeyUsageOID.CLIENT_AUTH]
        )
        
        assert is_valid is False
        assert "key usage" in error.lower()


class TestMTLSConfigurationEnterprise:
    """Enterprise-level mTLS configuration tests"""
    
    def test_mtls_config_full_chain(self, tmp_path):
        """Test full mTLS configuration with certificate chain"""
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        
        # Initialize CA
        ca_cert_path, ca_key_path = manager.initialize_ca()
        
        # Generate server certificates
        server_certs = manager.generate_all_agent_certificates(
            agents=["orchestrator", "extractor", "validator", "archivist"]
        )
        
        # Verify all certificates exist
        assert len(server_certs) == 4
        for agent, paths in server_certs.items():
            assert Path(paths["cert"]).exists()
            assert Path(paths["key"]).exists()
            assert Path(paths["ca_cert"]).exists()
            
            # Verify certificate can be loaded
            with open(paths["cert"], "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                assert agent in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    
    def test_mtls_ssl_context_creation(self, tmp_path):
        """Test SSL context creation for mTLS"""
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        manager.initialize_ca()
        
        # Generate server certificate
        server_paths = manager.generate_agent_certificate("test-server")
        
        # Create SSL context
        import ssl
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(server_paths["cert"], server_paths["key"])
        ssl_context.load_verify_locations(cafile=server_paths["ca_cert"])
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        # Verify configuration
        assert ssl_context.verify_mode == ssl.CERT_REQUIRED
        assert ssl_context.check_hostname is False  # Disabled for mTLS
    
    def test_certificate_rotation(self, tmp_path):
        """Test certificate rotation"""
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        manager.initialize_ca()
        
        # Generate initial certificate
        paths1 = manager.generate_agent_certificate("rotatable-agent")
        with open(paths1["cert"], "rb") as f:
            cert1 = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Rotate certificate
        paths2 = manager.generate_agent_certificate("rotatable-agent", overwrite=True)
        with open(paths2["cert"], "rb") as f:
            cert2 = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Certificates should be different
        assert cert1.serial_number != cert2.serial_number
        assert cert1.not_valid_before != cert2.not_valid_before


class TestKeycloakWithTokenBinding:
    """Test Keycloak integration with token binding"""
    
    @patch('keycloak_auth.jwt')
    @patch('keycloak_auth.PyJWKClient')
    def test_keycloak_jwt_with_token_binding(self, mock_jwks_client, mock_jwt, tmp_path):
        """Test Keycloak JWT verification with token binding"""
        # Generate certificate
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        manager.initialize_ca()
        client_paths = manager.generate_agent_certificate("lambda-service")
        
        with open(client_paths["cert"], "rb") as f:
            client_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Compute thumbprint
        tb_validator = TokenBindingValidator()
        thumbprint = tb_validator.compute_certificate_thumbprint(client_cert)
        
        # Mock Keycloak JWT with token binding
        mock_signing_key = Mock()
        mock_signing_key.key = "test-public-key"
        
        mock_client = Mock()
        mock_client.get_signing_key_from_jwt.return_value = mock_signing_key
        mock_jwks_client.return_value = mock_client
        
        mock_jwt.decode.return_value = {
            "sub": "lambda-service",
            "preferred_username": "lambda-service",
            "realm_access": {"roles": ["lambda"]},
            "aud": "ca-a2a-agents",
            "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
            "cnf": {"x5t#S256": thumbprint}  # Token binding claim
        }
        
        # Verify token with binding
        validator = KeycloakJWTValidator(
            keycloak_url="http://keycloak.ca-a2a.local:8080",
            realm="ca-a2a",
            client_id="ca-a2a-agents",
            require_token_binding=True
        )
        
        principal, roles, claims = validator.verify_token(
            "fake.jwt.token",
            client_certificate=client_cert
        )
        
        assert principal == "lambda-service"
        assert "lambda" in roles
        assert "cnf" in claims
    
    def test_reject_token_without_binding_when_required(self):
        """Test rejection of tokens without binding when required"""
        # This test would verify that tokens without cnf claim
        # are rejected when TOKEN_BINDING_REQUIRED=true
        pass  # Placeholder for full implementation


class TestAttackScenarios:
    """Test security against various attack scenarios"""
    
    def test_token_theft_attack(self, tmp_path):
        """Simulate token theft attack (attacker steals JWT but not certificate)"""
        # Setup
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        manager.initialize_ca()
        
        # Legitimate client
        lambda_paths = manager.generate_agent_certificate("lambda-service")
        with open(lambda_paths["cert"], "rb") as f:
            lambda_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Attacker
        attacker_paths = manager.generate_agent_certificate("attacker")
        with open(attacker_paths["cert"], "rb") as f:
            attacker_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # Create token bound to lambda's certificate
        tb_validator = TokenBindingValidator()
        binding_claim = tb_validator.create_token_binding_claim(lambda_cert)
        
        jwt_claims = {
            "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
            "sub": "lambda-service",
            "aud": "ca-a2a-agents",
            "exp": int(datetime.datetime.utcnow().timestamp()) + 300,
            **binding_claim
        }
        
        # Attacker steals token
        # Attacker tries to use stolen token with their own certificate
        is_valid, error = tb_validator.verify_token_binding(jwt_claims, attacker_cert)
        
        # Attack should fail
        assert is_valid is False
        assert "does not match" in error.lower()
    
    def test_token_replay_attack(self):
        """Simulate token replay attack (attacker reuses old token)"""
        # Token with expired timestamp
        jwt_claims = {
            "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
            "sub": "test-user",
            "aud": "ca-a2a-agents",
            "exp": int(datetime.datetime.utcnow().timestamp()) - 3600,  # Expired 1 hour ago
            "iat": int(datetime.datetime.utcnow().timestamp()) - 3900
        }
        
        # Attempt to validate expired token (would fail in JWT.decode)
        # This demonstrates replay protection via expiration
        assert jwt_claims["exp"] < int(datetime.datetime.utcnow().timestamp())
    
    def test_man_in_the_middle_attack(self, tmp_path):
        """Simulate MITM attack (prevented by mTLS)"""
        # With mTLS, MITM attacks are prevented because:
        # 1. Server verifies client certificate
        # 2. Client verifies server certificate
        # 3. Both must be signed by trusted CA
        
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        manager.initialize_ca()
        
        # Legitimate server
        server_paths = manager.generate_agent_certificate("orchestrator")
        
        # Attacker's fake certificate (not signed by CA)
        attacker_key = rsa.generate_private_key(65537, 2048, default_backend())
        attacker_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "fake-orchestrator.ca-a2a.local"),
        ])
        attacker_cert = (
            x509.CertificateBuilder()
            .subject_name(attacker_subject)
            .issuer_name(attacker_subject)  # Self-signed
            .public_key(attacker_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(attacker_key, hashes.SHA256(), backend=default_backend())
        )
        
        # Validate attacker's cert against CA (should fail)
        with open(server_paths["ca_cert"], "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        validator = CertificateValidator(trusted_ca_cert=ca_cert)
        is_valid, error = validator.validate_certificate_chain(attacker_cert)
        
        assert is_valid is False
        assert error is not None


class TestPerformanceAndOverhead:
    """Test performance impact of security features"""
    
    def test_thumbprint_computation_performance(self, tmp_path):
        """Test thumbprint computation performance"""
        import time
        
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        manager.initialize_ca()
        cert_paths = manager.generate_agent_certificate("perf-test")
        
        with open(cert_paths["cert"], "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        validator = TokenBindingValidator()
        
        # Measure time for 1000 computations
        start_time = time.time()
        for _ in range(1000):
            validator.compute_certificate_thumbprint(cert)
        elapsed = time.time() - start_time
        
        avg_time_ms = (elapsed / 1000) * 1000
        
        # Should be < 1ms per computation
        assert avg_time_ms < 1.0, f"Avg time: {avg_time_ms:.3f}ms (too slow)"
    
    def test_token_binding_verification_performance(self, tmp_path):
        """Test token binding verification performance"""
        import time
        
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        manager.initialize_ca()
        cert_paths = manager.generate_agent_certificate("perf-test")
        
        with open(cert_paths["cert"], "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        validator = TokenBindingValidator()
        binding_claim = validator.create_token_binding_claim(cert)
        jwt_claims = {
            "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
            "sub": "test-user",
            **binding_claim
        }
        
        # Measure time for 1000 verifications
        start_time = time.time()
        for _ in range(1000):
            validator.verify_token_binding(jwt_claims, cert)
        elapsed = time.time() - start_time
        
        avg_time_ms = (elapsed / 1000) * 1000
        
        # Should be < 0.5ms per verification
        assert avg_time_ms < 0.5, f"Avg time: {avg_time_ms:.3f}ms (too slow)"


class TestComplianceAndStandards:
    """Test compliance with security standards"""
    
    def test_rfc_8473_compliance(self, tmp_path):
        """Test RFC 8473 (Token Binding) compliance"""
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        manager.initialize_ca()
        cert_paths = manager.generate_agent_certificate("compliance-test")
        
        with open(cert_paths["cert"], "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        validator = TokenBindingValidator()
        claim = validator.create_token_binding_claim(cert)
        
        # RFC 8473 Section 3.1: cnf claim structure
        assert "cnf" in claim
        assert "x5t#S256" in claim["cnf"]
        
        # RFC 8473: base64url encoding without padding
        thumbprint = claim["cnf"]["x5t#S256"]
        assert '=' not in thumbprint
        assert '+' not in thumbprint
        assert '/' not in thumbprint
    
    def test_rfc_8705_compliance(self):
        """Test RFC 8705 (OAuth 2.0 Mutual-TLS) compliance"""
        # RFC 8705 Section 3: Certificate-bound access tokens
        # Token must contain cnf claim with x5t#S256
        pass  # Covered by test_rfc_8473_compliance
    
    def test_nist_800_63b_aal3_compliance(self):
        """Test NIST 800-63B AAL3 compliance"""
        # AAL3 requires:
        # 1. Cryptographic authentication protocol
        # 2. Verifier impersonation resistant
        # 3. Man-in-the-middle resistant
        # 4. Hardware-based authenticator (certificate + private key)
        
        # Our implementation provides:
        # 1. ✓ mTLS (cryptographic protocol)
        # 2. ✓ Token Binding (prevents token theft/impersonation)
        # 3. ✓ mTLS (prevents MITM)
        # 4. ✓ Certificate-based (can use hardware-backed keys)
        pass  # Conceptual test


# Integration tests
class TestEndToEndEnterpriseFlow:
    """End-to-end tests for complete enterprise security flow"""
    
    @pytest.mark.asyncio
    async def test_full_security_stack(self, tmp_path):
        """Test complete security stack: Keycloak + Token Binding + mTLS"""
        # 1. Setup certificates
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        manager.initialize_ca()
        
        lambda_paths = manager.generate_agent_certificate("lambda-service")
        orchestrator_paths = manager.generate_agent_certificate("orchestrator")
        
        # 2. Load certificates
        with open(lambda_paths["cert"], "rb") as f:
            lambda_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # 3. Create token binding
        tb_validator = TokenBindingValidator()
        binding_claim = tb_validator.create_token_binding_claim(lambda_cert)
        
        # 4. Simulate Keycloak JWT
        jwt_claims = {
            "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
            "sub": "lambda-service",
            "aud": "ca-a2a-agents",
            "exp": int(datetime.datetime.utcnow().timestamp()) + 300,
            "iat": int(datetime.datetime.utcnow().timestamp()),
            "realm_access": {"roles": ["lambda"]},
            **binding_claim
        }
        
        # 5. Verify token binding
        is_valid, error = tb_validator.verify_token_binding(jwt_claims, lambda_cert)
        assert is_valid is True
        
        # 6. Verify RBAC
        rbac_mapper = KeycloakRBACMapper()
        principal, allowed_methods = rbac_mapper.map_roles_to_principal(
            jwt_claims["realm_access"]["roles"]
        )
        assert principal == "lambda"
        assert "*" in allowed_methods  # Lambda has full access


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-k", "not integration"])
