"""
Test Suite for Token Binding and mTLS Implementation

Tests:
- Token binding certificate thumbprint computation
- Token binding validation
- Certificate validation
- mTLS configuration
- Keycloak JWT with token binding
- End-to-end mTLS + token binding flow
"""

import pytest
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Import modules under test
from token_binding import TokenBindingValidator, CertificateValidator
from mtls_manager import CertificateAuthority, MTLSConfigManager


class TestTokenBinding:
    """Test token binding functionality"""
    
    @pytest.fixture
    def test_certificate(self):
        """Generate a test certificate"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "test-service.ca-a2a.local"),
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
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
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
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True
            )
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )
        
        return cert, private_key
    
    def test_compute_certificate_thumbprint(self, test_certificate):
        """Test certificate thumbprint computation"""
        cert, _ = test_certificate
        validator = TokenBindingValidator()
        
        # Compute thumbprint
        thumbprint = validator.compute_certificate_thumbprint(cert, encoding="base64url")
        
        # Verify thumbprint format
        assert isinstance(thumbprint, str)
        assert len(thumbprint) > 0
        assert '=' not in thumbprint  # Base64url should not have padding
        
        # Verify thumbprint is deterministic
        thumbprint2 = validator.compute_certificate_thumbprint(cert, encoding="base64url")
        assert thumbprint == thumbprint2
    
    def test_compute_certificate_thumbprint_hex(self, test_certificate):
        """Test certificate thumbprint in hex encoding"""
        cert, _ = test_certificate
        validator = TokenBindingValidator()
        
        thumbprint = validator.compute_certificate_thumbprint(cert, encoding="hex")
        
        # Verify hex format (64 chars for SHA-256)
        assert isinstance(thumbprint, str)
        assert len(thumbprint) == 64
        assert all(c in '0123456789abcdef' for c in thumbprint)
    
    def test_create_token_binding_claim(self, test_certificate):
        """Test creation of token binding claim"""
        cert, _ = test_certificate
        validator = TokenBindingValidator()
        
        # Create claim
        claim = validator.create_token_binding_claim(cert)
        
        # Verify structure
        assert "cnf" in claim
        assert "x5t#S256" in claim["cnf"]
        assert isinstance(claim["cnf"]["x5t#S256"], str)
        assert len(claim["cnf"]["x5t#S256"]) > 0
    
    def test_extract_token_binding_claim(self):
        """Test extraction of token binding claim from JWT"""
        validator = TokenBindingValidator()
        
        # JWT claims with token binding
        claims_with_binding = {
            "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
            "sub": "test-user",
            "cnf": {
                "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg"
            }
        }
        
        # Extract binding
        binding = validator.extract_token_binding_claim(claims_with_binding)
        
        assert binding is not None
        assert binding["type"] == "x5t#S256"
        assert binding["value"] == "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg"
        
        # JWT claims without token binding
        claims_without_binding = {
            "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
            "sub": "test-user"
        }
        
        binding = validator.extract_token_binding_claim(claims_without_binding)
        assert binding is None
    
    def test_verify_token_binding_success(self, test_certificate):
        """Test successful token binding verification"""
        cert, _ = test_certificate
        validator = TokenBindingValidator()
        
        # Create token binding claim
        binding_claim = validator.create_token_binding_claim(cert)
        
        # Simulate JWT claims
        jwt_claims = {
            "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
            "sub": "test-user",
            **binding_claim
        }
        
        # Verify binding
        is_valid, error = validator.verify_token_binding(jwt_claims, cert)
        
        assert is_valid is True
        assert error is None
    
    def test_verify_token_binding_failure_missing_claim(self, test_certificate):
        """Test token binding verification failure (missing claim)"""
        cert, _ = test_certificate
        validator = TokenBindingValidator()
        
        # JWT without binding claim
        jwt_claims = {
            "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
            "sub": "test-user"
        }
        
        # Verify binding
        is_valid, error = validator.verify_token_binding(jwt_claims, cert)
        
        assert is_valid is False
        assert "missing" in error.lower()
    
    def test_verify_token_binding_failure_mismatch(self, test_certificate):
        """Test token binding verification failure (thumbprint mismatch)"""
        cert, _ = test_certificate
        validator = TokenBindingValidator()
        
        # JWT with wrong thumbprint
        jwt_claims = {
            "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
            "sub": "test-user",
            "cnf": {
                "x5t#S256": "WRONG_THUMBPRINT_VALUE_THAT_DOES_NOT_MATCH"
            }
        }
        
        # Verify binding
        is_valid, error = validator.verify_token_binding(jwt_claims, cert)
        
        assert is_valid is False
        assert "does not match" in error.lower()


class TestCertificateValidation:
    """Test certificate validation"""
    
    @pytest.fixture
    def valid_certificate(self):
        """Generate a valid test certificate"""
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "valid-service.ca-a2a.local"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CA A2A"),
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
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True
            )
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )
        
        return cert
    
    @pytest.fixture
    def expired_certificate(self):
        """Generate an expired certificate"""
        private_key = rsa.generate_private_key(65537, 2048, default_backend())
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "expired-service.ca-a2a.local"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=365))
            .not_valid_after(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
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
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True
            )
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )
        
        return cert
    
    def test_validate_certificate_success(self, valid_certificate):
        """Test successful certificate validation"""
        validator = CertificateValidator()
        
        is_valid, error = validator.validate_certificate(valid_certificate)
        
        assert is_valid is True
        assert error is None
    
    def test_validate_certificate_expired(self, expired_certificate):
        """Test certificate validation failure (expired)"""
        validator = CertificateValidator()
        
        is_valid, error = validator.validate_certificate(
            expired_certificate,
            check_expiration=True
        )
        
        assert is_valid is False
        assert "expired" in error.lower()
    
    def test_extract_certificate_info(self, valid_certificate):
        """Test certificate info extraction"""
        validator = CertificateValidator()
        
        info = validator.extract_certificate_info(valid_certificate)
        
        assert info["subject_common_name"] == "valid-service.ca-a2a.local"
        assert info["subject_organization"] == "CA A2A"
        assert "serial_number" in info
        assert "not_valid_before" in info
        assert "not_valid_after" in info


class TestCertificateAuthority:
    """Test certificate authority operations"""
    
    def test_generate_ca(self):
        """Test CA certificate generation"""
        ca = CertificateAuthority()
        
        cert, key = ca.generate_ca(
            common_name="Test CA",
            organization="Test Org",
            country="FR"
        )
        
        # Verify CA certificate
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Test CA"
        assert cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Test Org"
        
        # Verify CA extensions
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        ).value
        assert basic_constraints.ca is True
    
    def test_issue_client_certificate(self):
        """Test client certificate issuance"""
        ca = CertificateAuthority()
        ca.generate_ca(common_name="Test CA", organization="Test Org")
        
        # Issue client certificate
        cert, key = ca.issue_client_certificate(
            common_name="test-client.ca-a2a.local",
            organization="Test Org"
        )
        
        # Verify client certificate
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "test-client.ca-a2a.local"
        assert cert.issuer == ca.ca_cert.subject
        
        # Verify client extensions
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        ).value
        assert basic_constraints.ca is False
        
        # Verify extended key usage
        ext_key_usage = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
        ).value
        assert ExtendedKeyUsageOID.CLIENT_AUTH in ext_key_usage


class TestMTLSConfigManager:
    """Test mTLS configuration manager"""
    
    def test_initialize_ca(self, tmp_path):
        """Test CA initialization"""
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        
        ca_cert_path, ca_key_path = manager.initialize_ca()
        
        # Verify CA files exist
        assert Path(ca_cert_path).exists()
        assert Path(ca_key_path).exists()
        
        # Verify CA loaded
        assert manager.ca.ca_cert is not None
        assert manager.ca.ca_private_key is not None
    
    def test_generate_agent_certificate(self, tmp_path):
        """Test agent certificate generation"""
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        manager.initialize_ca()
        
        # Generate agent certificate
        paths = manager.generate_agent_certificate("orchestrator")
        
        # Verify certificate files exist
        assert Path(paths["cert"]).exists()
        assert Path(paths["key"]).exists()
        assert Path(paths["ca_cert"]).exists()
    
    def test_generate_all_agent_certificates(self, tmp_path):
        """Test generation of all agent certificates"""
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        manager.initialize_ca()
        
        # Generate certificates for all agents
        agents = ["orchestrator", "extractor", "validator"]
        results = manager.generate_all_agent_certificates(agents=agents)
        
        # Verify all certificates generated
        assert len(results) == len(agents)
        for agent in agents:
            assert agent in results
            assert Path(results[agent]["cert"]).exists()
            assert Path(results[agent]["key"]).exists()


class TestIntegration:
    """Integration tests for token binding + mTLS"""
    
    def test_end_to_end_token_binding(self, tmp_path):
        """Test end-to-end token binding flow"""
        # 1. Generate certificates
        manager = MTLSConfigManager(certs_dir=str(tmp_path))
        manager.initialize_ca()
        client_paths = manager.generate_agent_certificate("test-client")
        
        # 2. Load client certificate
        with open(client_paths["cert"], "rb") as f:
            client_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        # 3. Create token binding claim
        tb_validator = TokenBindingValidator()
        binding_claim = tb_validator.create_token_binding_claim(client_cert)
        
        # 4. Simulate JWT with binding
        jwt_claims = {
            "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
            "sub": "test-client",
            "aud": "ca-a2a-agents",
            "exp": int(datetime.datetime.utcnow().timestamp()) + 300,
            **binding_claim
        }
        
        # 5. Verify token binding
        is_valid, error = tb_validator.verify_token_binding(jwt_claims, client_cert)
        
        assert is_valid is True
        assert error is None


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
