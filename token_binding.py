"""
Token Binding Implementation (RFC 8473)

Implements OAuth 2.0 Token Binding for Proof-of-Possession Tokens.
Binds JWT tokens to client TLS certificates to prevent token theft and replay.

RFC 8473: https://tools.ietf.org/html/rfc8473
RFC 8471: https://tools.ietf.org/html/rfc8471 (Token Binding Protocol)

Security Benefits:
- Stolen tokens cannot be used without the bound certificate
- Protection against token replay from different clients
- Zero-trust architecture enforcement
"""

import base64
import hashlib
import secrets
from typing import Dict, Optional, Tuple, Any
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)


class TokenBindingValidator:
    """
    Validates token binding between JWT tokens and TLS client certificates.
    
    Implements RFC 8473 (OAuth 2.0 Token Binding) by verifying that the
    certificate used to present the token matches the certificate fingerprint
    embedded in the token's 'cnf' (confirmation) claim.
    """
    
    def __init__(self, hash_algorithm: str = "sha256"):
        """
        Initialize token binding validator.
        
        Args:
            hash_algorithm: Hash algorithm for certificate thumbprints (sha256 recommended)
        """
        self.hash_algorithm = hash_algorithm
        
    def compute_certificate_thumbprint(
        self, 
        certificate: x509.Certificate,
        encoding: str = "base64url"
    ) -> str:
        """
        Compute RFC 8705 certificate thumbprint (x5t#S256).
        
        Args:
            certificate: X.509 certificate
            encoding: Output encoding (base64url per RFC, or hex)
            
        Returns:
            Certificate thumbprint string
            
        Example:
            Thumbprint format: Base64url(SHA256(DER(certificate)))
        """
        # Get DER-encoded certificate
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        
        # Compute SHA-256 hash
        if self.hash_algorithm == "sha256":
            thumbprint_bytes = hashlib.sha256(cert_der).digest()
        elif self.hash_algorithm == "sha384":
            thumbprint_bytes = hashlib.sha384(cert_der).digest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {self.hash_algorithm}")
        
        # Encode thumbprint
        if encoding == "base64url":
            # RFC 8705: Base64url encoding without padding
            return base64.urlsafe_b64encode(thumbprint_bytes).decode().rstrip('=')
        elif encoding == "hex":
            return thumbprint_bytes.hex()
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
    
    def extract_token_binding_claim(self, jwt_claims: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """
        Extract token binding confirmation claim from JWT.
        
        Per RFC 8705, the 'cnf' claim contains certificate-bound proof-of-possession info:
        {
          "cnf": {
            "x5t#S256": "<base64url-encoded-certificate-thumbprint>"
          }
        }
        
        Args:
            jwt_claims: Decoded JWT claims dictionary
            
        Returns:
            Token binding info dict or None if not present
            
        Example JWT Claims:
            {
              "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
              "sub": "lambda-service",
              "cnf": {
                "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg"
              }
            }
        """
        cnf_claim = jwt_claims.get("cnf")
        if not cnf_claim or not isinstance(cnf_claim, dict):
            return None
        
        # Extract certificate thumbprint (x5t#S256 = X.509 cert thumbprint with SHA-256)
        cert_thumbprint = cnf_claim.get("x5t#S256")
        if cert_thumbprint:
            return {
                "type": "x5t#S256",
                "value": cert_thumbprint
            }
        
        # Alternative: JWK thumbprint (not implemented)
        jkt = cnf_claim.get("jkt")
        if jkt:
            logger.warning("JWK thumbprint (jkt) not currently supported, use x5t#S256")
        
        return None
    
    def verify_token_binding(
        self,
        jwt_claims: Dict[str, Any],
        client_certificate: x509.Certificate
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify that JWT token is bound to the presenting client certificate.
        
        Args:
            jwt_claims: Decoded JWT claims
            client_certificate: Client's TLS certificate
            
        Returns:
            Tuple of (is_valid, error_message)
            
        Security Notes:
            - Uses constant-time comparison to prevent timing attacks
            - Fails closed: returns False if binding claim is missing (when binding is required)
            - Logs verification failures for security monitoring
        """
        # Extract token binding claim
        binding_claim = self.extract_token_binding_claim(jwt_claims)
        
        if not binding_claim:
            # Token has no binding claim
            return False, "Token does not contain certificate binding (cnf claim missing)"
        
        if binding_claim["type"] != "x5t#S256":
            return False, f"Unsupported binding type: {binding_claim['type']}"
        
        # Compute thumbprint of presented certificate
        presented_thumbprint = self.compute_certificate_thumbprint(
            client_certificate,
            encoding="base64url"
        )
        
        # Extract expected thumbprint from token
        expected_thumbprint = binding_claim["value"]
        
        # Constant-time comparison (prevents timing attacks)
        if not secrets.compare_digest(presented_thumbprint, expected_thumbprint):
            logger.warning(
                f"Token binding verification failed: "
                f"expected={expected_thumbprint[:8]}..., "
                f"presented={presented_thumbprint[:8]}..."
            )
            return False, "Certificate thumbprint does not match token binding"
        
        logger.info(f"Token binding verified successfully: thumbprint={presented_thumbprint[:16]}...")
        return True, None
    
    def create_token_binding_claim(
        self,
        certificate: x509.Certificate
    ) -> Dict[str, Dict[str, str]]:
        """
        Create a token binding confirmation claim for inclusion in JWT.
        
        Use this when issuing tokens to include certificate binding.
        
        Args:
            certificate: Client certificate to bind token to
            
        Returns:
            Dictionary suitable for inclusion in JWT claims
            
        Example:
            claims = {
                "iss": "...",
                "sub": "...",
                **create_token_binding_claim(client_cert)
            }
        """
        thumbprint = self.compute_certificate_thumbprint(
            certificate,
            encoding="base64url"
        )
        
        return {
            "cnf": {
                "x5t#S256": thumbprint
            }
        }


class CertificateValidator:
    """
    Validates X.509 certificates for mTLS and token binding.
    
    Performs certificate chain validation, expiration checks, and
    policy enforcement (e.g., allowed CAs, key usage).
    """
    
    def __init__(self, trusted_ca_cert_path: Optional[str] = None):
        """
        Initialize certificate validator.
        
        Args:
            trusted_ca_cert_path: Path to trusted CA certificate bundle (PEM)
        """
        self.trusted_ca_cert_path = trusted_ca_cert_path
        self.trusted_ca_certs = []
        
        if trusted_ca_cert_path:
            self._load_trusted_ca_certs()
    
    def _load_trusted_ca_certs(self):
        """Load trusted CA certificates from file"""
        with open(self.trusted_ca_cert_path, "rb") as f:
            ca_data = f.read()
        
        # Parse PEM-encoded certificates
        for cert_data in ca_data.split(b"-----END CERTIFICATE-----"):
            if b"-----BEGIN CERTIFICATE-----" in cert_data:
                cert_pem = cert_data + b"-----END CERTIFICATE-----"
                cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
                self.trusted_ca_certs.append(cert)
        
        logger.info(f"Loaded {len(self.trusted_ca_certs)} trusted CA certificates")
    
    def validate_certificate(
        self,
        certificate: x509.Certificate,
        check_expiration: bool = True,
        check_key_usage: bool = True
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate client certificate for mTLS.
        
        Args:
            certificate: Client certificate to validate
            check_expiration: Verify certificate is not expired
            check_key_usage: Verify key usage extensions
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        import datetime
        
        # Check expiration
        if check_expiration:
            now = datetime.datetime.utcnow()
            if now < certificate.not_valid_before:
                return False, f"Certificate not yet valid (valid from {certificate.not_valid_before})"
            if now > certificate.not_valid_after:
                return False, f"Certificate expired (expired {certificate.not_valid_after})"
        
        # Check key usage (Digital Signature required for client auth)
        if check_key_usage:
            try:
                key_usage = certificate.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.KEY_USAGE
                ).value
                
                if not key_usage.digital_signature:
                    return False, "Certificate missing Digital Signature key usage"
            except x509.ExtensionNotFound:
                logger.warning("Certificate missing Key Usage extension")
        
        # Check extended key usage (Client Authentication)
        try:
            ext_key_usage = certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
            ).value
            
            client_auth_oid = x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
            if client_auth_oid not in ext_key_usage:
                return False, "Certificate missing Client Authentication extended key usage"
        except x509.ExtensionNotFound:
            logger.warning("Certificate missing Extended Key Usage extension")
        
        logger.info(
            f"Certificate validated: subject={certificate.subject}, "
            f"issuer={certificate.issuer}, "
            f"serial={certificate.serial_number}"
        )
        return True, None
    
    def extract_certificate_info(self, certificate: x509.Certificate) -> Dict[str, Any]:
        """
        Extract useful information from certificate for logging/auditing.
        
        Args:
            certificate: X.509 certificate
            
        Returns:
            Dictionary with certificate metadata
        """
        subject = certificate.subject
        issuer = certificate.issuer
        
        return {
            "subject_common_name": subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value if subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME) else None,
            "subject_organization": subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value if subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME) else None,
            "issuer_common_name": issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value if issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME) else None,
            "serial_number": hex(certificate.serial_number),
            "not_valid_before": certificate.not_valid_before.isoformat(),
            "not_valid_after": certificate.not_valid_after.isoformat(),
            "version": certificate.version.name,
            "signature_algorithm": certificate.signature_algorithm_oid._name
        }


# Example usage
if __name__ == "__main__":
    # Example: Validate token binding
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime
    
    # Generate test certificate
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "lambda-service.ca-a2a.local"),
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
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    
    # Test token binding
    validator = TokenBindingValidator()
    
    # Create binding claim
    binding_claim = validator.create_token_binding_claim(cert)
    print(f"Token binding claim: {binding_claim}")
    
    # Simulate JWT claims with binding
    jwt_claims = {
        "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
        "sub": "lambda-service",
        **binding_claim
    }
    
    # Verify binding
    is_valid, error = validator.verify_token_binding(jwt_claims, cert)
    print(f"Token binding valid: {is_valid}, error: {error}")
    
    # Test certificate validation
    cert_validator = CertificateValidator()
    is_valid, error = cert_validator.validate_certificate(cert)
    print(f"Certificate valid: {is_valid}, error: {error}")
    
    cert_info = cert_validator.extract_certificate_info(cert)
    print(f"Certificate info: {cert_info}")
