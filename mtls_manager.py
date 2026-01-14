"""
Mutual TLS (mTLS) Certificate Management

Provides utilities for generating, managing, and validating X.509 certificates
for mutual TLS authentication in the A2A protocol.

Security Features:
- Certificate generation with proper key usage extensions
- Certificate chain validation
- Certificate revocation list (CRL) support (future)
- OCSP responder integration (future)
"""

import os
import datetime
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)


class CertificateAuthority:
    """
    Internal Certificate Authority for A2A mTLS certificates.
    
    Manages CA certificate and issues client certificates for agents.
    In production, replace with enterprise PKI (e.g., AWS ACM Private CA).
    """
    
    def __init__(
        self,
        ca_cert_path: Optional[str] = None,
        ca_key_path: Optional[str] = None,
        ca_password: Optional[bytes] = None
    ):
        """
        Initialize Certificate Authority.
        
        Args:
            ca_cert_path: Path to CA certificate (PEM)
            ca_key_path: Path to CA private key (PEM)
            ca_password: Password for encrypted CA private key
        """
        self.ca_cert = None
        self.ca_private_key = None
        
        if ca_cert_path and ca_key_path:
            self.load_ca(ca_cert_path, ca_key_path, ca_password)
    
    def load_ca(
        self,
        cert_path: str,
        key_path: str,
        password: Optional[bytes] = None
    ):
        """Load existing CA certificate and private key"""
        with open(cert_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        with open(key_path, "rb") as f:
            self.ca_private_key = serialization.load_pem_private_key(
                f.read(),
                password=password,
                backend=default_backend()
            )
        
        logger.info(f"Loaded CA certificate: {self.ca_cert.subject}")
    
    def generate_ca(
        self,
        common_name: str = "CA A2A Root CA",
        organization: str = "CA A2A",
        country: str = "FR",
        validity_days: int = 3650  # 10 years
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Generate new self-signed CA certificate.
        
        Args:
            common_name: CA common name
            organization: Organization name
            country: Country code (2 letters)
            validity_days: Certificate validity period
            
        Returns:
            Tuple of (certificate, private_key)
        """
        # Generate CA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,  # 4096-bit for CA (higher security)
            backend=default_backend()
        )
        
        # Create CA subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_days))
            # CA extensions
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,  # CA can sign certificates
                    crl_sign=True,       # CA can sign CRLs
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False
            )
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )
        
        self.ca_cert = cert
        self.ca_private_key = private_key
        
        logger.info(f"Generated CA certificate: {subject}")
        return cert, private_key
    
    def issue_client_certificate(
        self,
        common_name: str,
        organization: str = "CA A2A",
        country: str = "FR",
        validity_days: int = 365,
        key_size: int = 2048
    ) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """
        Issue a client certificate signed by this CA.
        
        Args:
            common_name: Client common name (e.g., "orchestrator.ca-a2a.local")
            organization: Organization name
            country: Country code
            validity_days: Certificate validity period
            key_size: RSA key size (2048 or 4096)
            
        Returns:
            Tuple of (certificate, private_key)
        """
        if not self.ca_cert or not self.ca_private_key:
            raise RuntimeError("CA not initialized. Load or generate CA first.")
        
        # Generate client private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Create client subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Build certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_days))
            # Client certificate extensions
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,  # Required for client auth
                    content_commitment=False,
                    key_encipherment=True,   # For TLS key exchange
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
                    ExtendedKeyUsageOID.CLIENT_AUTH,  # TLS client authentication
                    ExtendedKeyUsageOID.SERVER_AUTH   # Can also act as server (agent-to-agent)
                ]),
                critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_private_key.public_key()),
                critical=False
            )
            # Subject Alternative Name (for hostname validation)
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(common_name),
                    x509.DNSName(f"*.{common_name.split('.', 1)[-1]}") if '.' in common_name else x509.DNSName(common_name)
                ]),
                critical=False
            )
            .sign(self.ca_private_key, hashes.SHA256(), backend=default_backend())
        )
        
        logger.info(
            f"Issued client certificate: subject={subject}, "
            f"serial={hex(cert.serial_number)}, "
            f"valid_until={cert.not_valid_after}"
        )
        return cert, private_key
    
    def save_certificate(
        self,
        certificate: x509.Certificate,
        output_path: str
    ):
        """Save certificate to PEM file"""
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(cert_pem)
        
        logger.info(f"Saved certificate to {output_path}")
    
    def save_private_key(
        self,
        private_key: rsa.RSAPrivateKey,
        output_path: str,
        password: Optional[bytes] = None
    ):
        """
        Save private key to PEM file.
        
        Args:
            private_key: RSA private key
            output_path: Output file path
            password: Optional encryption password (recommended for production)
        """
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        else:
            encryption = serialization.NoEncryption()
            logger.warning("Saving private key without encryption (not recommended for production)")
        
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(key_pem)
        
        # Set restrictive permissions (Unix-like systems)
        try:
            os.chmod(output_path, 0o600)  # Owner read/write only
        except Exception:
            pass  # Windows doesn't support chmod
        
        logger.info(f"Saved private key to {output_path}")


class MTLSConfigManager:
    """
    Manages mTLS configuration for A2A agents.
    
    Provides convenient methods to generate and manage certificates
    for all agents in the system.
    """
    
    def __init__(self, certs_dir: str = "./certs"):
        """
        Initialize mTLS config manager.
        
        Args:
            certs_dir: Base directory for storing certificates
        """
        self.certs_dir = Path(certs_dir)
        self.ca_dir = self.certs_dir / "ca"
        self.agents_dir = self.certs_dir / "agents"
        
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.agents_dir.mkdir(parents=True, exist_ok=True)
        
        self.ca = CertificateAuthority()
    
    def initialize_ca(
        self,
        force: bool = False
    ) -> Tuple[str, str]:
        """
        Initialize or load CA certificate.
        
        Args:
            force: Force regeneration even if CA exists
            
        Returns:
            Tuple of (ca_cert_path, ca_key_path)
        """
        ca_cert_path = self.ca_dir / "ca-cert.pem"
        ca_key_path = self.ca_dir / "ca-key.pem"
        
        if ca_cert_path.exists() and ca_key_path.exists() and not force:
            logger.info("Loading existing CA")
            self.ca.load_ca(str(ca_cert_path), str(ca_key_path))
        else:
            logger.info("Generating new CA")
            cert, key = self.ca.generate_ca(
                common_name="CA A2A Root CA",
                organization="CA A2A",
                country="FR"
            )
            self.ca.save_certificate(cert, str(ca_cert_path))
            self.ca.save_private_key(key, str(ca_key_path))
        
        return str(ca_cert_path), str(ca_key_path)
    
    def generate_agent_certificate(
        self,
        agent_name: str,
        force: bool = False
    ) -> Dict[str, str]:
        """
        Generate certificate for an agent.
        
        Args:
            agent_name: Agent name (e.g., "orchestrator", "extractor")
            force: Force regeneration even if certificate exists
            
        Returns:
            Dictionary with certificate paths
        """
        agent_dir = self.agents_dir / agent_name
        agent_dir.mkdir(parents=True, exist_ok=True)
        
        cert_path = agent_dir / f"{agent_name}-cert.pem"
        key_path = agent_dir / f"{agent_name}-key.pem"
        
        if cert_path.exists() and key_path.exists() and not force:
            logger.info(f"Certificate for {agent_name} already exists")
            return {
                "cert": str(cert_path),
                "key": str(key_path),
                "ca_cert": str(self.ca_dir / "ca-cert.pem")
            }
        
        # Generate certificate
        common_name = f"{agent_name}.ca-a2a.local"
        cert, key = self.ca.issue_client_certificate(
            common_name=common_name,
            organization="CA A2A",
            country="FR",
            validity_days=365
        )
        
        self.ca.save_certificate(cert, str(cert_path))
        self.ca.save_private_key(key, str(key_path))
        
        logger.info(f"Generated certificate for {agent_name}")
        
        return {
            "cert": str(cert_path),
            "key": str(key_path),
            "ca_cert": str(self.ca_dir / "ca-cert.pem")
        }
    
    def generate_all_agent_certificates(
        self,
        agents: list = None,
        force: bool = False
    ) -> Dict[str, Dict[str, str]]:
        """
        Generate certificates for all agents.
        
        Args:
            agents: List of agent names (defaults to standard agents)
            force: Force regeneration
            
        Returns:
            Dictionary mapping agent names to certificate paths
        """
        if agents is None:
            agents = ["orchestrator", "extractor", "validator", "archivist", "keycloak", "lambda"]
        
        results = {}
        for agent_name in agents:
            results[agent_name] = self.generate_agent_certificate(agent_name, force=force)
        
        return results


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Initialize mTLS configuration
    mtls_manager = MTLSConfigManager(certs_dir="./certs")
    
    # Generate CA
    ca_cert_path, ca_key_path = mtls_manager.initialize_ca()
    print(f"CA Certificate: {ca_cert_path}")
    print(f"CA Private Key: {ca_key_path}")
    
    # Generate certificates for all agents
    agent_certs = mtls_manager.generate_all_agent_certificates()
    
    print("\nGenerated agent certificates:")
    for agent, paths in agent_certs.items():
        print(f"\n{agent}:")
        print(f"  Certificate: {paths['cert']}")
        print(f"  Private Key: {paths['key']}")
        print(f"  CA Certificate: {paths['ca_cert']}")
