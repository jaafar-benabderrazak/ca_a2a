"""
Enhanced BaseAgent with mTLS and Token Binding Support

This module extends the base_agent.py with:
- Mutual TLS (mTLS) support for server-side authentication
- Client certificate extraction from TLS connections
- Token binding validation using client certificates
- SSL/TLS configuration management
"""

import ssl
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class MTLSConfig:
    """
    Configuration for mutual TLS.
    
    Manages SSL context with client certificate verification.
    """
    
    def __init__(
        self,
        server_cert_path: str,
        server_key_path: str,
        ca_cert_path: str,
        require_client_cert: bool = True
    ):
        """
        Initialize mTLS configuration.
        
        Args:
            server_cert_path: Path to server certificate (PEM)
            server_key_path: Path to server private key (PEM)
            ca_cert_path: Path to trusted CA certificate (PEM)
            require_client_cert: Require clients to present certificates
        """
        self.server_cert_path = server_cert_path
        self.server_key_path = server_key_path
        self.ca_cert_path = ca_cert_path
        self.require_client_cert = require_client_cert
        
        # Validate paths
        for path in [server_cert_path, server_key_path, ca_cert_path]:
            if not Path(path).exists():
                raise FileNotFoundError(f"Certificate file not found: {path}")
        
        self.ssl_context = self._create_ssl_context()
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create SSL context for mTLS.
        
        Returns:
            Configured SSL context
        """
        # Create SSL context for server
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load server certificate and private key
        ssl_context.load_cert_chain(
            certfile=self.server_cert_path,
            keyfile=self.server_key_path
        )
        
        # Load trusted CA certificates (for verifying client certificates)
        ssl_context.load_verify_locations(cafile=self.ca_cert_path)
        
        # Configure client certificate verification
        if self.require_client_cert:
            ssl_context.verify_mode = ssl.CERT_REQUIRED
        else:
            ssl_context.verify_mode = ssl.CERT_OPTIONAL
        
        # Security settings
        ssl_context.check_hostname = False  # We're the server, not checking our own hostname
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2  # Minimum TLS 1.2
        
        # Cipher suites (strong ciphers only)
        ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        logger.info(
            f"SSL context created: require_client_cert={self.require_client_cert}, "
            f"min_version=TLSv1.2"
        )
        
        return ssl_context


def extract_client_certificate(request: web.Request) -> Optional[x509.Certificate]:
    """
    Extract client certificate from HTTPS request.
    
    Args:
        request: aiohttp Request object
        
    Returns:
        Client certificate or None if not present
    """
    try:
        # Get peer certificate from TLS connection
        transport = request.transport
        if transport is None:
            return None
        
        ssl_object = transport.get_extra_info('ssl_object')
        if ssl_object is None:
            return None
        
        # Get peer certificate in DER format
        cert_der = ssl_object.getpeercert(binary_form=True)
        if cert_der is None:
            return None
        
        # Parse DER-encoded certificate
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        logger.debug(
            f"Extracted client certificate: subject={cert.subject}, "
            f"serial={hex(cert.serial_number)}"
        )
        
        return cert
        
    except Exception as e:
        logger.warning(f"Failed to extract client certificate: {e}")
        return None


# Example: Enhanced BaseAgent usage pattern
"""
To integrate mTLS into your existing BaseAgent, you would:

1. Initialize MTLSConfig:
   mtls_config = MTLSConfig(
       server_cert_path="./certs/agents/orchestrator/orchestrator-cert.pem",
       server_key_path="./certs/agents/orchestrator/orchestrator-key.pem",
       ca_cert_path="./certs/ca/ca-cert.pem",
       require_client_cert=True
   )

2. Pass SSL context to aiohttp server:
   web.run_app(
       app, 
       host='0.0.0.0',
       port=8001,
       ssl_context=mtls_config.ssl_context  # Enable mTLS
   )

3. Extract client certificate in request handler:
   async def handle_http_message(self, request: web.Request) -> web.Response:
       # Extract client certificate
       client_cert = extract_client_certificate(request)
       
       # Pass to security manager for token binding validation
       principal, auth_ctx = await self.security.authenticate_and_authorize(
           headers={k: v for k, v in request.headers.items()},
           message_method=message.method,
           message_dict=data,
           client_certificate=client_cert  # <-- Enable token binding
       )

4. Update A2ASecurityManager.authenticate_and_authorize() signature:
   async def authenticate_and_authorize(
       self,
       headers: Dict[str, str],
       method: str,
       message_dict: Dict[str, Any],
       client_certificate: Optional[x509.Certificate] = None  # <-- Add this
   ) -> Dict[str, Any]:
       # ... existing code ...
       
       # Pass certificate to Keycloak validator
       username, roles, claims = self.keycloak_validator.verify_token(
           token,
           client_certificate=client_certificate  # <-- Enable token binding
       )
"""

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    print("mTLS Configuration Example:")
    print("=" * 60)
    print("""
    # 1. Generate certificates (using mtls_manager.py)
    from mtls_manager import MTLSConfigManager
    
    mtls_manager = MTLSConfigManager(certs_dir="./certs")
    mtls_manager.initialize_ca()
    agent_certs = mtls_manager.generate_agent_certificate("orchestrator")
    
    # 2. Configure mTLS
    mtls_config = MTLSConfig(
        server_cert_path=agent_certs['cert'],
        server_key_path=agent_certs['key'],
        ca_cert_path=agent_certs['ca_cert'],
        require_client_cert=True
    )
    
    # 3. Start agent with mTLS
    app = web.Application()
    app.router.add_post('/message', handle_message)
    
    web.run_app(
        app,
        host='0.0.0.0',
        port=8001,
        ssl_context=mtls_config.ssl_context
    )
    """)
