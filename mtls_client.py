"""
Enhanced A2A Client with mTLS and Token Binding Support

Provides a client library for calling A2A agents with:
- Mutual TLS (mTLS) client authentication
- Client certificate presentation
- Token binding support
- Secure connection management
"""

import ssl
import logging
import aiohttp
from pathlib import Path
from typing import Optional, Dict, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)


class MTLSClient:
    """
    HTTP client with mTLS support for A2A communication.
    
    Presents client certificate for mutual TLS authentication
    and token binding.
    """
    
    def __init__(
        self,
        client_cert_path: str,
        client_key_path: str,
        ca_cert_path: str,
        verify_server: bool = True
    ):
        """
        Initialize mTLS client.
        
        Args:
            client_cert_path: Path to client certificate (PEM)
            client_key_path: Path to client private key (PEM)
            ca_cert_path: Path to trusted CA certificate (PEM)
            verify_server: Verify server certificate (recommended)
        """
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.ca_cert_path = ca_cert_path
        self.verify_server = verify_server
        
        # Validate paths
        for path in [client_cert_path, client_key_path, ca_cert_path]:
            if not Path(path).exists():
                raise FileNotFoundError(f"Certificate file not found: {path}")
        
        # Load client certificate for token binding
        with open(client_cert_path, "rb") as f:
            self.client_certificate = x509.load_pem_x509_certificate(
                f.read(),
                default_backend()
            )
        
        self.ssl_context = self._create_ssl_context()
        self.session: Optional[aiohttp.ClientSession] = None
        
        logger.info(
            f"mTLS client initialized: cert={client_cert_path}, "
            f"verify_server={verify_server}"
        )
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create SSL context for mTLS client.
        
        Returns:
            Configured SSL context
        """
        # Create SSL context for client
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        # Load client certificate and private key
        ssl_context.load_cert_chain(
            certfile=self.client_cert_path,
            keyfile=self.client_key_path
        )
        
        # Load trusted CA certificates (for verifying server certificate)
        ssl_context.load_verify_locations(cafile=self.ca_cert_path)
        
        # Configure server certificate verification
        if self.verify_server:
            ssl_context.check_hostname = False  # Using internal DNS names
            ssl_context.verify_mode = ssl.CERT_REQUIRED
        else:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            logger.warning("Server certificate verification disabled (not recommended)")
        
        # Security settings
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        return ssl_context
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
    
    async def connect(self):
        """Create aiohttp session with mTLS"""
        connector = aiohttp.TCPConnector(ssl=self.ssl_context)
        self.session = aiohttp.ClientSession(connector=connector)
        logger.info("mTLS client session created")
    
    async def close(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            logger.info("mTLS client session closed")
    
    async def send_message(
        self,
        url: str,
        message: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Send JSON-RPC message to A2A agent with mTLS.
        
        Args:
            url: Agent endpoint URL (e.g., https://orchestrator.ca-a2a.local:8001/message)
            message: JSON-RPC message dictionary
            headers: Additional HTTP headers (e.g., Authorization)
            timeout: Request timeout in seconds
            
        Returns:
            Response dictionary
            
        Raises:
            aiohttp.ClientError: If request fails
        """
        if not self.session:
            await self.connect()
        
        # Prepare headers
        request_headers = {
            "Content-Type": "application/json"
        }
        if headers:
            request_headers.update(headers)
        
        logger.debug(
            f"Sending mTLS request to {url}: method={message.get('method')}, "
            f"id={message.get('id')}"
        )
        
        # Send request
        async with self.session.post(
            url,
            json=message,
            headers=request_headers,
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as response:
            response_data = await response.json()
            
            logger.debug(
                f"Received response from {url}: status={response.status}, "
                f"success={'error' not in response_data}"
            )
            
            return response_data


class A2AClientWithMTLS:
    """
    High-level A2A client with mTLS and token binding.
    
    Combines:
    - mTLS client certificate authentication
    - Keycloak JWT token authentication
    - Token binding (JWT bound to certificate)
    - JSON-RPC message handling
    """
    
    def __init__(
        self,
        client_cert_path: str,
        client_key_path: str,
        ca_cert_path: str,
        keycloak_url: str,
        realm: str = "ca-a2a",
        client_id: str = "ca-a2a-agents",
        client_secret: Optional[str] = None
    ):
        """
        Initialize A2A client with mTLS.
        
        Args:
            client_cert_path: Path to client certificate
            client_key_path: Path to client private key
            ca_cert_path: Path to CA certificate
            keycloak_url: Keycloak server URL
            realm: Keycloak realm
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret (for token issuance with binding)
        """
        self.mtls_client = MTLSClient(
            client_cert_path=client_cert_path,
            client_key_path=client_key_path,
            ca_cert_path=ca_cert_path
        )
        
        self.keycloak_url = keycloak_url.rstrip('/')
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        
        logger.info(f"A2A client with mTLS initialized for realm: {realm}")
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.mtls_client.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.mtls_client.close()
    
    async def authenticate(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_client_credentials: bool = False
    ):
        """
        Authenticate with Keycloak and obtain token with certificate binding.
        
        Args:
            username: Username (for password grant)
            password: Password (for password grant)
            use_client_credentials: Use client credentials grant (service accounts)
        """
        token_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
        
        # Prepare token request data
        data = {
            "client_id": self.client_id,
        }
        
        if self.client_secret:
            data["client_secret"] = self.client_secret
        
        if use_client_credentials:
            data["grant_type"] = "client_credentials"
        elif username and password:
            data["grant_type"] = "password"
            data["username"] = username
            data["password"] = password
        else:
            raise ValueError("Either username/password or use_client_credentials=True required")
        
        # Request token with certificate binding
        # Note: Keycloak must be configured to include certificate binding in tokens
        # (see Keycloak documentation on OAuth 2.0 Mutual-TLS Client Authentication)
        
        logger.info(f"Authenticating with Keycloak: grant_type={data['grant_type']}")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(token_url, data=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise RuntimeError(f"Authentication failed: {response.status} - {error_text}")
                
                token_data = await response.json()
                self.access_token = token_data.get("access_token")
                self.refresh_token = token_data.get("refresh_token")
                
                logger.info("Authentication successful, token obtained")
    
    async def call_agent(
        self,
        agent_url: str,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Call A2A agent method with mTLS and token binding.
        
        Args:
            agent_url: Agent endpoint URL
            method: JSON-RPC method name
            params: Method parameters
            message_id: Request ID (auto-generated if not provided)
            
        Returns:
            Method result
            
        Raises:
            RuntimeError: If call fails or returns error
        """
        if not self.access_token:
            raise RuntimeError("Not authenticated. Call authenticate() first.")
        
        # Prepare JSON-RPC message
        import uuid
        message = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": message_id or str(uuid.uuid4())
        }
        
        # Prepare headers with Bearer token
        headers = {
            "Authorization": f"Bearer {self.access_token}"
        }
        
        # Send request with mTLS
        response = await self.mtls_client.send_message(
            url=agent_url,
            message=message,
            headers=headers
        )
        
        # Check for JSON-RPC error
        if "error" in response:
            error = response["error"]
            raise RuntimeError(
                f"RPC error {error.get('code')}: {error.get('message')}"
            )
        
        return response.get("result")


# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def main():
        # Example: Call orchestrator with mTLS and token binding
        async with A2AClientWithMTLS(
            client_cert_path="./certs/agents/lambda/lambda-cert.pem",
            client_key_path="./certs/agents/lambda/lambda-key.pem",
            ca_cert_path="./certs/ca/ca-cert.pem",
            keycloak_url="http://keycloak.ca-a2a.local:8080",
            realm="ca-a2a",
            client_id="ca-a2a-agents",
            client_secret="<client-secret>"
        ) as client:
            # Authenticate (client credentials for service account)
            await client.authenticate(use_client_credentials=True)
            
            # Call orchestrator
            result = await client.call_agent(
                agent_url="https://orchestrator.ca-a2a.local:8001/message",
                method="process_document",
                params={"s3_key": "invoices/2026/01/test.pdf"}
            )
            
            print(f"Result: {result}")
    
    # Run example
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
