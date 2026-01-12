#!/usr/bin/env python3
"""
Example client demonstrating Keycloak OAuth2 authentication for CA-A2A services.

This script shows how to:
1. Authenticate with Keycloak using username/password
2. Obtain access and refresh tokens
3. Call A2A services with Keycloak JWT tokens
4. Refresh tokens when they expire
5. Handle authentication errors

Usage:
    python keycloak_client_example.py [--username USERNAME] [--password PASSWORD]
"""

import os
import sys
import time
import argparse
import json
import logging
from typing import Dict, Any, Optional, Tuple

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class KeycloakA2AClient:
    """
    Client for authenticating with Keycloak and calling A2A services.
    """
    
    def __init__(
        self,
        keycloak_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        orchestrator_url: str = "http://orchestrator.ca-a2a.local:8001"
    ):
        """
        Initialize Keycloak A2A client.
        
        Args:
            keycloak_url: Base URL of Keycloak server (e.g., http://keycloak.ca-a2a.local:8080)
            realm: Keycloak realm name (e.g., ca-a2a)
            client_id: Client ID (e.g., ca-a2a-agents)
            client_secret: Client secret
            orchestrator_url: URL of the orchestrator service
        """
        self.keycloak_url = keycloak_url.rstrip('/')
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.orchestrator_url = orchestrator_url
        
        self.token_endpoint = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
        
        # Token storage
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: int = 0
    
    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate with Keycloak using username/password.
        
        Args:
            username: Keycloak username
            password: Keycloak password
        
        Returns:
            True if authentication successful, False otherwise
        """
        logger.info(f"Authenticating user: {username}")
        
        try:
            response = requests.post(
                self.token_endpoint,
                data={
                    "grant_type": "password",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "username": username,
                    "password": password,
                    "scope": "openid profile email"
                },
                timeout=10
            )
            
            response.raise_for_status()
            tokens = response.json()
            
            self.access_token = tokens["access_token"]
            self.refresh_token = tokens.get("refresh_token")
            expires_in = tokens.get("expires_in", 300)
            self.token_expires_at = int(time.time()) + expires_in
            
            logger.info(f"✓ Authentication successful (token expires in {expires_in}s)")
            return True
            
        except requests.RequestException as e:
            logger.error(f"✗ Authentication failed: {e}")
            if hasattr(e.response, 'text'):
                logger.error(f"  Response: {e.response.text}")
            return False
    
    def refresh_access_token(self) -> bool:
        """
        Refresh the access token using the refresh token.
        
        Returns:
            True if refresh successful, False otherwise
        """
        if not self.refresh_token:
            logger.error("No refresh token available")
            return False
        
        logger.info("Refreshing access token...")
        
        try:
            response = requests.post(
                self.token_endpoint,
                data={
                    "grant_type": "refresh_token",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "refresh_token": self.refresh_token
                },
                timeout=10
            )
            
            response.raise_for_status()
            tokens = response.json()
            
            self.access_token = tokens["access_token"]
            # Some configurations return a new refresh token
            self.refresh_token = tokens.get("refresh_token", self.refresh_token)
            expires_in = tokens.get("expires_in", 300)
            self.token_expires_at = int(time.time()) + expires_in
            
            logger.info(f"✓ Token refreshed (expires in {expires_in}s)")
            return True
            
        except requests.RequestException as e:
            logger.error(f"✗ Token refresh failed: {e}")
            return False
    
    def ensure_valid_token(self) -> bool:
        """
        Ensure we have a valid access token, refreshing if necessary.
        
        Returns:
            True if valid token available, False otherwise
        """
        if not self.access_token:
            logger.error("No access token. Please authenticate first.")
            return False
        
        # Check if token is about to expire (with 30s buffer)
        if int(time.time()) + 30 >= self.token_expires_at:
            logger.info("Token is expiring soon, refreshing...")
            return self.refresh_access_token()
        
        return True
    
    def call_a2a_method(
        self,
        method: str,
        params: Dict[str, Any],
        service_url: Optional[str] = None
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Call an A2A JSON-RPC method with Keycloak authentication.
        
        Args:
            method: JSON-RPC method name (e.g., "process_document", "list_skills")
            params: Method parameters
            service_url: Service URL (defaults to orchestrator)
        
        Returns:
            Tuple of (success, response_dict)
        """
        if not self.ensure_valid_token():
            return False, {"error": "No valid access token"}
        
        url = service_url or self.orchestrator_url
        
        # Construct JSON-RPC request
        jsonrpc_request = {
            "jsonrpc": "2.0",
            "id": int(time.time() * 1000),
            "method": method,
            "params": params
        }
        
        try:
            logger.info(f"Calling {method} on {url}...")
            
            response = requests.post(
                f"{url}/message",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.access_token}"
                },
                json=jsonrpc_request,
                timeout=30
            )
            
            response.raise_for_status()
            result = response.json()
            
            if "error" in result:
                logger.error(f"✗ Method call failed: {result['error']}")
                return False, result
            
            logger.info(f"✓ Method call successful")
            return True, result
            
        except requests.RequestException as e:
            logger.error(f"✗ HTTP request failed: {e}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    logger.error(f"  Error details: {error_detail}")
                    return False, error_detail
                except:
                    logger.error(f"  Response: {e.response.text}")
            return False, {"error": str(e)}


def main():
    """Example usage of KeycloakA2AClient"""
    
    parser = argparse.ArgumentParser(description="Keycloak A2A Client Example")
    parser.add_argument("--keycloak-url", default="http://keycloak.ca-a2a.local:8080", help="Keycloak URL")
    parser.add_argument("--realm", default="ca-a2a", help="Keycloak realm")
    parser.add_argument("--client-id", default="ca-a2a-agents", help="Client ID")
    parser.add_argument("--client-secret", help="Client secret (or set KEYCLOAK_CLIENT_SECRET env var)")
    parser.add_argument("--username", default="admin-user", help="Username")
    parser.add_argument("--password", help="Password (or set KEYCLOAK_PASSWORD env var)")
    parser.add_argument("--orchestrator-url", default="http://orchestrator.ca-a2a.local:8001", help="Orchestrator URL")
    
    args = parser.parse_args()
    
    # Get client secret from env or args
    client_secret = args.client_secret or os.getenv("KEYCLOAK_CLIENT_SECRET")
    if not client_secret:
        logger.error("Client secret required (use --client-secret or KEYCLOAK_CLIENT_SECRET env var)")
        sys.exit(1)
    
    # Get password from env or args
    password = args.password or os.getenv("KEYCLOAK_PASSWORD")
    if not password:
        logger.error("Password required (use --password or KEYCLOAK_PASSWORD env var)")
        sys.exit(1)
    
    # Initialize client
    client = KeycloakA2AClient(
        keycloak_url=args.keycloak_url,
        realm=args.realm,
        client_id=args.client_id,
        client_secret=client_secret,
        orchestrator_url=args.orchestrator_url
    )
    
    # Authenticate
    if not client.authenticate(username=args.username, password=password):
        logger.error("Authentication failed, exiting")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("KEYCLOAK AUTHENTICATION SUCCESSFUL")
    print("="*60 + "\n")
    
    # Example 1: Get orchestrator skills
    print("Example 1: Get orchestrator skills...")
    success, response = client.call_a2a_method("list_skills", {})
    if success:
        print(f"  Skills: {json.dumps(response.get('result', {}), indent=2)}")
    print()
    
    # Example 2: Get orchestrator health
    print("Example 2: Get orchestrator health...")
    success, response = client.call_a2a_method("get_health", {})
    if success:
        print(f"  Health: {json.dumps(response.get('result', {}), indent=2)}")
    print()
    
    # Example 3: Process document (if S3 bucket has files)
    print("Example 3: Process document...")
    success, response = client.call_a2a_method(
        "process_document",
        {
            "document_id": "test-doc-" + str(int(time.time())),
            "s3_bucket": "ca-a2a-documents-555043101106",
            "s3_key": "test_upload_alb.pdf"
        }
    )
    if success:
        print(f"  Result: {json.dumps(response.get('result', {}), indent=2)}")
    else:
        print(f"  Note: This may fail if the document doesn't exist, which is expected for this demo")
    print()
    
    # Example 4: Test token refresh
    print("Example 4: Test token refresh...")
    if client.refresh_access_token():
        print("  ✓ Token refresh successful")
        # Call another method with refreshed token
        success, response = client.call_a2a_method("list_skills", {})
        if success:
            print("  ✓ Method call with refreshed token successful")
    print()
    
    print("="*60)
    print("ALL EXAMPLES COMPLETED")
    print("="*60)
    print("\nYou can now use this pattern in your applications:")
    print("  1. Create KeycloakA2AClient instance")
    print("  2. Authenticate with username/password")
    print("  3. Call A2A methods with automatic token management")
    print("  4. Tokens are automatically refreshed when needed")
    print()


if __name__ == "__main__":
    main()

