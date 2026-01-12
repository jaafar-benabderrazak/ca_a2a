"""
Keycloak OAuth2/OIDC Integration for A2A Security

Provides JWT validation using Keycloak's public keys (JWKS endpoint)
and role-based access control mapping.
"""

import os
import time
import logging
import requests
from typing import Dict, Any, Tuple, Optional, List
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

try:
    import jwt
    from jwt import PyJWKClient
except ImportError:
    logger.warning("PyJWT not installed. Keycloak authentication will not work.")
    jwt = None
    PyJWKClient = None


class KeycloakJWTValidator:
    """
    Validates JWT tokens issued by Keycloak.
    
    Features:
    - Fetches public keys from Keycloak JWKS endpoint
    - Caches public keys for performance
    - Validates token signature, expiration, issuer, audience
    - Extracts user roles for RBAC
    """
    
    def __init__(
        self,
        keycloak_url: str,
        realm: str,
        client_id: str,
        cache_ttl: int = 3600
    ):
        """
        Initialize Keycloak JWT validator.
        
        Args:
            keycloak_url: Base URL of Keycloak server (e.g., http://keycloak.ca-a2a.local:8080)
            realm: Keycloak realm name (e.g., ca-a2a)
            client_id: Expected audience/client ID (e.g., ca-a2a-agents)
            cache_ttl: How long to cache public keys (seconds)
        """
        if jwt is None or PyJWKClient is None:
            raise ImportError("PyJWT is required for Keycloak authentication. Install with: pip install PyJWT[crypto]")
        
        self.keycloak_url = keycloak_url.rstrip('/')
        self.realm = realm
        self.client_id = client_id
        self.cache_ttl = cache_ttl
        
        # JWKS endpoint
        self.jwks_uri = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/certs"
        self.issuer = f"{self.keycloak_url}/realms/{self.realm}"
        
        # Initialize JWKS client (with caching)
        self.jwks_client = PyJWKClient(
            self.jwks_uri,
            cache_keys=True,
            max_cached_keys=16,
            cache_jwk_set_ttl=cache_ttl
        )
        
        logger.info(f"Keycloak JWT validator initialized for realm: {realm}")
        logger.info(f"JWKS endpoint: {self.jwks_uri}")
    
    def verify_token(self, token: str) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Verify JWT token from Keycloak.
        
        Returns:
            Tuple of (principal, roles, claims)
            
        Raises:
            jwt.InvalidTokenError: If token is invalid
        """
        try:
            # Get signing key from JWKS
            signing_key = self.jwks_client.get_signing_key_from_jwt(token)
            
            # Decode and verify token
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=self.issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True
                }
            )
            
            # Extract principal (username)
            principal = claims.get('preferred_username') or claims.get('sub')
            
            # Extract roles from token
            # Keycloak puts roles in: realm_access.roles or resource_access.<client>.roles
            roles = self._extract_roles(claims)
            
            logger.info(f"Token verified for principal: {principal}, roles: {roles}")
            
            return principal, roles, claims
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            raise
        except jwt.InvalidAudienceError:
            logger.warning(f"Invalid audience. Expected: {self.client_id}")
            raise
        except jwt.InvalidIssuerError:
            logger.warning(f"Invalid issuer. Expected: {self.issuer}")
            raise
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            raise
    
    def _extract_roles(self, claims: Dict[str, Any]) -> List[str]:
        """Extract roles from Keycloak token claims"""
        roles = []
        
        # Realm roles
        realm_access = claims.get('realm_access', {})
        if isinstance(realm_access, dict):
            realm_roles = realm_access.get('roles', [])
            if isinstance(realm_roles, list):
                roles.extend(realm_roles)
        
        # Client-specific roles
        resource_access = claims.get('resource_access', {})
        if isinstance(resource_access, dict):
            client_access = resource_access.get(self.client_id, {})
            if isinstance(client_access, dict):
                client_roles = client_access.get('roles', [])
                if isinstance(client_roles, list):
                    roles.extend(client_roles)
        
        return list(set(roles))  # Remove duplicates


class KeycloakRBACMapper:
    """
    Maps Keycloak roles to A2A RBAC principals and permissions.
    """
    
    def __init__(self, role_mapping: Optional[Dict[str, Dict[str, Any]]] = None):
        """
        Initialize RBAC mapper.
        
        Args:
            role_mapping: Dict mapping Keycloak roles to RBAC config
                Example:
                {
                    "admin": {"principal": "admin", "methods": ["*"]},
                    "lambda": {"principal": "lambda", "methods": ["*"]},
                    "orchestrator": {"principal": "orchestrator", "methods": ["extract_document", ...]},
                }
        """
        self.role_mapping = role_mapping or self._default_role_mapping()
    
    def _default_role_mapping(self) -> Dict[str, Dict[str, Any]]:
        """Default role to principal mapping"""
        return {
            "admin": {
                "principal": "admin",
                "methods": ["*"],
                "description": "Full administrative access"
            },
            "lambda": {
                "principal": "lambda",
                "methods": ["*"],
                "description": "Lambda service account - full access"
            },
            "orchestrator": {
                "principal": "orchestrator",
                "methods": [
                    "extract_document",
                    "validate_document",
                    "archive_document",
                    "list_skills",
                    "get_health"
                ],
                "description": "Orchestrator service"
            },
            "document-processor": {
                "principal": "document-processor",
                "methods": [
                    "process_document",
                    "extract_document",
                    "validate_document",
                    "archive_document"
                ],
                "description": "Document processing role"
            },
            "viewer": {
                "principal": "viewer",
                "methods": ["list_skills", "get_health"],
                "description": "Read-only access"
            }
        }
    
    def map_roles_to_principal(
        self,
        keycloak_roles: List[str]
    ) -> Tuple[str, List[str]]:
        """
        Map Keycloak roles to A2A principal and allowed methods.
        
        Returns:
            Tuple of (principal, allowed_methods)
        """
        # Find best matching role (admin > lambda > orchestrator > viewer)
        priority_order = ["admin", "lambda", "document-processor", "orchestrator", "viewer"]
        
        principal = "unknown"
        all_methods = set()
        
        for role in priority_order:
            if role in keycloak_roles and role in self.role_mapping:
                mapping = self.role_mapping[role]
                principal = mapping["principal"]
                methods = mapping["methods"]
                
                # If wildcard, return immediately
                if "*" in methods:
                    return principal, ["*"]
                
                all_methods.update(methods)
        
        return principal, list(all_methods)


class KeycloakAuthClient:
    """
    Client for authenticating with Keycloak and obtaining tokens.
    """
    
    def __init__(
        self,
        keycloak_url: str,
        realm: str,
        client_id: str,
        client_secret: Optional[str] = None
    ):
        """
        Initialize Keycloak auth client.
        
        Args:
            keycloak_url: Base URL of Keycloak server
            realm: Keycloak realm name
            client_id: Client ID for authentication
            client_secret: Client secret (for confidential clients)
        """
        self.keycloak_url = keycloak_url.rstrip('/')
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        
        self.token_endpoint = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
    
    def authenticate_password(
        self,
        username: str,
        password: str
    ) -> Tuple[str, str, int]:
        """
        Authenticate using username/password (Resource Owner Password Credentials flow).
        
        Returns:
            Tuple of (access_token, refresh_token, expires_in)
        """
        data = {
            "grant_type": "password",
            "client_id": self.client_id,
            "username": username,
            "password": password,
            "scope": "openid profile email"
        }
        
        if self.client_secret:
            data["client_secret"] = self.client_secret
        
        try:
            response = requests.post(self.token_endpoint, data=data, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            return (
                result["access_token"],
                result.get("refresh_token", ""),
                result.get("expires_in", 300)
            )
        except requests.RequestException as e:
            logger.error(f"Keycloak authentication failed: {e}")
            raise Exception(f"Authentication failed: {e}")
    
    def refresh_token(self, refresh_token: str) -> Tuple[str, str, int]:
        """
        Refresh access token using refresh token.
        
        Returns:
            Tuple of (access_token, refresh_token, expires_in)
        """
        data = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": refresh_token
        }
        
        if self.client_secret:
            data["client_secret"] = self.client_secret
        
        try:
            response = requests.post(self.token_endpoint, data=data, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            return (
                result["access_token"],
                result.get("refresh_token", refresh_token),  # Some configs return new refresh token
                result.get("expires_in", 300)
            )
        except requests.RequestException as e:
            logger.error(f"Token refresh failed: {e}")
            raise Exception(f"Token refresh failed: {e}")


# Example usage
if __name__ == "__main__":
    # Initialize validator
    validator = KeycloakJWTValidator(
        keycloak_url="http://keycloak.ca-a2a.local:8080",
        realm="ca-a2a",
        client_id="ca-a2a-agents"
    )
    
    # Initialize auth client
    auth_client = KeycloakAuthClient(
        keycloak_url="http://keycloak.ca-a2a.local:8080",
        realm="ca-a2a",
        client_id="ca-a2a-agents",
        client_secret=os.getenv("KEYCLOAK_CLIENT_SECRET")
    )
    
    # Authenticate and get token
    access_token, refresh_token, expires_in = auth_client.authenticate_password(
        username="lambda-service",
        password=os.getenv("LAMBDA_SERVICE_PASSWORD")
    )
    
    print(f"Access token obtained (expires in {expires_in}s)")
    
    # Verify token
    principal, roles, claims = validator.verify_token(access_token)
    print(f"Principal: {principal}")
    print(f"Roles: {roles}")
    
    # Map roles to RBAC
    mapper = KeycloakRBACMapper()
    rbac_principal, allowed_methods = mapper.map_roles_to_principal(roles)
    print(f"RBAC Principal: {rbac_principal}")
    print(f"Allowed Methods: {allowed_methods}")

