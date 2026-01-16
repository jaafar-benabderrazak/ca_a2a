"""
Helper utilities for attack scenario testing
============================================

Provides utilities for:
- Keycloak authentication and token management
- Test fixtures and mock data generation
- Connection testing and health checks
"""

import time
import logging
import requests
from typing import Optional, Tuple, Dict, Any
from test_config import get_test_config

logger = logging.getLogger(__name__)


class KeycloakTokenHelper:
    """Helper for obtaining JWT tokens from Keycloak for testing"""
    
    def __init__(self):
        self.config = get_test_config()
        self.token_endpoint = (
            f"{self.config.keycloak_url}/realms/{self.config.keycloak_realm}"
            f"/protocol/openid-connect/token"
        )
        self._cached_token: Optional[str] = None
        self._token_expiry: int = 0
    
    def get_valid_token(self, force_refresh: bool = False) -> Optional[str]:
        """
        Get a valid JWT token for testing.
        
        Priority:
        1. Pre-configured TEST_JWT_TOKEN from env
        2. Cached token (if not expired)
        3. Authenticate with Keycloak using credentials
        
        Args:
            force_refresh: Force new token acquisition
            
        Returns:
            Valid JWT token or None if unable to obtain
        """
        
        # Priority 1: Pre-configured token
        if self.config.test_jwt_token and not force_refresh:
            logger.info("Using pre-configured JWT token from TEST_JWT_TOKEN")
            return self.config.test_jwt_token
        
        # Priority 2: Cached token
        if self._cached_token and time.time() < self._token_expiry and not force_refresh:
            logger.info("Using cached JWT token")
            return self._cached_token
        
        # Priority 3: Authenticate with Keycloak
        if self.config.test_password:
            logger.info("Authenticating with Keycloak to obtain new token")
            token = self._authenticate_with_keycloak()
            if token:
                return token
        
        logger.warning(
            "Unable to obtain JWT token. Set TEST_JWT_TOKEN or TEST_PASSWORD environment variable."
        )
        return None
    
    def _authenticate_with_keycloak(self) -> Optional[str]:
        """
        Authenticate with Keycloak using password grant.
        
        Returns:
            Access token or None if authentication failed
        """
        try:
            data = {
                "grant_type": "password",
                "client_id": self.config.keycloak_client_id,
                "username": self.config.test_username,
                "password": self.config.test_password,
                "scope": "openid profile email"
            }
            
            if self.config.keycloak_client_secret:
                data["client_secret"] = self.config.keycloak_client_secret
            
            response = requests.post(
                self.token_endpoint,
                data=data,
                timeout=self.config.timeout_seconds
            )
            
            if response.status_code == 200:
                result = response.json()
                access_token = result["access_token"]
                expires_in = result.get("expires_in", 300)
                
                # Cache token
                self._cached_token = access_token
                self._token_expiry = int(time.time()) + expires_in - 60  # 60s buffer
                
                logger.info(f"Successfully obtained JWT token (expires in {expires_in}s)")
                return access_token
            else:
                logger.error(
                    f"Keycloak authentication failed: {response.status_code} - {response.text}"
                )
                return None
                
        except requests.RequestException as e:
            logger.error(f"Failed to connect to Keycloak: {e}")
            return None
    
    def get_token_for_role(self, role: str) -> Optional[str]:
        """
        Get a token with specific role (requires different user accounts).
        
        This is a placeholder - in real testing, you'd have multiple
        test users with different roles configured in Keycloak.
        """
        # For now, return the default token
        # In production, you'd switch users based on role
        logger.info(f"Requested token for role: {role}")
        return self.get_valid_token()


class ServiceHealthChecker:
    """Check health and availability of services"""
    
    def __init__(self):
        self.config = get_test_config()
    
    def check_orchestrator_health(self) -> Tuple[bool, str]:
        """
        Check if orchestrator service is reachable.
        
        Returns:
            Tuple of (is_healthy, message)
        """
        try:
            response = requests.get(
                f"{self.config.orchestrator_url}/health",
                timeout=self.config.timeout_seconds
            )
            
            if response.status_code == 200:
                return True, "Orchestrator is healthy"
            else:
                return False, f"Orchestrator returned {response.status_code}"
                
        except requests.exceptions.ConnectionError:
            return False, "Connection refused - service not running"
        except requests.exceptions.Timeout:
            return False, "Request timed out"
        except Exception as e:
            return False, f"Health check failed: {str(e)}"
    
    def check_keycloak_health(self) -> Tuple[bool, str]:
        """
        Check if Keycloak is reachable.
        
        Returns:
            Tuple of (is_healthy, message)
        """
        try:
            # Check Keycloak realm endpoint
            realm_url = f"{self.config.keycloak_url}/realms/{self.config.keycloak_realm}"
            response = requests.get(realm_url, timeout=self.config.timeout_seconds)
            
            if response.status_code == 200:
                return True, "Keycloak is healthy"
            else:
                return False, f"Keycloak returned {response.status_code}"
                
        except requests.exceptions.ConnectionError:
            return False, "Connection refused - Keycloak not running"
        except requests.exceptions.Timeout:
            return False, "Request timed out"
        except Exception as e:
            return False, f"Health check failed: {str(e)}"
    
    def check_all_services(self) -> Dict[str, Tuple[bool, str]]:
        """
        Check all required services.
        
        Returns:
            Dict mapping service name to (is_healthy, message)
        """
        return {
            "orchestrator": self.check_orchestrator_health(),
            "keycloak": self.check_keycloak_health()
        }
    
    def print_health_status(self):
        """Print health status of all services"""
        print("\n" + "="*80)
        print("SERVICE HEALTH CHECK")
        print("="*80)
        
        results = self.check_all_services()
        
        for service, (is_healthy, message) in results.items():
            # Use ASCII-safe status indicators for Windows compatibility
            status = "[OK] HEALTHY" if is_healthy else "[FAIL] UNHEALTHY"
            print(f"{service.upper():20} {status:20} {message}")
        
        print("="*80 + "\n")
        
        return all(healthy for healthy, _ in results.values())


def create_mock_jwt_payload(
    username: str = "test-user",
    roles: list = None,
    expired: bool = False
) -> Dict[str, Any]:
    """
    Create mock JWT payload for testing.
    
    Args:
        username: Username for the token
        roles: List of roles (default: ["viewer"])
        expired: Whether token should be expired
        
    Returns:
        JWT payload dict
    """
    import datetime
    
    if roles is None:
        roles = ["viewer"]
    
    now = datetime.datetime.now(datetime.timezone.utc)
    
    if expired:
        exp = now - datetime.timedelta(hours=1)
        iat = now - datetime.timedelta(hours=2)
    else:
        exp = now + datetime.timedelta(hours=1)
        iat = now
    
    return {
        "sub": username,
        "preferred_username": username,
        "exp": int(exp.timestamp()),
        "iat": int(iat.timestamp()),
        "iss": f"http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
        "aud": "ca-a2a-agents",
        "realm_access": {
            "roles": roles
        }
    }


if __name__ == "__main__":
    # Test health checking
    logging.basicConfig(level=logging.INFO)
    
    from test_config import print_test_config
    
    config = get_test_config()
    print_test_config(config)
    
    # Check service health
    checker = ServiceHealthChecker()
    all_healthy = checker.print_health_status()
    
    # Try to get JWT token
    if all_healthy:
        token_helper = KeycloakTokenHelper()
        token = token_helper.get_valid_token()
        
        if token:
            print(f"✅ Successfully obtained JWT token")
            print(f"   Token length: {len(token)} characters")
            print(f"   Token preview: {token[:50]}...")
        else:
            print("❌ Failed to obtain JWT token")
            print("   Set TEST_JWT_TOKEN or TEST_PASSWORD environment variable")

