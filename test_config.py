"""
Test Configuration for Attack Scenarios
========================================

Centralized configuration for running attack scenario tests against:
- Local development environment (localhost)
- AWS ECS deployment (via ALB or internal endpoints)
- Keycloak authentication

Usage:
    export TEST_ENV=aws  # or 'local'
    python test_attack_scenarios.py
"""

import os
from typing import Optional
from dataclasses import dataclass


@dataclass
class TestConfig:
    """Configuration for attack scenario tests"""
    
    # Environment selection
    environment: str  # 'local', 'aws', 'custom'
    
    # Orchestrator endpoint
    orchestrator_url: str
    
    # Keycloak configuration
    keycloak_url: str
    keycloak_realm: str
    keycloak_client_id: str
    keycloak_client_secret: Optional[str]
    
    # Test credentials
    test_username: Optional[str]
    test_password: Optional[str]
    
    # Pre-obtained JWT token (optional, overrides auth)
    test_jwt_token: Optional[str]
    
    # Test behavior
    skip_on_connection_error: bool
    timeout_seconds: int
    verbose: bool


def load_test_config() -> TestConfig:
    """
    Load test configuration from environment variables.
    
    Environment Variables:
        TEST_ENV: 'local', 'aws', or 'custom' (default: 'local')
        
        # Custom URLs (for TEST_ENV=custom)
        ORCHESTRATOR_URL: Custom orchestrator endpoint
        KEYCLOAK_URL: Custom Keycloak endpoint
        
        # Keycloak configuration
        KEYCLOAK_REALM: Keycloak realm (default: 'ca-a2a')
        KEYCLOAK_CLIENT_ID: Client ID (default: 'ca-a2a-agents')
        KEYCLOAK_CLIENT_SECRET: Client secret (optional)
        
        # Test credentials
        TEST_USERNAME: Username for authentication (default: 'test-user')
        TEST_PASSWORD: Password for authentication
        TEST_JWT_TOKEN: Pre-obtained JWT token (bypasses auth)
        
        # Test behavior
        SKIP_ON_CONNECTION_ERROR: Skip tests if service unavailable (default: 'false')
        TEST_TIMEOUT: Request timeout in seconds (default: 10)
        TEST_VERBOSE: Enable verbose output (default: 'false')
    """
    
    env = os.getenv('TEST_ENV', 'local').lower()
    
    # Determine orchestrator URL based on environment
    if env == 'local':
        orchestrator_url = 'http://localhost:8001'
        keycloak_url = 'http://localhost:8080'
    elif env == 'aws':
        # Use ALB DNS from ca-a2a-config.env
        alb_dns = os.getenv('ALB_DNS', 'ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com')
        orchestrator_url = f'http://{alb_dns}'
        
        # Keycloak in AWS (if deployed) or local
        keycloak_url = os.getenv('KEYCLOAK_URL', 'http://keycloak.ca-a2a.local:8080')
    else:  # custom
        orchestrator_url = os.getenv('ORCHESTRATOR_URL', 'http://localhost:8001')
        keycloak_url = os.getenv('KEYCLOAK_URL', 'http://localhost:8080')
    
    return TestConfig(
        environment=env,
        orchestrator_url=orchestrator_url,
        keycloak_url=keycloak_url,
        keycloak_realm=os.getenv('KEYCLOAK_REALM', 'ca-a2a'),
        keycloak_client_id=os.getenv('KEYCLOAK_CLIENT_ID', 'ca-a2a-agents'),
        keycloak_client_secret=os.getenv('KEYCLOAK_CLIENT_SECRET'),
        test_username=os.getenv('TEST_USERNAME', 'test-user'),
        test_password=os.getenv('TEST_PASSWORD'),
        test_jwt_token=os.getenv('TEST_JWT_TOKEN'),
        skip_on_connection_error=os.getenv('SKIP_ON_CONNECTION_ERROR', 'false').lower() == 'true',
        timeout_seconds=int(os.getenv('TEST_TIMEOUT', '10')),
        verbose=os.getenv('TEST_VERBOSE', 'false').lower() == 'true'
    )


def print_test_config(config: TestConfig):
    """Print test configuration (safe, no secrets)"""
    print("\n" + "="*80)
    print("ATTACK SCENARIO TEST CONFIGURATION")
    print("="*80)
    print(f"Environment:          {config.environment}")
    print(f"Orchestrator URL:     {config.orchestrator_url}")
    print(f"Keycloak URL:         {config.keycloak_url}")
    print(f"Keycloak Realm:       {config.keycloak_realm}")
    print(f"Keycloak Client ID:   {config.keycloak_client_id}")
    print(f"Test Username:        {config.test_username}")
    print(f"JWT Token Provided:   {'Yes' if config.test_jwt_token else 'No'}")
    print(f"Skip on Error:        {config.skip_on_connection_error}")
    print(f"Timeout:              {config.timeout_seconds}s")
    print(f"Verbose:              {config.verbose}")
    print("="*80 + "\n")


# Singleton instance
_config: Optional[TestConfig] = None


def get_test_config() -> TestConfig:
    """Get or create singleton test configuration"""
    global _config
    if _config is None:
        _config = load_test_config()
    return _config


if __name__ == "__main__":
    # Test configuration loading
    config = load_test_config()
    print_test_config(config)

