#!/usr/bin/env python3
"""
Test Environment Setup Script
==============================

Prepares the test environment for attack scenario testing:
1. Validates configuration
2. Checks service availability
3. Obtains authentication tokens
4. Verifies connectivity

Usage:
    # Local testing
    TEST_ENV=local python setup_test_environment.py
    
    # AWS testing
    TEST_ENV=aws ALB_DNS=ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com python setup_test_environment.py
    
    # With pre-configured token
    TEST_JWT_TOKEN=eyJhbGc... python setup_test_environment.py
"""

import sys
import logging
from test_config import get_test_config, print_test_config
from test_helpers import ServiceHealthChecker, KeycloakTokenHelper

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Main setup routine"""
    
    print("\n" + "="*80)
    print("CA-A2A ATTACK SCENARIO TEST ENVIRONMENT SETUP")
    print("="*80 + "\n")
    
    # Step 1: Load and validate configuration
    logger.info("Step 1: Loading test configuration...")
    config = get_test_config()
    print_test_config(config)
    
    # Step 2: Check service health
    logger.info("Step 2: Checking service health...")
    checker = ServiceHealthChecker()
    health_results = checker.check_all_services()
    checker.print_health_status()
    
    orchestrator_healthy = health_results["orchestrator"][0]
    keycloak_healthy = health_results["keycloak"][0]
    
    # Step 3: Obtain authentication token
    logger.info("Step 3: Obtaining JWT authentication token...")
    
    token_helper = KeycloakTokenHelper()
    token = token_helper.get_valid_token()
    
    print("\n" + "="*80)
    print("AUTHENTICATION STATUS")
    print("="*80)
    
    if token:
        print(f"[OK] JWT Token:       Successfully obtained")
        print(f"     Token Length:    {len(token)} characters")
        print(f"     Token Preview:   {token[:60]}...")
        
        # Decode token to show info (without verification for preview)
        try:
            import jwt
            decoded = jwt.decode(token, options={"verify_signature": False})
            print(f"     Username:        {decoded.get('preferred_username', decoded.get('sub'))}")
            print(f"     Expires:         {decoded.get('exp')}")
            
            # Extract roles
            roles = []
            if 'realm_access' in decoded and 'roles' in decoded['realm_access']:
                roles.extend(decoded['realm_access']['roles'])
            print(f"     Roles:           {', '.join(roles) if roles else 'None'}")
        except Exception as e:
            logger.debug(f"Could not decode token for preview: {e}")
    else:
        print(f"[FAIL] JWT Token:     NOT OBTAINED")
        print(f"       Action:        Set TEST_JWT_TOKEN or TEST_PASSWORD")
    
    print("="*80 + "\n")
    
    # Step 4: Test connectivity with a simple request
    if orchestrator_healthy and token:
        logger.info("Step 4: Testing authenticated request...")
        
        import requests
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            # Try a simple JSON-RPC request
            payload = {
                "jsonrpc": "2.0",
                "method": "get_health",
                "params": {},
                "id": "test-setup-1"
            }
            
            response = requests.post(
                f"{config.orchestrator_url}/jsonrpc",
                json=payload,
                headers=headers,
                timeout=config.timeout_seconds
            )
            
            print("\n" + "="*80)
            print("CONNECTIVITY TEST")
            print("="*80)
            print(f"[OK] Status Code:     {response.status_code}")
            print(f"     Response Time:   {response.elapsed.total_seconds():.3f}s")
            
            if response.status_code == 200:
                print(f"     Message:         Authenticated request successful")
            elif response.status_code == 401:
                print(f"     Message:         Authentication failed (check token)")
            elif response.status_code == 403:
                print(f"     Message:         Authorization failed (check roles)")
            else:
                print(f"     Message:         Unexpected response")
            
            print("="*80 + "\n")
            
        except requests.RequestException as e:
            logger.error(f"Connectivity test failed: {e}")
    else:
        logger.warning("Skipping connectivity test (service unavailable or no token)")
    
    # Step 5: Final summary
    print("\n" + "="*80)
    print("SETUP SUMMARY")
    print("="*80)
    
    all_ready = orchestrator_healthy and token
    
    if all_ready:
        print("[OK] Environment Status:  READY FOR TESTING")
        print("\nNext Steps:")
        print("  1. Run full test suite:         pytest test_attack_scenarios.py -v")
        print("  2. Run specific scenario:       pytest test_attack_scenarios.py::TestScenario01_JWTTokenTheft -v")
        print("  3. Generate HTML report:        pytest test_attack_scenarios.py --html=report.html")
        print("\nEnvironment Variables (save these for later):")
        print(f"  export TEST_ENV={config.environment}")
        print(f"  export ORCHESTRATOR_URL={config.orchestrator_url}")
        if token and not config.test_jwt_token:
            print(f"  export TEST_JWT_TOKEN='{token}'")
    else:
        print("[FAIL] Environment Status:  NOT READY")
        print("\nIssues Found:")
        
        if not orchestrator_healthy:
            print("  - Orchestrator service is not reachable")
            print(f"    URL: {config.orchestrator_url}")
            print("    Action: Start the service or update ORCHESTRATOR_URL")
        
        if not token:
            print("  - JWT authentication token not available")
            print("    Action: Set TEST_JWT_TOKEN or TEST_PASSWORD environment variable")
        
        if not keycloak_healthy:
            print("  - Keycloak is not reachable (authentication will fail)")
            print(f"    URL: {config.keycloak_url}")
            print("    Action: Start Keycloak or provide TEST_JWT_TOKEN directly")
    
    print("="*80 + "\n")
    
    # Exit code
    return 0 if all_ready else 1


if __name__ == "__main__":
    sys.exit(main())

