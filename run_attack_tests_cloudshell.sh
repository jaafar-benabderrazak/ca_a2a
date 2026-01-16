#!/bin/bash
# CA-A2A Attack Scenario Tests - AWS CloudShell Edition
# ======================================================
#
# Run attack scenario tests directly from AWS CloudShell
# with automatic service discovery and configuration

set -e

echo "================================================================================"
echo "CA-A2A ATTACK TESTS - AWS CLOUDSHELL"
echo "================================================================================"
echo ""

# Step 1: Install dependencies
echo "[1/6] Installing Python dependencies..."
pip install --quiet pytest requests PyJWT[crypto] cryptography 2>&1 | grep -v "already satisfied" || true
echo "✓ Dependencies installed"
echo ""

# Step 2: Detect AWS region
if [ -z "$AWS_REGION" ]; then
    export AWS_REGION=$(aws configure get region || echo "eu-west-3")
fi
echo "[2/6] AWS Region: $AWS_REGION"

# Step 3: Discover orchestrator service
echo "[3/6] Discovering orchestrator service..."

# Try to find the ALB
ALB_DNS=$(aws elbv2 describe-load-balancers \
    --region $AWS_REGION \
    --query 'LoadBalancers[?contains(LoadBalancerName, `ca-a2a`)].DNSName' \
    --output text 2>/dev/null || echo "")

if [ -z "$ALB_DNS" ]; then
    echo "⚠  Could not auto-discover ALB. Checking ECS services..."
    
    # Try to get internal service endpoint
    CLUSTER_ARN=$(aws ecs list-clusters --region $AWS_REGION --query 'clusterArns[?contains(@, `ca-a2a`)]' --output text | head -1)
    
    if [ -n "$CLUSTER_ARN" ]; then
        echo "✓ Found ECS cluster: $(basename $CLUSTER_ARN)"
        
        # Get orchestrator service
        SERVICE_ARN=$(aws ecs list-services --cluster $CLUSTER_ARN --region $AWS_REGION \
            --query 'serviceArns[?contains(@, `orchestrator`)]' --output text | head -1)
        
        if [ -n "$SERVICE_ARN" ]; then
            echo "✓ Found orchestrator service: $(basename $SERVICE_ARN)"
            
            # Try to use internal DNS
            ORCHESTRATOR_URL="http://orchestrator.ca-a2a.local:8001"
            echo "  Using internal DNS: $ORCHESTRATOR_URL"
        fi
    fi
else
    ORCHESTRATOR_URL="http://$ALB_DNS"
    echo "✓ Found ALB: $ALB_DNS"
fi

if [ -z "$ORCHESTRATOR_URL" ]; then
    echo "✗ Could not discover orchestrator endpoint"
    echo "  Please set manually:"
    echo "  export ORCHESTRATOR_URL=http://your-orchestrator-url"
    exit 1
fi

export ORCHESTRATOR_URL
echo ""

# Step 4: Check for JWT token
echo "[4/6] Checking authentication..."
if [ -z "$TEST_JWT_TOKEN" ]; then
    echo "⚠  No JWT token provided"
    echo ""
    echo "To obtain a token, you can:"
    echo "  1. Use AWS Secrets Manager (if token is stored there)"
    echo "  2. Authenticate with Keycloak manually"
    echo "  3. Use service account credentials"
    echo ""
    echo "For now, attempting to proceed without token (tests may fail)..."
    echo "To set token: export TEST_JWT_TOKEN='your-token'"
else
    echo "✓ JWT token configured (${#TEST_JWT_TOKEN} characters)"
fi
echo ""

# Step 5: Configure test environment
echo "[5/6] Configuring test environment..."
export TEST_ENV=aws
export KEYCLOAK_URL="http://keycloak.ca-a2a.local:8080"
export KEYCLOAK_REALM="ca-a2a"
export KEYCLOAK_CLIENT_ID="ca-a2a-agents"
export TEST_TIMEOUT=30
export SKIP_ON_CONNECTION_ERROR=false

echo "  TEST_ENV:          $TEST_ENV"
echo "  ORCHESTRATOR_URL:  $ORCHESTRATOR_URL"
echo "  KEYCLOAK_URL:      $KEYCLOAK_URL"
echo ""

# Step 6: Run setup validation
echo "[6/6] Validating environment..."
echo "================================================================================"
python3 setup_test_environment.py
SETUP_EXIT=$?

if [ $SETUP_EXIT -ne 0 ]; then
    echo ""
    echo "================================================================================"
    echo "⚠  ENVIRONMENT NOT READY"
    echo "================================================================================"
    echo ""
    echo "Common issues in CloudShell:"
    echo ""
    echo "1. JWT Token Missing:"
    echo "   export TEST_JWT_TOKEN='your-jwt-token'"
    echo ""
    echo "2. Service Not Accessible:"
    echo "   - Check ECS service is running"
    echo "   - Verify security groups allow CloudShell access"
    echo "   - Try internal DNS: orchestrator.ca-a2a.local:8001"
    echo ""
    echo "3. Get Token from Keycloak (if accessible):"
    echo "   TOKEN=\$(curl -s -X POST http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token \\"
    echo "     -d 'client_id=ca-a2a-agents' \\"
    echo "     -d 'username=test-user' \\"
    echo "     -d 'password=your-password' \\"
    echo "     -d 'grant_type=password' | jq -r '.access_token')"
    echo "   export TEST_JWT_TOKEN=\$TOKEN"
    echo ""
    echo "To skip setup and run tests anyway:"
    echo "  export SKIP_ON_CONNECTION_ERROR=true"
    echo "  pytest test_attack_scenarios.py -v"
    echo ""
    exit 1
fi

echo ""
echo "================================================================================"
echo "✓ ENVIRONMENT READY - RUNNING TESTS"
echo "================================================================================"
echo ""

# Run pytest with appropriate options
PYTEST_ARGS="-v --tb=short"

# Check if HTML report requested
if [ "$1" == "--html" ]; then
    REPORT_FILE="attack_report_$(date +%Y%m%d_%H%M%S).html"
    PYTEST_ARGS="$PYTEST_ARGS --html=$REPORT_FILE --self-contained-html"
    echo "HTML report will be saved to: $REPORT_FILE"
    echo ""
fi

# Run tests
python3 -m pytest test_attack_scenarios.py $PYTEST_ARGS

TEST_EXIT=$?

echo ""
echo "================================================================================"
echo "TEST RESULTS"
echo "================================================================================"

if [ $TEST_EXIT -eq 0 ]; then
    echo "✓ All tests passed - Security controls validated"
elif [ $TEST_EXIT -eq 1 ]; then
    echo "✗ Some tests failed - Security vulnerabilities detected"
    echo "  Review failures above and fix vulnerabilities"
elif [ $TEST_EXIT -eq 5 ]; then
    echo "⚠  No tests collected - Check test file"
else
    echo "✗ Test execution error (exit code: $TEST_EXIT)"
fi

echo "================================================================================"

exit $TEST_EXIT

