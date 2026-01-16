#!/bin/bash
# CA-A2A Attack Scenario Test Runner for AWS Environment
# ========================================================
#
# Runs attack scenario tests against AWS ECS deployment
#
# Usage:
#   ./run_attack_tests_aws.sh [OPTIONS]
#
# Options:
#   --token TOKEN         Use pre-configured JWT token
#   --username USER       Keycloak username (default: test-user)
#   --password PASS       Keycloak password
#   --alb-dns DNS         ALB DNS name (from ca-a2a-config.env)
#   --verbose             Enable verbose output
#   --html                Generate HTML report
#   --skip-on-error       Skip tests if services unavailable
#
# Examples:
#   # With pre-configured token
#   ./run_attack_tests_aws.sh --token "eyJhbGc..."
#
#   # With Keycloak credentials
#   ./run_attack_tests_aws.sh --username admin --password secret
#
#   # Generate HTML report
#   ./run_attack_tests_aws.sh --token "..." --html

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
TEST_USERNAME="test-user"
TEST_PASSWORD=""
TEST_JWT_TOKEN=""
ALB_DNS=""
VERBOSE="false"
GENERATE_HTML="false"
SKIP_ON_ERROR="false"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --token)
            TEST_JWT_TOKEN="$2"
            shift 2
            ;;
        --username)
            TEST_USERNAME="$2"
            shift 2
            ;;
        --password)
            TEST_PASSWORD="$2"
            shift 2
            ;;
        --alb-dns)
            ALB_DNS="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE="true"
            shift
            ;;
        --html)
            GENERATE_HTML="true"
            shift
            ;;
        --skip-on-error)
            SKIP_ON_ERROR="true"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo "================================================================================"
echo "CA-A2A ATTACK SCENARIO TESTS - AWS ENVIRONMENT"
echo "================================================================================"
echo ""

# Step 1: Load AWS configuration
if [ -f "ca-a2a-config.env" ]; then
    echo -e "${GREEN}✓${NC} Loading AWS configuration from ca-a2a-config.env"
    source ca-a2a-config.env
    
    # Use ALB_DNS from config if not provided
    if [ -z "$ALB_DNS" ] && [ -n "$ALB_DNS" ]; then
        ALB_DNS="$ALB_DNS"
    fi
else
    echo -e "${YELLOW}⚠${NC} ca-a2a-config.env not found"
fi

# Verify ALB DNS
if [ -z "$ALB_DNS" ]; then
    echo -e "${RED}✗${NC} ALB DNS not configured"
    echo "   Please provide --alb-dns or set ALB_DNS in ca-a2a-config.env"
    exit 1
fi

echo -e "${GREEN}✓${NC} ALB DNS: $ALB_DNS"

# Step 2: Set environment variables for tests
export TEST_ENV="aws"
export ORCHESTRATOR_URL="http://${ALB_DNS}"
export KEYCLOAK_URL="http://keycloak.ca-a2a.local:8080"
export KEYCLOAK_REALM="ca-a2a"
export KEYCLOAK_CLIENT_ID="ca-a2a-agents"
export TEST_USERNAME="$TEST_USERNAME"
export TEST_VERBOSE="$VERBOSE"
export SKIP_ON_CONNECTION_ERROR="$SKIP_ON_ERROR"

if [ -n "$TEST_PASSWORD" ]; then
    export TEST_PASSWORD="$TEST_PASSWORD"
fi

if [ -n "$TEST_JWT_TOKEN" ]; then
    export TEST_JWT_TOKEN="$TEST_JWT_TOKEN"
fi

# Step 3: Check Python dependencies
echo ""
echo "Checking Python dependencies..."
python3 -c "import pytest, requests, jwt" 2>/dev/null || {
    echo -e "${RED}✗${NC} Missing dependencies"
    echo "   Installing required packages..."
    pip install pytest requests PyJWT[crypto] pytest-html
}
echo -e "${GREEN}✓${NC} Dependencies installed"

# Step 4: Run environment setup
echo ""
echo "Running environment setup..."
echo "================================================================================"
python3 setup_test_environment.py || {
    echo ""
    echo -e "${RED}✗${NC} Environment setup failed"
    
    if [ "$SKIP_ON_ERROR" = "false" ]; then
        echo "   Use --skip-on-error to continue anyway"
        exit 1
    else
        echo "   Continuing anyway (--skip-on-error enabled)"
    fi
}

# Step 5: Run tests
echo ""
echo "================================================================================"
echo "RUNNING ATTACK SCENARIO TESTS"
echo "================================================================================"
echo ""

PYTEST_ARGS="-v --tb=short"

if [ "$VERBOSE" = "true" ]; then
    PYTEST_ARGS="$PYTEST_ARGS -s"
fi

if [ "$GENERATE_HTML" = "true" ]; then
    REPORT_FILE="attack_report_$(date +%Y%m%d_%H%M%S).html"
    PYTEST_ARGS="$PYTEST_ARGS --html=$REPORT_FILE --self-contained-html"
    echo "HTML report will be saved to: $REPORT_FILE"
    echo ""
fi

# Run pytest
python3 -m pytest test_attack_scenarios.py $PYTEST_ARGS

TEST_EXIT_CODE=$?

echo ""
echo "================================================================================"
echo "TEST EXECUTION COMPLETE"
echo "================================================================================"

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓${NC} All tests passed"
elif [ $TEST_EXIT_CODE -eq 1 ]; then
    echo -e "${RED}✗${NC} Some tests failed - Security vulnerabilities detected"
elif [ $TEST_EXIT_CODE -eq 5 ]; then
    echo -e "${YELLOW}⚠${NC} No tests collected"
else
    echo -e "${RED}✗${NC} Test execution error (exit code: $TEST_EXIT_CODE)"
fi

if [ "$GENERATE_HTML" = "true" ] && [ -f "$REPORT_FILE" ]; then
    echo ""
    echo "View HTML report: $REPORT_FILE"
fi

echo "================================================================================"

exit $TEST_EXIT_CODE

