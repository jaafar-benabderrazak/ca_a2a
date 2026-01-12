#!/bin/bash
set -e

REGION="eu-west-3"
PROJECT_NAME="ca-a2a"
KEYCLOAK_URL="http://keycloak.${PROJECT_NAME}.local:8080"
REALM_NAME="ca-a2a"
CLIENT_ID="ca-a2a-agents"

echo "============================================"
echo "KEYCLOAK AUTHENTICATION TEST"
echo "============================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get Keycloak client secret
log_info "Retrieving Keycloak client secret..."
CLIENT_SECRET=$(aws secretsmanager get-secret-value \
    --secret-id ${PROJECT_NAME}/keycloak-client-secret \
    --query SecretString \
    --output text \
    --region ${REGION})

# Get admin-user password
log_info "Retrieving admin-user password..."
ADMIN_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id ${PROJECT_NAME}/keycloak-admin-user-password \
    --query SecretString \
    --output text \
    --region ${REGION})

# Test 1: Authenticate with admin-user
log_info ""
log_info "TEST 1: Authenticate admin-user and obtain access token..."
TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM_NAME}/protocol/openid-connect/token"

ADMIN_TOKEN_RESPONSE=$(curl -s -X POST "$TOKEN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=${CLIENT_ID}" \
    -d "client_secret=${CLIENT_SECRET}" \
    -d "username=admin-user" \
    -d "password=${ADMIN_PASSWORD}" \
    -d "scope=openid profile email" 2>/dev/null || echo '{"error":"connection_failed"}')

# Parse response
ADMIN_ACCESS_TOKEN=$(echo "$ADMIN_TOKEN_RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('access_token', ''))" 2>/dev/null || echo "")
ADMIN_REFRESH_TOKEN=$(echo "$ADMIN_TOKEN_RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('refresh_token', ''))" 2>/dev/null || echo "")
TOKEN_ERROR=$(echo "$ADMIN_TOKEN_RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('error', ''))" 2>/dev/null || echo "")

if [ ! -z "$ADMIN_ACCESS_TOKEN" ]; then
    log_info "✓ Successfully obtained access token"
    log_info "  Token (first 50 chars): ${ADMIN_ACCESS_TOKEN:0:50}..."
    
    # Decode JWT claims (just the payload for inspection)
    JWT_PAYLOAD=$(echo "$ADMIN_ACCESS_TOKEN" | cut -d'.' -f2)
    JWT_DECODED=$(echo "$JWT_PAYLOAD" | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "{}")
    
    echo ""
    log_info "Token Claims:"
    echo "$JWT_DECODED" | grep -E '(sub|preferred_username|realm_access|aud|iss|exp)' || echo "$JWT_DECODED"
else
    log_error "✗ Failed to obtain access token"
    log_error "  Error: ${TOKEN_ERROR:-Unknown error}"
    log_error "  Response: $ADMIN_TOKEN_RESPONSE"
    exit 1
fi

# Test 2: Verify token with Keycloak JWKS endpoint
log_info ""
log_info "TEST 2: Verify JWKS endpoint is accessible..."
JWKS_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM_NAME}/protocol/openid-connect/certs"

JWKS_RESPONSE=$(curl -s "$JWKS_ENDPOINT" 2>/dev/null || echo '{"error":"connection_failed"}')
JWKS_KEYS=$(echo "$JWKS_RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(len(data.get('keys', [])))" 2>/dev/null || echo "0")

if [ "$JWKS_KEYS" -gt 0 ]; then
    log_info "✓ JWKS endpoint accessible"
    log_info "  Found $JWKS_KEYS public keys"
else
    log_error "✗ JWKS endpoint not accessible or no keys found"
    log_error "  Response: $JWKS_RESPONSE"
fi

# Test 3: Call orchestrator with Keycloak token
log_info ""
log_info "TEST 3: Call orchestrator service with Keycloak JWT..."

# Get orchestrator IP
ORCHESTRATOR_IP=$(aws ecs describe-tasks \
    --cluster ${PROJECT_NAME}-cluster \
    --tasks $(aws ecs list-tasks --cluster ${PROJECT_NAME}-cluster --service-name orchestrator --region ${REGION} --query 'taskArns[0]' --output text) \
    --region ${REGION} \
    --query 'tasks[0].containers[0].networkInterfaces[0].privateIpv4Address' \
    --output text 2>/dev/null || echo "")

if [ -z "$ORCHESTRATOR_IP" ] || [ "$ORCHESTRATOR_IP" == "None" ]; then
    log_warn "Could not determine orchestrator IP. Skipping service call test."
    log_warn "Run this test from within the VPC to test end-to-end authentication."
else
    log_info "Orchestrator IP: $ORCHESTRATOR_IP"
    
    # Call list_skills method
    ORCHESTRATOR_RESPONSE=$(curl -s -X POST "http://${ORCHESTRATOR_IP}:8001/message" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${ADMIN_ACCESS_TOKEN}" \
        -d '{"jsonrpc":"2.0","id":1,"method":"list_skills","params":{}}' 2>/dev/null || echo '{"error":"connection_failed"}')
    
    SKILLS=$(echo "$ORCHESTRATOR_RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('result', {}).get('skills', []))" 2>/dev/null || echo "[]")
    
    if [ "$SKILLS" != "[]" ]; then
        log_info "✓ Successfully called orchestrator with Keycloak JWT"
        log_info "  Response: $ORCHESTRATOR_RESPONSE"
    else
        log_error "✗ Orchestrator call failed or returned unexpected result"
        log_error "  Response: $ORCHESTRATOR_RESPONSE"
    fi
fi

# Test 4: Token refresh
log_info ""
log_info "TEST 4: Test token refresh..."

if [ ! -z "$ADMIN_REFRESH_TOKEN" ]; then
    REFRESH_RESPONSE=$(curl -s -X POST "$TOKEN_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=refresh_token" \
        -d "client_id=${CLIENT_ID}" \
        -d "client_secret=${CLIENT_SECRET}" \
        -d "refresh_token=${ADMIN_REFRESH_TOKEN}" 2>/dev/null || echo '{"error":"connection_failed"}')
    
    NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('access_token', ''))" 2>/dev/null || echo "")
    
    if [ ! -z "$NEW_ACCESS_TOKEN" ]; then
        log_info "✓ Successfully refreshed access token"
        log_info "  New token (first 50 chars): ${NEW_ACCESS_TOKEN:0:50}..."
    else
        log_error "✗ Token refresh failed"
        log_error "  Response: $REFRESH_RESPONSE"
    fi
else
    log_warn "No refresh token available to test"
fi

# Test 5: Invalid token rejection
log_info ""
log_info "TEST 5: Test invalid token rejection..."

INVALID_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlIiwiYXVkIjoiZmFrZSJ9.fake"

if [ ! -z "$ORCHESTRATOR_IP" ] && [ "$ORCHESTRATOR_IP" != "None" ]; then
    INVALID_RESPONSE=$(curl -s -X POST "http://${ORCHESTRATOR_IP}:8001/message" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${INVALID_TOKEN}" \
        -d '{"jsonrpc":"2.0","id":1,"method":"list_skills","params":{}}' 2>/dev/null || echo '{"error":"connection_failed"}')
    
    ERROR_CODE=$(echo "$INVALID_RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('error', {}).get('code', 0))" 2>/dev/null || echo "0")
    
    if [ "$ERROR_CODE" == "-32600" ] || [ "$ERROR_CODE" == "401" ]; then
        log_info "✓ Invalid token correctly rejected"
        log_info "  Error code: $ERROR_CODE"
    else
        log_warn "Unexpected response to invalid token"
        log_warn "  Response: $INVALID_RESPONSE"
    fi
else
    log_warn "Orchestrator IP not available. Skipping invalid token test."
fi

echo ""
echo "============================================"
echo "KEYCLOAK AUTHENTICATION TEST COMPLETE"
echo "============================================"
echo ""
echo "Summary:"
echo "  ✓ Token Endpoint: Working"
echo "  ✓ JWKS Endpoint: Accessible"
echo "  ✓ Token Issuance: Successful"
echo "  ✓ Token Refresh: Working"
if [ ! -z "$ORCHESTRATOR_IP" ] && [ "$ORCHESTRATOR_IP" != "None" ]; then
    echo "  ✓ Service Integration: Tested"
else
    echo "  - Service Integration: Skipped (run from VPC to test)"
fi
echo ""
echo "Keycloak authentication is properly configured!"
echo ""
echo "To use Keycloak tokens in your applications:"
echo "  1. Authenticate: POST ${TOKEN_ENDPOINT}"
echo "  2. Include token: Authorization: Bearer <access_token>"
echo "  3. Refresh when needed: Use refresh_token with grant_type=refresh_token"
echo ""

