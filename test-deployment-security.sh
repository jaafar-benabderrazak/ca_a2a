#!/bin/bash
###############################################################################
# CA A2A - Deployment and Security Test Script
# Tests all deployed services and security features
# Usage: ./test-deployment-security.sh [--region us-east-1] [--alb <alb-dns>]
###############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
GRAY='\033[0;90m'

# Default configuration
REGION="${AWS_REGION:-us-east-1}"
ALB_DNS="${ALB_DNS:-ca-a2a-alb-1063189579.us-east-1.elb.amazonaws.com}"
PROJECT_NAME="ca-a2a"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --alb) ALB_DNS="$2"; shift 2 ;;
        *) shift ;;
    esac
done

BASE_URL="http://${ALB_DNS}"

# Test counters
PASSED=0
FAILED=0
WARNINGS=0

# Output functions
print_header() { echo -e "\n${CYAN}$(printf '=%.0s' {1..70})${NC}"; echo -e "${CYAN} $1${NC}"; echo -e "${CYAN}$(printf '=%.0s' {1..70})${NC}"; }
print_pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASSED++)); }
print_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAILED++)); }
print_warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)); }
print_info() { echo -e "  ${GRAY}[INFO]${NC} $1"; }

# Banner
echo -e "${BLUE}"
cat << "EOF"
 ██████╗ █████╗        █████╗ ██████╗  █████╗ 
██╔════╝██╔══██╗      ██╔══██╗╚════██╗██╔══██╗
██║     ███████║█████╗███████║ █████╔╝███████║
██║     ██╔══██║╚════╝██╔══██║██╔═══╝ ██╔══██║
╚██████╗██║  ██║      ██║  ██║███████╗██║  ██║
 ╚═════╝╚═╝  ╚═╝      ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                               
  Deployment & Security Test Suite
EOF
echo -e "${NC}"
echo "  Region: ${REGION}"
echo "  ALB: ${ALB_DNS}"
echo ""

###############################################################################
# 1. ECS Service Health Tests
###############################################################################

print_header "1. ECS Services Health Check"

SERVICES=("orchestrator" "extractor" "validator" "archivist" "keycloak" "mcp-server")

for service in "${SERVICES[@]}"; do
    result=$(aws ecs describe-services \
        --cluster ${PROJECT_NAME}-cluster \
        --services "$service" \
        --region "$REGION" \
        --query 'services[0].[runningCount,desiredCount]' \
        --output text 2>/dev/null || echo "0 0")
    
    running=$(echo "$result" | awk '{print $1}')
    desired=$(echo "$result" | awk '{print $2}')
    
    if [[ "$running" == "$desired" && "$running" -gt 0 ]]; then
        print_pass "$service : $running/$desired tasks running"
    else
        print_fail "$service : $running/$desired tasks running"
    fi
done

###############################################################################
# 2. ALB Health Endpoint Tests
###############################################################################

print_header "2. ALB Endpoint Accessibility"

# Test health endpoint
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${BASE_URL}/health" 2>/dev/null || echo "000")
if [[ "$status" == "200" ]]; then
    print_pass "Orchestrator Health : HTTP $status"
else
    print_fail "Orchestrator Health : HTTP $status"
fi

# Test agent card
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${BASE_URL}/.well-known/agent.json" 2>/dev/null || echo "000")
if [[ "$status" == "200" ]]; then
    print_pass "Agent Card : HTTP $status"
else
    print_fail "Agent Card : HTTP $status"
fi

# Test A2A endpoint (expects 405 for GET)
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${BASE_URL}/a2a" 2>/dev/null || echo "000")
if [[ "$status" == "200" || "$status" == "405" ]]; then
    print_pass "A2A Endpoint : HTTP $status"
else
    print_info "A2A Endpoint : HTTP $status"
fi

###############################################################################
# 3. Security Header Tests
###############################################################################

print_header "3. Security Headers Validation"

headers=$(curl -sI --max-time 10 "${BASE_URL}/health" 2>/dev/null)

# Check X-Content-Type-Options
if echo "$headers" | grep -qi "X-Content-Type-Options.*nosniff"; then
    print_pass "X-Content-Type-Options : nosniff"
else
    print_warn "X-Content-Type-Options : Not present or incorrect"
fi

# Check X-Frame-Options
if echo "$headers" | grep -qi "X-Frame-Options"; then
    value=$(echo "$headers" | grep -i "X-Frame-Options" | awk '{print $2}' | tr -d '\r')
    print_pass "X-Frame-Options : $value"
else
    print_warn "X-Frame-Options : Not present"
fi

# Check Content-Security-Policy
if echo "$headers" | grep -qi "Content-Security-Policy"; then
    print_pass "Content-Security-Policy : Present"
else
    print_warn "Content-Security-Policy : Not present"
fi

###############################################################################
# 4. CORS Security Tests
###############################################################################

print_header "4. CORS Security Validation"

# Test with malicious origin
cors_response=$(curl -sI --max-time 10 \
    -H "Origin: https://malicious-site.com" \
    -X OPTIONS \
    "${BASE_URL}/health" 2>/dev/null)

allow_origin=$(echo "$cors_response" | grep -i "Access-Control-Allow-Origin" | awk '{print $2}' | tr -d '\r')

if [[ "$allow_origin" == "*" || "$allow_origin" == "https://malicious-site.com" ]]; then
    print_fail "CORS allows untrusted origin: $allow_origin"
else
    print_pass "CORS blocks untrusted origin (or not configured for wildcard)"
fi

###############################################################################
# 5. Input Validation Tests
###############################################################################

print_header "5. Input Validation & Injection Prevention"

# SQL Injection test
sql_payload="'; DROP TABLE documents; --"
response=$(curl -s --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"document_id\": \"$sql_payload\"}" \
    "${BASE_URL}/a2a" 2>/dev/null)

if echo "$response" | grep -q "DROP TABLE"; then
    print_fail "SQL Injection : Payload reflected in response"
else
    print_pass "SQL Injection : Payload not reflected"
fi

# XSS test
xss_payload="<script>alert('xss')</script>"
response=$(curl -s --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"content\": \"$xss_payload\"}" \
    "${BASE_URL}/a2a" 2>/dev/null)

if echo "$response" | grep -q "<script>"; then
    print_fail "XSS : Script tag reflected in response"
else
    print_pass "XSS : Script tag not reflected"
fi

# Path traversal test
path_payload="../../../etc/passwd"
response=$(curl -s --max-time 10 \
    -X POST \
    -H "Content-Type: application/json" \
    -d "{\"path\": \"$path_payload\"}" \
    "${BASE_URL}/a2a" 2>/dev/null)

if echo "$response" | grep -q "root:"; then
    print_fail "Path Traversal : System file accessible"
else
    print_pass "Path Traversal : Blocked or not exploitable"
fi

###############################################################################
# 6. Rate Limiting Tests
###############################################################################

print_header "6. Rate Limiting (Basic Check)"

print_info "Sending 50 rapid requests..."

rate_limited=false
success_count=0

for i in {1..50}; do
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "${BASE_URL}/health" 2>/dev/null || echo "000")
    if [[ "$status" == "429" ]]; then
        rate_limited=true
    elif [[ "$status" == "200" ]]; then
        ((success_count++))
    fi
done

if $rate_limited; then
    print_pass "Rate limiting active: Some requests returned 429"
else
    print_warn "Rate limiting not detected: $success_count/50 requests succeeded"
fi

###############################################################################
# 7. AWS Infrastructure Security
###############################################################################

print_header "7. AWS Infrastructure Security"

# Check RDS public accessibility
print_info "Checking RDS configuration..."
rds_info=$(aws rds describe-db-instances \
    --region "$REGION" \
    --query 'DBInstances[?contains(DBInstanceIdentifier, `ca-a2a`)].{ID:DBInstanceIdentifier,Public:PubliclyAccessible,Encrypted:StorageEncrypted}' \
    --output json 2>/dev/null)

if echo "$rds_info" | jq -e '.[] | select(.Public == false)' > /dev/null 2>&1; then
    print_pass "RDS is not publicly accessible"
else
    print_fail "RDS may be publicly accessible"
fi

if echo "$rds_info" | jq -e '.[] | select(.Encrypted == true)' > /dev/null 2>&1; then
    print_pass "RDS storage is encrypted"
else
    print_fail "RDS storage is NOT encrypted"
fi

# Check S3 bucket public access block
print_info "Checking S3 bucket configuration..."
buckets=$(aws s3api list-buckets --query 'Buckets[?contains(Name, `ca-a2a`)].Name' --output text 2>/dev/null)

for bucket in $buckets; do
    public_block=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null | jq -r '.PublicAccessBlockConfiguration | .BlockPublicAcls and .BlockPublicPolicy')
    if [[ "$public_block" == "true" ]]; then
        print_pass "S3 $bucket : Public access blocked"
    else
        print_fail "S3 $bucket : Public access NOT fully blocked"
    fi
done

# Check Secrets Manager
print_info "Checking Secrets Manager..."
secrets_count=$(aws secretsmanager list-secrets \
    --region "$REGION" \
    --query 'length(SecretList[?contains(Name, `ca-a2a`) || contains(Name, `DbPassword`) || contains(Name, `Keycloak`)])' \
    --output text 2>/dev/null || echo "0")

if [[ "$secrets_count" -gt 0 ]]; then
    print_pass "Secrets Manager: $secrets_count secrets configured"
else
    print_warn "No secrets found in Secrets Manager"
fi

###############################################################################
# 8. End-to-End Workflow Test
###############################################################################

print_header "8. End-to-End Workflow Test"

print_info "Testing document processing workflow..."

test_payload=$(cat <<EOF
{
    "jsonrpc": "2.0",
    "id": "$(uuidgen 2>/dev/null || echo "test-$(date +%s)")",
    "method": "process_document",
    "params": {
        "document_name": "test_security_$(date +%Y%m%d_%H%M%S).txt",
        "content": "This is a test document for security validation.",
        "document_type": "test"
    }
}
EOF
)

response=$(curl -s --max-time 30 \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$test_payload" \
    "${BASE_URL}/a2a" 2>/dev/null)

status=$?
if [[ $status -eq 0 ]]; then
    if echo "$response" | jq -e '.result' > /dev/null 2>&1; then
        print_pass "Document processing accepted"
    elif echo "$response" | jq -e '.error' > /dev/null 2>&1; then
        error_msg=$(echo "$response" | jq -r '.error.message // .error')
        print_info "Document processing returned error: $error_msg"
    else
        print_info "Document processing response: $(echo "$response" | head -c 100)"
    fi
else
    print_info "Document processing request failed (may require auth)"
fi

###############################################################################
# Summary
###############################################################################

echo ""
echo -e "${CYAN}$(printf '=%.0s' {1..70})${NC}"
echo -e "${CYAN} TEST RESULTS SUMMARY${NC}"
echo -e "${CYAN}$(printf '=%.0s' {1..70})${NC}"
echo ""

TOTAL=$((PASSED + FAILED + WARNINGS))

echo -e "  Total Tests:  $TOTAL"
echo -e "  ${GREEN}Passed:       $PASSED${NC}"
if [[ $FAILED -gt 0 ]]; then
    echo -e "  ${RED}Failed:       $FAILED${NC}"
else
    echo -e "  ${GREEN}Failed:       $FAILED${NC}"
fi
if [[ $WARNINGS -gt 0 ]]; then
    echo -e "  ${YELLOW}Warnings:     $WARNINGS${NC}"
else
    echo -e "  ${GREEN}Warnings:     $WARNINGS${NC}"
fi
echo ""

if [[ $TOTAL -gt 0 ]]; then
    PASS_RATE=$((PASSED * 100 / TOTAL))
    if [[ $PASS_RATE -ge 80 ]]; then
        echo -e "  ${GREEN}Pass Rate:    ${PASS_RATE}%${NC}"
    elif [[ $PASS_RATE -ge 60 ]]; then
        echo -e "  ${YELLOW}Pass Rate:    ${PASS_RATE}%${NC}"
    else
        echo -e "  ${RED}Pass Rate:    ${PASS_RATE}%${NC}"
    fi
fi
echo ""

if [[ $FAILED -eq 0 ]]; then
    echo -e "  ${GREEN}✓ All critical security tests passed!${NC}"
else
    echo -e "  ${RED}✗ $FAILED critical issue(s) found - review failed tests${NC}"
fi

if [[ $WARNINGS -gt 0 ]]; then
    echo -e "  ${YELLOW}⚠ $WARNINGS warning(s) - consider addressing${NC}"
fi

echo ""
echo -e "${CYAN}$(printf '=%.0s' {1..70})${NC}"
echo ""

# Exit code
if [[ $FAILED -gt 0 ]]; then
    exit 1
else
    exit 0
fi

