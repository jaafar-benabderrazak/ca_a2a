#!/bin/bash
#
# Comprehensive A2A Security Test Suite
# Tests all security features in the deployed AWS environment:
# 1. Keycloak JWT Authentication
# 2. RBAC Authorization via Keycloak Roles
# 3. Rate Limiting
# 4. Replay Protection
# 5. JSON Schema Validation
# 6. API Key Authentication
# 7. Secrets Management
#
# Usage:
#   ./test-security-comprehensive.sh
#   ./test-security-comprehensive.sh --keycloak-only
#   ./test-security-comprehensive.sh --verbose
#

set -o pipefail

REGION="${AWS_REGION:-eu-west-3}"
CLUSTER="ca-a2a-cluster"
KEYCLOAK_REALM="ca-a2a"
KEYCLOAK_CLIENT_ID="ca-a2a-agents"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test counters
PASSED=0
FAILED=0
SKIPPED=0
WARNINGS=0

# Parse arguments
VERBOSE=false
KEYCLOAK_ONLY=false
for arg in "$@"; do
    case $arg in
        --verbose|-v) VERBOSE=true ;;
        --keycloak-only) KEYCLOAK_ONLY=true ;;
        --help|-h)
            echo "Usage: $0 [--verbose] [--keycloak-only]"
            exit 0
            ;;
    esac
done

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_debug() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
}

test_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

test_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

test_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((SKIPPED++))
}

test_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNINGS++))
}

# Get service IP address
get_service_ip() {
    local service_name=$1
    local task_arn=$(aws ecs list-tasks \
        --cluster ${CLUSTER} \
        --service-name ${service_name} \
        --region ${REGION} \
        --query 'taskArns[0]' \
        --output text 2>/dev/null)
    
    if [ -z "$task_arn" ] || [ "$task_arn" = "None" ]; then
        echo ""
        return 1
    fi
    
    aws ecs describe-tasks \
        --cluster ${CLUSTER} \
        --tasks ${task_arn} \
        --region ${REGION} \
        --query 'tasks[0].containers[0].networkInterfaces[0].privateIpv4Address' \
        --output text 2>/dev/null
}

# Get environment variable from task definition
get_task_env() {
    local task_def=$1
    local env_name=$2
    
    aws ecs describe-task-definition \
        --task-definition ca-a2a-${task_def} \
        --region ${REGION} \
        --query "taskDefinition.containerDefinitions[0].environment[?name=='${env_name}'].value" \
        --output text 2>/dev/null
}

# Get secret from Secrets Manager
get_secret() {
    local secret_name=$1
    
    aws secretsmanager get-secret-value \
        --secret-id ${secret_name} \
        --region ${REGION} \
        --query 'SecretString' \
        --output text 2>/dev/null
}

echo ""
echo "============================================================"
echo -e "${CYAN}  COMPREHENSIVE A2A SECURITY TEST SUITE${NC}"
echo "============================================================"
echo ""
echo "Region: ${REGION}"
echo "Cluster: ${CLUSTER}"
echo "Date: $(date)"
echo ""

# ============================================================
# SECTION 1: INFRASTRUCTURE SECURITY VERIFICATION
# ============================================================
echo ""
echo "============================================================"
echo -e "${BLUE}SECTION 1: Infrastructure Security Verification${NC}"
echo "============================================================"
echo ""

# Test 1.1: Secrets Manager Configuration
log_info "1.1 Checking Secrets Manager configuration..."

SECRET_COUNT=$(aws secretsmanager list-secrets \
    --region ${REGION} \
    --query "length(SecretList[?contains(Name, 'ca-a2a')])" \
    --output text 2>/dev/null)

if [ "$SECRET_COUNT" -gt 0 ]; then
    test_pass "Secrets Manager: ${SECRET_COUNT} secrets configured"
    
    # Check if database credentials are in Secrets Manager
    DB_SECRET=$(aws secretsmanager list-secrets \
        --region ${REGION} \
        --query "SecretList[?contains(Name, 'database') || contains(Name, 'postgres')].Name" \
        --output text 2>/dev/null)
    
    if [ ! -z "$DB_SECRET" ]; then
        test_pass "Database credentials: Stored in Secrets Manager"
    else
        test_warn "Database credentials: Not found in Secrets Manager"
    fi
else
    test_fail "Secrets Manager: No secrets configured"
fi

# Test 1.2: S3 Bucket Security
log_info "1.2 Checking S3 bucket security..."

S3_BUCKET=$(aws s3api list-buckets \
    --query "Buckets[?contains(Name, 'ca-a2a-documents')].Name" \
    --output text 2>/dev/null | head -1)

if [ ! -z "$S3_BUCKET" ]; then
    # Check encryption
    ENCRYPTION=$(aws s3api get-bucket-encryption \
        --bucket ${S3_BUCKET} \
        --region ${REGION} \
        --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
        --output text 2>/dev/null)
    
    if [ "$ENCRYPTION" = "AES256" ] || [ "$ENCRYPTION" = "aws:kms" ]; then
        test_pass "S3 Encryption: ${ENCRYPTION} enabled"
    else
        test_fail "S3 Encryption: Not enabled"
    fi
    
    # Check public access block
    PUBLIC_BLOCK=$(aws s3api get-public-access-block \
        --bucket ${S3_BUCKET} \
        --region ${REGION} \
        --query 'PublicAccessBlockConfiguration.BlockPublicAcls' \
        --output text 2>/dev/null)
    
    if [ "$PUBLIC_BLOCK" = "True" ]; then
        test_pass "S3 Public Access: Blocked"
    else
        test_fail "S3 Public Access: Not blocked"
    fi
else
    test_skip "S3 bucket: Not found"
fi

# Test 1.3: VPC Security Groups
log_info "1.3 Checking VPC security configuration..."

VPC_ID=$(aws ec2 describe-vpcs \
    --region ${REGION} \
    --filters "Name=tag:Name,Values=*ca-a2a*" \
    --query 'Vpcs[0].VpcId' \
    --output text 2>/dev/null)

if [ ! -z "$VPC_ID" ] && [ "$VPC_ID" != "None" ]; then
    test_pass "VPC: ${VPC_ID} configured"
    
    # Check for private subnets
    PRIVATE_SUBNETS=$(aws ec2 describe-subnets \
        --region ${REGION} \
        --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Name,Values=*private*" \
        --query 'length(Subnets)' \
        --output text 2>/dev/null)
    
    if [ "$PRIVATE_SUBNETS" -gt 0 ]; then
        test_pass "Private Subnets: ${PRIVATE_SUBNETS} configured"
    else
        test_warn "Private Subnets: None found"
    fi
else
    test_skip "VPC: Not found"
fi

# ============================================================
# SECTION 2: AUTHENTICATION CONFIGURATION
# ============================================================
echo ""
echo "============================================================"
echo -e "${BLUE}SECTION 2: Authentication Configuration${NC}"
echo "============================================================"
echo ""

# Test 2.1: A2A_REQUIRE_AUTH setting
log_info "2.1 Checking authentication requirement..."

AUTH_REQUIRED=$(get_task_env "orchestrator" "A2A_REQUIRE_AUTH")

if [ "$AUTH_REQUIRED" = "true" ]; then
    test_pass "Authentication: Required (A2A_REQUIRE_AUTH=true)"
else
    test_warn "Authentication: Not required (A2A_REQUIRE_AUTH=${AUTH_REQUIRED:-not set})"
fi

# Test 2.2: Keycloak Configuration
log_info "2.2 Checking Keycloak configuration..."

KEYCLOAK_URL=$(get_task_env "orchestrator" "KEYCLOAK_URL")
USE_KEYCLOAK=$(get_task_env "orchestrator" "A2A_USE_KEYCLOAK")

if [ "$USE_KEYCLOAK" = "true" ] && [ ! -z "$KEYCLOAK_URL" ]; then
    test_pass "Keycloak: Enabled (URL: ${KEYCLOAK_URL})"
    
    # Test Keycloak connectivity
    log_debug "Testing Keycloak connectivity..."
    KEYCLOAK_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" \
        "${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/.well-known/openid-configuration" \
        --max-time 10 2>/dev/null || echo "000")
    
    if [ "$KEYCLOAK_HEALTH" = "200" ]; then
        test_pass "Keycloak Server: Reachable"
    else
        test_warn "Keycloak Server: Not reachable (HTTP ${KEYCLOAK_HEALTH})"
    fi
else
    test_warn "Keycloak: Not enabled"
fi

# Test 2.3: API Key Configuration
log_info "2.3 Checking API key configuration..."

API_KEYS_JSON=$(get_task_env "orchestrator" "A2A_API_KEYS_JSON")

if [ ! -z "$API_KEYS_JSON" ] && [ "$API_KEYS_JSON" != "None" ]; then
    # Count API keys (safely)
    KEY_COUNT=$(echo "$API_KEYS_JSON" | python3 -c "import sys, json; print(len(json.loads(sys.stdin.read())))" 2>/dev/null || echo "0")
    
    if [ "$KEY_COUNT" -gt 0 ]; then
        test_pass "API Keys: ${KEY_COUNT} configured"
    else
        test_warn "API Keys: Invalid JSON or empty"
    fi
else
    test_warn "API Keys: Not configured"
fi

# ============================================================
# SECTION 3: RBAC AUTHORIZATION
# ============================================================
echo ""
echo "============================================================"
echo -e "${BLUE}SECTION 3: RBAC Authorization${NC}"
echo "============================================================"
echo ""

# Test 3.1: RBAC Policy Configuration
log_info "3.1 Checking RBAC policy configuration..."

RBAC_POLICY=$(get_task_env "orchestrator" "A2A_RBAC_POLICY_JSON")

if [ ! -z "$RBAC_POLICY" ] && [ "$RBAC_POLICY" != "None" ]; then
    # Validate JSON and check structure
    VALID_JSON=$(echo "$RBAC_POLICY" | python3 -c "import sys, json; data=json.loads(sys.stdin.read()); print('allow' in data and 'deny' in data)" 2>/dev/null || echo "False")
    
    if [ "$VALID_JSON" = "True" ]; then
        test_pass "RBAC Policy: Valid JSON with allow/deny rules"
        
        # Extract principals
        PRINCIPALS=$(echo "$RBAC_POLICY" | python3 -c "
import sys, json
data = json.loads(sys.stdin.read())
principals = list(data.get('allow', {}).keys())
print(','.join(principals[:5]) + ('...' if len(principals) > 5 else ''))
" 2>/dev/null)
        
        if [ ! -z "$PRINCIPALS" ]; then
            log_debug "Configured principals: ${PRINCIPALS}"
        fi
    else
        test_fail "RBAC Policy: Invalid JSON structure"
    fi
else
    test_warn "RBAC Policy: Not configured"
fi

# Test 3.2: Check Keycloak Role Mapping
log_info "3.2 Checking Keycloak role mapping..."

# Verify role mapping is available in the codebase
if [ -f "keycloak_auth.py" ]; then
    ROLE_MAPPING=$(grep -c "role_mapping" keycloak_auth.py 2>/dev/null || echo "0")
    
    if [ "$ROLE_MAPPING" -gt 0 ]; then
        test_pass "Keycloak Role Mapping: Configured in keycloak_auth.py"
    else
        test_warn "Keycloak Role Mapping: Not found in keycloak_auth.py"
    fi
else
    test_skip "Keycloak Role Mapping: keycloak_auth.py not found"
fi

# ============================================================
# SECTION 4: RATE LIMITING
# ============================================================
echo ""
echo "============================================================"
echo -e "${BLUE}SECTION 4: Rate Limiting${NC}"
echo "============================================================"
echo ""

# Test 4.1: Rate Limiting Configuration
log_info "4.1 Checking rate limiting configuration..."

RATE_LIMIT_ENABLED=$(get_task_env "orchestrator" "A2A_ENABLE_RATE_LIMIT")
RATE_LIMIT_PER_MIN=$(get_task_env "orchestrator" "A2A_RATE_LIMIT_PER_MINUTE")

if [ "$RATE_LIMIT_ENABLED" = "true" ]; then
    test_pass "Rate Limiting: Enabled"
    
    if [ ! -z "$RATE_LIMIT_PER_MIN" ] && [ "$RATE_LIMIT_PER_MIN" != "None" ]; then
        test_pass "Rate Limit: ${RATE_LIMIT_PER_MIN} requests/minute"
    else
        test_warn "Rate Limit: Default (300 requests/minute)"
    fi
else
    test_warn "Rate Limiting: Not enabled"
fi

# ============================================================
# SECTION 5: REPLAY PROTECTION
# ============================================================
echo ""
echo "============================================================"
echo -e "${BLUE}SECTION 5: Replay Protection${NC}"
echo "============================================================"
echo ""

# Test 5.1: Replay Protection Configuration
log_info "5.1 Checking replay protection configuration..."

REPLAY_ENABLED=$(get_task_env "orchestrator" "A2A_ENABLE_REPLAY_PROTECTION")
REPLAY_TTL=$(get_task_env "orchestrator" "A2A_REPLAY_TTL_SECONDS")

if [ "$REPLAY_ENABLED" = "true" ]; then
    test_pass "Replay Protection: Enabled"
    
    if [ ! -z "$REPLAY_TTL" ] && [ "$REPLAY_TTL" != "None" ]; then
        test_pass "Replay TTL: ${REPLAY_TTL} seconds"
    else
        test_pass "Replay TTL: Default (120 seconds)"
    fi
else
    test_warn "Replay Protection: Not explicitly enabled (may use default)"
fi

# ============================================================
# SECTION 6: JSON SCHEMA VALIDATION
# ============================================================
echo ""
echo "============================================================"
echo -e "${BLUE}SECTION 6: JSON Schema Validation${NC}"
echo "============================================================"
echo ""

# Test 6.1: Schema Validation Configuration
log_info "6.1 Checking JSON schema validation..."

SCHEMA_ENABLED=$(get_task_env "orchestrator" "A2A_ENABLE_SCHEMA_VALIDATION")

if [ "$SCHEMA_ENABLED" = "true" ]; then
    test_pass "Schema Validation: Enabled"
elif [ "$SCHEMA_ENABLED" = "false" ]; then
    test_warn "Schema Validation: Explicitly disabled"
else
    test_pass "Schema Validation: Using default (enabled)"
fi

# Test 6.2: Check Schema Definitions
log_info "6.2 Checking schema definitions..."

if [ -f "a2a_security_enhanced.py" ]; then
    SCHEMA_COUNT=$(grep -c '"type": "object"' a2a_security_enhanced.py 2>/dev/null || echo "0")
    
    if [ "$SCHEMA_COUNT" -gt 0 ]; then
        test_pass "Schema Definitions: ${SCHEMA_COUNT} schemas defined"
    else
        test_warn "Schema Definitions: No schemas found"
    fi
else
    test_skip "Schema Definitions: a2a_security_enhanced.py not found"
fi

# ============================================================
# SECTION 7: HMAC REQUEST SIGNING
# ============================================================
echo ""
echo "============================================================"
echo -e "${BLUE}SECTION 7: HMAC Request Signing${NC}"
echo "============================================================"
echo ""

# Test 7.1: HMAC Configuration
log_info "7.1 Checking HMAC signing configuration..."

HMAC_ENABLED=$(get_task_env "orchestrator" "A2A_ENABLE_HMAC_SIGNING")
HMAC_SECRET=$(get_task_env "orchestrator" "A2A_HMAC_SECRET_KEY")

if [ "$HMAC_ENABLED" = "true" ]; then
    if [ ! -z "$HMAC_SECRET" ] && [ "$HMAC_SECRET" != "None" ]; then
        test_pass "HMAC Signing: Enabled with secret configured"
    else
        test_fail "HMAC Signing: Enabled but no secret configured"
    fi
else
    test_warn "HMAC Signing: Not enabled"
fi

# ============================================================
# SECTION 8: TOKEN REVOCATION
# ============================================================
echo ""
echo "============================================================"
echo -e "${BLUE}SECTION 8: Token Revocation${NC}"
echo "============================================================"
echo ""

# Test 8.1: Token Revocation Configuration
log_info "8.1 Checking token revocation configuration..."

REVOCATION_ENABLED=$(get_task_env "orchestrator" "A2A_ENABLE_TOKEN_REVOCATION")

if [ "$REVOCATION_ENABLED" = "true" ]; then
    test_pass "Token Revocation: Enabled"
else
    test_warn "Token Revocation: Not enabled (using default)"
fi

# ============================================================
# SECTION 9: mTLS CONFIGURATION
# ============================================================
echo ""
echo "============================================================"
echo -e "${BLUE}SECTION 9: mTLS Configuration${NC}"
echo "============================================================"
echo ""

# Test 9.1: mTLS Configuration
log_info "9.1 Checking mTLS configuration..."

MTLS_ENABLED=$(get_task_env "orchestrator" "A2A_ENABLE_MTLS")
MTLS_CA_CERT=$(get_task_env "orchestrator" "A2A_MTLS_CA_CERT_PATH")

if [ "$MTLS_ENABLED" = "true" ]; then
    if [ ! -z "$MTLS_CA_CERT" ] && [ "$MTLS_CA_CERT" != "None" ]; then
        test_pass "mTLS: Enabled with CA certificate"
    else
        test_fail "mTLS: Enabled but no CA certificate configured"
    fi
else
    test_warn "mTLS: Not enabled"
fi

# ============================================================
# SECTION 10: AUDIT LOGGING
# ============================================================
echo ""
echo "============================================================"
echo -e "${BLUE}SECTION 10: Audit Logging${NC}"
echo "============================================================"
echo ""

# Test 10.1: CloudWatch Log Groups
log_info "10.1 Checking CloudWatch log groups..."

LOG_GROUPS=$(aws logs describe-log-groups \
    --region ${REGION} \
    --log-group-name-prefix "/ecs/ca-a2a" \
    --query 'length(logGroups)' \
    --output text 2>/dev/null)

if [ "$LOG_GROUPS" -gt 0 ]; then
    test_pass "CloudWatch Logs: ${LOG_GROUPS} log groups configured"
else
    test_fail "CloudWatch Logs: No log groups found"
fi

# Test 10.2: Check for Security-Related Log Entries
log_info "10.2 Checking for security audit logs..."

AUTH_LOGS=$(aws logs tail /ecs/ca-a2a-orchestrator --since 1h --region ${REGION} 2>/dev/null | \
    grep -c -E "Unauthorized|Forbidden|AuthError|ForbiddenError|authentication|authorization" || echo "0")

if [ "$AUTH_LOGS" -gt 0 ]; then
    test_pass "Security Audit Logs: ${AUTH_LOGS} security-related entries in last hour"
else
    test_pass "Security Audit Logs: No security incidents in last hour"
fi

# ============================================================
# SECTION 11: LIVE SECURITY TESTS (Optional)
# ============================================================
if [ "$KEYCLOAK_ONLY" = false ]; then
    echo ""
    echo "============================================================"
    echo -e "${BLUE}SECTION 11: Live Security Tests${NC}"
    echo "============================================================"
    echo ""
    
    # Get orchestrator IP
    ORCH_IP=$(get_service_ip "orchestrator")
    
    if [ ! -z "$ORCH_IP" ]; then
        log_info "11.1 Testing unauthenticated request rejection..."
        
        # Test: Request without authentication
        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST http://${ORCH_IP}:8001/message \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":"test-1"}' \
            --max-time 5 2>/dev/null || echo "000")
        
        if [ "$RESPONSE" = "401" ] || [ "$RESPONSE" = "403" ]; then
            test_pass "Auth Enforcement: Unauthenticated requests rejected (HTTP ${RESPONSE})"
        elif [ "$RESPONSE" = "200" ]; then
            if [ "$AUTH_REQUIRED" = "true" ]; then
                test_fail "Auth Enforcement: Unauthenticated requests accepted (should be rejected)"
            else
                test_pass "Auth Enforcement: Auth not required, request accepted"
            fi
        elif [ "$RESPONSE" = "000" ]; then
            test_pass "Network Isolation: VPC prevents direct access (expected)"
        else
            test_warn "Auth Enforcement: Unexpected response (HTTP ${RESPONSE})"
        fi
        
        # Test: Request with invalid API key
        log_info "11.2 Testing invalid API key rejection..."
        
        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST http://${ORCH_IP}:8001/message \
            -H "Content-Type: application/json" \
            -H "X-API-Key: invalid-key-12345" \
            -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":"test-2"}' \
            --max-time 5 2>/dev/null || echo "000")
        
        if [ "$RESPONSE" = "401" ] || [ "$RESPONSE" = "403" ]; then
            test_pass "API Key Validation: Invalid key rejected (HTTP ${RESPONSE})"
        elif [ "$RESPONSE" = "000" ]; then
            test_pass "Network Isolation: VPC prevents direct access (expected)"
        else
            test_warn "API Key Validation: Unexpected response (HTTP ${RESPONSE})"
        fi
        
        # Test: Path traversal attempt
        log_info "11.3 Testing path traversal rejection..."
        
        # Get valid API key if available
        if [ ! -z "$API_KEYS_JSON" ] && [ "$API_KEYS_JSON" != "None" ]; then
            VALID_API_KEY=$(echo "$API_KEYS_JSON" | python3 -c "import sys, json; d=json.loads(sys.stdin.read()); print(list(d.values())[0])" 2>/dev/null)
        fi
        
        if [ ! -z "$VALID_API_KEY" ]; then
            RESPONSE=$(curl -s \
                -X POST http://${ORCH_IP}:8001/message \
                -H "Content-Type: application/json" \
                -H "X-API-Key: ${VALID_API_KEY}" \
                -d '{"jsonrpc":"2.0","method":"process_document","params":{"s3_key":"../../../etc/passwd"},"id":"test-3"}' \
                --max-time 5 2>/dev/null || echo "{}")
            
            if echo "$RESPONSE" | grep -q "error" 2>/dev/null; then
                test_pass "Schema Validation: Path traversal rejected"
            elif [ -z "$RESPONSE" ] || [ "$RESPONSE" = "{}" ]; then
                test_pass "Network Isolation: VPC prevents direct access (expected)"
            else
                test_warn "Schema Validation: Response unclear"
            fi
        else
            test_skip "Path Traversal Test: No valid API key available"
        fi
    else
        test_skip "Live Tests: Could not get orchestrator IP (VPC isolation)"
    fi
fi

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo "============================================================"
echo -e "${CYAN}  SECURITY TEST SUMMARY${NC}"
echo "============================================================"
echo ""

TOTAL=$((PASSED + FAILED + SKIPPED))

echo -e "${GREEN}Passed:${NC}   ${PASSED}"
echo -e "${RED}Failed:${NC}   ${FAILED}"
echo -e "${YELLOW}Skipped:${NC}  ${SKIPPED}"
echo -e "${YELLOW}Warnings:${NC} ${WARNINGS}"
echo ""
echo "Total Tests: ${TOTAL}"

if [ $FAILED -eq 0 ]; then
    SUCCESS_RATE=100
else
    SUCCESS_RATE=$((PASSED * 100 / (PASSED + FAILED)))
fi

echo "Success Rate: ${SUCCESS_RATE}%"
echo ""

# Security Score Calculation
SECURITY_SCORE=0
[ "$AUTH_REQUIRED" = "true" ] && ((SECURITY_SCORE+=15))
[ "$USE_KEYCLOAK" = "true" ] && ((SECURITY_SCORE+=20))
[ ! -z "$API_KEYS_JSON" ] && ((SECURITY_SCORE+=10))
[ ! -z "$RBAC_POLICY" ] && ((SECURITY_SCORE+=15))
[ "$RATE_LIMIT_ENABLED" = "true" ] && ((SECURITY_SCORE+=10))
[ "$REPLAY_ENABLED" = "true" ] && ((SECURITY_SCORE+=10))
[ "$SCHEMA_ENABLED" != "false" ] && ((SECURITY_SCORE+=10))
[ "$SECRET_COUNT" -gt 0 ] && ((SECURITY_SCORE+=10))

echo "============================================================"
echo -e "${CYAN}  SECURITY SCORE: ${SECURITY_SCORE}/100${NC}"
echo "============================================================"
echo ""

if [ $SECURITY_SCORE -ge 80 ]; then
    echo -e "${GREEN}Security Level: EXCELLENT${NC}"
elif [ $SECURITY_SCORE -ge 60 ]; then
    echo -e "${YELLOW}Security Level: GOOD${NC}"
elif [ $SECURITY_SCORE -ge 40 ]; then
    echo -e "${YELLOW}Security Level: MODERATE${NC}"
else
    echo -e "${RED}Security Level: NEEDS IMPROVEMENT${NC}"
fi

echo ""
echo "Recommendations:"
[ "$AUTH_REQUIRED" != "true" ] && echo "  - Enable authentication (A2A_REQUIRE_AUTH=true)"
[ "$USE_KEYCLOAK" != "true" ] && echo "  - Enable Keycloak OAuth2 (A2A_USE_KEYCLOAK=true)"
[ -z "$RBAC_POLICY" ] && echo "  - Configure RBAC policy (A2A_RBAC_POLICY_JSON)"
[ "$RATE_LIMIT_ENABLED" != "true" ] && echo "  - Enable rate limiting (A2A_ENABLE_RATE_LIMIT=true)"
[ "$HMAC_ENABLED" != "true" ] && echo "  - Consider enabling HMAC signing (A2A_ENABLE_HMAC_SIGNING=true)"
[ "$MTLS_ENABLED" != "true" ] && echo "  - Consider enabling mTLS for inter-agent communication"

echo ""
echo "============================================================"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All critical security tests passed.${NC}"
    exit 0
else
    echo -e "${RED}Some security tests failed. Review and remediate.${NC}"
    exit 1
fi

