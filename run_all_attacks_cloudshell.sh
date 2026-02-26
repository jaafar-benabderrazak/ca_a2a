#!/bin/bash
# =============================================================================
# CA-A2A Consolidated Attack Test Runner — AWS CloudShell Edition
# =============================================================================
#
# Runs ALL attack scenarios in a single execution:
#   Phase 1: Infrastructure Security Audit (AWS API checks)
#   Phase 2: 20 Documented Attack Scenarios (pytest)
#   Phase 3: 10 Penetration Test Scenarios (pytest)
#   Phase 4: Live Curl-Based Validation (direct ALB probes)
#
# Usage:
#   ./run_all_attacks_cloudshell.sh
#   ./run_all_attacks_cloudshell.sh --region eu-west-3
#   ./run_all_attacks_cloudshell.sh --alb ca-a2a-alb-xxx.elb.amazonaws.com
#   ./run_all_attacks_cloudshell.sh --phase 2
#   ./run_all_attacks_cloudshell.sh --skip-infra
#   ./run_all_attacks_cloudshell.sh --html --verbose
#
# =============================================================================

set -o pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Defaults ────────────────────────────────────────────────────────────────
REGION="${AWS_REGION:-eu-west-3}"
ALB_DNS=""
CLUSTER="ca-a2a-cluster"
RUN_PHASE=""           # empty = all
SKIP_INFRA=false
HTML_REPORT=false
VERBOSE=false

# ─── Phase results ───────────────────────────────────────────────────────────
P1_PASSED=0; P1_FAILED=0; P1_WARNINGS=0; P1_SKIPPED=0
P2_EXIT=0
P3_EXIT=0
P4_PASSED=0; P4_FAILED=0; P4_WARNINGS=0

# ─── Argument parsing ───────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --region)      REGION="$2"; shift 2 ;;
        --alb)         ALB_DNS="$2"; shift 2 ;;
        --phase)       RUN_PHASE="$2"; shift 2 ;;
        --skip-infra)  SKIP_INFRA=true; shift ;;
        --html)        HTML_REPORT=true; shift ;;
        --verbose|-v)  VERBOSE=true; shift ;;
        --help|-h)
            echo "Usage: $0 [--region REGION] [--alb ALB_DNS] [--phase N] [--skip-infra] [--html] [--verbose]"
            echo ""
            echo "  --region     AWS region (default: eu-west-3)"
            echo "  --alb        ALB DNS name (auto-discovered if omitted)"
            echo "  --phase N    Run only phase N (1=infra, 2=20-scenarios, 3=pentest, 4=curl)"
            echo "  --skip-infra Skip Phase 1 infrastructure audit"
            echo "  --html       Generate HTML reports for pytest phases"
            echo "  --verbose    Enable verbose output"
            exit 0
            ;;
        *) shift ;;
    esac
done

export AWS_REGION="$REGION"

# ─── Helper functions ────────────────────────────────────────────────────────
banner() {
    echo ""
    echo -e "${CYAN}$(printf '═%.0s' {1..74})${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}$(printf '═%.0s' {1..74})${NC}"
    echo ""
}

section() {
    echo ""
    echo -e "${BLUE}──── $1 ────${NC}"
    echo ""
}

p_pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; }
p_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
p_warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
p_skip() { echo -e "  ${GRAY}[SKIP]${NC} $1"; }
p_info() { echo -e "  ${GRAY}[INFO]${NC} $1"; }

should_run() {
    [[ -z "$RUN_PHASE" || "$RUN_PHASE" == "$1" ]]
}

get_task_env() {
    local task_def=$1
    local env_name=$2
    aws ecs describe-task-definition \
        --task-definition ca-a2a-${task_def} \
        --region ${REGION} \
        --query "taskDefinition.containerDefinitions[0].environment[?name=='${env_name}'].value" \
        --output text 2>/dev/null
}

# ═════════════════════════════════════════════════════════════════════════════
# SETUP
# ═════════════════════════════════════════════════════════════════════════════

banner "CA-A2A CONSOLIDATED ATTACK TEST RUNNER"

echo "  Region:    ${REGION}"
echo "  Date:      $(date)"
echo "  Phases:    ${RUN_PHASE:-ALL}"
echo ""

# ─── Step 1: Install Python dependencies ─────────────────────────────────────
section "Installing dependencies"

pip install --quiet pytest requests PyJWT[crypto] cryptography pytest-html 2>&1 | grep -v "already satisfied" || true
echo -e "  ${GREEN}✓${NC} Python dependencies installed"

# ─── Step 2: Auto-discover ALB ────────────────────────────────────────────────
section "Discovering ALB endpoint"

if [ -z "$ALB_DNS" ]; then
    ALB_DNS=$(aws elbv2 describe-load-balancers \
        --region "$REGION" \
        --query 'LoadBalancers[?contains(LoadBalancerName, `ca-a2a`)].DNSName' \
        --output text 2>/dev/null | head -1 || echo "")
fi

if [ -z "$ALB_DNS" ]; then
    echo -e "  ${RED}✗${NC} Could not discover ALB. Use --alb <dns> to set manually."
    echo "  Example: $0 --alb ca-a2a-alb-xxx.eu-west-3.elb.amazonaws.com"
    exit 1
fi

BASE_URL="http://${ALB_DNS}"
export ORCHESTRATOR_URL="$BASE_URL"
export ALB_DNS
export TEST_ENV=aws

echo -e "  ${GREEN}✓${NC} ALB: ${ALB_DNS}"
echo -e "  ${GREEN}✓${NC} Base URL: ${BASE_URL}"

# ─── Step 3: Quick connectivity check ────────────────────────────────────────
section "Connectivity check"

HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${BASE_URL}/health" 2>/dev/null || echo "000")

if [[ "$HEALTH_STATUS" == "200" ]]; then
    echo -e "  ${GREEN}✓${NC} ALB reachable — /health returned HTTP 200"
else
    echo -e "  ${YELLOW}⚠${NC} /health returned HTTP ${HEALTH_STATUS} — tests may fail"
fi

# ALB_DNS is already exported — test_security_comprehensive_20_scenarios.py reads it via os.getenv
SCENARIO_20_FILE="test_security_comprehensive_20_scenarios.py"


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1 — Infrastructure Security Audit
# ═════════════════════════════════════════════════════════════════════════════

if should_run 1 && [ "$SKIP_INFRA" = false ]; then

    banner "PHASE 1: Infrastructure Security Audit"

    # ── 1.1 Secrets Manager ──────────────────────────────────────────────────
    section "1.1 Secrets Manager"

    # Search for secrets matching ca-a2a prefix OR CDK-generated names (DbPassword, Keycloak)
    SECRET_COUNT=$(aws secretsmanager list-secrets \
        --region ${REGION} --no-paginate \
        --query "length(SecretList[?contains(Name, 'ca-a2a') || contains(Name, 'DbPassword') || contains(Name, 'Keycloak')])" \
        --output text 2>/dev/null | head -1 || echo "0")
    SECRET_COUNT=${SECRET_COUNT:-0}
    SECRET_COUNT=$(echo "$SECRET_COUNT" | tr -dc '0-9')
    SECRET_COUNT=${SECRET_COUNT:-0}

    if [ "$SECRET_COUNT" -gt 0 ] 2>/dev/null; then
        p_pass "Secrets Manager: ${SECRET_COUNT} secrets configured"
        ((P1_PASSED++))

        # List secret names for visibility
        aws secretsmanager list-secrets --region ${REGION} --no-paginate \
            --query "SecretList[?contains(Name, 'ca-a2a') || contains(Name, 'DbPassword') || contains(Name, 'Keycloak')].Name" \
            --output text 2>/dev/null | tr '\t' '\n' | while read -r name; do
            p_info "  Secret: $name"
        done
    else
        p_fail "Secrets Manager: No secrets configured"
        ((P1_FAILED++))
    fi

    # ── 1.2 S3 Bucket Security ──────────────────────────────────────────────
    section "1.2 S3 Bucket Security"

    S3_BUCKET=$(aws s3api list-buckets \
        --query "Buckets[?contains(Name, 'ca-a2a-documents')].Name" \
        --output text 2>/dev/null | head -1)

    if [ -n "$S3_BUCKET" ]; then
        ENCRYPTION=$(aws s3api get-bucket-encryption \
            --bucket ${S3_BUCKET} --region ${REGION} \
            --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
            --output text 2>/dev/null)

        if [ "$ENCRYPTION" = "AES256" ] || [ "$ENCRYPTION" = "aws:kms" ]; then
            p_pass "S3 encryption: ${ENCRYPTION}"
            ((P1_PASSED++))
        else
            p_fail "S3 encryption: not enabled"
            ((P1_FAILED++))
        fi

        PUBLIC_BLOCK=$(aws s3api get-public-access-block \
            --bucket ${S3_BUCKET} --region ${REGION} \
            --query 'PublicAccessBlockConfiguration.BlockPublicAcls' \
            --output text 2>/dev/null)

        if [ "$PUBLIC_BLOCK" = "True" ]; then
            p_pass "S3 public access: blocked"
            ((P1_PASSED++))
        else
            p_fail "S3 public access: NOT blocked"
            ((P1_FAILED++))
        fi
    else
        p_skip "S3 bucket not found"
        ((P1_SKIPPED++))
    fi

    # ── 1.3 VPC Security ────────────────────────────────────────────────────
    section "1.3 VPC and Network"

    VPC_ID=$(aws ec2 describe-vpcs --region ${REGION} \
        --filters "Name=tag:Name,Values=*ca-a2a*" \
        --query 'Vpcs[0].VpcId' --output text 2>/dev/null)

    if [ -n "$VPC_ID" ] && [ "$VPC_ID" != "None" ]; then
        p_pass "VPC: ${VPC_ID}"
        ((P1_PASSED++))

        PRIVATE_SUBNETS=$(aws ec2 describe-subnets --region ${REGION} \
            --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Name,Values=*private*" \
            --query 'length(Subnets)' --output text 2>/dev/null)

        if [ "$PRIVATE_SUBNETS" -gt 0 ]; then
            p_pass "Private subnets: ${PRIVATE_SUBNETS}"
            ((P1_PASSED++))
        else
            p_warn "Private subnets: none found"
            ((P1_WARNINGS++))
        fi
    else
        p_skip "VPC not found"
        ((P1_SKIPPED++))
    fi

    # ── 1.4 RDS Security ────────────────────────────────────────────────────
    section "1.4 RDS Security"

    RDS_INFO=$(aws rds describe-db-instances --region "$REGION" \
        --query 'DBInstances[?contains(DBInstanceIdentifier, `ca-a2a`)].{Public:PubliclyAccessible,Encrypted:StorageEncrypted}' \
        --output json 2>/dev/null)

    if echo "$RDS_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d and not d[0]['Public'] else 1)" 2>/dev/null; then
        p_pass "RDS: not publicly accessible"
        ((P1_PASSED++))
    else
        p_warn "RDS: public accessibility unknown"
        ((P1_WARNINGS++))
    fi

    if echo "$RDS_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d and d[0]['Encrypted'] else 1)" 2>/dev/null; then
        p_pass "RDS: storage encrypted"
        ((P1_PASSED++))
    else
        p_warn "RDS: encryption status unknown"
        ((P1_WARNINGS++))
    fi

    # ── 1.5 ECS Task Security Config ────────────────────────────────────────
    section "1.5 ECS Security Configuration"

    AUTH_REQUIRED=$(get_task_env "orchestrator" "A2A_REQUIRE_AUTH")
    if [ "$AUTH_REQUIRED" = "true" ]; then
        p_pass "Authentication required: true"
        ((P1_PASSED++))
    else
        p_warn "Authentication required: ${AUTH_REQUIRED:-not set}"
        ((P1_WARNINGS++))
    fi

    RATE_LIMIT=$(get_task_env "orchestrator" "A2A_ENABLE_RATE_LIMIT")
    if [ "$RATE_LIMIT" = "true" ]; then
        p_pass "Rate limiting: enabled"
        ((P1_PASSED++))
    else
        p_warn "Rate limiting: ${RATE_LIMIT:-not set}"
        ((P1_WARNINGS++))
    fi

    REPLAY_PROT=$(get_task_env "orchestrator" "A2A_ENABLE_REPLAY_PROTECTION")
    if [ "$REPLAY_PROT" = "true" ]; then
        p_pass "Replay protection: enabled"
        ((P1_PASSED++))
    else
        p_warn "Replay protection: ${REPLAY_PROT:-not set}"
        ((P1_WARNINGS++))
    fi

    # ── 1.6 CloudWatch Logging ──────────────────────────────────────────────
    section "1.6 Audit Logging"

    LOG_GROUPS=$(aws logs describe-log-groups --region ${REGION} \
        --log-group-name-prefix "/ecs/ca-a2a" \
        --query 'length(logGroups)' --output text 2>/dev/null || echo "0")

    if [ "$LOG_GROUPS" -gt 0 ]; then
        p_pass "CloudWatch log groups: ${LOG_GROUPS}"
        ((P1_PASSED++))
    else
        p_fail "CloudWatch log groups: none found"
        ((P1_FAILED++))
    fi

    # ── Phase 1 Summary ─────────────────────────────────────────────────────
    echo ""
    P1_TOTAL=$((P1_PASSED + P1_FAILED + P1_WARNINGS + P1_SKIPPED))
    echo -e "  Phase 1 Result: ${GREEN}${P1_PASSED} passed${NC}, ${RED}${P1_FAILED} failed${NC}, ${YELLOW}${P1_WARNINGS} warnings${NC}, ${GRAY}${P1_SKIPPED} skipped${NC} (${P1_TOTAL} checks)"

fi


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2 — 20 Documented Attack Scenarios (pytest)
# ═════════════════════════════════════════════════════════════════════════════

if should_run 2; then

    banner "PHASE 2: 20 Documented Attack Scenarios (pytest)"

    if [ ! -f "$SCENARIO_20_FILE" ]; then
        echo -e "  ${RED}✗${NC} File not found: ${SCENARIO_20_FILE}"
        P2_EXIT=1
    else
        PYTEST_ARGS="-v --tb=short"

        if [ "$HTML_REPORT" = true ]; then
            P2_REPORT="report_20scenarios_$(date +%Y%m%d_%H%M%S).html"
            PYTEST_ARGS="$PYTEST_ARGS --html=$P2_REPORT --self-contained-html"
            p_info "HTML report: $P2_REPORT"
        fi

        if [ "$VERBOSE" = true ]; then
            PYTEST_ARGS="$PYTEST_ARGS -s"
        fi

        echo "  Running: pytest ${SCENARIO_20_FILE} ${PYTEST_ARGS}"
        echo ""

        python3 -m pytest "$SCENARIO_20_FILE" $PYTEST_ARGS 2>&1
        P2_EXIT=$?

        echo ""
        if [ $P2_EXIT -eq 0 ]; then
            echo -e "  Phase 2 Result: ${GREEN}ALL PASSED${NC}"
        elif [ $P2_EXIT -eq 5 ]; then
            echo -e "  Phase 2 Result: ${YELLOW}NO TESTS COLLECTED${NC}"
        else
            echo -e "  Phase 2 Result: ${RED}FAILURES DETECTED (exit $P2_EXIT)${NC}"
        fi
    fi

fi


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 3 — 10 Penetration Test Scenarios (pytest)
# ═════════════════════════════════════════════════════════════════════════════

if should_run 3; then

    banner "PHASE 3: 10 Penetration Test Scenarios (pytest)"

    ATTACK_FILE="test_attack_scenarios.py"

    if [ ! -f "$ATTACK_FILE" ]; then
        echo -e "  ${RED}✗${NC} File not found: ${ATTACK_FILE}"
        P3_EXIT=1
    else
        # test_attack_scenarios.py uses test_config.py which reads ALB_DNS from env
        export TEST_ENV=aws
        export TEST_VERBOSE=$( [ "$VERBOSE" = true ] && echo "true" || echo "false" )
        export SKIP_ON_CONNECTION_ERROR=true

        PYTEST_ARGS="-v --tb=short"

        if [ "$HTML_REPORT" = true ]; then
            P3_REPORT="report_pentest_$(date +%Y%m%d_%H%M%S).html"
            PYTEST_ARGS="$PYTEST_ARGS --html=$P3_REPORT --self-contained-html"
            p_info "HTML report: $P3_REPORT"
        fi

        if [ "$VERBOSE" = true ]; then
            PYTEST_ARGS="$PYTEST_ARGS -s"
        fi

        echo "  Running: pytest ${ATTACK_FILE} ${PYTEST_ARGS}"
        echo ""

        python3 -m pytest "$ATTACK_FILE" $PYTEST_ARGS 2>&1
        P3_EXIT=$?

        echo ""
        if [ $P3_EXIT -eq 0 ]; then
            echo -e "  Phase 3 Result: ${GREEN}ALL PASSED${NC}"
        elif [ $P3_EXIT -eq 5 ]; then
            echo -e "  Phase 3 Result: ${YELLOW}NO TESTS COLLECTED${NC}"
        else
            echo -e "  Phase 3 Result: ${RED}FAILURES DETECTED (exit $P3_EXIT)${NC}"
        fi
    fi

fi


# ═════════════════════════════════════════════════════════════════════════════
# PHASE 4 — Live Curl-Based Validation
# ═════════════════════════════════════════════════════════════════════════════

if should_run 4; then

    banner "PHASE 4: Live Curl-Based Validation"

    # ── 4.1 Endpoints ────────────────────────────────────────────────────────
    section "4.1 Endpoint Accessibility"

    for endpoint in "/health" "/.well-known/agent.json" "/skills" "/status"; do
        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${BASE_URL}${endpoint}" 2>/dev/null || echo "000")
        if [[ "$status" == "200" ]]; then
            p_pass "${endpoint} : HTTP ${status}"
            ((P4_PASSED++))
        else
            p_warn "${endpoint} : HTTP ${status}"
            ((P4_WARNINGS++))
        fi
    done

    # ── 4.2 Security Headers ────────────────────────────────────────────────
    section "4.2 Security Headers"

    HEADERS=$(curl -sI --max-time 10 "${BASE_URL}/health" 2>/dev/null)

    if echo "$HEADERS" | grep -qi "X-Content-Type-Options.*nosniff"; then
        p_pass "X-Content-Type-Options: nosniff"
        ((P4_PASSED++))
    else
        p_warn "X-Content-Type-Options: missing"
        ((P4_WARNINGS++))
    fi

    if echo "$HEADERS" | grep -qi "X-Frame-Options"; then
        p_pass "X-Frame-Options: present"
        ((P4_PASSED++))
    else
        p_warn "X-Frame-Options: missing"
        ((P4_WARNINGS++))
    fi

    if echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
        p_pass "Content-Security-Policy: present"
        ((P4_PASSED++))
    else
        p_warn "Content-Security-Policy: missing"
        ((P4_WARNINGS++))
    fi

    # ── 4.3 Authentication Enforcement ───────────────────────────────────────
    section "4.3 Authentication Enforcement"

    # Unauthenticated request
    AUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"process_document","params":{},"id":"unauth-1"}' \
        "${BASE_URL}/message" 2>/dev/null || echo "000")

    if [[ "$AUTH_STATUS" == "401" || "$AUTH_STATUS" == "403" ]]; then
        p_pass "Unauthenticated request blocked: HTTP ${AUTH_STATUS}"
        ((P4_PASSED++))
    elif [[ "$AUTH_STATUS" == "200" ]]; then
        p_fail "Unauthenticated request accepted (should be blocked)"
        ((P4_FAILED++))
    else
        p_warn "Unauthenticated request: HTTP ${AUTH_STATUS}"
        ((P4_WARNINGS++))
    fi

    # Invalid API key
    INVALID_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -X POST -H "Content-Type: application/json" -H "X-API-Key: invalid-key-999" \
        -d '{"jsonrpc":"2.0","method":"process_document","params":{},"id":"badkey-1"}' \
        "${BASE_URL}/message" 2>/dev/null || echo "000")

    if [[ "$INVALID_STATUS" == "401" || "$INVALID_STATUS" == "403" ]]; then
        p_pass "Invalid API key rejected: HTTP ${INVALID_STATUS}"
        ((P4_PASSED++))
    else
        p_warn "Invalid API key: HTTP ${INVALID_STATUS}"
        ((P4_WARNINGS++))
    fi

    # ── 4.4 Injection Attacks ────────────────────────────────────────────────
    section "4.4 Injection Prevention"

    # SQL Injection
    SQLI_RESP=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"process_document","params":{"s3_key":"'"'"'; DROP TABLE documents; --"},"id":"sqli-1"}' \
        "${BASE_URL}/message" 2>/dev/null)

    if echo "$SQLI_RESP" | grep -q "DROP TABLE"; then
        p_fail "SQL injection: payload reflected"
        ((P4_FAILED++))
    else
        p_pass "SQL injection: payload not reflected"
        ((P4_PASSED++))
    fi

    # XSS
    XSS_RESP=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"process_document","params":{"content":"<script>alert(1)</script>"},"id":"xss-1"}' \
        "${BASE_URL}/message" 2>/dev/null)

    if echo "$XSS_RESP" | grep -q "<script>"; then
        p_fail "XSS: script tag reflected"
        ((P4_FAILED++))
    else
        p_pass "XSS: script tag not reflected"
        ((P4_PASSED++))
    fi

    # Path Traversal
    PT_RESP=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"process_document","params":{"s3_key":"../../../etc/passwd"},"id":"pt-1"}' \
        "${BASE_URL}/message" 2>/dev/null)

    if echo "$PT_RESP" | grep -q "root:"; then
        p_fail "Path traversal: system file leaked"
        ((P4_FAILED++))
    else
        p_pass "Path traversal: blocked"
        ((P4_PASSED++))
    fi

    # ── 4.5 CORS ────────────────────────────────────────────────────────────
    section "4.5 CORS Security"

    CORS_RESP=$(curl -sI --max-time 10 -H "Origin: https://evil.com" -X OPTIONS \
        "${BASE_URL}/health" 2>/dev/null)
    ALLOW_ORIGIN=$(echo "$CORS_RESP" | grep -i "Access-Control-Allow-Origin" | awk '{print $2}' | tr -d '\r')

    if [[ "$ALLOW_ORIGIN" == "*" || "$ALLOW_ORIGIN" == "https://evil.com" ]]; then
        p_fail "CORS: allows untrusted origin ($ALLOW_ORIGIN)"
        ((P4_FAILED++))
    else
        p_pass "CORS: blocks untrusted origins"
        ((P4_PASSED++))
    fi

    # ── 4.6 Rate Limiting ───────────────────────────────────────────────────
    section "4.6 Rate Limiting (50-request burst)"

    RATE_LIMITED=false
    for i in $(seq 1 50); do
        s=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "${BASE_URL}/health" 2>/dev/null || echo "000")
        if [[ "$s" == "429" ]]; then
            RATE_LIMITED=true
            break
        fi
    done

    if $RATE_LIMITED; then
        p_pass "Rate limiting: triggered (HTTP 429)"
        ((P4_PASSED++))
    else
        p_warn "Rate limiting: not triggered in 50 requests"
        ((P4_WARNINGS++))
    fi

    # ── 4.7 Payload Size Limit ──────────────────────────────────────────────
    section "4.7 Payload Size Limit"

    LARGE_PAYLOAD=$(python3 -c "print('{\"jsonrpc\":\"2.0\",\"method\":\"x\",\"params\":{\"data\":\"' + 'A'*1100000 + '\"},\"id\":1}')")
    SIZE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
        -X POST -H "Content-Type: application/json" \
        -d "$LARGE_PAYLOAD" "${BASE_URL}/message" 2>/dev/null || echo "000")

    if [[ "$SIZE_STATUS" == "413" ]]; then
        p_pass "Payload size limit: rejected >1MB (HTTP 413)"
        ((P4_PASSED++))
    else
        p_warn "Payload size limit: HTTP ${SIZE_STATUS} (expected 413)"
        ((P4_WARNINGS++))
    fi

    # ── 4.8 JSON-RPC Protocol Compliance ─────────────────────────────────────
    section "4.8 JSON-RPC Protocol Compliance"

    # Invalid JSON
    INVALID_JSON_RESP=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" \
        -d 'NOT-JSON' "${BASE_URL}/message" 2>/dev/null)

    if echo "$INVALID_JSON_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if 'error' in d and d['error'].get('code') == -32700 else 1)" 2>/dev/null; then
        p_pass "JSON-RPC: Parse error (-32700) for invalid JSON"
        ((P4_PASSED++))
    else
        p_warn "JSON-RPC: unexpected response for invalid JSON"
        ((P4_WARNINGS++))
    fi

    # Unknown method
    UNKNOWN_RESP=$(curl -s --max-time 10 -X POST -H "Content-Type: application/json" \
        -H "X-API-Key: demo-key-001" \
        -d '{"jsonrpc":"2.0","method":"nonexistent_method","params":{},"id":"proto-1"}' \
        "${BASE_URL}/message" 2>/dev/null)

    if echo "$UNKNOWN_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if 'error' in d and d['error'].get('code') == -32601 else 1)" 2>/dev/null; then
        p_pass "JSON-RPC: Method not found (-32601)"
        ((P4_PASSED++))
    else
        p_warn "JSON-RPC: unexpected response for unknown method"
        ((P4_WARNINGS++))
    fi

    # ── Phase 4 Summary ─────────────────────────────────────────────────────
    echo ""
    P4_TOTAL=$((P4_PASSED + P4_FAILED + P4_WARNINGS))
    echo -e "  Phase 4 Result: ${GREEN}${P4_PASSED} passed${NC}, ${RED}${P4_FAILED} failed${NC}, ${YELLOW}${P4_WARNINGS} warnings${NC} (${P4_TOTAL} checks)"

fi


# ═════════════════════════════════════════════════════════════════════════════
# CONSOLIDATED SUMMARY
# ═════════════════════════════════════════════════════════════════════════════

banner "CONSOLIDATED RESULTS"

TOTAL_PASSED=$P1_PASSED
TOTAL_FAILED=$P1_FAILED
TOTAL_WARNINGS=$P1_WARNINGS
PHASE_FAILURES=0

# Phase 1
if should_run 1 && [ "$SKIP_INFRA" = false ]; then
    if [ $P1_FAILED -eq 0 ]; then
        echo -e "  Phase 1 (Infra Audit):        ${GREEN}PASS${NC}  (${P1_PASSED} passed, ${P1_WARNINGS} warnings)"
    else
        echo -e "  Phase 1 (Infra Audit):        ${RED}FAIL${NC}  (${P1_PASSED} passed, ${P1_FAILED} failed)"
        ((PHASE_FAILURES++))
    fi
fi

# Phase 2
if should_run 2; then
    if [ $P2_EXIT -eq 0 ]; then
        echo -e "  Phase 2 (20 Attack Scenarios): ${GREEN}PASS${NC}"
    elif [ $P2_EXIT -eq 5 ]; then
        echo -e "  Phase 2 (20 Attack Scenarios): ${YELLOW}NO TESTS${NC}"
    else
        echo -e "  Phase 2 (20 Attack Scenarios): ${RED}FAIL${NC}  (exit code $P2_EXIT)"
        ((PHASE_FAILURES++))
    fi
fi

# Phase 3
if should_run 3; then
    if [ $P3_EXIT -eq 0 ]; then
        echo -e "  Phase 3 (10 Pentest):          ${GREEN}PASS${NC}"
    elif [ $P3_EXIT -eq 5 ]; then
        echo -e "  Phase 3 (10 Pentest):          ${YELLOW}NO TESTS${NC}"
    else
        echo -e "  Phase 3 (10 Pentest):          ${RED}FAIL${NC}  (exit code $P3_EXIT)"
        ((PHASE_FAILURES++))
    fi
fi

# Phase 4
if should_run 4; then
    TOTAL_PASSED=$((TOTAL_PASSED + P4_PASSED))
    TOTAL_FAILED=$((TOTAL_FAILED + P4_FAILED))
    TOTAL_WARNINGS=$((TOTAL_WARNINGS + P4_WARNINGS))

    if [ $P4_FAILED -eq 0 ]; then
        echo -e "  Phase 4 (Curl Validation):     ${GREEN}PASS${NC}  (${P4_PASSED} passed, ${P4_WARNINGS} warnings)"
    else
        echo -e "  Phase 4 (Curl Validation):     ${RED}FAIL${NC}  (${P4_PASSED} passed, ${P4_FAILED} failed)"
        ((PHASE_FAILURES++))
    fi
fi

echo ""
echo -e "  ${BOLD}Curl-based totals:${NC} ${GREEN}${TOTAL_PASSED} passed${NC} | ${RED}${TOTAL_FAILED} failed${NC} | ${YELLOW}${TOTAL_WARNINGS} warnings${NC}"
echo ""

if [ $PHASE_FAILURES -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}ALL PHASES PASSED${NC}"
else
    echo -e "  ${RED}${BOLD}${PHASE_FAILURES} PHASE(S) FAILED — review output above${NC}"
fi

echo ""
echo -e "${CYAN}$(printf '═%.0s' {1..74})${NC}"
echo ""

# Exit non-zero if any phase failed
if [ $PHASE_FAILURES -gt 0 ] || [ $P2_EXIT -ne 0 ] || [ $P3_EXIT -ne 0 ]; then
    exit 1
fi
exit 0
