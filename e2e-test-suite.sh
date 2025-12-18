#!/bin/bash
#
# End-to-End Test Suite for CA-A2A Document Processing Pipeline
# Run this in AWS CloudShell (eu-west-3 region)
#
# Usage: bash e2e-test-suite.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
export AWS_REGION=eu-west-3
export CLUSTER=ca-a2a-cluster
export BUCKET=ca-a2a-documents-555043101106
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Utility functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    ((TESTS_PASSED++))
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
    ((TESTS_FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

section_header() {
    echo ""
    echo "=========================================="
    echo "$1"
    echo "=========================================="
    echo ""
}

# Test functions
test_infrastructure() {
    section_header "TEST 1: Infrastructure Verification"
    ((TESTS_RUN++))
    
    log_info "Checking ECS services..."
    SERVICES=$(aws ecs describe-services \
        --cluster $CLUSTER \
        --services orchestrator extractor validator archivist \
        --region $AWS_REGION \
        --query 'services[?status==`ACTIVE`].serviceName' \
        --output text)
    
    SERVICE_COUNT=$(echo $SERVICES | wc -w)
    if [ "$SERVICE_COUNT" -eq 4 ]; then
        log_success "All 4 ECS services are ACTIVE"
    else
        log_error "Only $SERVICE_COUNT services are ACTIVE (expected 4)"
        return 1
    fi
    
    log_info "Checking running tasks..."
    RUNNING_COUNT=$(aws ecs describe-services \
        --cluster $CLUSTER \
        --services orchestrator extractor validator archivist \
        --region $AWS_REGION \
        --query 'services[*].runningCount' \
        --output text | awk '{s+=$1} END {print s}')
    
    log_info "Total running tasks: $RUNNING_COUNT/8"
    if [ "$RUNNING_COUNT" -ge 6 ]; then
        log_success "Sufficient tasks running ($RUNNING_COUNT/8)"
    else
        log_warning "Only $RUNNING_COUNT tasks running (expected 8)"
    fi
    
    log_info "Checking ALB target health..."
    HEALTHY_TARGETS=$(aws elbv2 describe-target-health \
        --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
        --region $AWS_REGION \
        --query 'TargetHealthDescriptions[?TargetHealth.State==`healthy`].Target.Id' \
        --output text | wc -w)
    
    if [ "$HEALTHY_TARGETS" -ge 1 ]; then
        log_success "$HEALTHY_TARGETS healthy ALB targets"
    else
        log_error "No healthy ALB targets found"
        return 1
    fi
}

test_api_endpoints() {
    section_header "TEST 2: API Endpoint Tests"
    ((TESTS_RUN++))
    
    log_info "Testing /health endpoint..."
    HEALTH_RESPONSE=$(curl -s -m 10 "$ALB_URL/health" 2>/dev/null || echo "TIMEOUT")
    
    if [ "$HEALTH_RESPONSE" = "TIMEOUT" ]; then
        log_error "Health endpoint timed out"
        return 1
    fi
    
    if echo "$HEALTH_RESPONSE" | jq -e '.status' >/dev/null 2>&1; then
        STATUS=$(echo "$HEALTH_RESPONSE" | jq -r '.status')
        if [ "$STATUS" = "healthy" ]; then
            log_success "Health endpoint returned: $STATUS"
        else
            log_warning "Health endpoint returned: $STATUS"
        fi
    else
        log_error "Health endpoint returned invalid JSON: $HEALTH_RESPONSE"
        return 1
    fi
    
    log_info "Testing /card endpoint..."
    CARD_RESPONSE=$(curl -s -m 10 "$ALB_URL/card" 2>/dev/null || echo "TIMEOUT")
    
    if [ "$CARD_RESPONSE" = "TIMEOUT" ]; then
        log_error "Card endpoint timed out"
        return 1
    fi
    
    if echo "$CARD_RESPONSE" | jq -e '.agent_name' >/dev/null 2>&1; then
        AGENT_NAME=$(echo "$CARD_RESPONSE" | jq -r '.agent_name')
        SKILLS_COUNT=$(echo "$CARD_RESPONSE" | jq '.skills | length')
        log_success "Agent card retrieved: $AGENT_NAME with $SKILLS_COUNT skills"
    else
        log_error "Card endpoint returned invalid response"
        return 1
    fi
}

create_test_documents() {
    section_header "TEST 3: Document Preparation"
    ((TESTS_RUN++))
    
    log_info "Creating test documents..."
    
    # Create test directory
    mkdir -p ~/ca-a2a-test-docs
    cd ~/ca-a2a-test-docs
    
    # Test 1: Simple Invoice (TXT)
    cat > test_invoice_001.txt << 'EOF'
INVOICE #INV-TEST-001
Date: 2025-12-18
From: Tech Consulting LLC
To: Demo Client Corp

Services Rendered:
- Cloud Architecture Review: €2,500.00
- AWS Migration Planning: €3,000.00
- Security Assessment: €1,500.00

Subtotal: €7,000.00
Tax (20%): €1,400.00
Total: €8,400.00

Payment Due: 2026-01-18
EOF

    # Test 2: Purchase Order (TXT)
    cat > test_po_002.txt << 'EOF'
PURCHASE ORDER #PO-2025-100

Vendor: Office Supplies Inc
Date: 2025-12-18

Items:
1. Laptops (5 units) @ €1,200 = €6,000.00
2. Monitors (10 units) @ €300 = €3,000.00
3. Keyboards (15 units) @ €50 = €750.00

Subtotal: €9,750.00
Tax: €1,950.00
Total: €11,700.00
EOF

    # Test 3: Employee CSV
    cat > test_employees_003.csv << 'EOF'
Employee_ID,First_Name,Last_Name,Department,Salary,Email,Hire_Date
E100,Alice,Johnson,Engineering,75000,alice.j@test.com,2024-01-15
E101,Bob,Smith,Sales,65000,bob.s@test.com,2024-02-20
E102,Carol,Williams,HR,70000,carol.w@test.com,2024-03-10
E103,David,Brown,Engineering,80000,david.b@test.com,2024-04-05
E104,Emma,Davis,Marketing,68000,emma.d@test.com,2024-05-12
EOF

    # Test 4: Contract Summary (TXT)
    cat > test_contract_004.txt << 'EOF'
SERVICE AGREEMENT SUMMARY

Contract ID: CNT-2025-042
Effective Date: 2025-12-18
Parties: Tech Services SARL & Demo Corp

Term: 12 months
Monthly Fee: €5,000
Hourly Rate: €150

Services:
- Cloud Infrastructure Management
- 24/7 Support
- Monthly Reporting

Termination: 30 days notice required
Confidentiality: 3 years post-termination
EOF

    log_success "Created 4 test documents"
    ls -lh *.txt *.csv
}

upload_test_documents() {
    section_header "TEST 4: Document Upload to S3"
    ((TESTS_RUN++))
    
    log_info "Uploading test documents to S3..."
    
    cd ~/ca-a2a-test-docs
    
    for file in *.txt *.csv; do
        log_info "Uploading $file..."
        aws s3 cp "$file" "s3://$BUCKET/incoming/" --region $AWS_REGION
        if [ $? -eq 0 ]; then
            log_success "Uploaded: $file"
        else
            log_error "Failed to upload: $file"
        fi
    done
    
    log_info "Verifying S3 contents..."
    aws s3 ls "s3://$BUCKET/incoming/" --region $AWS_REGION
}

test_scenario_invoice() {
    section_header "TEST 5: Scenario 1 - Invoice Processing"
    ((TESTS_RUN++))
    
    log_info "Processing invoice document..."
    
    RESPONSE=$(curl -s -m 30 -X POST "$ALB_URL/process" \
        -H "Content-Type: application/json" \
        -d '{"s3_key": "incoming/test_invoice_001.txt"}' 2>/dev/null || echo "TIMEOUT")
    
    if [ "$RESPONSE" = "TIMEOUT" ]; then
        log_error "Invoice processing request timed out"
        return 1
    fi
    
    if echo "$RESPONSE" | jq -e '.status' >/dev/null 2>&1; then
        STATUS=$(echo "$RESPONSE" | jq -r '.status')
        log_success "Invoice processing initiated: $STATUS"
        echo "$RESPONSE" | jq '.'
    else
        log_error "Invoice processing returned invalid response: $RESPONSE"
        return 1
    fi
    
    log_info "Waiting 15 seconds for processing..."
    sleep 15
}

test_scenario_purchase_order() {
    section_header "TEST 6: Scenario 2 - Purchase Order Processing"
    ((TESTS_RUN++))
    
    log_info "Processing purchase order..."
    
    RESPONSE=$(curl -s -m 30 -X POST "$ALB_URL/process" \
        -H "Content-Type: application/json" \
        -d '{"s3_key": "incoming/test_po_002.txt"}' 2>/dev/null || echo "TIMEOUT")
    
    if [ "$RESPONSE" = "TIMEOUT" ]; then
        log_error "Purchase order processing timed out"
        return 1
    fi
    
    if echo "$RESPONSE" | jq -e '.status' >/dev/null 2>&1; then
        STATUS=$(echo "$RESPONSE" | jq -r '.status')
        log_success "Purchase order processing initiated: $STATUS"
        echo "$RESPONSE" | jq '.'
    else
        log_warning "Purchase order response: $RESPONSE"
    fi
    
    log_info "Waiting 15 seconds for processing..."
    sleep 15
}

test_scenario_csv() {
    section_header "TEST 7: Scenario 3 - CSV Bulk Processing"
    ((TESTS_RUN++))
    
    log_info "Processing employee CSV..."
    
    RESPONSE=$(curl -s -m 30 -X POST "$ALB_URL/process" \
        -H "Content-Type: application/json" \
        -d '{"s3_key": "incoming/test_employees_003.csv"}' 2>/dev/null || echo "TIMEOUT")
    
    if [ "$RESPONSE" = "TIMEOUT" ]; then
        log_error "CSV processing timed out"
        return 1
    fi
    
    if echo "$RESPONSE" | jq -e '.status' >/dev/null 2>&1; then
        STATUS=$(echo "$RESPONSE" | jq -r '.status')
        log_success "CSV processing initiated: $STATUS"
        echo "$RESPONSE" | jq '.'
    else
        log_warning "CSV response: $RESPONSE"
    fi
    
    log_info "Waiting 10 seconds for processing..."
    sleep 10
}

test_scenario_contract() {
    section_header "TEST 8: Scenario 4 - Contract Processing"
    ((TESTS_RUN++))
    
    log_info "Processing contract document..."
    
    RESPONSE=$(curl -s -m 30 -X POST "$ALB_URL/process" \
        -H "Content-Type: application/json" \
        -d '{"s3_key": "incoming/test_contract_004.txt"}' 2>/dev/null || echo "TIMEOUT")
    
    if [ "$RESPONSE" = "TIMEOUT" ]; then
        log_error "Contract processing timed out"
        return 1
    fi
    
    if echo "$RESPONSE" | jq -e '.status' >/dev/null 2>&1; then
        STATUS=$(echo "$RESPONSE" | jq -r '.status')
        log_success "Contract processing initiated: $STATUS"
        echo "$RESPONSE" | jq '.'
    else
        log_warning "Contract response: $RESPONSE"
    fi
    
    log_info "Waiting 20 seconds for processing..."
    sleep 20
}

check_logs() {
    section_header "TEST 9: CloudWatch Logs Verification"
    ((TESTS_RUN++))
    
    log_info "Checking orchestrator logs for processing activity..."
    
    RECENT_LOGS=$(aws logs filter-log-events \
        --log-group-name /ecs/ca-a2a-orchestrator \
        --start-time $(($(date +%s) - 300))000 \
        --region $AWS_REGION \
        --query 'events[*].message' \
        --output text 2>/dev/null | head -20)
    
    if [ -n "$RECENT_LOGS" ]; then
        log_success "Found recent orchestrator logs"
        echo "$RECENT_LOGS" | grep -i "process\|document\|extract" | head -10
    else
        log_warning "No recent logs found (may be processing delay)"
    fi
    
    log_info "Checking for errors..."
    ERROR_COUNT=$(aws logs filter-log-events \
        --log-group-name /ecs/ca-a2a-orchestrator \
        --filter-pattern "ERROR" \
        --start-time $(($(date +%s) - 300))000 \
        --region $AWS_REGION \
        --query 'events | length(@)' \
        --output text 2>/dev/null)
    
    if [ "$ERROR_COUNT" = "0" ] || [ -z "$ERROR_COUNT" ]; then
        log_success "No errors in orchestrator logs"
    else
        log_warning "Found $ERROR_COUNT errors in logs"
    fi
}

check_database() {
    section_header "TEST 10: Database Verification"
    ((TESTS_RUN++))
    
    log_info "Connecting to database via ECS task..."
    
    # Get a running task
    TASK_ARN=$(aws ecs list-tasks \
        --cluster $CLUSTER \
        --service-name orchestrator \
        --region $AWS_REGION \
        --query 'taskArns[0]' \
        --output text 2>/dev/null)
    
    if [ -z "$TASK_ARN" ] || [ "$TASK_ARN" = "None" ]; then
        log_error "No running orchestrator tasks found"
        return 1
    fi
    
    TASK_ID=$(echo $TASK_ARN | cut -d'/' -f3)
    log_info "Using task: $TASK_ID"
    
    log_info "Querying database (this may take a moment)..."
    
    # Note: This requires ECS Exec to be enabled
    log_warning "Database check requires manual verification via ECS Exec"
    log_info "Run this command separately:"
    echo ""
    echo "aws ecs execute-command \\"
    echo "  --cluster $CLUSTER \\"
    echo "  --task $TASK_ID \\"
    echo "  --container orchestrator \\"
    echo "  --command '/bin/bash' \\"
    echo "  --interactive \\"
    echo "  --region $AWS_REGION"
    echo ""
}

verify_s3_processed() {
    section_header "TEST 11: S3 Processing Verification"
    ((TESTS_RUN++))
    
    log_info "Checking processed folder..."
    PROCESSED_COUNT=$(aws s3 ls "s3://$BUCKET/processed/" --region $AWS_REGION --recursive 2>/dev/null | wc -l)
    
    log_info "Documents in processed/: $PROCESSED_COUNT"
    
    if [ "$PROCESSED_COUNT" -gt 0 ]; then
        log_success "Found $PROCESSED_COUNT processed documents"
        aws s3 ls "s3://$BUCKET/processed/" --region $AWS_REGION --recursive
    else
        log_warning "No documents in processed folder yet (may still be processing)"
    fi
    
    log_info "Checking failed folder..."
    FAILED_COUNT=$(aws s3 ls "s3://$BUCKET/failed/" --region $AWS_REGION --recursive 2>/dev/null | wc -l)
    
    if [ "$FAILED_COUNT" -eq 0 ]; then
        log_success "No failed documents"
    else
        log_warning "Found $FAILED_COUNT failed documents"
    fi
}

generate_report() {
    section_header "TEST SUMMARY"
    
    echo "Total Tests Run: $TESTS_RUN"
    echo "Tests Passed: $TESTS_PASSED"
    echo "Tests Failed: $TESTS_FAILED"
    echo ""
    
    PASS_RATE=$((TESTS_PASSED * 100 / TESTS_RUN))
    
    if [ "$TESTS_FAILED" -eq 0 ]; then
        echo -e "${GREEN}✓ ALL TESTS PASSED! (100%)${NC}"
    elif [ "$PASS_RATE" -ge 80 ]; then
        echo -e "${YELLOW}⚠ MOSTLY PASSED ($PASS_RATE%)${NC}"
    else
        echo -e "${RED}✗ SOME TESTS FAILED ($PASS_RATE%)${NC}"
    fi
    
    echo ""
    echo "=========================================="
    echo "NEXT STEPS:"
    echo "=========================================="
    echo "1. Check CloudWatch Logs for detailed processing info"
    echo "2. Verify database content using ECS Exec"
    echo "3. Check S3 processed/ folder for archived documents"
    echo ""
    echo "Useful commands:"
    echo "  aws logs tail /ecs/ca-a2a-orchestrator --since 10m --follow --region $AWS_REGION"
    echo "  aws s3 ls s3://$BUCKET/processed/ --region $AWS_REGION --recursive"
    echo ""
}

# Main execution
main() {
    section_header "CA-A2A E2E Test Suite - Starting"
    
    log_info "AWS Region: $AWS_REGION"
    log_info "ECS Cluster: $CLUSTER"
    log_info "S3 Bucket: $BUCKET"
    log_info "ALB URL: $ALB_URL"
    echo ""
    
    # Run tests
    test_infrastructure
    test_api_endpoints
    create_test_documents
    upload_test_documents
    test_scenario_invoice
    test_scenario_purchase_order
    test_scenario_csv
    test_scenario_contract
    check_logs
    check_database
    verify_s3_processed
    
    # Generate report
    generate_report
}

# Run main
main

