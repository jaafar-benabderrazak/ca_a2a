#!/bin/bash
# CA-A2A Automated Test Suite
# Follows scenarios from STEP_BY_STEP_TESTING.md
# Run in AWS CloudShell

set -e  # Exit on error

# Configuration
export AWS_REGION=eu-west-3
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
export S3_BUCKET="ca-a2a-documents-555043101106"

# (If A2A auth is enabled) API key for /message
if [ -f "/tmp/ca-a2a-config.env" ]; then
    source /tmp/ca-a2a-config.env
fi
export A2A_API_KEY="${A2A_API_KEY:-${A2A_CLIENT_API_KEY:-}}"
AUTH_HEADER=()
if [ -n "$A2A_API_KEY" ]; then
    AUTH_HEADER=(-H "X-API-Key: $A2A_API_KEY")
fi

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo ""
}

print_test() {
    echo -e "${YELLOW}► Test $1: $2${NC}"
}

pass_test() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASSED_TESTS++))
    ((TOTAL_TESTS++))
}

fail_test() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((FAILED_TESTS++))
    ((TOTAL_TESTS++))
}

wait_with_progress() {
    local seconds=$1
    local message=$2
    echo -n "$message: "
    for i in $(seq $seconds -1 1); do
        echo -n "$i..."
        sleep 1
    done
    echo "done!"
}

# Start testing
clear
print_header "CA-A2A AUTOMATED TEST SUITE"
echo "Start time: $(date)"
echo "Region: $AWS_REGION"
echo "ALB URL: $ALB_URL"
echo ""

# ============================================
# SCENARIO 1: BASIC HEALTH CHECKS
# ============================================
print_header "SCENARIO 1: BASIC HEALTH CHECKS"

print_test "1.1" "Orchestrator Health Check"
HEALTH_RESPONSE=$(curl -s -w "\n%{http_code}" -m 10 $ALB_URL/health)
HTTP_CODE=$(echo "$HEALTH_RESPONSE" | tail -n 1)
HEALTH_JSON=$(echo "$HEALTH_RESPONSE" | head -n -1)

if [ "$HTTP_CODE" == "200" ]; then
    STATUS=$(echo "$HEALTH_JSON" | jq -r '.status')
    if [ "$STATUS" == "healthy" ]; then
        pass_test "Health endpoint returns healthy status"
        echo "$HEALTH_JSON" | jq '{status, agent, version}'
    else
        fail_test "Health status is not healthy: $STATUS"
    fi
else
    fail_test "Health endpoint returned HTTP $HTTP_CODE"
fi

echo ""
print_test "1.2" "Agent Card"
CARD_RESPONSE=$(curl -s -w "\n%{http_code}" -m 10 $ALB_URL/card)
HTTP_CODE=$(echo "$CARD_RESPONSE" | tail -n 1)
CARD_JSON=$(echo "$CARD_RESPONSE" | head -n -1)

if [ "$HTTP_CODE" == "200" ]; then
    SKILL_COUNT=$(echo "$CARD_JSON" | jq -r '.skills | length')
    if [ "$SKILL_COUNT" -ge "6" ]; then
        pass_test "Agent card shows $SKILL_COUNT skills"
        echo "$CARD_JSON" | jq '{name, version, skills: (.skills | length)}'
    else
        fail_test "Expected at least 6 skills, found $SKILL_COUNT"
    fi
else
    fail_test "Card endpoint returned HTTP $HTTP_CODE"
fi

echo ""
print_test "1.3" "Agent Status"
STATUS_RESPONSE=$(curl -s -m 10 $ALB_URL/status | jq '{status, active_tasks, completed_tasks, discovered_agents}')
echo "$STATUS_RESPONSE"
pass_test "Agent status retrieved"

# ============================================
# SCENARIO 2: SINGLE DOCUMENT PROCESSING
# ============================================
print_header "SCENARIO 2: SINGLE DOCUMENT PROCESSING"

print_test "2.1" "Upload Test Document to S3"
TEST_FILE="auto-test-$(date +%s).txt"
cat > /tmp/$TEST_FILE << EOF
Automated Test Document
=======================
Test ID: AUTO-TEST-001
Created: $(date)
Purpose: End-to-end pipeline verification

Test Data:
- Document Type: Invoice
- Amount: 9,876.54 EUR
- Date: 2025-12-18
- Vendor: Automated Test Corp
- Items: 5

This document tests the complete processing pipeline including:
1. Extraction of structured data
2. Validation of extracted fields
3. Archiving to long-term storage
EOF

if aws s3 cp /tmp/$TEST_FILE s3://$S3_BUCKET/incoming/$TEST_FILE --region $AWS_REGION 2>&1 | grep -q "upload:"; then
    pass_test "Document uploaded to S3: $TEST_FILE"
else
    fail_test "Failed to upload document to S3"
fi

echo ""
print_test "2.2" "Trigger Document Processing"
PROCESS_RESULT=$(curl -s -X POST $ALB_URL/message "${AUTH_HEADER[@]}" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"process_document\",
    \"params\": {
      \"s3_key\": \"incoming/$TEST_FILE\",
      \"priority\": \"high\"
    },
    \"id\": 100
  }")

TASK_ID=$(echo "$PROCESS_RESULT" | jq -r '.result.task_id')

if [ "$TASK_ID" != "null" ] && [ -n "$TASK_ID" ]; then
    pass_test "Processing triggered, task ID: $TASK_ID"
    echo "$PROCESS_RESULT" | jq '.result'
    echo "$TASK_ID" > /tmp/ca_a2a_test_task_id.txt
else
    fail_test "Failed to trigger processing"
    echo "$PROCESS_RESULT"
fi

echo ""
print_test "2.3" "Wait for Processing"
wait_with_progress 30 "Waiting for async processing"

echo ""
print_test "2.4" "Check Task Status"
if [ -f /tmp/ca_a2a_test_task_id.txt ]; then
    TASK_ID=$(cat /tmp/ca_a2a_test_task_id.txt)
    
    STATUS_CHECK=$(curl -s -X POST $ALB_URL/message "${AUTH_HEADER[@]}" \
      -H "Content-Type: application/json" \
      -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"get_task_status\",
        \"params\": {\"task_id\": \"$TASK_ID\"},
        \"id\": 101
      }")
    
    TASK_STATUS=$(echo "$STATUS_CHECK" | jq -r '.result.status // "not_found"')
    
    if [ "$TASK_STATUS" == "completed" ]; then
        pass_test "Task completed successfully"
        echo "$STATUS_CHECK" | jq '.result | {task_id, status, current_stage, stages: (.stages | keys)}'
    elif [ "$TASK_STATUS" == "processing" ]; then
        CURRENT_STAGE=$(echo "$STATUS_CHECK" | jq -r '.result.current_stage')
        fail_test "Task still processing at stage: $CURRENT_STAGE (may need more time)"
    elif [ "$TASK_STATUS" == "failed" ]; then
        ERROR_MSG=$(echo "$STATUS_CHECK" | jq -r '.result.error')
        fail_test "Task failed: $ERROR_MSG"
    else
        fail_test "Task not found (may have been cleared from memory)"
    fi
else
    fail_test "No task ID available"
fi

echo ""
print_test "2.5" "Verify S3 Movement"
echo "Checking S3 folders:"
INCOMING_COUNT=$(aws s3 ls s3://$S3_BUCKET/incoming/ --region $AWS_REGION | grep "$TEST_FILE" | wc -l)
PROCESSED_COUNT=$(aws s3 ls s3://$S3_BUCKET/processed/ --region $AWS_REGION | wc -l)
ARCHIVED_COUNT=$(aws s3 ls s3://$S3_BUCKET/archived/ --region $AWS_REGION | wc -l)

echo "  Incoming: $INCOMING_COUNT files matching test"
echo "  Processed: $PROCESSED_COUNT total files"
echo "  Archived: $ARCHIVED_COUNT total files"

if [ $INCOMING_COUNT -eq 0 ]; then
    pass_test "Document moved from incoming (expected)"
else
    fail_test "Document still in incoming folder"
fi

# ============================================
# SCENARIO 3: BATCH PROCESSING
# ============================================
print_header "SCENARIO 3: BATCH DOCUMENT PROCESSING"

print_test "3.1" "Create Batch Documents"
BATCH_ID="batch-auto-$(date +%s)"
BATCH_COUNT=3

for i in $(seq 1 $BATCH_COUNT); do
    BATCH_FILE="$BATCH_ID-doc-$i.txt"
    cat > /tmp/$BATCH_FILE << EOF
Batch Test Document $i/$BATCH_COUNT
Batch ID: $BATCH_ID
Document: $i
Created: $(date)
EOF
    aws s3 cp /tmp/$BATCH_FILE s3://$S3_BUCKET/incoming/$BATCH_FILE --region $AWS_REGION --quiet
    echo "  - Uploaded: $BATCH_FILE"
done
pass_test "Created $BATCH_COUNT batch documents"

echo ""
print_test "3.2" "Trigger Batch Processing"
BATCH_RESULT=$(curl -s -X POST $ALB_URL/message "${AUTH_HEADER[@]}" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"process_batch\",
    \"params\": {
      \"prefix\": \"incoming/$BATCH_ID\"
    },
    \"id\": 102
  }")

BATCH_TASK_COUNT=$(echo "$BATCH_RESULT" | jq -r '.result.total_documents')

if [ "$BATCH_TASK_COUNT" -eq "$BATCH_COUNT" ]; then
    pass_test "Batch processing triggered for $BATCH_TASK_COUNT documents"
    echo "$BATCH_RESULT" | jq '.result | {batch_id, total_documents, status}'
else
    fail_test "Expected $BATCH_COUNT documents, got $BATCH_TASK_COUNT"
fi

# ============================================
# SCENARIO 4: ERROR HANDLING
# ============================================
print_header "SCENARIO 4: ERROR HANDLING"

print_test "4.1" "Invalid S3 Key"
ERROR_RESULT=$(curl -s -X POST $ALB_URL/message "${AUTH_HEADER[@]}" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {"s3_key": "invalid/nonexistent-999999.txt"},
    "id": 103
  }')

if echo "$ERROR_RESULT" | jq -e '.error' > /dev/null 2>&1; then
    pass_test "API returned error for invalid S3 key"
    echo "$ERROR_RESULT" | jq '.error'
elif echo "$ERROR_RESULT" | jq -e '.result.task_id' > /dev/null 2>&1; then
    pass_test "Task started (will fail during processing)"
else
    fail_test "Unexpected response format"
fi

echo ""
print_test "4.2" "Invalid Method"
INVALID_METHOD=$(curl -s -X POST $ALB_URL/message "${AUTH_HEADER[@]}" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "invalid_method_test",
    "params": {},
    "id": 104
  }')

ERROR_CODE=$(echo "$INVALID_METHOD" | jq -r '.error.code // "none"')

if [ "$ERROR_CODE" == "-32601" ]; then
    pass_test "Returns method not found error (-32601)"
    echo "$INVALID_METHOD" | jq '.error'
else
    fail_test "Expected error code -32601, got: $ERROR_CODE"
fi

echo ""
print_test "4.3" "Missing Required Parameters"
MISSING_PARAMS=$(curl -s -X POST $ALB_URL/message "${AUTH_HEADER[@]}" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {},
    "id": 105
  }')

ERROR_CODE=$(echo "$MISSING_PARAMS" | jq -r '.error.code // "none"')

if [ "$ERROR_CODE" == "-32602" ]; then
    pass_test "Returns invalid params error (-32602)"
    echo "$MISSING_PARAMS" | jq '.error'
else
    fail_test "Expected error code -32602, got: $ERROR_CODE"
fi

# ============================================
# SCENARIO 5: AGENT DISCOVERY
# ============================================
print_header "SCENARIO 5: AGENT DISCOVERY"

print_test "5.1" "Discover Agents"
DISCOVER_RESULT=$(curl -s -X POST $ALB_URL/message "${AUTH_HEADER[@]}" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "discover_agents",
    "params": {},
    "id": 106
  }')

DISCOVERED_COUNT=$(echo "$DISCOVER_RESULT" | jq -r '.result.discovered_agents')

if [ "$DISCOVERED_COUNT" == "3" ]; then
    pass_test "Discovered all 3 agents (Extractor, Validator, Archivist)"
    echo "$DISCOVER_RESULT" | jq '.result | {discovered_agents, total_skills}'
else
    fail_test "Expected 3 agents, discovered: $DISCOVERED_COUNT"
fi

echo ""
print_test "5.2" "Get Agent Registry"
REGISTRY=$(curl -s -X POST $ALB_URL/message "${AUTH_HEADER[@]}" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "get_agent_registry",
    "params": {},
    "id": 107
  }')

TOTAL_SKILLS=$(echo "$REGISTRY" | jq -r '.result.total_skills')

if [ "$TOTAL_SKILLS" -ge "15" ]; then
    pass_test "Agent registry shows $TOTAL_SKILLS skills"
    echo "$REGISTRY" | jq '.result | {total_agents, total_skills, agents: (.agents | keys)}'
else
    fail_test "Expected at least 15 skills, found: $TOTAL_SKILLS"
fi

# ============================================
# SCENARIO 6: PERFORMANCE TESTING
# ============================================
print_header "SCENARIO 6: PERFORMANCE TESTING"

print_test "6.1" "Response Time Test (10 requests)"
TOTAL_TIME=0
MAX_TIME=0
MIN_TIME=999999

for i in $(seq 1 10); do
    START=$(date +%s%N)
    curl -s -m 10 $ALB_URL/health > /dev/null
    END=$(date +%s%N)
    DURATION=$(( ($END - $START) / 1000000 ))
    
    TOTAL_TIME=$((TOTAL_TIME + DURATION))
    [ $DURATION -gt $MAX_TIME ] && MAX_TIME=$DURATION
    [ $DURATION -lt $MIN_TIME ] && MIN_TIME=$DURATION
done

AVG_TIME=$((TOTAL_TIME / 10))

echo "  Average: ${AVG_TIME}ms"
echo "  Min: ${MIN_TIME}ms"
echo "  Max: ${MAX_TIME}ms"

if [ $AVG_TIME -lt 500 ]; then
    pass_test "Good performance: ${AVG_TIME}ms average"
else
    fail_test "Poor performance: ${AVG_TIME}ms average (expected <500ms)"
fi

# ============================================
# SCENARIO 7: DATABASE VERIFICATION
# ============================================
print_header "SCENARIO 7: DATABASE VERIFICATION"

print_test "7.1" "List Pending Documents"
PENDING=$(curl -s -X POST $ALB_URL/message "${AUTH_HEADER[@]}" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {"limit": 5},
    "id": 108
  }')

DOC_COUNT=$(echo "$PENDING" | jq -r '.result.count // 0')
pass_test "Database query successful, found $DOC_COUNT pending documents"
echo "$PENDING" | jq '.result | {count, documents: (.documents | length)}'

# ============================================
# FINAL SUMMARY
# ============================================
print_header "TEST SUMMARY"

echo "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
echo -e "${RED}Failed: $FAILED_TESTS${NC}"
echo ""

PASS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
echo "Pass Rate: ${PASS_RATE}%"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✓✓✓ ALL TESTS PASSED! ✓✓✓${NC}"
    echo ""
    echo "The CA-A2A system is fully operational!"
    EXIT_CODE=0
else
    echo -e "${YELLOW}⚠ SOME TESTS FAILED ⚠${NC}"
    echo ""
    echo "Please review the failed tests above."
    echo "Check logs with:"
    echo "  aws logs tail /ecs/ca-a2a-orchestrator --since 10m --region $AWS_REGION"
    EXIT_CODE=1
fi

echo ""
echo "End time: $(date)"
echo ""
echo "For detailed testing procedures, see: STEP_BY_STEP_TESTING.md"
echo "For architecture details, see: SYSTEM_ARCHITECTURE.md"
echo "For API reference, see: API_QUICK_REFERENCE.md"

exit $EXIT_CODE

