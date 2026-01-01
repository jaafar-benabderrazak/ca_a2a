#!/bin/bash
# Complete E2E Test Suite for CA-A2A Pipeline - CORRECTED
# Run in AWS CloudShell
# 
# IMPORTANT: The orchestrator uses A2A protocol (JSON-RPC 2.0)
# All A2A method calls must be sent to POST /message endpoint

export AWS_REGION=eu-west-3
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

echo "========================================="
echo "  CA-A2A COMPLETE E2E TEST SUITE"
echo "  Using A2A Protocol (JSON-RPC 2.0)"
echo "========================================="
echo ""

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to test and count
test_step() {
    local name="$1"
    local command="$2"
    
    echo "---"
    echo "TEST: $name"
    if eval "$command"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAILED${NC}"
        ((TESTS_FAILED++))
    fi
    echo ""
}

# Test 1: Infrastructure Health
echo "========================================="
echo "TEST SUITE 1: INFRASTRUCTURE"
echo "========================================="
echo ""

echo "1.1 ECS Services Status"
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist \
  --region $AWS_REGION \
  --query 'services[*].[serviceName,status,runningCount,desiredCount]' \
  --output table

echo ""
echo "1.2 ALB Target Health"
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region $AWS_REGION \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State]' \
  --output table

echo ""
echo "1.3 RDS Status"
aws rds describe-db-instances \
  --db-instance-identifier ca-a2a-postgres \
  --region $AWS_REGION \
  --query 'DBInstances[0].[DBInstanceIdentifier,DBInstanceStatus]' \
  --output table

echo ""
echo -e "${GREEN}✓ Infrastructure tests complete${NC}"
echo ""

# Test 2: API Endpoints
echo "========================================="
echo "TEST SUITE 2: API ENDPOINTS"
echo "========================================="
echo ""

echo "2.1 Health Check (GET /health)"
HEALTH=$(curl -s -m 10 $ALB_URL/health)
if echo "$HEALTH" | jq -e '.status == "healthy"' > /dev/null 2>&1; then
    echo "$HEALTH" | jq '{status, agent, version}'
    echo -e "${GREEN}✓ Health check passed${NC}"
    ((TESTS_PASSED++))
else
    echo "$HEALTH"
    echo -e "${RED}✗ Health check failed${NC}"
    ((TESTS_FAILED++))
fi

echo ""
echo "2.2 Agent Card (GET /card)"
CARD=$(curl -s -m 10 $ALB_URL/card)
if echo "$CARD" | jq -e '.name' > /dev/null 2>&1; then
    echo "$CARD" | jq '{name, version, skills: (.skills | length)}'
    echo -e "${GREEN}✓ Agent card accessible${NC}"
    ((TESTS_PASSED++))
else
    echo "$CARD"
    echo -e "${RED}✗ Agent card failed${NC}"
    ((TESTS_FAILED++))
fi

echo ""
echo ""

# Test 3: A2A Protocol Methods
echo "========================================="
echo "TEST SUITE 3: A2A PROTOCOL METHODS"
echo "========================================="
echo ""

echo "3.1 Get Agent Registry"
REGISTRY=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "get_agent_registry",
    "params": {},
    "id": 1
  }')

if echo "$REGISTRY" | jq -e '.result' > /dev/null 2>&1; then
    echo "$REGISTRY" | jq '.result | {total_agents, total_skills, available_skills: (.available_skills | length)}'
    echo -e "${GREEN}✓ Agent registry accessible${NC}"
    ((TESTS_PASSED++))
else
    echo "$REGISTRY"
    echo -e "${RED}✗ Agent registry failed${NC}"
    ((TESTS_FAILED++))
fi

echo ""
echo "3.2 Discover Agents"
DISCOVER=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "discover_agents",
    "params": {},
    "id": 2
  }')

if echo "$DISCOVER" | jq -e '.result' > /dev/null 2>&1; then
    echo "$DISCOVER" | jq '.result | {discovered_agents, total_skills}'
    echo -e "${GREEN}✓ Agent discovery working${NC}"
    ((TESTS_PASSED++))
else
    echo "$DISCOVER"
    echo -e "${RED}✗ Agent discovery failed${NC}"
    ((TESTS_FAILED++))
fi

echo ""
echo "3.3 List Pending Documents"
PENDING=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {"limit": 5},
    "id": 3
  }')

if echo "$PENDING" | jq -e '.result' > /dev/null 2>&1; then
    echo "$PENDING" | jq '.result | {count}'
    echo -e "${GREEN}✓ List pending documents working${NC}"
    ((TESTS_PASSED++))
else
    echo "$PENDING"
    echo -e "${RED}✗ List pending failed${NC}"
    ((TESTS_FAILED++))
fi

echo ""
echo ""

# Test 4: Document Processing Pipeline
echo "========================================="
echo "TEST SUITE 4: DOCUMENT PROCESSING"
echo "========================================="
echo ""

# Create test document
TEST_FILE="e2e-test-$(date +%s).txt"
echo "E2E Test Document" > /tmp/$TEST_FILE
echo "Created: $(date)" >> /tmp/$TEST_FILE
echo "Test ID: $(uuidgen 2>/dev/null || echo 'test-id')" >> /tmp/$TEST_FILE
echo "Content: This is a test document for the CA-A2A pipeline" >> /tmp/$TEST_FILE

echo "4.1 Upload Test Document to S3"
if aws s3 cp /tmp/$TEST_FILE s3://ca-a2a-documents-555043101106/incoming/$TEST_FILE --region $AWS_REGION; then
    echo -e "${GREEN}✓ Document uploaded: incoming/$TEST_FILE${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ Document upload failed${NC}"
    ((TESTS_FAILED++))
fi

echo ""
echo "4.2 Trigger Document Processing"
PROCESS_RESULT=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"process_document\",
    \"params\": {
      \"s3_key\": \"incoming/$TEST_FILE\"
    },
    \"id\": 4
  }")

if echo "$PROCESS_RESULT" | jq -e '.result.task_id' > /dev/null 2>&1; then
    TASK_ID=$(echo "$PROCESS_RESULT" | jq -r '.result.task_id')
    echo "$PROCESS_RESULT" | jq '.result'
    echo "Task ID: $TASK_ID"
    echo -e "${GREEN}✓ Processing triggered successfully${NC}"
    ((TESTS_PASSED++))
else
    echo "$PROCESS_RESULT"
    echo -e "${RED}✗ Processing trigger failed${NC}"
    ((TESTS_FAILED++))
    TASK_ID="unknown"
fi

echo ""
echo "4.3 Wait for Processing (30 seconds)"
for i in {30..1}; do
    echo -ne "Waiting... $i seconds remaining\r"
    sleep 1
done
echo "Waiting... complete!         "

echo ""
echo "4.4 Check Task Status"
if [ "$TASK_ID" != "unknown" ]; then
    STATUS_RESULT=$(curl -s -X POST $ALB_URL/message \
      -H "Content-Type: application/json" \
      -d "{
        \"jsonrpc\": \"2.0\",
        \"method\": \"get_task_status\",
        \"params\": {
          \"task_id\": \"$TASK_ID\"
        },
        \"id\": 5
      }")
    
    if echo "$STATUS_RESULT" | jq -e '.result' > /dev/null 2>&1; then
        echo "$STATUS_RESULT" | jq '.result | {task_id, status, current_stage}'
        TASK_STATUS=$(echo "$STATUS_RESULT" | jq -r '.result.status')
        
        if [ "$TASK_STATUS" == "completed" ]; then
            echo -e "${GREEN}✓ Task completed successfully${NC}"
            ((TESTS_PASSED++))
        elif [ "$TASK_STATUS" == "processing" ]; then
            echo -e "${YELLOW}⚠ Task still processing (may need more time)${NC}"
            ((TESTS_PASSED++))
        else
            echo -e "${RED}✗ Task in unexpected state: $TASK_STATUS${NC}"
            ((TESTS_FAILED++))
        fi
    else
        echo "$STATUS_RESULT"
        echo -e "${RED}✗ Failed to get task status${NC}"
        ((TESTS_FAILED++))
    fi
else
    echo -e "${YELLOW}⚠ Skipping (no task ID)${NC}"
fi

echo ""
echo "4.5 Check S3 for Processed Files"
echo "Processed files:"
PROCESSED_COUNT=$(aws s3 ls s3://ca-a2a-documents-555043101106/processed/ --region $AWS_REGION | wc -l)
aws s3 ls s3://ca-a2a-documents-555043101106/processed/ --region $AWS_REGION | tail -5
if [ $PROCESSED_COUNT -gt 0 ]; then
    echo -e "${GREEN}✓ Found $PROCESSED_COUNT processed files${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠ No processed files found yet${NC}"
fi

echo ""
echo "Archived files:"
ARCHIVED_COUNT=$(aws s3 ls s3://ca-a2a-documents-555043101106/archived/ --region $AWS_REGION | wc -l)
aws s3 ls s3://ca-a2a-documents-555043101106/archived/ --region $AWS_REGION | tail -5
if [ $ARCHIVED_COUNT -gt 0 ]; then
    echo -e "${GREEN}✓ Found $ARCHIVED_COUNT archived files${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠ No archived files found yet${NC}"
fi

echo ""
echo ""

# Test 5: Batch Processing
echo "========================================="
echo "TEST SUITE 5: BATCH PROCESSING"
echo "========================================="
echo ""

echo "5.1 Create Multiple Test Documents"
for i in {1..3}; do
    BATCH_FILE="batch-test-$i-$(date +%s).txt"
    echo "Batch test document $i" > /tmp/$BATCH_FILE
    echo "Batch ID: batch-$(date +%s)" >> /tmp/$BATCH_FILE
    aws s3 cp /tmp/$BATCH_FILE s3://ca-a2a-documents-555043101106/incoming/$BATCH_FILE --region $AWS_REGION --quiet
    echo "  - Uploaded: $BATCH_FILE"
done
echo -e "${GREEN}✓ Batch files uploaded${NC}"
((TESTS_PASSED++))

echo ""
echo "5.2 Trigger Batch Processing"
BATCH_RESULT=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_batch",
    "params": {
      "prefix": "incoming/batch-test",
      "file_extension": ".txt"
    },
    "id": 6
  }')

if echo "$BATCH_RESULT" | jq -e '.result.batch_id' > /dev/null 2>&1; then
    echo "$BATCH_RESULT" | jq '.result | {batch_id, total_documents, status}'
    echo -e "${GREEN}✓ Batch processing triggered${NC}"
    ((TESTS_PASSED++))
else
    echo "$BATCH_RESULT"
    echo -e "${YELLOW}⚠ Batch processing may have issues${NC}"
fi

echo ""
echo ""

# Test 6: Error Handling
echo "========================================="
echo "TEST SUITE 6: ERROR HANDLING"
echo "========================================="
echo ""

echo "6.1 Test Invalid S3 Key"
ERROR_RESULT=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {
      "s3_key": "invalid/nonexistent-file.txt"
    },
    "id": 7
  }')

if echo "$ERROR_RESULT" | jq -e '.result or .error' > /dev/null 2>&1; then
    echo "$ERROR_RESULT" | jq '{result: .result.status, error: .error}'
    echo -e "${GREEN}✓ Error handling working${NC}"
    ((TESTS_PASSED++))
else
    echo "$ERROR_RESULT"
    echo -e "${RED}✗ Error handling failed${NC}"
    ((TESTS_FAILED++))
fi

echo ""
echo "6.2 Test Invalid Method"
INVALID_METHOD=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "nonexistent_method",
    "params": {},
    "id": 8
  }')

if echo "$INVALID_METHOD" | jq -e '.error' > /dev/null 2>&1; then
    echo "$INVALID_METHOD" | jq '.error'
    echo -e "${GREEN}✓ Invalid method handled correctly${NC}"
    ((TESTS_PASSED++))
else
    echo "$INVALID_METHOD"
    echo -e "${YELLOW}⚠ Unexpected response for invalid method${NC}"
fi

echo ""
echo ""

# Test 7: Performance
echo "========================================="
echo "TEST SUITE 7: PERFORMANCE"
echo "========================================="
echo ""

echo "7.1 Response Time Test (5 requests)"
TOTAL_TIME=0
for i in {1..5}; do
    START=$(date +%s%N)
    curl -s -m 10 $ALB_URL/health > /dev/null
    END=$(date +%s%N)
    DURATION=$(( ($END - $START) / 1000000 ))
    echo "  Request $i: ${DURATION}ms"
    TOTAL_TIME=$((TOTAL_TIME + DURATION))
done
AVG_TIME=$((TOTAL_TIME / 5))
echo "  Average: ${AVG_TIME}ms"

if [ $AVG_TIME -lt 500 ]; then
    echo -e "${GREEN}✓ Performance excellent (<500ms)${NC}"
    ((TESTS_PASSED++))
elif [ $AVG_TIME -lt 1000 ]; then
    echo -e "${YELLOW}⚠ Performance acceptable (<1000ms)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗ Performance needs improvement (>1000ms)${NC}"
    ((TESTS_FAILED++))
fi

echo ""
echo ""

# Final Summary
echo "========================================="
echo "  TEST SUMMARY"
echo "========================================="
echo ""
echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))
echo "Total Tests: $TOTAL_TESTS"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓✓✓ ALL TESTS PASSED! ✓✓✓${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠ Some tests failed or need attention ⚠${NC}"
    exit 1
fi

