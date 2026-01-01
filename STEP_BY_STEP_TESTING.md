# CA-A2A Step-by-Step Testing Guide

**Version:** 1.0  
**Last Updated:** December 18, 2025  
**Purpose:** Comprehensive testing scenarios for the CA-A2A document processing pipeline

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Test Environment Setup](#test-environment-setup)
3. [Scenario 1: Basic Health Checks](#scenario-1-basic-health-checks)
4. [Scenario 2: Single Document Processing](#scenario-2-single-document-processing)
5. [Scenario 3: Batch Document Processing](#scenario-3-batch-document-processing)
6. [Scenario 4: Error Handling](#scenario-4-error-handling)
7. [Scenario 5: Agent Discovery](#scenario-5-agent-discovery)
8. [Scenario 6: Performance Testing](#scenario-6-performance-testing)
9. [Scenario 7: Database Verification](#scenario-7-database-verification)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Tools
- AWS CLI configured with SSO
- `jq` for JSON processing
- `curl` for API testing
- Access to AWS CloudShell (recommended)

### Environment Variables
```bash
export AWS_REGION=eu-west-3
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
export S3_BUCKET="ca-a2a-documents-555043101106"
```

---

## Test Environment Setup

### Step 1: Verify AWS Access

```bash
echo "=== Verifying AWS Access ==="
aws sts get-caller-identity --region $AWS_REGION

# Expected output:
# {
#     "UserId": "...",
#     "Account": "555043101106",
#     "Arn": "arn:aws:sts::555043101106:assumed-role/..."
# }
```

### Step 2: Verify Infrastructure

```bash
echo "=== Checking ECS Services ==="
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist \
  --region $AWS_REGION \
  --query 'services[*].[serviceName,status,runningCount,desiredCount]' \
  --output table

# Expected: All services ACTIVE with running = desired
```

### Step 3: Verify ALB

```bash
echo "=== Checking ALB Target Health ==="
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region $AWS_REGION \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State]' \
  --output table

# Expected: All targets showing "healthy"
```

---

## Scenario 1: Basic Health Checks

### Test 1.1: Orchestrator Health

**Purpose:** Verify the orchestrator is responding

```bash
echo "=== Test 1.1: Health Check ==="
curl -s $ALB_URL/health | jq '.'
```

**Expected Output:**
```json
{
  "status": "healthy",
  "agent": "Orchestrator",
  "version": "1.0.0",
  "timestamp": 123456.789,
  "uptime_seconds": 1234.56,
  "dependencies": {}
}
```

**Success Criteria:**
- ✅ HTTP 200 status
- ✅ `status` field is `"healthy"`
- ✅ Response time < 500ms

---

### Test 1.2: Agent Card

**Purpose:** Verify agent capabilities are exposed

```bash
echo "=== Test 1.2: Agent Card ==="
curl -s $ALB_URL/card | jq '{name, version, skills: (.skills | length)}'
```

**Expected Output:**
```json
{
  "name": "Orchestrator",
  "version": "1.0.0",
  "skills": 6
}
```

**Success Criteria:**
- ✅ HTTP 200 status
- ✅ Returns agent name and version
- ✅ Has 6 skills defined

---

### Test 1.3: Agent Status

**Purpose:** Get detailed status information

```bash
echo "=== Test 1.3: Agent Status ==="
curl -s $ALB_URL/status | jq '{status, active_tasks, completed_tasks, discovered_agents}'
```

**Expected Output:**
```json
{
  "status": "healthy",
  "active_tasks": 0,
  "completed_tasks": 5,
  "discovered_agents": 3
}
```

**Success Criteria:**
- ✅ HTTP 200 status
- ✅ Shows task counts
- ✅ Shows discovered agents

---

## Scenario 2: Single Document Processing

### Test 2.1: Upload Document

**Purpose:** Upload a test document to S3

```bash
echo "=== Test 2.1: Upload Document ==="

# Create test document
TEST_FILE="test-$(date +%s).txt"
cat > /tmp/$TEST_FILE << 'EOF'
Test Document for CA-A2A Pipeline
----------------------------------
Document ID: TEST-001
Created: $(date)
Content Type: Plain Text

This is a test document to verify the complete processing pipeline.

Key Information:
- Document Type: Invoice
- Amount: 1,234.56
- Date: 2025-12-18
- Vendor: Test Vendor Inc.

Test data for extraction and validation.
EOF

# Upload to S3
aws s3 cp /tmp/$TEST_FILE s3://$S3_BUCKET/incoming/$TEST_FILE --region $AWS_REGION

echo "✓ Uploaded: $TEST_FILE"
echo "S3 Key: incoming/$TEST_FILE"
```

**Success Criteria:**
- ✅ File uploaded without errors
- ✅ File visible in S3 bucket

---

### Test 2.2: Trigger Processing

**Purpose:** Start document processing via API

```bash
echo "=== Test 2.2: Trigger Processing ==="

# Call process_document method
RESULT=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"process_document\",
    \"params\": {
      \"s3_key\": \"incoming/$TEST_FILE\",
      \"priority\": \"normal\"
    },
    \"id\": 1
  }")

echo "$RESULT" | jq '.'

# Extract task ID
TASK_ID=$(echo "$RESULT" | jq -r '.result.task_id')
echo ""
echo "Task ID: $TASK_ID"

# Save for later tests
echo "$TASK_ID" > /tmp/last_task_id.txt
```

**Expected Output:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "task_id": "uuid-here",
    "s3_key": "incoming/test-xxx.txt",
    "status": "processing",
    "message": "Document processing started"
  }
}
```

**Success Criteria:**
- ✅ HTTP 200 status
- ✅ Returns valid task_id (UUID format)
- ✅ Status is "processing"

---

### Test 2.3: Monitor Processing (Wait)

**Purpose:** Wait for async processing to complete

```bash
echo "=== Test 2.3: Waiting for Processing ==="

# Wait 30 seconds
for i in {30..1}; do
  echo -ne "Waiting... $i seconds remaining\r"
  sleep 1
done
echo "Waiting... complete!         "
```

---

### Test 2.4: Check Task Status

**Purpose:** Verify processing completed successfully

```bash
echo "=== Test 2.4: Check Task Status ==="

# Read task ID from previous test
TASK_ID=$(cat /tmp/last_task_id.txt)

# Query task status
STATUS_RESULT=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"get_task_status\",
    \"params\": {
      \"task_id\": \"$TASK_ID\"
    },
    \"id\": 2
  }")

echo "$STATUS_RESULT" | jq '.'

# Check if completed
TASK_STATUS=$(echo "$STATUS_RESULT" | jq -r '.result.status // "not_found"')
echo ""
echo "Task Status: $TASK_STATUS"

if [ "$TASK_STATUS" == "completed" ]; then
  echo "✓ Processing completed successfully"
  
  # Show stages
  echo ""
  echo "Completed Stages:"
  echo "$STATUS_RESULT" | jq '.result.stages | keys[]'
elif [ "$TASK_STATUS" == "processing" ]; then
  echo "⚠ Still processing (may need more time)"
  echo "Current stage: $(echo "$STATUS_RESULT" | jq -r '.result.current_stage')"
elif [ "$TASK_STATUS" == "failed" ]; then
  echo "✗ Processing failed"
  echo "Error: $(echo "$STATUS_RESULT" | jq -r '.result.error')"
else
  echo "✗ Task not found (may have been cleared from memory)"
fi
```

**Expected Output (Success):**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "task_id": "uuid",
    "s3_key": "incoming/test-xxx.txt",
    "status": "completed",
    "current_stage": "completed",
    "started_at": "2025-12-18T21:00:00",
    "completed_at": "2025-12-18T21:00:30",
    "stages": {
      "extraction": {
        "status": "completed",
        "completed_at": "2025-12-18T21:00:10"
      },
      "validation": {
        "status": "completed",
        "completed_at": "2025-12-18T21:00:20"
      },
      "archiving": {
        "status": "completed",
        "completed_at": "2025-12-18T21:00:30"
      }
    }
  }
}
```

**Success Criteria:**
- ✅ Task status is "completed"
- ✅ All three stages completed
- ✅ Total processing time < 60 seconds

---

### Test 2.5: Verify S3 Movement

**Purpose:** Confirm document moved from incoming to archived

```bash
echo "=== Test 2.5: Verify S3 Movement ==="

# Check incoming (should be gone or moved)
echo "Incoming folder:"
aws s3 ls s3://$S3_BUCKET/incoming/ --region $AWS_REGION | grep "$TEST_FILE" || echo "  (file moved - expected)"

echo ""
echo "Processed folder:"
aws s3 ls s3://$S3_BUCKET/processed/ --region $AWS_REGION | tail -5

echo ""
echo "Archived folder:"
aws s3 ls s3://$S3_BUCKET/archived/ --region $AWS_REGION | tail -5
```

**Success Criteria:**
- ✅ File no longer in incoming/
- ✅ File appears in processed/ or archived/

---

### Test 2.6: Check Orchestrator Logs

**Purpose:** Verify no errors in logs

```bash
echo "=== Test 2.6: Check Logs ==="

# Get recent logs
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 2m \
  --region $AWS_REGION \
  --format short | grep -E "task_id=$TASK_ID|ERROR" | tail -20

# Count errors
ERROR_COUNT=$(aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "ERROR" \
  --start-time $(($(date +%s) - 120))000 \
  --region $AWS_REGION \
  --query 'events | length(@)' \
  --output text)

echo ""
echo "Errors in last 2 minutes: $ERROR_COUNT"

if [ "$ERROR_COUNT" -eq "0" ]; then
  echo "✓ No errors found"
else
  echo "⚠ Found $ERROR_COUNT errors - check logs"
fi
```

**Success Criteria:**
- ✅ No ERROR entries related to this task
- ✅ Processing stages logged successfully

---

## Scenario 3: Batch Document Processing

### Test 3.1: Create Multiple Documents

**Purpose:** Create a batch of test documents

```bash
echo "=== Test 3.1: Create Batch Documents ==="

BATCH_ID="batch-$(date +%s)"

for i in {1..5}; do
  BATCH_FILE="$BATCH_ID-doc-$i.txt"
  cat > /tmp/$BATCH_FILE << EOF
Batch Test Document $i
Batch ID: $BATCH_ID
Document Number: $i
Created: $(date)
Content: Test data for batch processing scenario
EOF
  
  aws s3 cp /tmp/$BATCH_FILE s3://$S3_BUCKET/incoming/$BATCH_FILE --region $AWS_REGION --quiet
  echo "  ✓ Uploaded: $BATCH_FILE"
done

echo ""
echo "Batch ID: $BATCH_ID"
echo "Documents created: 5"
```

---

### Test 3.2: Trigger Batch Processing

**Purpose:** Process multiple documents in one call

```bash
echo "=== Test 3.2: Trigger Batch Processing ==="

BATCH_RESULT=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"process_batch\",
    \"params\": {
      \"prefix\": \"incoming/$BATCH_ID\",
      \"file_extension\": \".txt\"
    },
    \"id\": 3
  }")

echo "$BATCH_RESULT" | jq '.'

BATCH_TASK_ID=$(echo "$BATCH_RESULT" | jq -r '.result.batch_id')
TOTAL_DOCS=$(echo "$BATCH_RESULT" | jq -r '.result.total_documents')

echo ""
echo "Batch Task ID: $BATCH_TASK_ID"
echo "Total Documents: $TOTAL_DOCS"
```

**Expected Output:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "batch_id": "uuid",
    "total_documents": 5,
    "task_ids": ["uuid1", "uuid2", ...],
    "status": "processing",
    "message": "Batch processing started for 5 documents"
  }
}
```

**Success Criteria:**
- ✅ Returns batch_id
- ✅ total_documents matches uploaded count
- ✅ Returns array of task_ids

---

### Test 3.3: Monitor Batch Progress

**Purpose:** Check batch processing completion

```bash
echo "=== Test 3.3: Monitor Batch Progress ==="

echo "Waiting 60 seconds for batch processing..."
sleep 60

# Check pending documents
PENDING=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {"limit": 20},
    "id": 4
  }')

echo "$PENDING" | jq '.result | {count, documents: (.documents | length)}'

echo ""
echo "Documents still pending:"
echo "$PENDING" | jq -r '.result.documents[].s3_key' | grep "$BATCH_ID" || echo "  (none - all completed)"
```

**Success Criteria:**
- ✅ Pending count decreases over time
- ✅ Eventually all documents processed

---

## Scenario 4: Error Handling

### Test 4.1: Invalid S3 Key

**Purpose:** Verify error handling for nonexistent files

```bash
echo "=== Test 4.1: Test Invalid S3 Key ==="

ERROR_RESULT=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {
      "s3_key": "invalid/nonexistent-file-12345.txt"
    },
    "id": 5
  }')

echo "$ERROR_RESULT" | jq '.'

# Check if error or successful response with eventual failure
if echo "$ERROR_RESULT" | jq -e '.error' > /dev/null 2>&1; then
  echo "✓ API returned error (immediate validation)"
elif echo "$ERROR_RESULT" | jq -e '.result.task_id' > /dev/null 2>&1; then
  TASK_ID=$(echo "$ERROR_RESULT" | jq -r '.result.task_id')
  echo "  Task started: $TASK_ID"
  echo "  Waiting 20 seconds to check failure..."
  sleep 20
  
  # Check task status
  STATUS=$(curl -s -X POST $ALB_URL/message \
    -H "Content-Type: application/json" \
    -d "{
      \"jsonrpc\": \"2.0\",
      \"method\": \"get_task_status\",
      \"params\": {\"task_id\": \"$TASK_ID\"},
      \"id\": 6
    }")
  
  TASK_STATUS=$(echo "$STATUS" | jq -r '.result.status // "not_found"')
  if [ "$TASK_STATUS" == "failed" ]; then
    echo "✓ Task failed as expected"
    echo "Error: $(echo "$STATUS" | jq -r '.result.error')"
  else
    echo "⚠ Task status: $TASK_STATUS"
  fi
fi
```

**Success Criteria:**
- ✅ System handles error gracefully
- ✅ Returns error message or failed task status
- ✅ No system crash or timeout

---

### Test 4.2: Invalid Method

**Purpose:** Test API error handling for unknown methods

```bash
echo "=== Test 4.2: Test Invalid Method ==="

INVALID_METHOD=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "nonexistent_method_xyz",
    "params": {},
    "id": 7
  }')

echo "$INVALID_METHOD" | jq '.'

# Check for JSON-RPC error
ERROR_CODE=$(echo "$INVALID_METHOD" | jq -r '.error.code // "none"')

if [ "$ERROR_CODE" != "none" ]; then
  echo "✓ Returned JSON-RPC error"
  echo "Error code: $ERROR_CODE"
  echo "Message: $(echo "$INVALID_METHOD" | jq -r '.error.message')"
else
  echo "✗ Did not return proper error"
fi
```

**Expected Output:**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32601,
    "message": "Method not found: nonexistent_method_xyz"
  },
  "id": 7
}
```

**Success Criteria:**
- ✅ Returns JSON-RPC error
- ✅ Error code is -32601 (Method not found)
- ✅ Descriptive error message

---

### Test 4.3: Missing Required Parameters

**Purpose:** Test parameter validation

```bash
echo "=== Test 4.3: Test Missing Parameters ==="

MISSING_PARAMS=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {},
    "id": 8
  }')

echo "$MISSING_PARAMS" | jq '.'

ERROR_CODE=$(echo "$MISSING_PARAMS" | jq -r '.error.code // "none"')

if [ "$ERROR_CODE" == "-32602" ]; then
  echo "✓ Returned parameter validation error"
else
  echo "⚠ Error code: $ERROR_CODE (expected -32602)"
fi
```

**Success Criteria:**
- ✅ Returns error code -32602 (Invalid params)
- ✅ Error message indicates missing parameter

---

## Scenario 5: Agent Discovery

### Test 5.1: Discover Agents

**Purpose:** Trigger agent discovery and verify all agents found

```bash
echo "=== Test 5.1: Discover Agents ==="

DISCOVER_RESULT=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "discover_agents",
    "params": {},
    "id": 9
  }')

echo "$DISCOVER_RESULT" | jq '.result'

DISCOVERED=$(echo "$DISCOVER_RESULT" | jq -r '.result.discovered_agents')
TOTAL_SKILLS=$(echo "$DISCOVER_RESULT" | jq -r '.result.total_skills')

echo ""
echo "Discovered Agents: $DISCOVERED"
echo "Total Skills: $TOTAL_SKILLS"

if [ "$DISCOVERED" -eq "3" ]; then
  echo "✓ All agents discovered (Extractor, Validator, Archivist)"
else
  echo "⚠ Expected 3 agents, found $DISCOVERED"
fi
```

**Expected Output:**
```json
{
  "discovered_agents": 3,
  "total_skills": 17,
  "agents": [
    {
      "name": "Extractor",
      "endpoint": "http://...",
      "status": "active",
      "skills_count": 6
    },
    ...
  ],
  "discovery_timestamp": "2025-12-18T21:00:00"
}
```

**Success Criteria:**
- ✅ Discovers 3 agents
- ✅ Total skills >= 15
- ✅ All agents status "active"

---

### Test 5.2: Get Agent Registry

**Purpose:** Retrieve complete agent registry

```bash
echo "=== Test 5.2: Get Agent Registry ==="

REGISTRY=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "get_agent_registry",
    "params": {},
    "id": 10
  }')

echo "$REGISTRY" | jq '.result | {
  total_agents,
  active_agents,
  total_skills,
  agents: (.agents | keys)
}'

# List all available skills
echo ""
echo "Available Skills:"
echo "$REGISTRY" | jq -r '.result.available_skills[]' | sort
```

**Success Criteria:**
- ✅ Returns complete registry
- ✅ Lists all agents and their skills
- ✅ Shows available_skills array

---

## Scenario 6: Performance Testing

### Test 6.1: Response Time Test

**Purpose:** Measure API response times

```bash
echo "=== Test 6.1: Response Time Test ==="

TOTAL_TIME=0
MAX_TIME=0
MIN_TIME=999999

for i in {1..10}; do
  START=$(date +%s%N)
  curl -s -m 10 $ALB_URL/health > /dev/null
  END=$(date +%s%N)
  DURATION=$(( ($END - $START) / 1000000 ))
  
  echo "Request $i: ${DURATION}ms"
  
  TOTAL_TIME=$((TOTAL_TIME + DURATION))
  [ $DURATION -gt $MAX_TIME ] && MAX_TIME=$DURATION
  [ $DURATION -lt $MIN_TIME ] && MIN_TIME=$DURATION
done

AVG_TIME=$((TOTAL_TIME / 10))

echo ""
echo "Summary:"
echo "  Average: ${AVG_TIME}ms"
echo "  Min: ${MIN_TIME}ms"
echo "  Max: ${MAX_TIME}ms"

if [ $AVG_TIME -lt 200 ]; then
  echo "✓ Excellent performance (<200ms)"
elif [ $AVG_TIME -lt 500 ]; then
  echo "✓ Good performance (<500ms)"
elif [ $AVG_TIME -lt 1000 ]; then
  echo "⚠ Acceptable performance (<1000ms)"
else
  echo "✗ Poor performance (>1000ms)"
fi
```

**Success Criteria:**
- ✅ Average response time < 500ms
- ✅ No timeouts
- ✅ Consistent response times

---

### Test 6.2: Concurrent Requests

**Purpose:** Test system under concurrent load

```bash
echo "=== Test 6.2: Concurrent Requests ==="

# Run 5 concurrent requests
for i in {1..5}; do
  (
    START=$(date +%s%N)
    RESULT=$(curl -s -m 10 $ALB_URL/health)
    END=$(date +%s%N)
    DURATION=$(( ($END - $START) / 1000000 ))
    echo "Thread $i: ${DURATION}ms"
  ) &
done

# Wait for all to complete
wait

echo "✓ All concurrent requests completed"
```

**Success Criteria:**
- ✅ All requests complete successfully
- ✅ No significant performance degradation
- ✅ No errors under concurrent load

---

## Scenario 7: Database Verification

### Test 7.1: List Pending Documents

**Purpose:** Query database via API

```bash
echo "=== Test 7.1: List Pending Documents ==="

PENDING=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {"limit": 10},
    "id": 11
  }')

echo "$PENDING" | jq '.result'

DOC_COUNT=$(echo "$PENDING" | jq -r '.result.count')
echo ""
echo "Pending documents: $DOC_COUNT"

# Show details if any
if [ "$DOC_COUNT" -gt "0" ]; then
  echo ""
  echo "Document details:"
  echo "$PENDING" | jq -r '.result.documents[] | "\(.s3_key) - \(.status)"'
fi
```

**Success Criteria:**
- ✅ Returns document list
- ✅ Shows correct counts
- ✅ Includes document metadata

---

## Troubleshooting

### Issue: Task Status Returns Null

**Cause:** Task ID not found in memory (completed or failed tasks may be cleared)

**Solution:**
1. Check orchestrator logs for the task ID
2. Query database directly if needed
3. Tasks are stored in memory and may be cleared after completion

```bash
# Check logs for task
TASK_ID="your-task-id"
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "$TASK_ID" \
  --region $AWS_REGION \
  --query 'events[*].message' \
  --output text
```

---

### Issue: Document Not Processing

**Causes:**
1. S3 file permissions
2. Agent communication failure
3. Database connection issue

**Diagnosis:**
```bash
# Check all agent logs
for agent in orchestrator extractor validator archivist; do
  echo "=== $agent logs ==="
  aws logs tail /ecs/ca-a2a-$agent \
    --since 5m \
    --region $AWS_REGION \
    --format short | grep -i "error\|fail" | tail -10
done
```

---

### Issue: ALB Timeout

**Cause:** Network connectivity or agent unresponsive

**Solution:**
```bash
# Check target health
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region $AWS_REGION

# Restart orchestrator if needed
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --force-new-deployment \
  --region $AWS_REGION
```

---

## Summary Checklist

After completing all scenarios, verify:

- [ ] All health checks pass
- [ ] Single document processing works end-to-end
- [ ] Batch processing handles multiple documents
- [ ] Error handling works correctly
- [ ] Agent discovery finds all agents (3)
- [ ] Performance is acceptable (<500ms avg)
- [ ] Database queries work via API
- [ ] S3 documents move through pipeline
- [ ] Logs show no critical errors
- [ ] All ECS services running at desired count

---

**Testing Complete!** 🎉

For architecture details, see `SYSTEM_ARCHITECTURE.md`  
For API reference, see `API_QUICK_REFERENCE.md`

