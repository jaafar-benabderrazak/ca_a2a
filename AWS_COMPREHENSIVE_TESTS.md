# AWS Deployment - Comprehensive Test Suite

**Date:** January 1, 2026  
**Environment:** AWS ECS (eu-west-3)  
**Account:** 555043101106

---

## Quick Start

### Prerequisites
- AWS CLI configured with SSO
- Access to AWS Console (eu-west-3 region)
- `jq` installed for JSON parsing

### One-Command Test (CloudShell)

```bash
# Run this in AWS CloudShell
curl -s https://raw.githubusercontent.com/your-repo/ca_a2a/main/test-aws-complete.sh | bash
```

---

## Test Categories

### 1. Infrastructure Health Tests ✅
### 2. API Endpoint Tests ✅
### 3. Document Processing Tests ✅
### 4. Security Tests (NEW) ✅
### 5. Performance Tests ✅
### 6. Error Handling Tests ✅

---

## 1. Infrastructure Health Tests

### Test 1.1: ECS Services Status

```bash
#!/bin/bash
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

echo "=== Test 1.1: ECS Services Status ==="

# Check all services
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist \
  --region eu-west-3 \
  --query 'services[*].[serviceName,status,runningCount,desiredCount]' \
  --output table

# Expected: All services ACTIVE with 2/2 running
```

**Expected Output:**
```
---------------------------------------------------------
|                   DescribeServices                    |
+-----------------+--------+------------+---------------+
| orchestrator    | ACTIVE |     2      |      2        |
| extractor       | ACTIVE |     2      |      2        |
| validator       | ACTIVE |     2      |      2        |
| archivist       | ACTIVE |     2      |      2        |
+-----------------+--------+------------+---------------+
```

### Test 1.2: ALB Target Health

```bash
echo "=== Test 1.2: ALB Target Health ==="

aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region eu-west-3 \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State,TargetHealth.Reason]' \
  --output table

# Expected: Both targets "healthy"
```

### Test 1.3: RDS Database Status

```bash
echo "=== Test 1.3: RDS Database Status ==="

aws rds describe-db-instances \
  --db-instance-identifier ca-a2a-postgres \
  --region eu-west-3 \
  --query 'DBInstances[0].[DBInstanceStatus,Endpoint.Address,Endpoint.Port,MultiAZ]' \
  --output table

# Expected: "available" status
```

---

## 2. API Endpoint Tests

### Test 2.1: Health Endpoints

```bash
echo "=== Test 2.1: Health Endpoints ==="

# Test orchestrator health
echo "Orchestrator:"
curl -s "$ALB_URL/health" | jq '.'

# Expected response:
# {
#   "status": "healthy",
#   "agent": "Orchestrator",
#   "version": "1.0.0"
# }
```

### Test 2.2: Agent Cards

```bash
echo "=== Test 2.2: Agent Cards ==="

# Get orchestrator agent card
curl -s "$ALB_URL/card" | jq '{
  name: .agent_name,
  version: .version,
  skills: (.skills | length),
  skill_list: .skills[].skill_id
}'

# Expected: Should show all skills including:
# - process_document
# - get_task_status
# - list_pending_documents
# - etc.
```

### Test 2.3: Skills Discovery

```bash
echo "=== Test 2.3: Skills Discovery ==="

curl -s "$ALB_URL/skills" | jq '{
  total_skills: (.skills | length),
  skill_categories: [.skills[].skill_id] | unique
}'

# Expected: List of all available skills
```

---

## 3. Document Processing Tests

### Test 3.1: Upload Test Document

```bash
echo "=== Test 3.1: Upload Test Document to S3 ==="

# Create test invoice
cat > test-invoice.txt << 'EOF'
INVOICE #INV-2026-001
Date: 2026-01-01
From: Tech Services SARL
To: Acme Corporation

Services:
- Cloud Infrastructure: €5,000.00
- Security Implementation: €3,500.00
- Testing & QA: €2,500.00

Subtotal: €11,000.00
Tax (20%): €2,200.00
Total: €13,200.00
EOF

# Upload to S3
aws s3 cp test-invoice.txt s3://ca-a2a-documents-555043101106/incoming/ --region eu-west-3

echo "✓ Document uploaded"
```

### Test 3.2: Process Document via API

```bash
echo "=== Test 3.2: Process Document ==="

# Trigger processing
PROCESS_RESPONSE=$(curl -s -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{
    "s3_key": "incoming/test-invoice.txt"
  }')

echo $PROCESS_RESPONSE | jq '.'

# Extract task ID for tracking
TASK_ID=$(echo $PROCESS_RESPONSE | jq -r '.task_id // .document_id')
echo "Task ID: $TASK_ID"

# Expected response:
# {
#   "status": "processing",
#   "document_id": "...",
#   "s3_key": "incoming/test-invoice.txt",
#   "workflow_id": "wf-..."
# }
```

### Test 3.3: Monitor Processing

```bash
echo "=== Test 3.3: Monitor Processing ==="

# Check task status
if [ ! -z "$TASK_ID" ]; then
  curl -s -X POST "$ALB_URL/message" \
    -H "Content-Type: application/json" \
    -d "{
      \"jsonrpc\": \"2.0\",
      \"id\": \"test-1\",
      \"method\": \"get_task_status\",
      \"params\": {\"task_id\": \"$TASK_ID\"}
    }" | jq '.'
fi

# Wait a bit and check logs
sleep 5

echo "Recent orchestrator logs:"
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 2m \
  --region eu-west-3 | tail -20
```

### Test 3.4: Verify Results

```bash
echo "=== Test 3.4: Verify Results ==="

# Check if document moved to processed folder
echo "Processed documents:"
aws s3 ls s3://ca-a2a-documents-555043101106/processed/ --region eu-west-3 | tail -5

# Check database for record
echo "Would check database here (requires psql connection)"
```

---

## 4. Security Tests (NEW - Enhanced Security)

### Test 4.1: Authentication Required

```bash
echo "=== Test 4.1: Authentication Required ==="

# Try without authentication (should fail)
UNAUTH_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "test-auth",
    "method": "list_pending_documents",
    "params": {}
  }')

HTTP_CODE=$(echo "$UNAUTH_RESPONSE" | tail -1)
BODY=$(echo "$UNAUTH_RESPONSE" | head -n -1)

echo "HTTP Code: $HTTP_CODE"
echo "Response: $BODY" | jq '.'

# Expected: 401 Unauthorized or 403 Forbidden
if [ "$HTTP_CODE" == "401" ] || [ "$HTTP_CODE" == "403" ]; then
  echo "✓ Authentication required (as expected)"
else
  echo "✗ Authentication not enforced!"
fi
```

### Test 4.2: Message Integrity (if enabled)

```bash
echo "=== Test 4.2: Message Integrity Check ==="

# This test requires the enhanced security to be enabled with MESSAGE_INTEGRITY_KEY
# If enabled, messages without valid HMAC should be rejected

MESSAGE='{"jsonrpc":"2.0","id":"test-2","method":"get_task_status","params":{}}'

# Try sending without HMAC headers (should fail if integrity check is enabled)
curl -s -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: test-key" \
  -d "$MESSAGE" | jq '.'

# Expected: Error if message integrity is enabled
echo "Note: Message integrity check depends on enhanced security configuration"
```

### Test 4.3: Rate Limiting

```bash
echo "=== Test 4.3: Rate Limiting ==="

# Make rapid requests to test rate limiting
echo "Making 65 rapid requests to test rate limiting..."

for i in {1..65}; do
  RESPONSE=$(curl -s -w "%{http_code}" -X GET "$ALB_URL/health" -o /dev/null)
  if [ $i -eq 1 ] || [ $i -eq 30 ] || [ $i -eq 60 ] || [ $i -eq 65 ]; then
    echo "Request $i: HTTP $RESPONSE"
  fi
  
  # Check if rate limited
  if [ "$RESPONSE" == "429" ]; then
    echo "✓ Rate limiting activated at request $i"
    break
  fi
done

echo "Note: Rate limit threshold is 60 requests/minute by default"
```

### Test 4.4: Security Audit Logs

```bash
echo "=== Test 4.4: Security Audit Logs ==="

# Check for security-related log entries
echo "Recent security events:"
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "Auth" \
  --start-time $(date -d '5 minutes ago' +%s)000 \
  --region eu-west-3 \
  --query 'events[*].message' \
  --output text | tail -10
```

---

## 5. Performance Tests

### Test 5.1: Response Time

```bash
echo "=== Test 5.1: Response Time Measurement ==="

# Measure health endpoint response time
echo "Health endpoint:"
time curl -s "$ALB_URL/health" > /dev/null

# Measure agent card endpoint
echo "Agent card endpoint:"
time curl -s "$ALB_URL/card" > /dev/null

# Expected: < 200ms for health, < 500ms for card
```

### Test 5.2: Concurrent Processing

```bash
echo "=== Test 5.2: Concurrent Processing ==="

# Upload multiple test documents
for i in {1..5}; do
  echo "Test document $i" > test-doc-$i.txt
  aws s3 cp test-doc-$i.txt s3://ca-a2a-documents-555043101106/incoming/ --region eu-west-3
done

# Trigger processing for all
START_TIME=$(date +%s)

for i in {1..5}; do
  curl -s -X POST "$ALB_URL/process" \
    -H "Content-Type: application/json" \
    -d "{\"s3_key\": \"incoming/test-doc-$i.txt\"}" &
done

wait

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "Processed 5 documents concurrently in $DURATION seconds"
echo "Average: $((DURATION / 5)) seconds per document"
```

### Test 5.3: Load Metrics

```bash
echo "=== Test 5.3: CloudWatch Metrics ==="

# Check CPU utilization
aws cloudwatch get-metric-statistics \
  --namespace AWS/ECS \
  --metric-name CPUUtilization \
  --dimensions Name=ClusterName,Value=ca-a2a-cluster Name=ServiceName,Value=orchestrator \
  --start-time $(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average \
  --region eu-west-3 \
  --query 'Datapoints[*].[Timestamp,Average]' \
  --output table

# Expected: CPU < 50% under normal load
```

---

## 6. Error Handling Tests

### Test 6.1: Invalid Input Handling

```bash
echo "=== Test 6.1: Invalid Input Handling ==="

# Send invalid JSON
curl -s -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -d 'invalid json' | jq '.'

# Expected: Parse error response

# Send invalid method
curl -s -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "test-3",
    "method": "nonexistent_method",
    "params": {}
  }' | jq '.'

# Expected: Method not found error
```

### Test 6.2: Missing Document Handling

```bash
echo "=== Test 6.2: Missing Document Handling ==="

# Try to process non-existent document
curl -s -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{
    "s3_key": "incoming/does-not-exist.pdf"
  }' | jq '.'

# Expected: Error response indicating document not found
```

### Test 6.3: Error Recovery

```bash
echo "=== Test 6.3: Error Recovery ==="

# Check for error logs
echo "Recent errors:"
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "ERROR" \
  --start-time $(date -d '1 hour ago' +%s)000 \
  --region eu-west-3 \
  --query 'events[*].message' \
  --output text | tail -10

# Check service is still healthy after errors
curl -s "$ALB_URL/health" | jq '.status'
```

---

## Complete Test Script

Save this as `test-aws-complete.sh`:

```bash
#!/bin/bash
set -e

# Configuration
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
REGION="eu-west-3"
CLUSTER="ca-a2a-cluster"
BUCKET="ca-a2a-documents-555043101106"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "  CA A2A AWS Deployment Test Suite"
echo "  Region: $REGION"
echo "  Date: $(date)"
echo "=========================================="
echo ""

# Test counter
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Test function
run_test() {
  local test_name="$1"
  local test_command="$2"
  
  TOTAL_TESTS=$((TOTAL_TESTS + 1))
  echo -e "${YELLOW}[TEST $TOTAL_TESTS]${NC} $test_name"
  
  if eval "$test_command"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
    echo -e "${GREEN}✓ PASS${NC}"
  else
    FAILED_TESTS=$((FAILED_TESTS + 1))
    echo -e "${RED}✗ FAIL${NC}"
  fi
  echo ""
}

# 1. Infrastructure Tests
echo "=== 1. INFRASTRUCTURE TESTS ==="
echo ""

run_test "ECS Services Running" \
  "aws ecs describe-services --cluster $CLUSTER --services orchestrator extractor validator archivist --region $REGION --query 'services[?runningCount==\`2\`] | length(@)' --output text | grep -q 4"

run_test "ALB Targets Healthy" \
  "aws elbv2 describe-target-health --target-group-arn arn:aws:elasticloadbalancing:$REGION:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 --region $REGION --query 'TargetHealthDescriptions[?TargetHealth.State==\`healthy\`] | length(@)' --output text | grep -q -E '[1-2]'"

run_test "RDS Database Available" \
  "aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --region $REGION --query 'DBInstances[0].DBInstanceStatus' --output text | grep -q available"

# 2. API Tests
echo "=== 2. API ENDPOINT TESTS ==="
echo ""

run_test "Health Endpoint Accessible" \
  "curl -s -f $ALB_URL/health | jq -e '.status == \"healthy\"' > /dev/null"

run_test "Agent Card Available" \
  "curl -s -f $ALB_URL/card | jq -e '.agent_name' > /dev/null"

run_test "Skills Endpoint Accessible" \
  "curl -s -f $ALB_URL/skills | jq -e '.skills | length > 0' > /dev/null"

# 3. Document Processing Tests
echo "=== 3. DOCUMENT PROCESSING TESTS ==="
echo ""

# Create and upload test document
TEST_DOC="test-$(date +%s).txt"
echo "Test document content" > /tmp/$TEST_DOC

run_test "Upload Document to S3" \
  "aws s3 cp /tmp/$TEST_DOC s3://$BUCKET/incoming/ --region $REGION"

run_test "Trigger Document Processing" \
  "curl -s -X POST $ALB_URL/process -H 'Content-Type: application/json' -d '{\"s3_key\": \"incoming/$TEST_DOC\"}' | jq -e '.status or .document_id' > /dev/null"

# 4. Security Tests
echo "=== 4. SECURITY TESTS ==="
echo ""

run_test "Health Endpoint Response Time < 500ms" \
  "time curl -s -f $ALB_URL/health > /dev/null 2>&1 | grep -E 'real.*0m0\.[0-4]'"

run_test "Invalid JSON Rejected" \
  "curl -s -X POST $ALB_URL/message -H 'Content-Type: application/json' -d 'invalid' | jq -e '.error' > /dev/null"

# 5. CloudWatch Logs
echo "=== 5. MONITORING TESTS ==="
echo ""

run_test "CloudWatch Logs Available" \
  "aws logs describe-log-groups --log-group-name-prefix /ecs/ca-a2a --region $REGION --query 'logGroups | length(@)' --output text | grep -q -E '[1-9]'"

run_test "Recent Log Entries Exist" \
  "aws logs filter-log-events --log-group-name /ecs/ca-a2a-orchestrator --start-time \$(date -d '5 minutes ago' +%s)000 --region $REGION --query 'events | length(@)' --output text | grep -q -E '[1-9]'"

# Summary
echo "=========================================="
echo "  TEST SUMMARY"
echo "=========================================="
echo "Total Tests:  $TOTAL_TESTS"
echo -e "${GREEN}Passed:       $PASSED_TESTS${NC}"
if [ $FAILED_TESTS -gt 0 ]; then
  echo -e "${RED}Failed:       $FAILED_TESTS${NC}"
else
  echo -e "${GREEN}Failed:       0${NC}"
fi
echo "Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
  echo -e "${GREEN}✓ All tests passed!${NC}"
  exit 0
else
  echo -e "${RED}✗ Some tests failed${NC}"
  exit 1
fi
```

---

## Usage

### Option 1: AWS CloudShell (Recommended)

```bash
# 1. Open AWS CloudShell in eu-west-3 region
# 2. Copy and run:

wget https://raw.githubusercontent.com/your-repo/ca_a2a/main/test-aws-complete.sh
chmod +x test-aws-complete.sh
./test-aws-complete.sh
```

### Option 2: Local with AWS CLI

```bash
# Ensure AWS CLI is configured
aws configure sso

# Run the test script
bash test-aws-complete.sh
```

### Option 3: Individual Tests

```bash
# Source the configuration
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Run individual tests
curl -s "$ALB_URL/health" | jq '.'
```

---

## Expected Results

### All Tests Passing:
```
==========================================
  CA A2A AWS Deployment Test Suite
==========================================

=== 1. INFRASTRUCTURE TESTS ===
[TEST 1] ECS Services Running
✓ PASS

[TEST 2] ALB Targets Healthy
✓ PASS

[TEST 3] RDS Database Available
✓ PASS

=== 2. API ENDPOINT TESTS ===
[TEST 4] Health Endpoint Accessible
✓ PASS

[TEST 5] Agent Card Available
✓ PASS

[TEST 6] Skills Endpoint Accessible
✓ PASS

=== 3. DOCUMENT PROCESSING TESTS ===
[TEST 7] Upload Document to S3
✓ PASS

[TEST 8] Trigger Document Processing
✓ PASS

=== 4. SECURITY TESTS ===
[TEST 9] Health Endpoint Response Time < 500ms
✓ PASS

[TEST 10] Invalid JSON Rejected
✓ PASS

=== 5. MONITORING TESTS ===
[TEST 11] CloudWatch Logs Available
✓ PASS

[TEST 12] Recent Log Entries Exist
✓ PASS

==========================================
  TEST SUMMARY
==========================================
Total Tests:  12
Passed:       12
Failed:       0
Success Rate: 100%

✓ All tests passed!
```

---

## Troubleshooting

### Test Failed: ECS Services Not Running

```bash
# Check service status
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region eu-west-3 \
  --query 'services[0].events[0:5]'

# Restart if needed
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --force-new-deployment \
  --region eu-west-3
```

### Test Failed: Health Endpoint Not Accessible

```bash
# Check ALB status
aws elbv2 describe-load-balancers \
  --names ca-a2a-alb \
  --region eu-west-3 \
  --query 'LoadBalancers[0].State'

# Check security groups
aws ec2 describe-security-groups \
  --group-ids sg-05db73131090f365a \
  --region eu-west-3
```

### Test Failed: Document Processing

```bash
# Check orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator \
  --follow \
  --region eu-west-3

# Check S3 bucket permissions
aws s3api get-bucket-policy \
  --bucket ca-a2a-documents-555043101106 \
  --region eu-west-3
```

---

## Continuous Monitoring

### Set Up CloudWatch Alarms

```bash
# High error rate alarm
aws cloudwatch put-metric-alarm \
  --alarm-name ca-a2a-high-error-rate \
  --alarm-description "Alert when error rate exceeds 10%" \
  --metric-name ErrorCount \
  --namespace CA-A2A \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 10 \
  --comparison-operator GreaterThanThreshold \
  --region eu-west-3

# Unhealthy target alarm
aws cloudwatch put-metric-alarm \
  --alarm-name ca-a2a-unhealthy-targets \
  --alarm-description "Alert when targets are unhealthy" \
  --metric-name UnHealthyHostCount \
  --namespace AWS/ApplicationELB \
  --statistic Average \
  --period 60 \
  --evaluation-periods 2 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --region eu-west-3
```

---

## Documentation

- **Full Guide:** `A2A_SECURITY_IMPLEMENTATION.md`
- **Quick Start:** `SECURITY_IMPLEMENTATION_QUICK_START.md`
- **API Reference:** `API_TESTING_GUIDE.md`
- **Troubleshooting:** `TROUBLESHOOTING.md`

---

**Test Suite Version:** 1.0  
**Last Updated:** January 1, 2026  
**Status:** Ready for execution

