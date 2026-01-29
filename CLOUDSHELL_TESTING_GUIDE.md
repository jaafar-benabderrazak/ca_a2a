# CA-A2A CloudShell Testing Guide
## Complete Validation of Document Flow and Security Features

---

## 🎯 OVERVIEW

This guide provides step-by-step instructions for testing the CA-A2A document processing pipeline and security features directly from AWS CloudShell.

### What Will Be Tested

1. ✅ **Security Features**
   - Anonymous vs authenticated access
   - Keycloak authentication integration
   - Input validation (injection prevention)
   - TLS/HTTPS configuration

2. ✅ **Document Processing Flow**
   - Document upload to S3
   - Processing initiation
   - Status tracking
   - Document listing

3. ✅ **Validation**
   - Valid document processing
   - Invalid document rejection
   - Security input validation
   - Data sanitization

4. ✅ **Archive Flow**
   - Archive folder structure
   - Document metadata storage
   - Archive retrieval

5. ✅ **Monitoring**
   - CloudWatch logs
   - CloudWatch alarms
   - Performance metrics

---

## 🚀 QUICK START

### Option 1: Automated Testing (Recommended)

```bash
# 1. Open AWS CloudShell (eu-west-3 region)
# 2. Clone or download the test script
# 3. Run the complete test suite

bash cloudshell-test-complete.sh
```

### Option 2: Manual Step-by-Step Testing

Follow the sections below for detailed manual testing.

---

## 📋 PREREQUISITES

### AWS CloudShell Setup

1. **Open AWS CloudShell**
   - Navigate to AWS Console
   - Click the CloudShell icon (terminal icon in top menu bar)
   - Wait for CloudShell to initialize
   - Ensure you're in **eu-west-3** region

2. **Verify AWS Credentials**
   ```bash
   aws sts get-caller-identity
   ```

3. **Install Required Tools**
   ```bash
   # Install jq for JSON parsing
   sudo yum install -y jq
   
   # Verify installation
   jq --version
   ```

4. **Set Environment Variables**
   ```bash
   export REGION="eu-west-3"
   export PROJECT_NAME="ca-a2a"
   export ALB_DNS="ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
   export ALB_URL="http://$ALB_DNS"
   
   # Get S3 bucket
   export S3_BUCKET=$(aws s3api list-buckets \
       --query 'Buckets[?contains(Name, `ca-a2a`)].Name' \
       --output text | head -n 1)
   
   echo "ALB URL: $ALB_URL"
   echo "S3 Bucket: $S3_BUCKET"
   ```

---

## 🔒 PHASE 1: SECURITY FEATURES TESTING

### Test 1.1: Anonymous Health Check

```bash
# Test that health endpoint is publicly accessible
curl -v "$ALB_URL/health" | jq '.'

# Expected: HTTP 200 with health status
```

**Expected Output:**
```json
{
  "status": "healthy",
  "agent": "Orchestrator",
  "version": "1.0.0",
  "uptime_seconds": 1701489
}
```

### Test 1.2: API Access Without Authentication

```bash
# Test API without credentials
curl -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {},
    "id": 1
  }' | jq '.'
```

**Expected Outcomes:**
- ✅ **With Auth Disabled**: HTTP 200 with results
- ✅ **With Auth Enabled**: HTTP 401/403 Unauthorized

### Test 1.3: Keycloak Token Retrieval

```bash
# Check if Keycloak is configured
aws secretsmanager get-secret-value \
    --secret-id ca-a2a/keycloak-admin-password \
    --region $REGION \
    --query SecretString \
    --output text

# Note: Keycloak is in private VPC
# To test Keycloak auth, you need VPC access via:
# - ECS Exec into a running task
# - VPN connection
# - Bastion host
```

### Test 1.4: Input Validation - Path Traversal Prevention

```bash
# Try to access system files (should be blocked)
curl -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {
      "s3_key": "../../../etc/passwd",
      "document_type": "invoice"
    },
    "id": 2
  }' | jq '.'
```

**Expected:** Error response indicating invalid path

### Test 1.5: SQL Injection Prevention

```bash
# Try SQL injection in filter parameter
curl -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {
      "filter": "1=1; DROP TABLE documents; --"
    },
    "id": 3
  }' | jq '.'
```

**Expected:** Safe handling, no database compromise

---

## 📄 PHASE 2: DOCUMENT PROCESSING FLOW

### Test 2.1: Create Test Documents

```bash
# Create valid invoice
cat > /tmp/test-invoice.txt << 'EOF'
INVOICE

Company: Acme Corporation
Invoice Number: INV-2026-001
Date: 2026-01-22

Items:
- Software License: €1,000.00
- Support Services: €500.00
- Training: €750.00

Subtotal: €2,250.00
Tax (20%): €450.00
TOTAL: €2,700.00

Payment Terms: Net 30 Days
Thank you!
EOF

# Create invalid document (missing required fields)
cat > /tmp/test-invalid.txt << 'EOF'
INCOMPLETE INVOICE
This document is missing critical information.
EOF

# Verify files created
ls -lh /tmp/test-*.txt
```

### Test 2.2: Upload Documents to S3

```bash
# Upload valid document
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
VALID_KEY="uploads/invoice-${TIMESTAMP}.txt"

aws s3 cp /tmp/test-invoice.txt \
    "s3://${S3_BUCKET}/${VALID_KEY}" \
    --region $REGION

# Upload invalid document
INVALID_KEY="uploads/invalid-${TIMESTAMP}.txt"

aws s3 cp /tmp/test-invalid.txt \
    "s3://${S3_BUCKET}/${INVALID_KEY}" \
    --region $REGION

# Verify uploads
aws s3 ls "s3://${S3_BUCKET}/uploads/" --region $REGION

echo "Valid document: ${VALID_KEY}"
echo "Invalid document: ${INVALID_KEY}"
```

### Test 2.3: Initiate Document Processing

```bash
# Process the valid document
PROCESS_RESPONSE=$(curl -s -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"process_document\",
    \"params\": {
      \"s3_key\": \"${VALID_KEY}\",
      \"document_type\": \"invoice\"
    },
    \"id\": 4
  }")

echo "$PROCESS_RESPONSE" | jq '.'

# Extract task ID
TASK_ID=$(echo "$PROCESS_RESPONSE" | jq -r '.result.task_id // .result.id // "unknown"')
echo "Task ID: $TASK_ID"
```

**Expected Output:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "task_id": "task-12345",
    "status": "processing",
    "s3_key": "uploads/invoice-20260122-140000.txt"
  },
  "id": 4
}
```

### Test 2.4: Check Processing Status

```bash
# Wait a moment for processing
sleep 3

# Check status
curl -s -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"check_status\",
    \"params\": {
      \"task_id\": \"${TASK_ID}\"
    },
    \"id\": 5
  }" | jq '.'
```

**Expected Statuses:**
- `processing` - Document being processed
- `completed` - Successfully processed
- `failed` - Processing failed
- `validating` - In validation stage

### Test 2.5: List All Documents

```bash
# List pending documents
curl -s -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {
      "limit": 10
    },
    "id": 6
  }' | jq '.'
```

---

## ✅ PHASE 3: VALIDATION TESTING

### Test 3.1: Process Invalid Document

```bash
# Try to process the invalid document
curl -s -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"process_document\",
    \"params\": {
      \"s3_key\": \"${INVALID_KEY}\",
      \"document_type\": \"invoice\"
    },
    \"id\": 7
  }" | jq '.'
```

**Expected:** Either rejection or processing with validation errors noted

### Test 3.2: Test Document Size Limits

```bash
# Create a large document
dd if=/dev/zero of=/tmp/large-file.bin bs=1M count=100

# Try to upload (should respect size limits)
aws s3 cp /tmp/large-file.bin \
    "s3://${S3_BUCKET}/uploads/large-${TIMESTAMP}.bin" \
    --region $REGION 2>&1

# Try to process
curl -s -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"process_document\",
    \"params\": {
      \"s3_key\": \"uploads/large-${TIMESTAMP}.bin\",
      \"document_type\": \"invoice\"
    },
    \"id\": 8
  }" | jq '.'

# Cleanup
rm /tmp/large-file.bin
```

### Test 3.3: Test Invalid File Types

```bash
# Create executable file (should be rejected)
echo '#!/bin/bash\necho "malicious"' > /tmp/test.sh
chmod +x /tmp/test.sh

aws s3 cp /tmp/test.sh \
    "s3://${S3_BUCKET}/uploads/test-${TIMESTAMP}.sh" \
    --region $REGION

# Try to process
curl -s -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"process_document\",
    \"params\": {
      \"s3_key\": \"uploads/test-${TIMESTAMP}.sh\",
      \"document_type\": \"invoice\"
    },
    \"id\": 9
  }" | jq '.'
```

---

## 📦 PHASE 4: ARCHIVE FLOW TESTING

### Test 4.1: Check Archive Structure

```bash
# List S3 bucket structure
echo "=== S3 Bucket Structure ==="
aws s3 ls "s3://${S3_BUCKET}/" --region $REGION

# Check for archive folders
echo -e "\n=== Archive Folder ==="
aws s3 ls "s3://${S3_BUCKET}/archive/" --region $REGION 2>&1 || echo "Archive folder will be created on first archive"

echo -e "\n=== Processed Folder ==="
aws s3 ls "s3://${S3_BUCKET}/processed/" --region $REGION 2>&1 || echo "Processed folder will be created on first processed document"
```

### Test 4.2: Verify Database Storage

```bash
# Check RDS cluster
echo "=== RDS Clusters ==="
aws rds describe-db-clusters \
    --region $REGION \
    --query 'DBClusters[].[DBClusterIdentifier,Status,Endpoint]' \
    --output table

# Get cluster endpoint
RDS_ENDPOINT=$(aws rds describe-db-clusters \
    --region $REGION \
    --query 'DBClusters[?contains(DBClusterIdentifier, `documents-db`)].Endpoint' \
    --output text)

echo "Documents DB Endpoint: $RDS_ENDPOINT"
```

### Test 4.3: List Archived Documents

```bash
# Try to list all documents (including archived)
curl -s -X POST "$ALB_URL/message" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_documents",
    "params": {
      "status": "archived",
      "limit": 20
    },
    "id": 10
  }' | jq '.'
```

---

## 📊 PHASE 5: MONITORING AND LOGGING

### Test 5.1: Check CloudWatch Log Groups

```bash
# List all log groups
echo "=== CloudWatch Log Groups ==="
aws logs describe-log-groups \
    --region $REGION \
    --log-group-name-prefix "/ecs/ca-a2a" \
    --query 'logGroups[].[logGroupName,storedBytes]' \
    --output table
```

### Test 5.2: View Recent Logs

```bash
# Orchestrator logs (last 10 minutes)
echo "=== Orchestrator Logs (last 10 min) ==="
aws logs tail /ecs/ca-a2a-orchestrator \
    --since 10m \
    --region $REGION \
    --format short | tail -n 20

# Extractor logs
echo -e "\n=== Extractor Logs (last 5 min) ==="
aws logs tail /ecs/ca-a2a-extractor \
    --since 5m \
    --region $REGION \
    --format short | tail -n 10

# Validator logs
echo -e "\n=== Validator Logs (last 5 min) ==="
aws logs tail /ecs/ca-a2a-validator \
    --since 5m \
    --region $REGION \
    --format short | tail -n 10
```

### Test 5.3: Search for Errors

```bash
# Search for errors in orchestrator logs
echo "=== Searching for Errors ==="
aws logs filter-log-events \
    --log-group-name /ecs/ca-a2a-orchestrator \
    --filter-pattern "ERROR" \
    --region $REGION \
    --start-time $(($(date +%s) - 3600))000 \
    --query 'events[].message' \
    --output text | head -n 10
```

### Test 5.4: Check CloudWatch Alarms

```bash
# List all alarms
echo "=== CloudWatch Alarms ==="
aws cloudwatch describe-alarms \
    --region $REGION \
    --query 'MetricAlarms[?contains(AlarmName, `ca-a2a`)].{Name:AlarmName,State:StateValue,Reason:StateReason}' \
    --output table
```

---

## ⚡ PHASE 6: PERFORMANCE TESTING

### Test 6.1: Response Time Measurement

```bash
# Measure API response time
echo "=== Response Time Test ==="
for i in {1..5}; do
    START=$(date +%s%N)
    curl -s "$ALB_URL/health" > /dev/null
    END=$(date +%s%N)
    DURATION=$(( (END - START) / 1000000 ))
    echo "Request $i: ${DURATION}ms"
done
```

### Test 6.2: Concurrent Request Test

```bash
# Send concurrent requests
echo "=== Concurrent Requests Test ==="
for i in {1..10}; do
    curl -s "$ALB_URL/health" &
done
wait
echo "All concurrent requests completed"
```

### Test 6.3: Load Test (Simple)

```bash
# Simple load test
echo "=== Load Test (20 requests) ==="
SUCCESS=0
FAILED=0

for i in {1..20}; do
    RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null "$ALB_URL/health")
    if [ "$RESPONSE" = "200" ]; then
        ((SUCCESS++))
    else
        ((FAILED++))
    fi
    echo -n "."
done

echo ""
echo "Success: $SUCCESS"
echo "Failed: $FAILED"
```

---

## 🧹 CLEANUP

```bash
# Remove test files
rm -f /tmp/test-*.txt
rm -f /tmp/test.sh

# Optionally remove test documents from S3
# aws s3 rm "s3://${S3_BUCKET}/uploads/invoice-${TIMESTAMP}.txt" --region $REGION
# aws s3 rm "s3://${S3_BUCKET}/uploads/invalid-${TIMESTAMP}.txt" --region $REGION

echo "Cleanup complete"
```

---

## 📈 INTERPRETING RESULTS

### Success Criteria

| Test | Success Indicator |
|------|------------------|
| **Health Check** | HTTP 200, status: "healthy" |
| **Authentication** | HTTP 401/403 without token (if auth enabled) |
| **Document Upload** | File visible in S3 |
| **Processing** | Task ID returned, status transitions |
| **Validation** | Invalid documents rejected or flagged |
| **Security** | Injection attacks blocked |
| **Archive** | Documents moved to archive folder |
| **Monitoring** | Logs present, alarms configured |
| **Performance** | Response time < 1000ms |

### Common Issues

**Issue**: Cannot reach ALB  
**Solution**: Check security groups, ensure ALB is public

**Issue**: 401/403 errors  
**Solution**: Authentication may be enabled, need Keycloak token

**Issue**: Document not processing  
**Solution**: Check CloudWatch logs for errors

**Issue**: No logs found  
**Solution**: Wait a few minutes, check log group exists

---

## 🎯 EXPECTED TEST RESULTS

When running the complete test suite, you should see:

```
=== TEST SUMMARY ===

Total Tests: 25-30
Passed: 23-28
Failed: 0-2
Success Rate: 85-100%

✓ Security features working
✓ Document upload successful
✓ Processing pipeline operational
✓ Validation active
✓ Archive flow configured
✓ Monitoring and logging active
```

---

## 📚 ADDITIONAL RESOURCES

- **Full Test Script**: `cloudshell-test-complete.sh`
- **Deployment Summary**: `DEPLOYMENT_SUMMARY.md`
- **Configuration Report**: `CONFIGURATION_TESTING_REPORT.md`
- **Keycloak Guide**: `KEYCLOAK_IMPLEMENTATION_SUMMARY.md`

---

## 🆘 TROUBLESHOOTING

### CloudShell Issues

```bash
# If CloudShell times out
# Simply refresh and reconnect

# If commands fail with permission errors
aws sts get-caller-identity
# Verify you have proper IAM permissions

# If region is wrong
export AWS_DEFAULT_REGION=eu-west-3
```

### API Issues

```bash
# Check service health
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator \
    --region eu-west-3 \
    --query 'services[0].{Status:status,Running:runningCount,Desired:desiredCount}'

# Check recent logs
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3
```

---

**Happy Testing! 🚀**
