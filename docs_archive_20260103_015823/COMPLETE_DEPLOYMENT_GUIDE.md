# Complete Deployment Guide - Archivist Fix + S3 Event Pipeline

**Date:** 2026-01-02  
**Environment:** AWS CloudShell (eu-west-3)

---

## 📋 Overview

This guide covers two deployments:
1. **Archivist Fix** - Add MCP_SERVER_URL and deploy updated image (~3 minutes)
2. **S3 Event Pipeline** - Automated document processing (~5 minutes)

---

## 🚀 Part 1: Deploy Archivist Fix

### Upload and Run Script

```bash
# In CloudShell:
chmod +x deploy-archivist-fix.sh
./deploy-archivist-fix.sh
```

### Expected Output:

```
Step 1: Registering new task definition with MCP_SERVER_URL...
✓ New task definition registered: revision X

Step 2: Updating service to use new task definition...
| serviceName | taskDefinition           | desiredCount | runningCount |
| archivist   | ca-a2a-archivist:X       | 2            | 2            |

Step 3: Waiting 45 seconds for new tasks to start...
...

Step 6: Recent archivist logs:
Using MCP HTTP client: http://mcp-server.ca-a2a.local:8000
Schema initialization timed out - continuing...
Archivist initialized

✓ ARCHIVIST DEPLOYMENT COMPLETE
```

### Verification:

```bash
# Check service is healthy
aws ecs describe-services --cluster ca-a2a-cluster --services archivist \
  --region eu-west-3 --query 'services[0].[desiredCount,runningCount]'
# Expected: [2, 2]

# Check logs for MCP HTTP client
aws logs tail /ecs/ca-a2a-archivist --since 5m --region eu-west-3 | grep "MCP HTTP"
# Expected: "Using MCP HTTP client: http://mcp-server.ca-a2a.local:8000"
```

---

## 🚀 Part 2: Setup S3 Event Pipeline

### Upload and Run Script

```bash
# In CloudShell:
chmod +x setup-s3-event-pipeline.sh
./setup-s3-event-pipeline.sh
```

### What This Creates:

1. **SQS Queue:** `ca-a2a-document-uploads`
   - Receives S3 events
   - Triggers Lambda function

2. **S3 Event Notification:**
   - Trigger: `s3:ObjectCreated:*`
   - Filter: `invoices/*.pdf`
   - Target: SQS queue

3. **Lambda Function:** `ca-a2a-s3-processor`
   - Runtime: Python 3.11
   - VPC: Same as ECS tasks (can reach orchestrator)
   - Trigger: SQS messages
   - Action: Calls orchestrator API

4. **IAM Role:** `ca-a2a-lambda-s3-processor-role`
   - Lambda execution permissions
   - VPC access
   - SQS read/write
   - S3 read access

### Expected Output:

```
Step 1: Creating SQS queue...
✓ SQS Queue created: https://sqs.eu-west-3.amazonaws.com/555043101106/ca-a2a-document-uploads

Step 2: Setting SQS policy...
✓ SQS policy updated

Step 3: Configuring S3 bucket...
✓ S3 event notification configured
  Trigger: s3:ObjectCreated:* for invoices/*.pdf

Step 4: Creating Lambda execution role...
✓ Lambda role ready

Step 5: Creating Lambda function code...
✓ Lambda function code packaged

Step 6: Getting VPC configuration...
✓ VPC Configuration found

Step 7: Creating Lambda function...
✓ Lambda function ready

Step 8: Configuring SQS trigger...
✓ Lambda trigger configured

Step 9: Testing the pipeline...
✓ Test file uploaded
(Processing logs will appear)

✓ S3 EVENT PIPELINE SETUP COMPLETE
```

### Verification:

```bash
# 1. Check SQS queue exists
aws sqs list-queues --region eu-west-3 | grep ca-a2a-document-uploads

# 2. Check Lambda function
aws lambda get-function --function-name ca-a2a-s3-processor --region eu-west-3

# 3. Check S3 notification
aws s3api get-bucket-notification-configuration \
  --bucket ca-a2a-documents-555043101106 --region eu-west-3

# 4. Test by uploading a file
aws s3 cp facture_acme_dec2025.pdf \
  s3://ca-a2a-documents-555043101106/invoices/2026/01/test_auto_$(date +%s).pdf \
  --region eu-west-3

# 5. Watch Lambda logs
aws logs tail /aws/lambda/ca-a2a-s3-processor --follow --region eu-west-3

# 6. Watch orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3 | grep process_document
```

---

## 🧪 Testing the Complete System

### Test 1: Upload New Invoice

```bash
# Create a test invoice
echo "Test Invoice $(date)" > test_invoice.pdf

# Upload to S3 (this will trigger the pipeline)
aws s3 cp test_invoice.pdf \
  s3://ca-a2a-documents-555043101106/invoices/2026/01/test_invoice_$(date +%s).pdf \
  --region eu-west-3

# Wait 10 seconds
sleep 10

# Check Lambda processed it
aws logs tail /aws/lambda/ca-a2a-s3-processor --since 1m --region eu-west-3

# Check orchestrator received it
aws logs tail /ecs/ca-a2a-orchestrator --since 1m --region eu-west-3 \
  | grep -E "process_document|task_id"
```

### Test 2: Monitor the Full Pipeline

```bash
# Terminal 1: Watch S3 events → Lambda
aws logs tail /aws/lambda/ca-a2a-s3-processor --follow --region eu-west-3

# Terminal 2: Watch orchestrator processing
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3

# Terminal 3: Upload test file
aws s3 cp your_invoice.pdf \
  s3://ca-a2a-documents-555043101106/invoices/2026/01/ \
  --region eu-west-3
```

You should see:
1. **Lambda logs:** "Processing: s3://ca-a2a-documents-555043101106/invoices/..."
2. **Lambda logs:** "✓ Processing started: {...}"
3. **Orchestrator logs:** "Starting document processing: task_id=..."
4. **Orchestrator logs:** "Extraction completed"
5. **Orchestrator logs:** "Validation completed"
6. **Orchestrator logs:** "Archiving completed"

---

## 📊 Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Complete Pipeline                         │
└─────────────────────────────────────────────────────────────┘

User uploads invoice.pdf
         ↓
    S3 Bucket (invoices/)
         ↓
    S3 Event Notification
         ↓
    SQS Queue (ca-a2a-document-uploads)
         ↓
    Lambda (ca-a2a-s3-processor)
         ↓ HTTP POST /a2a
    Orchestrator (ECS Task)
         ↓
    ┌─────────┬──────────┬───────────┐
    ↓         ↓          ↓           ↓
Extractor  Validator  Archivist  MCP Server
    ↓         ↓          ↓           ↓
    └─────────┴──────────┴───────────┘
         ↓
    PostgreSQL + S3
```

---

## 🔍 Troubleshooting

### Issue: Lambda Can't Reach Orchestrator

**Check:**
```bash
# Verify Lambda is in correct VPC
aws lambda get-function-configuration \
  --function-name ca-a2a-s3-processor \
  --region eu-west-3 \
  --query 'VpcConfig'

# Check security group allows outbound traffic
aws ec2 describe-security-groups \
  --group-ids <security-group-id> \
  --region eu-west-3
```

**Fix:** Update Lambda VPC configuration in the script

### Issue: SQS Messages Not Being Processed

**Check:**
```bash
# Check SQS queue depth
aws sqs get-queue-attributes \
  --queue-url <queue-url> \
  --attribute-names All \
  --region eu-west-3

# Check Lambda event source mapping
aws lambda list-event-source-mappings \
  --function-name ca-a2a-s3-processor \
  --region eu-west-3
```

**Fix:** Ensure Lambda has SQS trigger enabled

### Issue: S3 Events Not Reaching SQS

**Check:**
```bash
# Verify S3 notification configuration
aws s3api get-bucket-notification-configuration \
  --bucket ca-a2a-documents-555043101106 \
  --region eu-west-3

# Check SQS policy allows S3
aws sqs get-queue-attributes \
  --queue-url <queue-url> \
  --attribute-names Policy \
  --region eu-west-3
```

**Fix:** Re-run setup script to fix policies

---

## 📈 Monitoring Commands

```bash
# Dashboard view
watch -n 5 'echo "=== Service Status ===" && \
  aws ecs describe-services --cluster ca-a2a-cluster --services archivist orchestrator \
  --region eu-west-3 --query "services[*].[serviceName,runningCount,desiredCount]" --output table && \
  echo "" && echo "=== SQS Depth ===" && \
  aws sqs get-queue-attributes --queue-url <queue-url> \
  --attribute-names ApproximateNumberOfMessages --region eu-west-3 --output table'

# Recent Lambda invocations
aws logs tail /aws/lambda/ca-a2a-s3-processor --since 10m --region eu-west-3 \
  | grep -E "Processing:|✓|✗"

# Recent orchestrator processing
aws logs tail /ecs/ca-a2a-orchestrator --since 10m --region eu-west-3 \
  | grep -E "task_id|completed|failed"
```

---

## ✅ Success Criteria

After both deployments, you should have:

### Archivist:
- ✅ 2/2 tasks running and healthy
- ✅ Logs show "Using MCP HTTP client"
- ✅ No more DNS resolution errors

### S3 Event Pipeline:
- ✅ SQS queue created
- ✅ S3 notifications configured
- ✅ Lambda function deployed
- ✅ Lambda can reach orchestrator
- ✅ New PDF uploads trigger processing automatically

### End-to-End Test:
```bash
# Upload file
aws s3 cp test.pdf s3://ca-a2a-documents-555043101106/invoices/2026/01/test.pdf

# Within 30 seconds, see:
# - Lambda log: "Processing: s3://..."
# - Lambda log: "✓ Processing started"
# - Orchestrator log: "task_id=..."
# - Orchestrator log: "Extraction completed"
```

---

## 🎯 Execution Summary

**Run these commands in CloudShell:**

```bash
# 1. Deploy archivist fix (~3 min)
chmod +x deploy-archivist-fix.sh
./deploy-archivist-fix.sh

# 2. Setup S3 event pipeline (~5 min)
chmod +x setup-s3-event-pipeline.sh
./setup-s3-event-pipeline.sh

# 3. Test end-to-end
aws s3 cp facture_acme_dec2025.pdf \
  s3://ca-a2a-documents-555043101106/invoices/2026/01/final_test_$(date +%s).pdf \
  --region eu-west-3

# 4. Watch processing
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3
```

**Total Time:** ~10 minutes  
**Result:** Fully automated document processing pipeline! 🚀

---

## 📄 Files Created

- `deploy-archivist-fix.sh` - Archivist deployment script
- `setup-s3-event-pipeline.sh` - S3 event pipeline setup
- This guide

**All ready to run in CloudShell!**

