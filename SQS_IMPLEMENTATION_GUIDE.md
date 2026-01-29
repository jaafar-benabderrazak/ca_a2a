# SQS Automatic Document Processing - Implementation Guide

## 🎉 **OVERVIEW**

This update enables **fully automatic document processing** in your CA-A2A system. Documents uploaded to S3 are automatically detected and processed without requiring manual API calls or authentication.

---

## 🏗️ **ARCHITECTURE**

### **Before (Manual Triggering)**:
```
User → API (with JWT) → Orchestrator → Process Document
```

### **After (Automatic Processing)**:
```
User → S3 Upload → S3 Event → SQS → Orchestrator (polling) → Process Document
                                                    ↓
                                                Auto-detect & process
```

---

## 🔧 **WHAT CHANGED**

### **1. Orchestrator Agent (`orchestrator_agent.py`)**

#### **Added Features:**
- ✅ SQS client initialization
- ✅ Background polling loop (every 10 seconds)
- ✅ S3 event notification parsing
- ✅ Automatic document type detection
- ✅ Error handling with exponential backoff
- ✅ Long polling (20 seconds wait time)
- ✅ Batch message processing (up to 10 messages)

#### **New Methods:**
```python
async def _initialize_sqs()           # Set up SQS client and queue
async def _sqs_polling_loop()         # Main polling loop
async def _poll_sqs_messages()        # Fetch messages from SQS
async def _process_sqs_message()      # Handle individual message
async def _handle_s3_event()          # Process S3 event notification
def _get_document_type()              # Map file extension to type
```

#### **Environment Variables:**
```bash
SQS_ENABLED=true                      # Enable/disable SQS polling
SQS_QUEUE_NAME=ca-a2a-document-processing
AWS_REGION=eu-west-3
SQS_POLL_INTERVAL=10                  # Seconds between polls
SQS_MAX_MESSAGES=10                   # Max messages per poll
SQS_WAIT_TIME=20                      # Long polling wait time
```

---

### **2. Requirements (`requirements.txt`)**

**Added:**
```
boto3>=1.34.0  # For SQS polling (synchronous client)
```

---

### **3. Deployment Script (`deploy-sqs-orchestrator.sh`)**

**Automated steps:**
1. ✅ Verify/create SQS queue
2. ✅ Build Docker image with boto3
3. ✅ Push to ECR
4. ✅ Update task definition with SQS env vars
5. ✅ Add IAM permissions for SQS
6. ✅ Deploy new orchestrator version
7. ✅ Test automatic processing

---

## 🚀 **DEPLOYMENT INSTRUCTIONS**

### **Prerequisites:**

1. AWS CLI configured and authenticated
2. Docker installed and running
3. Existing CA-A2A infrastructure deployed

### **Step 1: Make Script Executable**

```bash
chmod +x deploy-sqs-orchestrator.sh
```

### **Step 2: Run Deployment**

```bash
# From CloudShell or local terminal
./deploy-sqs-orchestrator.sh
```

**Deployment time**: ~5-7 minutes

### **Step 3: Verify Deployment**

```bash
# Check orchestrator logs for SQS activity
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3 --filter-pattern "SQS"

# Check service status
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region eu-west-3 \
  --query 'services[0].{Status:status,Running:runningCount,Desired:desiredCount}'

# Check SQS queue
aws sqs get-queue-attributes \
  --queue-url $(aws sqs get-queue-url --queue-name ca-a2a-document-processing --region eu-west-3 --query 'QueueUrl' --output text) \
  --attribute-names ApproximateNumberOfMessages \
  --region eu-west-3
```

---

## 📋 **HOW IT WORKS**

### **Document Processing Flow:**

1. **User uploads document** to S3:
   ```bash
   aws s3 cp invoice.pdf s3://ca-a2a-documents/uploads/
   ```

2. **S3 triggers event** → Sends notification to SQS queue

3. **Orchestrator polls SQS** (every 10 seconds):
   - Receives up to 10 messages
   - Uses long polling (waits 20s for messages)

4. **Orchestrator processes message**:
   - Parses S3 event notification
   - Extracts bucket name and object key
   - Checks if key is in `uploads/` folder
   - Skips folders (keys ending with `/`)

5. **Automatic processing starts**:
   - Detects document type from file extension
   - Calls `handle_process_document()` internally
   - Creates task ID and tracking record

6. **Message deleted** from SQS after successful processing

7. **Pipeline executes**:
   - Extraction (Extractor agent)
   - Validation (Validator agent)
   - Archiving (Archivist agent)

---

## 🔍 **FILE TYPE DETECTION**

**Automatic mapping:**
```python
.pdf, .csv, .txt  → invoice
.jpg, .jpeg, .png → receipt
.json, .xml       → structured_data
```

**Override:** Specify document type in S3 metadata:
```bash
aws s3 cp invoice.pdf s3://ca-a2a-documents/uploads/ \
  --metadata document-type=invoice
```

---

## 📊 **MONITORING**

### **CloudWatch Logs**

**Key log patterns to watch:**

```bash
# SQS initialization
aws logs tail /ecs/ca-a2a-orchestrator --region eu-west-3 --filter-pattern "SQS"

# Automatic processing triggers
aws logs tail /ecs/ca-a2a-orchestrator --region eu-west-3 --filter-pattern "Auto-processing"

# Error messages
aws logs tail /ecs/ca-a2a-orchestrator --region eu-west-3 --filter-pattern "ERROR"

# Processing completion
aws logs tail /ecs/ca-a2a-orchestrator --region eu-west-3 --filter-pattern "completed successfully"
```

### **Expected Log Messages:**

```
✓ SQS queue found: https://sqs.eu-west-3.amazonaws.com/...
✓ SQS polling started (interval: 10s, max messages: 10)
Received 1 message(s) from SQS
S3 event: ObjectCreated:Put, bucket: ca-a2a-documents, key: uploads/invoice.pdf
🚀 Auto-processing document from S3 event: uploads/invoice.pdf (type: invoice)
✓ Processing initiated: task_id=abc-123, s3_key=uploads/invoice.pdf
✓ Message abc-456 processed and deleted from queue
Task abc-123: Pipeline completed successfully
```

### **Health Check**

```bash
# Check orchestrator health (includes SQS status)
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health | jq '.sqs_polling'
```

**Expected response:**
```json
{
  "sqs_polling": {
    "enabled": true,
    "available": true,
    "queue_url": "https://sqs.eu-west-3.amazonaws.com/555043101106/ca-a2a-document-processing",
    "polling_active": true
  }
}
```

---

## 🧪 **TESTING**

### **Test 1: Upload and Monitor**

```bash
# Create test invoice
cat > test-invoice.txt << 'EOF'
INVOICE
Company: Test Corp
Date: 2026-01-22
Amount: €500.00
EOF

# Upload to S3
aws s3 cp test-invoice.txt s3://ca-a2a-documents/uploads/ --region eu-west-3

# Watch processing in real-time
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3 --filter-pattern "process"
```

### **Test 2: Batch Upload**

```bash
# Upload multiple documents
for i in {1..5}; do
  echo "INVOICE $i - Amount: €$((i * 100)).00" > invoice-$i.txt
  aws s3 cp invoice-$i.txt s3://ca-a2a-documents/uploads/ --region eu-west-3
done

# Check SQS queue
aws sqs get-queue-attributes \
  --queue-url $(aws sqs get-queue-url --queue-name ca-a2a-document-processing --region eu-west-3 --query 'QueueUrl' --output text) \
  --attribute-names ApproximateNumberOfMessages,ApproximateNumberOfMessagesNotVisible \
  --region eu-west-3
```

### **Test 3: Verify Processing Complete**

```bash
# Wait 30 seconds
sleep 30

# Check processed folder
aws s3 ls s3://ca-a2a-documents/processed/ --recursive --region eu-west-3

# Check uploads folder (should be empty or reduced)
aws s3 ls s3://ca-a2a-documents/uploads/ --recursive --region eu-west-3
```

---

## 🛡️ **ERROR HANDLING**

### **Resilience Features:**

1. **Exponential Backoff**: On errors, wait 2^n seconds before retry (max 60s)
2. **Consecutive Error Limit**: Stops after 5 consecutive failures
3. **Message Retention**: Failed messages remain in SQS for reprocessing
4. **Malformed Message Handling**: Invalid JSON is logged and deleted
5. **Long Polling**: Reduces empty responses and API costs

### **Common Errors & Solutions:**

| Error | Cause | Solution |
|-------|-------|----------|
| `NonExistentQueue` | SQS queue not created | Run `enable-auto-processing.sh` |
| `AccessDenied` | Missing IAM permissions | Script adds SQS policy automatically |
| `boto3 not available` | Package not installed | Rebuild with updated requirements.txt |
| `Timeout` | Network issues | Automatic retry with backoff |

---

## 🎛️ **CONFIGURATION**

### **Adjust Polling Behavior:**

Edit task definition environment variables:

```json
{
  "name": "SQS_POLL_INTERVAL",
  "value": "5"  // Poll every 5 seconds (more frequent)
}
```

```json
{
  "name": "SQS_MAX_MESSAGES",
  "value": "5"  // Process 5 messages at a time
}
```

```json
{
  "name": "SQS_WAIT_TIME",
  "value": "10"  // Long poll for 10 seconds
}
```

**Redeploy** after changes:
```bash
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --force-new-deployment \
  --region eu-west-3
```

---

## 📈 **PERFORMANCE METRICS**

### **Expected Performance:**

| Metric | Value | Notes |
|--------|-------|-------|
| **Detection Latency** | < 30 seconds | S3 event → SQS → Poll |
| **Processing Start** | < 5 seconds | After message received |
| **Throughput** | 10 docs/poll | Configurable via SQS_MAX_MESSAGES |
| **Concurrent Processing** | Unlimited | Each document gets own task |

### **Cost Optimization:**

- **Long Polling**: Reduces SQS API calls by 95%
- **Batch Processing**: Processes up to 10 messages per API call
- **Event-Driven**: No idle CPU usage between uploads

---

## 🔄 **ROLLBACK**

### **Disable SQS Polling:**

```bash
# Set environment variable to disable
aws ecs describe-task-definition \
  --task-definition ca-a2a-orchestrator \
  --region eu-west-3 | \
jq '.taskDefinition | .containerDefinitions[0].environment |= 
  map(if .name == "SQS_ENABLED" then .value = "false" else . end)' | \
aws ecs register-task-definition --cli-input-json file:///dev/stdin --region eu-west-3

# Update service
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --force-new-deployment \
  --region eu-west-3
```

### **Revert to Previous Version:**

```bash
# Use previous task definition
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --task-definition ca-a2a-orchestrator:<previous-revision> \
  --region eu-west-3
```

---

## 🎓 **BEST PRACTICES**

### **1. Upload Naming Convention**

```
uploads/
  ├── invoices/
  │   └── 2026-01-22-acme-corp.pdf
  ├── receipts/
  │   └── 2026-01-22-expense-001.jpg
  └── bulk/
      └── batch-20260122.csv
```

### **2. Monitoring Dashboard**

**Key metrics to track:**
- Documents uploaded per hour
- Processing completion rate
- Average processing time
- SQS queue depth
- Error rate

### **3. Alerting**

Set up CloudWatch alarms:

```bash
# Alarm if SQS queue depth > 50
aws cloudwatch put-metric-alarm \
  --alarm-name ca-a2a-sqs-high-queue-depth \
  --alarm-description "SQS queue has too many pending messages" \
  --metric-name ApproximateNumberOfMessagesVisible \
  --namespace AWS/SQS \
  --statistic Average \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 50 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=QueueName,Value=ca-a2a-document-processing \
  --region eu-west-3
```

---

## 📚 **ADDITIONAL RESOURCES**

- **SQS Documentation**: https://docs.aws.amazon.com/sqs/
- **S3 Event Notifications**: https://docs.aws.amazon.com/AmazonS3/latest/userguide/NotificationHowTo.html
- **ECS Task Definitions**: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definitions.html

---

## ✅ **SUCCESS CRITERIA**

Your deployment is successful when:

1. ✅ Orchestrator logs show "SQS polling started"
2. ✅ Health check returns `"polling_active": true`
3. ✅ Test document upload triggers automatic processing
4. ✅ Document moves from `uploads/` to `processed/`
5. ✅ No errors in CloudWatch logs

---

## 🎉 **CONGRATULATIONS!**

Your CA-A2A system now features **fully automatic document processing**!

**Before**: Manual API calls with authentication required  
**After**: Drop files in S3, automatic processing begins

**Next Enhancement Ideas:**
- Add document prioritization based on S3 metadata
- Implement dead-letter queue for failed messages
- Add SNS notifications for processing completion
- Create CloudWatch dashboard for monitoring

---

**Implementation Date**: 2026-01-22  
**Version**: 1.0.0  
**Status**: ✅ Production Ready
