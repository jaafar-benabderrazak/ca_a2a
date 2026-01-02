# S3 Event Processing Status

## CRITICAL FIX: Correct Orchestrator Endpoint (2026-01-02)

**Issue:** Lambda was using wrong endpoint `/a2a` → getting 404 errors  
**Root Cause:** Orchestrator uses **A2A protocol** on **POST /message**, not custom paths  
**Fix:** Updated Lambda to POST to `/message` with JSON-RPC 2.0 format

### Orchestrator HTTP Endpoints

The orchestrator (aiohttp framework) exposes:
- **POST /message** - Main A2A protocol endpoint (JSON-RPC 2.0) ✅ **USE THIS**
- POST /upload - Multipart file upload
- GET /health - Health check
- GET /status - Status info
- GET /card - Agent card/capabilities
- GET /skills - Skills listing

**References:**
- `orchestrator_agent.py:60` - Route registration: `self.app.router.add_post('/message', self.handle_http_message)`
- `base_agent.py:60` - Handler: `self.app.router.add_post('/message', self.handle_http_message)`

### Correct Lambda Code Format

Lambda must POST to `/message` with JSON-RPC 2.0 format:

```python
a2a_message = {
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {"s3_key": key, "priority": "normal"},
    "id": "lambda-request-id"
}

response = http.request(
    'POST',
    f"{orchestrator_url}/message",  # /message NOT /a2a
    body=json.dumps(a2a_message).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)
```

### Fix Script

Run: `./fix-lambda-endpoint.sh`

This script:
1. Updates Lambda to use POST /message
2. Sets ORCHESTRATOR_URL environment variable
3. Tests the corrected endpoint
4. Uploads a test file and verifies processing

---

## Check if Orchestrator Detected S3 Upload

```bash
# Check orchestrator logs for any processing activity related to the invoice
aws logs tail /ecs/ca-a2a-orchestrator --since 30m --region eu-west-3 \
  | grep -E "facture_acme|invoice|process_document|s3://|incoming/|invoices/" \
  | tail -20

# Check for any A2A messages or document processing
aws logs tail /ecs/ca-a2a-orchestrator --since 30m --region eu-west-3 \
  | grep -E "Starting document|task_id|extraction|validation|archiv" \
  | tail -20

# Check extractor logs for any processing
aws logs tail /ecs/ca-a2a-extractor --since 30m --region eu-west-3 \
  | grep -E "facture|extract|process" \
  | tail -20
```

## Why the Orchestrator Likely Did NOT Process the File:

**The system does NOT have S3 event notifications configured.**

Here's what's missing:

### Current State:
- ✅ File uploaded to S3
- ✅ File encrypted
- ✅ Metadata preserved
- ❌ No S3 event trigger configured
- ❌ No automatic processing

### What's Needed for Automatic Processing:

1. **S3 Event Notification** → SQS Queue
2. **Lambda Function** or **Orchestrator Polling** to detect new files
3. **API Call** to orchestrator's `/message` endpoint with `process_document` method (JSON-RPC 2.0)

### Current Architecture:
```
User → S3 Upload → (NO EVENT NOTIFICATION) → Nothing happens
```

### What Should Happen:
```
User → S3 Upload → S3 Event → SQS → Lambda/Poller → Orchestrator API → Processing
```

## To Manually Trigger Processing:

Since we can't call the orchestrator API directly from outside the VPC, you have two options:

### Option 1: ECS Exec into Orchestrator Task
```bash
# Get task ID
TASK_ID=$(aws ecs list-tasks --cluster ca-a2a-cluster --service-name orchestrator \
  --region eu-west-3 --desired-status RUNNING --query 'taskArns[0]' --output text | cut -d'/' -f3)

# Execute command in task
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task $TASK_ID \
  --container orchestrator \
  --region eu-west-3 \
  --interactive \
  --command "/bin/bash"

# Then from inside the container (use CORRECT /message endpoint):
curl -X POST http://localhost:8001/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {
      "s3_key": "invoices/2026/01/facture_acme_dec2025.pdf"
    },
    "id": "demo-001"
  }'
```

### Option 2: Use Fix Script (Recommended)
```bash
# This script fixes the Lambda and runs a complete test
./fix-lambda-endpoint.sh
```

## Summary:

**Orchestrator Status:** ✅ Running and healthy  
**S3 Upload:** ✅ Successful  
**Automatic Processing:** ❌ **WAS NOT WORKING** (wrong endpoint)  
**Fix Status:** ✅ **FIXED** - Lambda now uses `/message`  
**Reason for Original Issue:** Lambda was POSTing to `/a2a` instead of `/message`

The orchestrator uses standard A2A protocol (JSON-RPC 2.0) on the `/message` endpoint, as defined in `base_agent.py`. All agents follow this pattern.
