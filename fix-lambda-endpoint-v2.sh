#!/bin/bash
# Fix Lambda to use correct orchestrator endpoint - V2 with correct handler

set -e

REGION="${REGION:-eu-west-3}"
LAMBDA_NAME="${LAMBDA_NAME:-ca-a2a-s3-processor}"
ORCH_IP="${ORCH_IP:-10.0.10.25}"

echo "============================================"
echo "FIXING LAMBDA ENDPOINT (V2)"
echo "============================================"
echo ""
echo "Correct orchestrator endpoint: POST /message"
echo "Orchestrator uses A2A protocol (JSON-RPC 2.0)"
echo ""

# Create corrected Lambda code with CORRECT filename to match handler
cat > lambda_s3_processor.py << 'LAMBDA_EOF'
import json
import boto3
import urllib3
import os
from urllib.parse import unquote_plus

http = urllib3.PoolManager()

# Orchestrator base URL (no path - we'll add /message)
orchestrator_base_url = os.environ.get('ORCHESTRATOR_URL', 'http://orchestrator.ca-a2a.local:8001')

def lambda_handler(event, context):
    print(f"Received {len(event.get('Records', []))} SQS records")
    print(f"Orchestrator URL: {orchestrator_base_url}")
    
    processed = 0
    errors = []
    
    for record in event.get('Records', []):
        try:
            # Parse SQS message (contains S3 event)
            message_body = json.loads(record['body'])
            
            # Process each S3 record in the message
            for s3_record in message_body.get('Records', []):
                bucket = s3_record['s3']['bucket']['name']
                key = unquote_plus(s3_record['s3']['object']['key'])
                
                print(f"Processing: s3://{bucket}/{key}")
                
                # Build A2A protocol message (JSON-RPC 2.0)
                a2a_message = {
                    "jsonrpc": "2.0",
                    "method": "process_document",
                    "params": {
                        "s3_key": key,
                        "priority": "normal"
                    },
                    "id": f"lambda-{context.aws_request_id}"
                }
                
                print(f"Sending to: {orchestrator_base_url}/message")
                print(f"Payload: {json.dumps(a2a_message)}")
                
                # POST to /message endpoint (A2A protocol)
                response = http.request(
                    'POST',
                    f"{orchestrator_base_url}/message",  # Correct endpoint!
                    body=json.dumps(a2a_message).encode('utf-8'),
                    headers={
                        'Content-Type': 'application/json',
                        'X-Correlation-ID': f"lambda-{context.aws_request_id}"
                    },
                    timeout=30.0
                )
                
                print(f"Orchestrator response: {response.status}")
                print(f"Response body: {response.data.decode('utf-8')[:500]}")
                
                if response.status == 200:
                    result = json.loads(response.data.decode('utf-8'))
                    
                    # Check if A2A response contains error
                    if result.get('error'):
                        error_msg = f"Orchestrator error: {result['error']}"
                        print(f"✗ {error_msg}")
                        errors.append(error_msg)
                    else:
                        print(f"✓ Success: {result.get('result', {})}")
                        processed += 1
                else:
                    error_msg = f"HTTP {response.status}: {response.data.decode('utf-8')[:200]}"
                    print(f"✗ Error: {error_msg}")
                    errors.append(error_msg)
                    
        except Exception as e:
            error_msg = f"Exception: {str(e)}"
            print(f"✗ {error_msg}")
            errors.append(error_msg)
    
    return {
        'statusCode': 200 if not errors else 207,
        'body': json.dumps({
            'processed': processed,
            'errors': errors,
            'total_records': len(event.get('Records', []))
        })
    }
LAMBDA_EOF

# Create deployment package with CORRECT filename
echo "Creating deployment package..."
zip -q lambda_s3_processor_fixed.zip lambda_s3_processor.py

# Update Lambda function code
echo "Updating Lambda function: ${LAMBDA_NAME}..."
aws lambda update-function-code \
  --function-name "${LAMBDA_NAME}" \
  --zip-file fileb://lambda_s3_processor_fixed.zip \
  --region "${REGION}" \
  --output json | jq -r '.FunctionName, .LastModified, .CodeSha256, .State, .LastUpdateStatus'

echo ""
echo "✓ Lambda code updated with correct endpoint: /message"

# Update environment variable to ensure correct URL
echo ""
echo "Updating Lambda environment variables..."
aws lambda update-function-configuration \
  --function-name "${LAMBDA_NAME}" \
  --environment "Variables={ORCHESTRATOR_URL=http://${ORCH_IP}:8001}" \
  --region "${REGION}" \
  --output json | jq -r '.FunctionName, .Environment.Variables.ORCHESTRATOR_URL, .LastUpdateStatus'

echo "✓ Environment updated: ORCHESTRATOR_URL=http://${ORCH_IP}:8001"

# Cleanup
rm -f lambda_s3_processor.py lambda_s3_processor_fixed.zip

echo ""
echo "Waiting 20 seconds for Lambda to become active..."
sleep 20

# Check Lambda status
echo ""
echo "Checking Lambda status..."
aws lambda get-function-configuration \
  --function-name "${LAMBDA_NAME}" \
  --region "${REGION}" \
  --query '{State: State, LastUpdateStatus: LastUpdateStatus, Handler: Handler}' \
  --output json

echo ""
echo "============================================"
echo "TESTING CORRECTED LAMBDA"
echo "============================================"
echo ""

# Create test PDF
cat > pipeline_test.pdf << 'EOF'
%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj
4 0 obj<</Length 250>>stream
BT
/F1 18 Tf
50 700 Td
(PIPELINE TEST - ENDPOINT FIXED) Tj
/F1 12 Tf
50 650 Td
(Testing: POST /message endpoint) Tj
50 630 Td
(Date: 02 janvier 2026) Tj
50 610 Td
(Montant: 99,999.00 EUR) Tj
ET
endstream endobj
5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj
xref
0 6
trailer<</Size 6/Root 1 0 R>>
startxref
%%EOF
EOF

# Upload test file
TIMESTAMP=$(date +%s)
TEST_KEY="invoices/2026/01/pipeline_test_${TIMESTAMP}.pdf"

echo "Uploading test file: ${TEST_KEY}"
aws s3 cp pipeline_test.pdf \
  "s3://ca-a2a-documents-555043101106/${TEST_KEY}" \
  --region "${REGION}"

echo "✓ File uploaded"
echo ""
echo "Waiting 35 seconds for processing..."
sleep 35

echo ""
echo "============================================"
echo "LAMBDA LOGS (last 3 minutes)"
echo "============================================"
aws logs tail "/aws/lambda/${LAMBDA_NAME}" \
  --since 3m \
  --region "${REGION}" \
  --format short \
  --filter-pattern "?Processing ?Orchestrator ?Success ?Error" \
  | head -50

echo ""
echo "============================================"
echo "ORCHESTRATOR LOGS (last 3 minutes)"
echo "============================================"
aws logs tail "/ecs/ca-a2a-orchestrator" \
  --since 3m \
  --region "${REGION}" \
  --format short \
  | grep -v "GET /health" \
  | grep -E "process_document|Starting document|task_id|extraction|POST /message" \
  | head -30

# Cleanup
rm -f pipeline_test.pdf

echo ""
echo "============================================"
echo "SUMMARY"
echo "============================================"
echo "✓ Lambda updated to use POST /message"
echo "✓ Handler: lambda_s3_processor.lambda_handler"
echo "✓ Endpoint: http://${ORCH_IP}:8001/message"
echo "✓ Test file uploaded and pipeline triggered"
echo ""
echo "Check the logs above for processing results"
echo ""
echo "If you see 'Success' in Lambda logs and 'Starting document' in"
echo "Orchestrator logs, the pipeline is working!"

