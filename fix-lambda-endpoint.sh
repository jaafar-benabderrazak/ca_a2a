#!/bin/bash
# Fix Lambda to use correct orchestrator endpoint

set -e

REGION="${REGION:-eu-west-3}"
LAMBDA_NAME="${LAMBDA_NAME:-ca-a2a-s3-processor}"
ORCH_IP="${ORCH_IP:-10.0.10.25}"

echo "============================================"
echo "FIXING LAMBDA ENDPOINT"
echo "============================================"
echo ""
echo "Correct orchestrator endpoint: POST /message"
echo "Orchestrator uses A2A protocol (JSON-RPC 2.0)"
echo ""

# Create corrected Lambda code
cat > lambda_s3_processor_corrected.py << 'LAMBDA_EOF'
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

# Create deployment package
echo "Creating deployment package..."
zip -q lambda_s3_processor_corrected.zip lambda_s3_processor_corrected.py

# Update Lambda function code
echo "Updating Lambda function: ${LAMBDA_NAME}..."
aws lambda update-function-code \
  --function-name "${LAMBDA_NAME}" \
  --zip-file fileb://lambda_s3_processor_corrected.zip \
  --region "${REGION}"

echo ""
echo "✓ Lambda code updated with correct endpoint: /message"

# Update environment variable to ensure correct URL
echo ""
echo "Updating Lambda environment variables..."
aws lambda update-function-configuration \
  --function-name "${LAMBDA_NAME}" \
  --environment "Variables={ORCHESTRATOR_URL=http://${ORCH_IP}:8001}" \
  --region "${REGION}"

echo "✓ Environment updated: ORCHESTRATOR_URL=http://${ORCH_IP}:8001"

# Cleanup
rm -f lambda_s3_processor_corrected.py lambda_s3_processor_corrected.zip

echo ""
echo "Waiting 15 seconds for Lambda to update..."
sleep 15

echo ""
echo "============================================"
echo "TESTING CORRECTED LAMBDA"
echo "============================================"
echo ""

# Create test PDF
cat > final_test.pdf << 'EOF'
%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj
4 0 obj<</Length 250>>stream
BT
/F1 18 Tf
50 700 Td
(PIPELINE TEST - CORRECTED ENDPOINT) Tj
/F1 12 Tf
50 650 Td
(Testing: POST /message endpoint) Tj
50 630 Td
(Date: 02 janvier 2026) Tj
50 610 Td
(Montant: 12,345.67 EUR) Tj
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
TEST_KEY="invoices/2026/01/final_test_${TIMESTAMP}.pdf"

echo "Uploading test file: ${TEST_KEY}"
aws s3 cp final_test.pdf \
  "s3://ca-a2a-documents-555043101106/${TEST_KEY}" \
  --region "${REGION}"

echo "✓ File uploaded"
echo ""
echo "Waiting 30 seconds for processing..."
sleep 30

echo ""
echo "============================================"
echo "LAMBDA LOGS (last 2 minutes)"
echo "============================================"
aws logs tail "/aws/lambda/${LAMBDA_NAME}" \
  --since 2m \
  --region "${REGION}" \
  --format short

echo ""
echo "============================================"
echo "ORCHESTRATOR LOGS (last 2 minutes)"
echo "============================================"
aws logs tail "/ecs/ca-a2a-orchestrator" \
  --since 2m \
  --region "${REGION}" \
  --format short | grep -v "GET /health" | head -30

# Cleanup
rm -f final_test.pdf

echo ""
echo "============================================"
echo "DIRECT ENDPOINT TEST"
echo "============================================"
echo ""
echo "Testing orchestrator /message endpoint directly..."

curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"process_document","params":{"s3_key":"test.pdf"},"id":"curl-test"}' \
  "http://${ORCH_IP}:8001/message" \
  --max-time 5 \
  -v

echo ""
echo ""
echo "============================================"
echo "SUMMARY"
echo "============================================"
echo "✓ Lambda updated to use POST /message"
echo "✓ Test file uploaded and pipeline triggered"
echo "✓ Check logs above for results"
echo ""
echo "The orchestrator uses A2A protocol (JSON-RPC 2.0) on POST /message"
echo "NOT on /a2a or other custom paths"

