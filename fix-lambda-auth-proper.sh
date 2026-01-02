#!/bin/bash
# Proper fix: Add API key authentication to Lambda

set -e

REGION="${REGION:-eu-west-3}"
LAMBDA_NAME="${LAMBDA_NAME:-ca-a2a-s3-processor}"
ORCH_IP="${ORCH_IP:-10.0.10.25}"

# Generate a secure API key
API_KEY="lambda-s3-processor-$(openssl rand -hex 16)"

echo "============================================"
echo "ADD API KEY AUTH TO LAMBDA (PROPER FIX)"
echo "============================================"
echo ""
echo "Generated API key: ${API_KEY}"
echo ""

# Create Lambda code with API key support
cat > lambda_s3_processor.py << LAMBDA_EOF
import json
import boto3
import urllib3
import os
from urllib.parse import unquote_plus

http = urllib3.PoolManager()

orchestrator_base_url = os.environ.get('ORCHESTRATOR_URL', 'http://orchestrator.ca-a2a.local:8001')
api_key = os.environ.get('A2A_API_KEY', '')

def lambda_handler(event, context):
    print(f"Received {len(event.get('Records', []))} SQS records")
    print(f"Orchestrator URL: {orchestrator_base_url}")
    print(f"API Key configured: {'Yes' if api_key else 'No'}")
    
    processed = 0
    errors = []
    
    for record in event.get('Records', []):
        try:
            message_body = json.loads(record['body'])
            
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
                
                # Build headers with API key authentication
                headers = {
                    'Content-Type': 'application/json',
                    'X-Correlation-ID': f"lambda-{context.aws_request_id}"
                }
                
                # Add API key if configured
                if api_key:
                    headers['X-API-Key'] = api_key
                    print("Using API key authentication")
                
                print(f"Sending to: {orchestrator_base_url}/message")
                
                # POST to /message endpoint (A2A protocol)
                response = http.request(
                    'POST',
                    f"{orchestrator_base_url}/message",
                    body=json.dumps(a2a_message).encode('utf-8'),
                    headers=headers,
                    timeout=30.0
                )
                
                print(f"Orchestrator response: {response.status}")
                print(f"Response body: {response.data.decode('utf-8')[:500]}")
                
                if response.status == 200:
                    result = json.loads(response.data.decode('utf-8'))
                    
                    if result.get('error'):
                        error_msg = f"Orchestrator error: {result['error']}"
                        print(f"✗ {error_msg}")
                        errors.append(error_msg)
                    else:
                        print(f"✓ Success: {result.get('result', {})}")
                        processed += 1
                elif response.status == 401:
                    error_msg = "Authentication failed - check API key"
                    print(f"✗ {error_msg}")
                    errors.append(error_msg)
                elif response.status == 403:
                    error_msg = "Authorization failed - check permissions"
                    print(f"✗ {error_msg}")
                    errors.append(error_msg)
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
zip -q lambda_with_auth.zip lambda_s3_processor.py

# Update Lambda code
echo "Updating Lambda code..."
aws lambda update-function-code \
  --function-name "${LAMBDA_NAME}" \
  --zip-file fileb://lambda_with_auth.zip \
  --region "${REGION}" \
  --output json | jq -r '.FunctionName, .LastModified, .State'

echo "✓ Lambda code updated"

# Update Lambda environment with API key
echo ""
echo "Adding API key to Lambda environment..."
aws lambda update-function-configuration \
  --function-name "${LAMBDA_NAME}" \
  --environment "Variables={ORCHESTRATOR_URL=http://${ORCH_IP}:8001,A2A_API_KEY=${API_KEY}}" \
  --region "${REGION}" \
  --output json | jq -r '.FunctionName, .LastUpdateStatus'

echo "✓ API key added to Lambda"

# Cleanup
rm -f lambda_s3_processor.py lambda_with_auth.zip

# Now configure orchestrator to accept this API key
echo ""
echo "============================================"
echo "CONFIGURE ORCHESTRATOR"
echo "============================================"
echo ""
echo "Now we need to configure the orchestrator to accept this API key."
echo ""

# Create API keys JSON
API_KEYS_JSON="{\"lambda-s3-processor\":\"${API_KEY}\"}"

echo "Getting current orchestrator task definition..."
TASK_DEF_ARN=$(aws ecs describe-services \
  --cluster "ca-a2a-cluster" \
  --services "orchestrator" \
  --region "${REGION}" \
  --query 'services[0].taskDefinition' \
  --output text)

# Download and update task definition
aws ecs describe-task-definition \
  --task-definition "${TASK_DEF_ARN}" \
  --region "${REGION}" \
  --query 'taskDefinition' \
  > current_orch_taskdef.json

# Update task definition with API keys
jq --arg api_keys "${API_KEYS_JSON}" '
  {
    family: .family,
    taskRoleArn: .taskRoleArn,
    executionRoleArn: .executionRoleArn,
    networkMode: .networkMode,
    containerDefinitions: [
      .containerDefinitions[] | 
      if .name == "orchestrator" then
        .environment = (
          (.environment // []) |
          map(select(.name != "A2A_API_KEYS_JSON" and .name != "A2A_REQUIRE_AUTH")) +
          [
            {name: "A2A_REQUIRE_AUTH", value: "true"},
            {name: "A2A_API_KEYS_JSON", value: $api_keys}
          ]
        )
      else . end
    ],
    requiresCompatibilities: .requiresCompatibilities,
    cpu: .cpu,
    memory: .memory
  }
' current_orch_taskdef.json > updated_orch_taskdef.json

echo "Registering updated orchestrator task definition..."
NEW_TASK_DEF=$(aws ecs register-task-definition \
  --cli-input-json file://updated_orch_taskdef.json \
  --region "${REGION}" \
  --query 'taskDefinition.taskDefinitionArn' \
  --output text)

echo "New task definition: ${NEW_TASK_DEF}"

echo ""
echo "Updating orchestrator service..."
aws ecs update-service \
  --cluster "ca-a2a-cluster" \
  --service "orchestrator" \
  --task-definition "${NEW_TASK_DEF}" \
  --region "${REGION}" \
  --force-new-deployment \
  --query 'service.{serviceName: serviceName, taskDefinition: taskDefinition}' \
  --output json

# Cleanup
rm -f current_orch_taskdef.json updated_orch_taskdef.json

echo ""
echo "✓ Orchestrator configured with API key"
echo ""
echo "Waiting 60 seconds for orchestrator to redeploy..."
sleep 60

echo ""
echo "============================================"
echo "TESTING AUTHENTICATED PIPELINE"
echo "============================================"
echo ""

# Create and upload test file
cat > auth_proper_test.pdf << 'EOF'
%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj
4 0 obj<</Length 220>>stream
BT
/F1 16 Tf
50 700 Td
(AUTHENTICATED PIPELINE TEST) Tj
/F1 12 Tf
50 650 Td
(Using API key authentication) Tj
50 630 Td
(Date: 02 Jan 2026) Tj
50 610 Td
(Montant: 54,321.00 EUR) Tj
ET
endstream endobj
5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj
xref
0 6
trailer<</Size 6/Root 1 0 R>>
startxref
%%EOF
EOF

TIMESTAMP=$(date +%s)
TEST_KEY="invoices/2026/01/auth_proper_${TIMESTAMP}.pdf"

echo "Uploading: ${TEST_KEY}"
aws s3 cp auth_proper_test.pdf \
  "s3://ca-a2a-documents-555043101106/${TEST_KEY}" \
  --region "${REGION}"

rm -f auth_proper_test.pdf

echo "✓ Uploaded"
echo ""
echo "Waiting 30 seconds for processing..."
sleep 30

echo ""
echo "============================================"
echo "LAMBDA LOGS"
echo "============================================"
aws logs tail "/aws/lambda/${LAMBDA_NAME}" \
  --since 2m \
  --region "${REGION}" \
  --format short \
  | grep -E "Processing|Orchestrator|Success|Error|API|auth" \
  | tail -25

echo ""
echo "============================================"
echo "ORCHESTRATOR LOGS"
echo "============================================"
aws logs tail "/ecs/ca-a2a-orchestrator" \
  --since 2m \
  --region "${REGION}" \
  --format short \
  | grep -v "GET /health" \
  | grep -E "process_document|Starting document|POST /message|auth|API" \
  | tail -25

echo ""
echo "============================================"
echo "SUMMARY"
echo "============================================"
echo "✓ Lambda configured with API key authentication"
echo "✓ Orchestrator configured to accept API key"
echo "✓ A2A_REQUIRE_AUTH enabled on orchestrator"
echo "✓ Test file uploaded"
echo ""
echo "API Key: ${API_KEY}"
echo ""
echo "If you see HTTP 200 and 'Starting document', the"
echo "authenticated pipeline is working!"
echo ""
echo "⚠️  Save the API key for future reference"

