#!/bin/bash
# Fix orchestrator IP address in Lambda

set -e

REGION="${REGION:-eu-west-3}"
CLUSTER="ca-a2a-cluster"
SERVICE="orchestrator"
LAMBDA_NAME="ca-a2a-s3-processor"

echo "============================================"
echo "FIX ORCHESTRATOR IP IN LAMBDA"
echo "============================================"
echo ""

# Get current orchestrator task IPs
echo "1. Finding current orchestrator tasks..."
TASK_ARNS=$(aws ecs list-tasks \
  --cluster "${CLUSTER}" \
  --service-name "${SERVICE}" \
  --region "${REGION}" \
  --desired-status RUNNING \
  --query 'taskArns[]' \
  --output text)

if [ -z "$TASK_ARNS" ]; then
  echo "❌ No running orchestrator tasks found!"
  exit 1
fi

echo "Running tasks:"
echo "$TASK_ARNS"
echo ""

# Get task details including IPs
echo "2. Getting task IPs..."
TASK_DETAILS=$(aws ecs describe-tasks \
  --cluster "${CLUSTER}" \
  --tasks $TASK_ARNS \
  --region "${REGION}" \
  --output json)

# Extract private IPs
ORCHESTRATOR_IPS=$(echo "$TASK_DETAILS" | jq -r '
  .tasks[] |
  .attachments[] |
  .details[] |
  select(.name == "privateIPv4Address") |
  .value
')

echo "Orchestrator IPs:"
echo "$ORCHESTRATOR_IPS"
echo ""

# Use the first IP
ORCH_IP=$(echo "$ORCHESTRATOR_IPS" | head -1)

if [ -z "$ORCH_IP" ]; then
  echo "❌ Could not find orchestrator IP!"
  exit 1
fi

echo "Using orchestrator IP: ${ORCH_IP}"

# Get current Lambda API key
echo ""
echo "3. Getting current Lambda configuration..."
CURRENT_API_KEY=$(aws lambda get-function-configuration \
  --function-name "${LAMBDA_NAME}" \
  --region "${REGION}" \
  --query 'Environment.Variables.A2A_API_KEY' \
  --output text)

echo "Current API key: ${CURRENT_API_KEY}"

# Update Lambda environment with correct IP
echo ""
echo "4. Updating Lambda with correct orchestrator IP..."
aws lambda update-function-configuration \
  --function-name "${LAMBDA_NAME}" \
  --environment "Variables={ORCHESTRATOR_URL=http://${ORCH_IP}:8001,A2A_API_KEY=${CURRENT_API_KEY}}" \
  --region "${REGION}" \
  --query '{FunctionName: FunctionName, LastUpdateStatus: LastUpdateStatus}' \
  --output json

echo ""
echo "✓ Lambda updated with orchestrator IP: ${ORCH_IP}"

echo ""
echo "Waiting 20 seconds for Lambda update..."
sleep 20

echo ""
echo "============================================"
echo "VERIFY CONNECTIVITY"
echo "============================================"
echo ""

# We can't curl from CloudShell, but we can check from Lambda logs after upload
echo "Lambda will now connect to: http://${ORCH_IP}:8001/message"
echo ""

echo "============================================"
echo "FINAL PIPELINE TEST"
echo "============================================"
echo ""

# Upload test file
cat > working_pipeline_test.pdf << 'EOF'
%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj
4 0 obj<</Length 250>>stream
BT
/F1 18 Tf
50 700 Td
(COMPLETE PIPELINE TEST) Tj
/F1 14 Tf
50 650 Td
(With correct orchestrator IP) Tj
/F1 12 Tf
50 620 Td
(Date: 02 janvier 2026) Tj
50 600 Td
(Facture #2026-001) Tj
50 580 Td
(Montant Total: 99,999.99 EUR) Tj
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
TEST_KEY="invoices/2026/01/working_pipeline_${TIMESTAMP}.pdf"

echo "Uploading: ${TEST_KEY}"
aws s3 cp working_pipeline_test.pdf \
  "s3://ca-a2a-documents-555043101106/${TEST_KEY}" \
  --region "${REGION}"

rm -f working_pipeline_test.pdf

echo "✓ Uploaded"
echo ""
echo "Waiting 35 seconds for processing..."
sleep 35

echo ""
echo "============================================"
echo "LAMBDA LOGS (LATEST)"
echo "============================================"
aws logs tail "/aws/lambda/${LAMBDA_NAME}" \
  --since 2m \
  --region "${REGION}" \
  --format short \
  | tail -30

echo ""
echo "============================================"
echo "ORCHESTRATOR LOGS (LATEST)"
echo "============================================"
aws logs tail "/ecs/ca-a2a-orchestrator" \
  --since 2m \
  --region "${REGION}" \
  --format short \
  | grep -v "GET /health" \
  | tail -30

echo ""
echo "============================================"
echo "RESULT ANALYSIS"
echo "============================================"
echo ""

# Check for success
if aws logs tail "/aws/lambda/${LAMBDA_NAME}" --since 2m --region "${REGION}" | grep -q "✓ Success"; then
  echo "🎉 🎉 🎉 PIPELINE IS FULLY OPERATIONAL! 🎉 🎉 🎉"
  echo ""
  echo "✅ S3 Event → SQS → Lambda: WORKING"
  echo "✅ Lambda → Orchestrator connectivity: WORKING"
  echo "✅ API key authentication: WORKING"
  echo "✅ RBAC authorization: WORKING"
  echo "✅ Document processing started: CONFIRMED"
  echo ""
  echo "Configuration:"
  echo "  • Orchestrator IP: ${ORCH_IP}"
  echo "  • Orchestrator endpoint: http://${ORCH_IP}:8001/message"
  echo "  • Authentication: API key (lambda-s3-processor)"
  echo "  • RBAC: lambda-s3-processor allowed all methods"
  echo ""
  echo "You can now upload any PDF to trigger processing:"
  echo "  aws s3 cp myfile.pdf s3://ca-a2a-documents-555043101106/invoices/2026/01/"
  echo ""
  
  # Check if we can see task IDs in orchestrator logs
  if aws logs tail "/ecs/ca-a2a-orchestrator" --since 2m --region "${REGION}" | grep -q "task_id"; then
    echo "✅ Document processing task created!"
    echo ""
    echo "Latest task IDs:"
    aws logs tail "/ecs/ca-a2a-orchestrator" --since 2m --region "${REGION}" \
      | grep "task_id" \
      | tail -3
  fi
  
elif aws logs tail "/aws/lambda/${LAMBDA_NAME}" --since 2m --region "${REGION}" | grep -q "200"; then
  echo "✅ HTTP 200 received from orchestrator!"
  echo ""
  echo "Checking orchestrator logs for processing..."
  aws logs tail "/ecs/ca-a2a-orchestrator" \
    --since 2m \
    --region "${REGION}" \
    | grep -E "Starting document|task_id|process_document" \
    | tail -10
    
elif aws logs tail "/aws/lambda/${LAMBDA_NAME}" --since 2m --region "${REGION}" | grep -q "timeout\|ConnectTimeout"; then
  echo "❌ Still getting connection timeouts"
  echo ""
  echo "Current orchestrator IP: ${ORCH_IP}"
  echo ""
  echo "Possible issues:"
  echo "1. Security group not allowing Lambda → Orchestrator"
  echo "2. Network ACLs blocking traffic"
  echo "3. Orchestrator not fully started yet"
  
else
  echo "⚠️  Check the logs above for details"
fi

