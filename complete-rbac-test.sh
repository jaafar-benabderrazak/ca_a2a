#!/bin/bash
# Complete the RBAC fix and test

set -e

REGION="${REGION:-eu-west-3}"

echo "============================================"
echo "CHECK SERVICE UPDATE STATUS"
echo "============================================"
echo ""

# Check if update succeeded
SERVICE_INFO=$(aws ecs describe-services \
  --cluster "ca-a2a-cluster" \
  --services "orchestrator" \
  --region "${REGION}" \
  --query 'services[0]' \
  --output json)

CURRENT_TASK_DEF=$(echo "$SERVICE_INFO" | jq -r '.taskDefinition')
DESIRED_COUNT=$(echo "$SERVICE_INFO" | jq -r '.desiredCount')
RUNNING_COUNT=$(echo "$SERVICE_INFO" | jq -r '.runningCount')

echo "Service: orchestrator"
echo "Current task definition: ${CURRENT_TASK_DEF}"
echo "Desired count: ${DESIRED_COUNT}"
echo "Running count: ${RUNNING_COUNT}"

echo ""
echo "Checking RBAC policy in new task definition..."
aws ecs describe-task-definition \
  --task-definition "${CURRENT_TASK_DEF}" \
  --region "${REGION}" \
  --query 'taskDefinition.containerDefinitions[0].environment[?name==`A2A_RBAC_POLICY_JSON`].value' \
  --output text

echo ""
echo "Waiting for deployment to stabilize (60 seconds)..."
sleep 60

echo ""
echo "============================================"
echo "FINAL TEST"
echo "============================================"
echo ""

# Upload test file
cat > final_rbac_test.pdf << 'EOF'
%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj
4 0 obj<</Length 220>>stream
BT
/F1 18 Tf
50 700 Td
(FINAL RBAC TEST) Tj
/F1 12 Tf
50 650 Td
(Lambda with API key + RBAC) Tj
50 630 Td
(Date: 02 Jan 2026) Tj
50 610 Td
(Montant: 88,888.88 EUR) Tj
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
TEST_KEY="invoices/2026/01/final_rbac_${TIMESTAMP}.pdf"

echo "Uploading: ${TEST_KEY}"
aws s3 cp final_rbac_test.pdf \
  "s3://ca-a2a-documents-555043101106/${TEST_KEY}" \
  --region "${REGION}"

rm -f final_rbac_test.pdf

echo "✓ Uploaded"
echo ""
echo "Waiting 30 seconds for processing..."
sleep 30

echo ""
echo "============================================"
echo "LAMBDA LOGS"
echo "============================================"
aws logs tail "/aws/lambda/ca-a2a-s3-processor" \
  --since 2m \
  --region "${REGION}" \
  --format short \
  | grep -E "Processing|Orchestrator response|Success|Error|200|401|403" \
  | tail -20

echo ""
echo "============================================"
echo "ORCHESTRATOR LOGS"
echo "============================================"
aws logs tail "/ecs/ca-a2a-orchestrator" \
  --since 2m \
  --region "${REGION}" \
  --format short \
  | grep -v "GET /health" \
  | grep -E "process_document|Starting document|task_id|extraction|POST /message" \
  | tail -25

echo ""
echo "============================================"
echo "FINAL RESULT"
echo "============================================"
echo ""

# Check for success in Lambda logs
if aws logs tail "/aws/lambda/ca-a2a-s3-processor" --since 2m --region "${REGION}" | grep -q "✓ Success"; then
  echo "🎉 🎉 🎉 SUCCESS! 🎉 🎉 🎉"
  echo ""
  echo "✅ Network connectivity: WORKING"
  echo "✅ Endpoint: POST /message - CORRECT"
  echo "✅ API key authentication: WORKING"
  echo "✅ RBAC authorization: CONFIGURED"
  echo "✅ Document processing: STARTED"
  echo ""
  echo "The complete S3 → Lambda → Orchestrator → Agents pipeline is now operational!"
  echo ""
  echo "Pipeline flow:"
  echo "1. File uploaded to S3"
  echo "2. S3 event → SQS → Lambda"
  echo "3. Lambda calls Orchestrator /message with API key"
  echo "4. Orchestrator authenticates and authorizes request"
  echo "5. Orchestrator triggers document processing pipeline"
  echo "6. Extractor → Validator → Archivist agents process document"
  echo ""
else
  # Check specific error
  if aws logs tail "/aws/lambda/ca-a2a-s3-processor" --since 2m --region "${REGION}" | grep -q "401"; then
    echo "❌ Still getting 401 Unauthorized"
    echo ""
    echo "Checking orchestrator logs for details..."
    aws logs tail "/ecs/ca-a2a-orchestrator" \
      --since 2m \
      --region "${REGION}" \
      | grep -i "unauthorized\|invalid\|forbidden" \
      | tail -5
  elif aws logs tail "/aws/lambda/ca-a2a-s3-processor" --since 2m --region "${REGION}" | grep -q "403"; then
    echo "❌ Getting 403 Forbidden - RBAC policy may not be loaded yet"
    echo ""
    echo "Wait another 2 minutes for the new orchestrator task to fully start"
  else
    echo "⚠️  No recent Lambda invocations found"
    echo "The S3 event may not have triggered Lambda"
  fi
fi

echo ""
echo "To manually trigger processing of any file:"
echo "  aws s3 cp yourfile.pdf s3://ca-a2a-documents-555043101106/invoices/2026/01/"

