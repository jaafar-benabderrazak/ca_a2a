#!/bin/bash
# Quick fix: Disable authentication for S3→Lambda→Orchestrator pipeline testing

set -e

REGION="${REGION:-eu-west-3}"
CLUSTER="ca-a2a-cluster"
SERVICE="orchestrator"

echo "============================================"
echo "DISABLE AUTH FOR TESTING (QUICK FIX)"
echo "============================================"
echo ""
echo "This temporarily disables A2A_REQUIRE_AUTH for testing."
echo "For production, use proper authentication (see fix-lambda-auth-proper.sh)"
echo ""

# Get current task definition
echo "Getting current orchestrator task definition..."
TASK_DEF_ARN=$(aws ecs describe-services \
  --cluster "${CLUSTER}" \
  --services "${SERVICE}" \
  --region "${REGION}" \
  --query 'services[0].taskDefinition' \
  --output text)

echo "Current task definition: ${TASK_DEF_ARN}"

# Download task definition
aws ecs describe-task-definition \
  --task-definition "${TASK_DEF_ARN}" \
  --region "${REGION}" \
  --query 'taskDefinition' \
  > current_taskdef.json

# Extract essential fields and add/update A2A_REQUIRE_AUTH=false
jq '
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
          map(select(.name != "A2A_REQUIRE_AUTH")) + 
          [{name: "A2A_REQUIRE_AUTH", value: "false"}]
        )
      else . end
    ],
    requiresCompatibilities: .requiresCompatibilities,
    cpu: .cpu,
    memory: .memory
  }
' current_taskdef.json > updated_taskdef.json

echo ""
echo "Registering new task definition with A2A_REQUIRE_AUTH=false..."
NEW_TASK_DEF=$(aws ecs register-task-definition \
  --cli-input-json file://updated_taskdef.json \
  --region "${REGION}" \
  --query 'taskDefinition.taskDefinitionArn' \
  --output text)

echo "New task definition: ${NEW_TASK_DEF}"

echo ""
echo "Updating orchestrator service..."
aws ecs update-service \
  --cluster "${CLUSTER}" \
  --service "${SERVICE}" \
  --task-definition "${NEW_TASK_DEF}" \
  --region "${REGION}" \
  --force-new-deployment \
  --query 'service.{serviceName: serviceName, taskDefinition: taskDefinition, desiredCount: desiredCount}' \
  --output json

# Cleanup
rm -f current_taskdef.json updated_taskdef.json

echo ""
echo "✓ Orchestrator service updated"
echo ""
echo "Waiting 60 seconds for new task to start..."
sleep 60

echo ""
echo "Checking new task status..."
aws ecs list-tasks \
  --cluster "${CLUSTER}" \
  --service-name "${SERVICE}" \
  --region "${REGION}" \
  --desired-status RUNNING \
  --query 'taskArns[0]' \
  --output text

echo ""
echo "============================================"
echo "TESTING PIPELINE"
echo "============================================"
echo ""

# Upload test file
cat > auth_test.pdf << 'EOF'
%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj
4 0 obj<</Length 200>>stream
BT
/F1 16 Tf
50 700 Td
(AUTH DISABLED TEST) Tj
/F1 12 Tf
50 650 Td
(Testing without authentication) Tj
50 630 Td
(Date: 02 Jan 2026) Tj
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
TEST_KEY="invoices/2026/01/auth_test_${TIMESTAMP}.pdf"

echo "Uploading: ${TEST_KEY}"
aws s3 cp auth_test.pdf \
  "s3://ca-a2a-documents-555043101106/${TEST_KEY}" \
  --region "${REGION}"

rm -f auth_test.pdf

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
  | grep -E "Processing|Orchestrator|Success|Error|401|200" \
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
  | grep -E "process_document|Starting document|POST /message|Unauthorized" \
  | tail -20

echo ""
echo "============================================"
echo "SUMMARY"
echo "============================================"
echo "✓ A2A_REQUIRE_AUTH set to false"
echo "✓ Orchestrator redeployed"
echo "✓ Test file uploaded"
echo ""
echo "If you see HTTP 200 and 'Starting document' in logs,"
echo "the pipeline is working!"
echo ""
echo "⚠️  SECURITY WARNING:"
echo "Auth is disabled. For production, run:"
echo "  ./fix-lambda-auth-proper.sh"

