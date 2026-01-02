#!/bin/bash
# Check orchestrator deployment status and retry test

set -e

REGION="${REGION:-eu-west-3}"
LAMBDA_NAME="ca-a2a-s3-processor"
CLUSTER="ca-a2a-cluster"
SERVICE="orchestrator"

echo "============================================"
echo "VERIFY ORCHESTRATOR DEPLOYMENT"
echo "============================================"
echo ""

# Check orchestrator service status
echo "1. Checking orchestrator service status..."
aws ecs describe-services \
  --cluster "${CLUSTER}" \
  --services "${SERVICE}" \
  --region "${REGION}" \
  --query 'services[0].{
    serviceName: serviceName,
    taskDefinition: taskDefinition,
    runningCount: runningCount,
    desiredCount: desiredCount,
    deployments: deployments[*].{status: status, taskDefinition: taskDefinition, runningCount: runningCount}
  }' \
  --output json

echo ""
echo "2. Checking running tasks..."
TASK_ARN=$(aws ecs list-tasks \
  --cluster "${CLUSTER}" \
  --service-name "${SERVICE}" \
  --region "${REGION}" \
  --desired-status RUNNING \
  --query 'taskArns[0]' \
  --output text)

if [ -z "$TASK_ARN" ] || [ "$TASK_ARN" = "None" ]; then
  echo "❌ No running tasks found!"
  echo ""
  echo "Checking stopped tasks..."
  aws ecs list-tasks \
    --cluster "${CLUSTER}" \
    --service-name "${SERVICE}" \
    --region "${REGION}" \
    --desired-status STOPPED \
    --query 'taskArns[0]' \
    --output text
  
  exit 1
fi

echo "Running task: ${TASK_ARN}"

# Get task details including environment variables
echo ""
echo "3. Checking task environment variables..."
TASK_DEF=$(aws ecs describe-tasks \
  --cluster "${CLUSTER}" \
  --tasks "${TASK_ARN}" \
  --region "${REGION}" \
  --query 'tasks[0].taskDefinitionArn' \
  --output text)

echo "Task definition: ${TASK_DEF}"

# Check if A2A_REQUIRE_AUTH and A2A_API_KEYS_JSON are set
aws ecs describe-task-definition \
  --task-definition "${TASK_DEF}" \
  --region "${REGION}" \
  --query 'taskDefinition.containerDefinitions[0].environment[?name==`A2A_REQUIRE_AUTH` || name==`A2A_API_KEYS_JSON`]' \
  --output json

echo ""
echo "4. Checking orchestrator logs for startup..."
aws logs tail "/ecs/ca-a2a-orchestrator" \
  --since 5m \
  --region "${REGION}" \
  --format short \
  | grep -E "started on|initialized|A2A_REQUIRE_AUTH|api.key" \
  | tail -10

echo ""
echo "============================================"
echo "CHECK LAMBDA CONFIGURATION"
echo "============================================"
echo ""

# Get Lambda environment to see the API key
echo "Lambda environment variables:"
aws lambda get-function-configuration \
  --function-name "${LAMBDA_NAME}" \
  --region "${REGION}" \
  --query 'Environment.Variables' \
  --output json

echo ""
echo "============================================"
echo "WAIT FOR DEPLOYMENT TO STABILIZE"
echo "============================================"
echo ""

# Wait for deployment to be PRIMARY
echo "Waiting for deployment to become PRIMARY..."
for i in {1..12}; do
  DEPLOYMENT_STATUS=$(aws ecs describe-services \
    --cluster "${CLUSTER}" \
    --services "${SERVICE}" \
    --region "${REGION}" \
    --query 'services[0].deployments[?status==`PRIMARY`].{taskDef: taskDefinition, running: runningCount, status: status}' \
    --output json)
  
  PRIMARY_COUNT=$(echo "$DEPLOYMENT_STATUS" | jq -r '.[0].running // 0')
  
  if [ "$PRIMARY_COUNT" -ge 1 ]; then
    echo "✓ Deployment is PRIMARY with ${PRIMARY_COUNT} running task(s)"
    break
  fi
  
  echo "  Attempt $i/12: Waiting... (current running: ${PRIMARY_COUNT})"
  sleep 10
done

echo ""
echo "============================================"
echo "RETRY TEST"
echo "============================================"
echo ""

# Create and upload new test file
cat > retry_test.pdf << 'EOF'
%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj
4 0 obj<</Length 200>>stream
BT
/F1 16 Tf
50 700 Td
(RETRY AUTHENTICATED TEST) Tj
/F1 12 Tf
50 650 Td
(After deployment stabilized) Tj
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
TEST_KEY="invoices/2026/01/retry_auth_${TIMESTAMP}.pdf"

echo "Uploading: ${TEST_KEY}"
aws s3 cp retry_test.pdf \
  "s3://ca-a2a-documents-555043101106/${TEST_KEY}" \
  --region "${REGION}"

rm -f retry_test.pdf

echo "✓ Uploaded"
echo ""
echo "Waiting 25 seconds for processing..."
sleep 25

echo ""
echo "============================================"
echo "LAMBDA LOGS (RETRY)"
echo "============================================"
aws logs tail "/aws/lambda/${LAMBDA_NAME}" \
  --since 1m \
  --region "${REGION}" \
  --format short \
  | grep -E "Processing|Orchestrator response|Success|Error|auth|API" \
  | tail -20

echo ""
echo "============================================"
echo "ORCHESTRATOR LOGS (RETRY)"
echo "============================================"
aws logs tail "/ecs/ca-a2a-orchestrator" \
  --since 1m \
  --region "${REGION}" \
  --format short \
  | grep -v "GET /health" \
  | grep -E "process_document|Starting document|POST /message|auth|Unauthorized" \
  | tail -20

echo ""
echo "============================================"
echo "ANALYSIS"
echo "============================================"
echo ""

# Check if we see success
SUCCESS_COUNT=$(aws logs tail "/aws/lambda/${LAMBDA_NAME}" --since 1m --region "${REGION}" --format short | grep -c "✓ Success" || echo "0")

if [ "$SUCCESS_COUNT" -gt 0 ]; then
  echo "🎉 SUCCESS! Pipeline is working with authentication!"
  echo ""
  echo "✓ Lambda → Orchestrator: AUTHENTICATED"
  echo "✓ Document processing: STARTED"
else
  echo "⚠️  Still getting authentication errors"
  echo ""
  echo "Possible issues:"
  echo "1. Old orchestrator task still running (deployment not complete)"
  echo "2. API key mismatch between Lambda and Orchestrator"
  echo "3. Environment variable not loaded by orchestrator"
  echo ""
  echo "Let's check the task definition one more time..."
  
  CURRENT_TASK_DEF=$(aws ecs describe-services \
    --cluster "${CLUSTER}" \
    --services "${SERVICE}" \
    --region "${REGION}" \
    --query 'services[0].taskDefinition' \
    --output text)
  
  echo "Current task definition: ${CURRENT_TASK_DEF}"
  echo ""
  echo "Environment variables in task definition:"
  aws ecs describe-task-definition \
    --task-definition "${CURRENT_TASK_DEF}" \
    --region "${REGION}" \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`A2A_REQUIRE_AUTH` || name==`A2A_API_KEYS_JSON`]' \
    --output table
fi

