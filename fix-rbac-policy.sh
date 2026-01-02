#!/bin/bash
# Debug API key authentication issue

set -e

REGION="${REGION:-eu-west-3}"
API_KEY="lambda-s3-processor-8874cd28a261935853ead29ce36bc4e0"

echo "============================================"
echo "DEBUG API KEY AUTHENTICATION"
echo "============================================"
echo ""

# Calculate SHA256 hash locally to compare
echo "1. Calculate SHA256 hash of API key..."
LOCAL_HASH=$(echo -n "${API_KEY}" | sha256sum | cut -d' ' -f1)
echo "API Key: ${API_KEY}"
echo "SHA256:  ${LOCAL_HASH}"

echo ""
echo "2. Check what orchestrator sees..."
echo ""
echo "Orchestrator environment variables:"
aws ecs describe-task-definition \
  --task-definition "arn:aws:ecs:eu-west-3:555043101106:task-definition/ca-a2a-orchestrator:12" \
  --region "${REGION}" \
  --query 'taskDefinition.containerDefinitions[0].environment[?contains(name, `A2A`)]' \
  --output json | jq -r '.[] | "\(.name)=\(.value)"'

echo ""
echo "3. Check RBAC policy..."
RBAC_POLICY=$(aws ecs describe-task-definition \
  --task-definition "arn:aws:ecs:eu-west-3:555043101106:task-definition/ca-a2a-orchestrator:12" \
  --region "${REGION}" \
  --query 'taskDefinition.containerDefinitions[0].environment[?name==`A2A_RBAC_POLICY_JSON`].value' \
  --output text)

if [ -z "$RBAC_POLICY" ] || [ "$RBAC_POLICY" = "None" ]; then
  echo "⚠️  No RBAC policy configured (A2A_RBAC_POLICY_JSON not set)"
  echo ""
  echo "By default, if RBAC is empty, all methods may be denied!"
  echo "We need to add an RBAC policy that allows lambda-s3-processor to call process_document"
else
  echo "RBAC Policy: ${RBAC_POLICY}"
fi

echo ""
echo "============================================"
echo "FIX: ADD RBAC POLICY"
echo "============================================"
echo ""

# The RBAC policy needs to allow "lambda-s3-processor" to call methods
RBAC_JSON='{"allow":{"lambda-s3-processor":["*"]},"deny":{}}'

echo "Adding RBAC policy: ${RBAC_JSON}"
echo ""

# Download current task definition
aws ecs describe-task-definition \
  --task-definition "arn:aws:ecs:eu-west-3:555043101106:task-definition/ca-a2a-orchestrator:12" \
  --region "${REGION}" \
  --query 'taskDefinition' \
  > taskdef_with_rbac.json

# Add RBAC policy
jq --arg rbac "${RBAC_JSON}" '
  {
    family: .family,
    taskRoleArn: .taskRoleArn,
    executionRoleArn: .executionRoleArn,
    networkMode: .networkMode,
    containerDefinitions: [
      .containerDefinitions[] | 
      if .name == "orchestrator" then
        . + {
          environment: (
            (.environment // []) |
            map(select(.name != "A2A_RBAC_POLICY_JSON")) +
            [{name: "A2A_RBAC_POLICY_JSON", value: $rbac}]
          )
        }
      else . end
    ],
    requiresCompatibilities: .requiresCompatibilities,
    cpu: .cpu,
    memory: .memory
  }
' taskdef_with_rbac.json > taskdef_with_rbac_updated.json

echo "Registering task definition with RBAC policy..."
NEW_TASK_DEF=$(aws ecs register-task-definition \
  --cli-input-json file://taskdef_with_rbac_updated.json \
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
  --output json | jq -r '.service.{name: serviceName, taskDef: taskDefinition}'

# Cleanup
rm -f taskdef_with_rbac.json taskdef_with_rbac_updated.json

echo ""
echo "✓ RBAC policy added"
echo ""
echo "Waiting 60 seconds for deployment..."
sleep 60

echo ""
echo "============================================"
echo "TEST WITH RBAC"
echo "============================================"
echo ""

# Upload test file
cat > rbac_test.pdf << 'EOF'
%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj
4 0 obj<</Length 180>>stream
BT
/F1 16 Tf
50 700 Td
(RBAC POLICY TEST) Tj
/F1 12 Tf
50 650 Td
(With permissions configured) Tj
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
TEST_KEY="invoices/2026/01/rbac_test_${TIMESTAMP}.pdf"

echo "Uploading: ${TEST_KEY}"
aws s3 cp rbac_test.pdf \
  "s3://ca-a2a-documents-555043101106/${TEST_KEY}" \
  --region "${REGION}"

rm -f rbac_test.pdf

echo "✓ Uploaded"
echo ""
echo "Waiting 25 seconds for processing..."
sleep 25

echo ""
echo "============================================"
echo "LAMBDA LOGS"
echo "============================================"
aws logs tail "/aws/lambda/ca-a2a-s3-processor" \
  --since 1m \
  --region "${REGION}" \
  --format short \
  | grep -E "Processing|Orchestrator response|Success|Error|200|401" \
  | tail -15

echo ""
echo "============================================"
echo "ORCHESTRATOR LOGS"
echo "============================================"
aws logs tail "/ecs/ca-a2a-orchestrator" \
  --since 1m \
  --region "${REGION}" \
  --format short \
  | grep -v "GET /health" \
  | grep -E "process_document|Starting document|POST /message|Unauthorized|auth" \
  | tail -15

echo ""
echo "============================================"
echo "RESULT"
echo "============================================"
echo ""

# Check for success
if aws logs tail "/aws/lambda/ca-a2a-s3-processor" --since 1m --region "${REGION}" | grep -q "✓ Success"; then
  echo "🎉 SUCCESS! API key authentication with RBAC is working!"
  echo ""
  echo "✓ Lambda authenticated with API key"
  echo "✓ RBAC policy allows lambda-s3-processor to call methods"
  echo "✓ Document processing pipeline is operational"
else
  echo "⚠️  Still having issues. Let's check the orchestrator startup logs..."
  echo ""
  aws logs tail "/ecs/ca-a2a-orchestrator" \
    --since 3m \
    --region "${REGION}" \
    | grep -E "A2A|RBAC|api.key|require.auth" \
    | tail -20
fi

