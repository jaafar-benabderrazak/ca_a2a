#!/bin/bash
REGION="eu-west-3"
ACCOUNT_ID="555043101106"
TAG="native-mcp-complete-$(date +%Y%m%d%H%M%S)"

echo "============================================"
echo "DEPLOYING COMPLETE FIX"
echo "============================================"
echo ""
echo "This image includes:"
echo "  ✓ Fixed indentation in extractor_agent.py"
echo "  ✓ Native MCP implementation (no external server needed)"
echo ""

# Verify Python syntax
echo "1. Verifying Python syntax..."
python3 -m py_compile extractor_agent.py
if [ $? -eq 0 ]; then
    echo "   ✓ extractor_agent.py is valid"
else
    echo "   ✗ extractor_agent.py has syntax errors!"
    exit 1
fi

python3 -m py_compile mcp_context_auto.py
if [ $? -eq 0 ]; then
    echo "   ✓ mcp_context_auto.py is valid"
else
    echo "   ✗ mcp_context_auto.py has syntax errors!"
    exit 1
fi

# Build image
echo ""
echo "2. Building Docker image (--no-cache)..."
docker build --no-cache -t ca-a2a-extractor:${TAG} -f Dockerfile.extractor .

# Login to ECR
echo ""
echo "3. Logging into ECR..."
aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com

# Tag for ECR
echo ""
echo "4. Tagging image..."
docker tag ca-a2a-extractor:${TAG} ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/extractor:${TAG}
docker tag ca-a2a-extractor:${TAG} ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/extractor:latest

# Push to ECR
echo ""
echo "5. Pushing to ECR..."
docker push ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/extractor:${TAG}
docker push ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/extractor:latest

# Update ECS task definition
echo ""
echo "6. Updating ECS task definition..."
TASK_DEF=$(aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services extractor \
    --region ${REGION} \
    --query 'services[0].taskDefinition' \
    --output text)

aws ecs describe-task-definition \
    --task-definition ${TASK_DEF} \
    --region ${REGION} \
    --query 'taskDefinition' > taskdef.json

jq --arg IMG "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/extractor:${TAG}" \
    '.containerDefinitions[0].image = $IMG |
    del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy)' \
    taskdef.json > taskdef_new.json

NEW_TD=$(aws ecs register-task-definition \
    --cli-input-json file://taskdef_new.json \
    --region ${REGION} \
    --query 'taskDefinition.taskDefinitionArn' \
    --output text)

echo "   New task definition: $NEW_TD"

# Update service
echo ""
echo "7. Updating ECS service..."
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service extractor \
    --task-definition ${NEW_TD} \
    --force-new-deployment \
    --region ${REGION} > /dev/null

# Stop old tasks
echo ""
echo "8. Stopping old tasks..."
for TASK_ARN in $(aws ecs list-tasks --cluster ca-a2a-cluster --service-name extractor --region ${REGION} --query 'taskArns[]' --output text); do
    aws ecs stop-task --cluster ca-a2a-cluster --task ${TASK_ARN} --region ${REGION} --reason "Deploy complete fix" > /dev/null
    echo "   Stopped task"
done

echo ""
echo "9. Waiting 60 seconds for new tasks..."
sleep 60

echo ""
echo "============================================"
echo "DEPLOYMENT COMPLETE"
echo "============================================"
echo ""
echo "Checking status..."
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services extractor \
    --region ${REGION} \
    --query 'services[0].deployments[*].{Status:status,Running:runningCount,Desired:desiredCount,Image:taskDefinition}' \
    --output table

echo ""
echo "Recent logs (should show 'Using native MCP implementation'):"
aws logs tail /ecs/ca-a2a-extractor --since 1m --region ${REGION} | grep -E "native MCP|Extractor initialized|started successfully|ERROR|IndentationError" | tail -10

rm -f taskdef.json taskdef_new.json

echo ""
echo "✓ Deploy script complete!"
echo ""
echo "Next: Upload a PDF to test:"
echo "  aws s3 cp facture_acme_dec2025.pdf s3://ca-a2a-documents-555043101106/invoices/2026/01/test_\$(date +%s).pdf --region eu-west-3"

