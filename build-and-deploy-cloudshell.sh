#!/bin/bash
REGION="eu-west-3"
ACCOUNT_ID="555043101106"
TAG="final-working-$(date +%Y%m%d%H%M%S)"

echo "============================================"
echo "BUILDING AND DEPLOYING FROM CLOUDSHELL"
echo "============================================"
echo ""

# Verify files are in CloudShell
if [ ! -f "extractor_agent.py" ]; then
    echo "ERROR: extractor_agent.py not found!"
    echo "Please run: git pull"
    exit 1
fi

# Verify Python syntax
echo "1. Verifying Python syntax..."
python3 -m py_compile extractor_agent.py
if [ $? -ne 0 ]; then
    echo "  ✗ extractor_agent.py has errors!"
    exit 1
fi
echo "  ✓ extractor_agent.py is valid"

python3 -m py_compile mcp_context_auto.py
if [ $? -ne 0 ]; then
    echo "  ✗ mcp_context_auto.py has errors!"
    exit 1
fi
echo "  ✓ mcp_context_auto.py is valid"

# Show critical lines
echo ""
echo "2. Verifying indentation..."
echo "   Lines 313-315 of extractor_agent.py:"
sed -n '313,315p' extractor_agent.py | cat -A | head -3

# Build Docker image (no cache!)
echo ""
echo "3. Building Docker image (--no-cache, --pull)..."
docker build --no-cache --pull -t ca-a2a-extractor:${TAG} -f Dockerfile.extractor .

if [ $? -ne 0 ]; then
    echo "  ✗ Docker build failed!"
    exit 1
fi
echo "  ✓ Image built: ca-a2a-extractor:${TAG}"

# Login to ECR
echo ""
echo "4. Logging into ECR..."
aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com

# Tag
echo ""
echo "5. Tagging for ECR..."
docker tag ca-a2a-extractor:${TAG} ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/extractor:${TAG}
docker tag ca-a2a-extractor:${TAG} ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/extractor:latest

# Push
echo ""
echo "6. Pushing to ECR..."
docker push ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/extractor:${TAG}
docker push ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/extractor:latest

# Update task definition
echo ""
echo "7. Updating ECS task definition..."
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

echo "  ✓ New task definition: $NEW_TD"

# Update service
echo ""
echo "8. Updating ECS service..."
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service extractor \
    --task-definition ${NEW_TD} \
    --force-new-deployment \
    --region ${REGION} > /dev/null

# Stop old tasks
echo ""
echo "9. Stopping old tasks..."
for TASK_ARN in $(aws ecs list-tasks --cluster ca-a2a-cluster --service-name extractor --region ${REGION} --query 'taskArns[]' --output text); do
    aws ecs stop-task --cluster ca-a2a-cluster --task ${TASK_ARN} --region ${REGION} --reason "Deploy ${TAG}" > /dev/null
    echo "  Stopped task"
done

echo ""
echo "10. Waiting 70 seconds for new tasks to start..."
sleep 70

echo ""
echo "============================================"
echo "DEPLOYMENT STATUS"
echo "============================================"
echo ""

aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services extractor \
    --region ${REGION} \
    --query 'services[0].deployments[*].{Status:status,Running:runningCount,Desired:desiredCount,TaskDef:taskDefinition}' \
    --output table

echo ""
echo "Recent logs (should show NO IndentationError):"
aws logs tail /ecs/ca-a2a-extractor --since 2m --region ${REGION} | tail -30

rm -f taskdef.json taskdef_new.json

echo ""
echo "============================================"
echo "✓ BUILD AND DEPLOY COMPLETE!"
echo "============================================"
echo ""
echo "Image: ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/extractor:${TAG}"
echo ""
echo "If logs show 'Using native MCP implementation' and NO errors:"
echo "  Run: chmod +x test-full-pipeline.sh && ./test-full-pipeline.sh"

