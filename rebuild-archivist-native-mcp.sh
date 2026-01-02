#!/bin/bash
REGION="eu-west-3"
ACCOUNT_ID="555043101106"
TAG="native-mcp-$(date +%Y%m%d%H%M%S)"

echo "============================================"
echo "REBUILDING ARCHIVIST WITH NATIVE MCP"
echo "============================================"
echo ""

# Verify Python files
echo "1. Verifying Python code..."
python3 -m py_compile archivist_agent.py && echo "  ✓ archivist_agent.py valid" || exit 1
python3 -m py_compile mcp_context_auto.py && echo "  ✓ mcp_context_auto.py valid" || exit 1
python3 -m py_compile mcp_protocol.py && echo "  ✓ mcp_protocol.py valid" || exit 1

# Build image
echo ""
echo "2. Building Docker image (--no-cache)..."
docker build --no-cache --pull -t ca-a2a-archivist:${TAG} -f Dockerfile.archivist .

if [ $? -ne 0 ]; then
    echo "  ✗ Build failed!"
    exit 1
fi
echo "  ✓ Image built: ca-a2a-archivist:${TAG}"

# Login to ECR
echo ""
echo "3. Logging into ECR..."
aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com

# Tag
echo ""
echo "4. Tagging for ECR..."
docker tag ca-a2a-archivist:${TAG} ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/archivist:${TAG}
docker tag ca-a2a-archivist:${TAG} ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/archivist:latest

# Push
echo ""
echo "5. Pushing to ECR..."
docker push ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/archivist:${TAG}
docker push ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/archivist:latest

# Update task definition
echo ""
echo "6. Updating ECS task definition..."
TASK_DEF=$(aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services archivist \
    --region ${REGION} \
    --query 'services[0].taskDefinition' \
    --output text)

aws ecs describe-task-definition \
    --task-definition ${TASK_DEF} \
    --region ${REGION} \
    --query 'taskDefinition' > taskdef.json

jq --arg IMG "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/archivist:${TAG}" \
    '.containerDefinitions[0].image = $IMG |
    .containerDefinitions[0].environment = [.containerDefinitions[0].environment[] | select(.name!="MCP_SERVER_URL")] |
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
echo "7. Updating ECS service..."
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service archivist \
    --task-definition ${NEW_TD} \
    --force-new-deployment \
    --region ${REGION} > /dev/null

echo "  ✓ Service updated"

# Stop old tasks
echo ""
echo "8. Stopping old tasks..."
for TASK_ARN in $(aws ecs list-tasks --cluster ca-a2a-cluster --service-name archivist --region ${REGION} --query 'taskArns[]' --output text); do
    aws ecs stop-task --cluster ca-a2a-cluster --task ${TASK_ARN} --region ${REGION} --reason "Native MCP rebuild" > /dev/null
    echo "  Stopped task"
done

echo ""
echo "9. Waiting 70 seconds for new tasks..."
sleep 70

echo ""
echo "============================================"
echo "DEPLOYMENT STATUS"
echo "============================================"
echo ""

aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services archivist \
    --region ${REGION} \
    --query 'services[0].{Running:runningCount,Desired:desiredCount}' \
    --output table

echo ""
echo "Recent logs (should show 'Using native MCP implementation'):"
aws logs tail /ecs/ca-a2a-archivist --since 2m --region ${REGION} | grep -E "native MCP|PostgreSQL resource|MCP context|Archivist initialized|Cannot connect|ERROR" | tail -20

rm -f taskdef.json taskdef_new.json

echo ""
echo "============================================"
echo "✓ ARCHIVIST REBUILD COMPLETE"
echo "============================================"
echo ""
echo "Test the full pipeline:"
echo "  cd ~/ca_a2a"
echo "  ./test-full-pipeline.sh"

