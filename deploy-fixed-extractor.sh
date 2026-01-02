#!/bin/bash
# Deploy Fixed Extractor to AWS ECS
# Run this on your local machine with Docker installed

set -e

REGION="${REGION:-eu-west-3}"
CLUSTER="ca-a2a-cluster"
SERVICE="extractor"

echo "============================================"
echo "DEPLOY FIXED EXTRACTOR TO ECS"
echo "============================================"
echo ""

# Check Docker is running
echo "1. Checking Docker..."
if ! docker ps > /dev/null 2>&1; then
    echo "   ✗ Docker is not running. Please start Docker Desktop."
    exit 1
fi
echo "   ✓ Docker is running"

# Get AWS account
echo ""
echo "2. Getting AWS account info..."
AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
ECR_REPO="${AWS_ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a-extractor"
echo "   Account: ${AWS_ACCOUNT}"
echo "   ECR Repo: ${ECR_REPO}"

# Build Docker image
echo ""
echo "3. Building extractor Docker image..."
echo "   (This may take 2-3 minutes)"

docker build -t ca-a2a-extractor:fixed -f Dockerfile.extractor .

echo "   ✓ Image built successfully"

# Login to ECR
echo ""
echo "4. Logging in to ECR..."
aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${ECR_REPO}"

echo "   ✓ Logged in to ECR"

# Tag and push
echo ""
echo "5. Pushing image to ECR..."
echo "   (This may take 3-5 minutes depending on your connection)"

docker tag ca-a2a-extractor:fixed "${ECR_REPO}:fixed"
docker push "${ECR_REPO}:fixed"

echo "   ✓ Image pushed to ECR"

# Get current task definition
echo ""
echo "6. Updating ECS task definition..."

TASK_DEF_ARN=$(aws ecs describe-services \
    --cluster "${CLUSTER}" \
    --services "${SERVICE}" \
    --region "${REGION}" \
    --query 'services[0].taskDefinition' \
    --output text)

echo "   Current: ${TASK_DEF_ARN}"

# Download current task definition
aws ecs describe-task-definition \
    --task-definition "${TASK_DEF_ARN}" \
    --region "${REGION}" \
    --query 'taskDefinition' > extractor_taskdef.json

# Update image in task definition using jq
jq --arg image "${ECR_REPO}:fixed" '
    .containerDefinitions[0].image = $image |
    del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy)
' extractor_taskdef.json > extractor_taskdef_updated.json

# Register new task definition
echo "   Registering new task definition..."
NEW_TASK_DEF=$(aws ecs register-task-definition \
    --cli-input-json file://extractor_taskdef_updated.json \
    --region "${REGION}" \
    --query 'taskDefinition.taskDefinitionArn' \
    --output text)

echo "   New: ${NEW_TASK_DEF}"

# Update ECS service
echo ""
echo "7. Updating ECS service..."
aws ecs update-service \
    --cluster "${CLUSTER}" \
    --service "${SERVICE}" \
    --task-definition "${NEW_TASK_DEF}" \
    --force-new-deployment \
    --region "${REGION}" > /dev/null

echo "   ✓ Service updated - new tasks will start deploying"

# Cleanup
rm -f extractor_taskdef.json extractor_taskdef_updated.json

echo ""
echo "============================================"
echo "DEPLOYMENT INITIATED"
echo "============================================"
echo ""
echo "The fixed extractor is now deploying to ECS."
echo ""
echo "Wait 60-90 seconds for the new tasks to start, then run in CloudShell:"
echo "  ./test-complete-pipeline-simple.sh"
echo ""
echo "You should then see:"
echo "  ✅ PDF extraction completed"
echo "  ✅ Starting validation"
echo "  ✅ Starting archiving"
echo "  ✅ Pipeline completed successfully"
echo ""
echo "To monitor deployment:"
echo "  aws ecs describe-services --cluster ${CLUSTER} --services ${SERVICE} --region ${REGION} --query 'services[0].deployments'"
echo ""

# Wait and check status
echo "Waiting 15 seconds before checking deployment status..."
sleep 15

echo ""
echo "============================================"
echo "DEPLOYMENT STATUS"
echo "============================================"
aws ecs describe-services \
    --cluster "${CLUSTER}" \
    --services "${SERVICE}" \
    --region "${REGION}" \
    --query 'services[0].deployments[*].{Status: status, TaskDef: taskDefinition, Running: runningCount, Desired: desiredCount}' \
    --output table

echo ""
echo "Deployment in progress. New tasks with fixed code will start shortly."
echo ""
echo "Run './test-complete-pipeline-simple.sh' in CloudShell in about 60 seconds!"

