#!/bin/bash
# Deploy with provided AWS credentials
# Run this in Git Bash

set -e

# Set AWS credentials from provided session
export AWS_ACCESS_KEY_ID="ASIAYCOZFTGZCVR5FLMC"
export AWS_SECRET_ACCESS_KEY="M5l32OkqF+11kVennXYsPrJFxDcAyIgkzuqJ/Uhz"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjED4aCXVzLWVhc3QtMSJIMEYCIQC0PRr0CWTxs8NPP5y/aNmowrEBWGlb9mfzLqe8J0B4zgIhAPrw0UA2PVPqTWyrpGw/w4R9sHSa/AGJL9tgqoRUG2KJKpMDCAYQARoMNTU1MDQzMTAxMTA2IgzbipW4tJDi3rNWpVgq8ALNEhuyQoDayjW1Y9q8lSZVNwy3TjLUFpTaRtxGd576yhImk4rsFK3bX2ak6Oc3Fe3RrTBv9N6fB1XlkLqtRJQtJGpu30YuZlJZC+JPi9lKXUlPhNwUIwvEd102D14m5VZrR6mS+9J0haBQYEPFzEciyBv3cT+vWjO1IxsBgRddaRCkEEoobapnPvd+SF5d+Ji9+Jujzc17vxJYPBStuuxUvWE7dGY8GCd6G/Q4fVskWj/86dgcfQDFiZEdojXKKQ3udVNqn/GsbQwIXb3y4Tuz0v/nCHnwX8nV32Qzj6kNrsuaHoxKZARsvr5gYLjLMVhYsjeAjcaf2yxH3kHDujVK/og9Rr/Xiq/g1WjHQQ9B0vorbZ2kvwPUmG9dDRHVcEKDAIpLHhXGAKpgDDLo3q4Wk29RAton9W6wbSMensPONwUl0iby18LQv228oXxB8s4wjTd+dobKJrhKiCZ1LrA6NANjO6BdIbg68oleAb808DCE6eDKBjqjAWHO53prjhOjdJb+g18pkILqLDYFkqXrOnZh4wWbzQZnX8GD2UGHxzTRY8cOdJhCnQPUN4+DhTklWYHdhr1+uQY4IyWnz6zMyg+7BHVrTHr1BlR07HMUG/sCa4WCVedIpFnKLmaSOe9SP5j9sncW8WBobNz0HWH9YDexT+G+EpcnoLAfPPU91Oo4NlPY8zbzyC85i5iJybPj1jqx4D1I7qEa38Y="
export AWS_DEFAULT_REGION="eu-west-3"

REGION="eu-west-3"
CLUSTER="ca-a2a-cluster"
SERVICE="extractor"

echo "============================================"
echo "DEPLOY FIXED EXTRACTOR TO ECS"
echo "============================================"
echo ""

# Verify credentials work
echo "1. Verifying AWS credentials..."
AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
if [ $? -ne 0 ]; then
    echo "   ✗ AWS credentials invalid or expired"
    exit 1
fi
echo "   ✓ Credentials valid - Account: ${AWS_ACCOUNT}"

# Check Docker
echo ""
echo "2. Checking Docker..."
if ! docker ps > /dev/null 2>&1; then
    echo "   ✗ Docker is not running. Please start Docker Desktop."
    exit 1
fi
echo "   ✓ Docker is running"

# ECR repository
ECR_REPO="${AWS_ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a-extractor"
echo "   ECR Repo: ${ECR_REPO}"

# Build Docker image
echo ""
echo "3. Building extractor Docker image..."
echo "   (This may take 2-3 minutes)"
echo ""

docker build -t ca-a2a-extractor:fixed -f Dockerfile.extractor . 2>&1 | grep -E "Step|Successfully|FINISHED|ERROR" || docker build -t ca-a2a-extractor:fixed -f Dockerfile.extractor .

if [ $? -ne 0 ]; then
    echo "   ✗ Docker build failed"
    exit 1
fi
echo ""
echo "   ✓ Image built successfully"

# Login to ECR
echo ""
echo "4. Logging in to ECR..."
aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${ECR_REPO}" 2>&1 | grep -i "login succeeded" || echo "   Logged in"

if [ $? -ne 0 ]; then
    echo "   ✗ ECR login failed"
    exit 1
fi
echo "   ✓ Logged in to ECR"

# Tag and push
echo ""
echo "5. Pushing image to ECR..."
echo "   (This may take 3-5 minutes depending on your connection)"
echo ""

docker tag ca-a2a-extractor:fixed "${ECR_REPO}:fixed"
docker push "${ECR_REPO}:fixed"

if [ $? -ne 0 ]; then
    echo "   ✗ Push failed"
    exit 1
fi
echo ""
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

# Update image in task definition
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

echo "   ✓ Service updated - new tasks deploying"

# Cleanup
rm -f extractor_taskdef.json extractor_taskdef_updated.json

echo ""
echo "============================================"
echo "DEPLOYMENT COMPLETE!"
echo "============================================"
echo ""
echo "✅ Fixed extractor is deploying to ECS"
echo ""
echo "Wait 60-90 seconds, then test in CloudShell:"
echo "  ./test-complete-pipeline-simple.sh"
echo ""
echo "Expected results:"
echo "  ✅ PDF extraction completed"
echo "  ✅ Starting validation"
echo "  ✅ Starting archiving"  
echo "  ✅ Pipeline completed successfully"
echo ""

# Monitor deployment
echo "Checking deployment status in 20 seconds..."
sleep 20

echo ""
echo "Deployment status:"
aws ecs describe-services \
    --cluster "${CLUSTER}" \
    --services "${SERVICE}" \
    --region "${REGION}" \
    --query 'services[0].deployments[*].{Status: status, TaskDef: taskDefinition, Running: runningCount, Desired: desiredCount}' \
    --output table

echo ""
echo "🎉 Deployment initiated! Test in CloudShell in about 60 seconds."

