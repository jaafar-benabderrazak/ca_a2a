#!/bin/bash
set -e

export AWS_PROFILE=reply-sso
export AWS_REGION=eu-west-3
export ACCOUNT_ID="555043101106"
export PROJECT_NAME="ca-a2a"
export ECR_REPO="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}-agents"
export CLUSTER="${PROJECT_NAME}-cluster"

echo "=========================================="
echo "Rebuild and Redeploy Extractor"
echo "=========================================="
echo ""

# Step 1: Login to ECR
echo "[1/5] Logging in to ECR..."
aws ecr get-login-password --region ${AWS_REGION} --profile ${AWS_PROFILE} | docker login --username AWS --password-stdin ${ECR_REPO}
echo "  ✓ Logged in to ECR"

# Step 2: Build Docker image with pandas
echo ""
echo "[2/5] Building Docker image with updated requirements..."
docker build -t ${PROJECT_NAME}-agents:latest .
echo "  ✓ Image built"

# Step 3: Tag image
echo ""
echo "[3/5] Tagging image for ECR..."
docker tag ${PROJECT_NAME}-agents:latest ${ECR_REPO}:latest
docker tag ${PROJECT_NAME}-agents:latest ${ECR_REPO}:$(date +%Y%m%d-%H%M%S)
echo "  ✓ Image tagged"

# Step 4: Push to ECR
echo ""
echo "[4/5] Pushing image to ECR..."
docker push ${ECR_REPO}:latest
echo "  ✓ Image pushed"

# Step 5: Force redeploy extractor service
echo ""
echo "[5/5] Forcing extractor service redeployment..."
aws ecs update-service \
    --cluster ${CLUSTER} \
    --service extractor \
    --force-new-deployment \
    --region ${AWS_REGION} \
    --profile ${AWS_PROFILE} > /dev/null
echo "  ✓ Redeployment triggered"

echo ""
echo "=========================================="
echo "Waiting 90 seconds for new tasks to start..."
echo "=========================================="
sleep 90

echo ""
echo "=========================================="
echo "Service Status"
echo "=========================================="
aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services extractor \
    --region ${AWS_REGION} \
    --query 'services[*].[serviceName,runningCount,desiredCount,deployments[0].status]' \
    --output table \
    --profile ${AWS_PROFILE}

echo ""
echo "=========================================="
echo "Latest events:"
echo "=========================================="
aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services extractor \
    --region ${AWS_REGION} \
    --query 'services[0].events[0:3].[message]' \
    --output text \
    --profile ${AWS_PROFILE}

echo ""
echo "=========================================="
echo "Check logs with:"
echo "=========================================="
echo "aws logs tail /ecs/ca-a2a-extractor --since 5m --follow --region ${AWS_REGION} --profile ${AWS_PROFILE}"
echo ""

