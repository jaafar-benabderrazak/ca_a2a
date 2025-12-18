#!/bin/bash
# Check ECS deployment status and redeploy if needed

set -e

export AWS_REGION="eu-west-3"
export AWS_PROFILE="reply-sso"

echo "=========================================="
echo "Check ECS Deployment Status"
echo "=========================================="
echo ""

# Check if cluster exists
echo "[1/4] Checking ECS cluster..."
CLUSTER_STATUS=$(aws ecs describe-clusters \
    --clusters ca-a2a-cluster \
    --region $AWS_REGION \
    --query 'clusters[0].status' \
    --output text 2>&1)

if [[ $CLUSTER_STATUS == "ACTIVE" ]]; then
    echo "✓ Cluster exists: ca-a2a-cluster"
else
    echo "✗ Cluster not found: $CLUSTER_STATUS"
    echo "  Need to run full deployment: ./deploy-sso-phase1.sh then ./deploy-sso-phase2.sh"
    exit 1
fi

echo ""

# Check which services exist
echo "[2/4] Checking ECS services..."
SERVICES=$(aws ecs list-services \
    --cluster ca-a2a-cluster \
    --region $AWS_REGION \
    --query 'serviceArns' \
    --output text 2>&1)

if [ -z "$SERVICES" ]; then
    echo "✗ No services found in cluster"
    echo "  Need to run: ./deploy-sso-phase2.sh"
    exit 1
fi

echo "Found services:"
aws ecs list-services \
    --cluster ca-a2a-cluster \
    --region $AWS_REGION \
    --query 'serviceArns[*]' \
    --output table

echo ""

# Get service status
echo "[3/4] Checking service status..."
for service in extractor validator archivist; do
    STATUS=$(aws ecs describe-services \
        --cluster ca-a2a-cluster \
        --services ${service} \
        --region $AWS_REGION \
        --query 'services[0].[serviceName,runningCount,desiredCount]' \
        --output text 2>&1)
    
    if [[ $STATUS == *"ServiceNotFoundException"* ]]; then
        echo "  ✗ ${service}: NOT FOUND"
    else
        echo "  ${service}: ${STATUS}"
    fi
done

echo ""

# Check task definitions
echo "[4/4] Checking task definitions..."
for agent in orchestrator extractor validator archivist; do
    TD_STATUS=$(aws ecs describe-task-definition \
        --task-definition ca-a2a-${agent} \
        --region $AWS_REGION \
        --query 'taskDefinition.family' \
        --output text 2>&1)
    
    if [[ $TD_STATUS == *"Unable to describe"* ]]; then
        echo "  ✗ ca-a2a-${agent}: NOT FOUND"
    else
        echo "  ✓ ca-a2a-${agent}: EXISTS"
    fi
done

echo ""
echo "=========================================="
echo "Recommendation:"
echo "=========================================="
echo ""
echo "If services are missing, run Phase 2 deployment:"
echo "  ./deploy-sso-phase2.sh"
echo ""
echo "If services exist but tasks failing, run:"
echo "  ./complete-ecs-fix.sh"
echo ""

