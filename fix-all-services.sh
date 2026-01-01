#!/bin/bash
# Complete fix: Create orchestrator service and restart all services

set -e

export AWS_REGION="eu-west-3"
export AWS_PROFILE="reply-sso"

# Load configuration
source ca-a2a-config.env

echo "=========================================="
echo "Complete ECS Deployment Fix"
echo "=========================================="
echo ""

# Step 1: Create orchestrator service (missing)
echo "[1/4] Creating orchestrator service..."
ORCH_EXISTS=$(aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator \
    --region $AWS_REGION \
    --query 'services[0].serviceName' \
    --output text 2>&1 || echo "NOT_FOUND")

if [[ $ORCH_EXISTS == "NOT_FOUND" ]] || [[ $ORCH_EXISTS == "" ]]; then
    echo "  Creating orchestrator service with ALB..."
    
    aws ecs create-service \
        --cluster ca-a2a-cluster \
        --service-name orchestrator \
        --task-definition ca-a2a-orchestrator \
        --desired-count 2 \
        --launch-type FARGATE \
        --platform-version LATEST \
        --network-configuration "awsvpcConfiguration={subnets=[${PRIVATE_SUBNET_1},${PRIVATE_SUBNET_2}],securityGroups=[${ORCHESTRATOR_SG}],assignPublicIp=DISABLED}" \
        --load-balancers "targetGroupArn=${TG_ARN},containerName=orchestrator,containerPort=8001" \
        --health-check-grace-period-seconds 60 \
        --region $AWS_REGION
    
    echo "  ✓ Orchestrator service created"
else
    echo "  ✓ Orchestrator service already exists"
fi

echo ""

# Step 2: Wait for IAM/VPC propagation
echo "[2/4] Waiting 30 seconds for everything to stabilize..."
sleep 30

# Step 3: Stop all failing tasks
echo "[3/4] Stopping all failing tasks..."
for service in extractor validator archivist; do
    echo "  Stopping tasks for ${service}..."
    TASK_ARNS=$(aws ecs list-tasks \
        --cluster ca-a2a-cluster \
        --service-name ${service} \
        --region $AWS_REGION \
        --query 'taskArns' \
        --output text 2>&1 || echo "")
    
    if [ -n "$TASK_ARNS" ]; then
        for task in $TASK_ARNS; do
            aws ecs stop-task \
                --cluster ca-a2a-cluster \
                --task ${task} \
                --region $AWS_REGION \
                --output text > /dev/null 2>&1 || true
        done
        echo "    ✓ Stopped tasks for ${service}"
    else
        echo "    ℹ No running tasks for ${service}"
    fi
done

echo ""

# Step 4: Force new deployment for all services
echo "[4/4] Forcing new deployment for all services..."
for service in orchestrator extractor validator archivist; do
    echo "  Deploying ${service}..."
    aws ecs update-service \
        --cluster ca-a2a-cluster \
        --service ${service} \
        --force-new-deployment \
        --region $AWS_REGION \
        --output text > /dev/null 2>&1 || echo "    ⚠ ${service} service not found, skipping"
    echo "    ✓ Deployment triggered"
done

echo ""
echo "=========================================="
echo "Waiting 2 minutes for tasks to start..."
echo "=========================================="
sleep 120

# Check final status
echo ""
echo "=========================================="
echo "Final Status"
echo "=========================================="
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator extractor validator archivist \
    --region $AWS_REGION \
    --query 'services[*].[serviceName,runningCount,desiredCount,deployments[0].status]' \
    --output table

echo ""
echo "Latest events for each service:"
for service in orchestrator extractor validator archivist; do
    echo ""
    echo "=== ${service} ==="
    aws ecs describe-services \
        --cluster ca-a2a-cluster \
        --services ${service} \
        --region $AWS_REGION \
        --query 'services[0].events[0].message' \
        --output text 2>&1 || echo "Service not found"
done

echo ""
echo "=========================================="
echo "Next Steps:"
echo "=========================================="
echo "1. If orchestrator is running, test:"
echo "   curl http://${ALB_DNS}/health"
echo ""
echo "2. If tasks still failing, check logs:"
echo "   aws logs tail /ecs/ca-a2a-extractor --follow --region $AWS_REGION"
echo ""
echo "3. Check task failure reasons:"
echo "   aws ecs describe-services --cluster ca-a2a-cluster --services extractor --region $AWS_REGION --query 'services[0].events[0:3]'"
echo ""

