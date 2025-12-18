#!/bin/bash
# Force complete task restart after log group creation

set -e

export AWS_REGION="eu-west-3"
export AWS_PROFILE="reply-sso"

echo "=========================================="
echo "Force Complete Service Restart"
echo "=========================================="
echo ""

# Step 1: Stop ALL tasks (including pending/stopping ones)
echo "[1/3] Stopping all tasks to clear cached errors..."
for service in extractor validator archivist; do
    echo "  Stopping tasks for ${service}..."
    
    # Get ALL tasks (running, pending, stopped)
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
                --reason "Forcing restart after log group creation" \
                --output text > /dev/null 2>&1 || true
        done
        echo "    ✓ Stopped all tasks for ${service}"
    else
        echo "    ℹ No tasks found for ${service}"
    fi
done

echo ""
echo "[2/3] Waiting 45 seconds for tasks to fully stop and log groups to propagate..."
sleep 45

# Step 2: Scale down to 0, then back up to force completely fresh start
echo ""
echo "[3/3] Scaling services for complete refresh..."
for service in extractor validator archivist; do
    echo "  Refreshing ${service}..."
    
    # Scale to 0
    aws ecs update-service \
        --cluster ca-a2a-cluster \
        --service ${service} \
        --desired-count 0 \
        --region $AWS_REGION \
        --output text > /dev/null
    
    sleep 5
    
    # Scale back to 2 with force new deployment
    aws ecs update-service \
        --cluster ca-a2a-cluster \
        --service ${service} \
        --desired-count 2 \
        --force-new-deployment \
        --region $AWS_REGION \
        --output text > /dev/null
    
    echo "    ✓ Refreshed ${service}"
done

echo ""
echo "=========================================="
echo "Waiting 90 seconds for fresh tasks to start..."
echo "=========================================="
sleep 90

# Check status
echo ""
echo "=========================================="
echo "Service Status"
echo "=========================================="
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services extractor validator archivist \
    --region $AWS_REGION \
    --query 'services[*].[serviceName,runningCount,desiredCount,deployments[0].status]' \
    --output table

echo ""
echo "Latest events (should show no more log group errors):"
for service in extractor validator archivist; do
    echo ""
    echo "=== $service ==="
    aws ecs describe-services \
        --cluster ca-a2a-cluster \
        --services $service \
        --region $AWS_REGION \
        --query 'services[0].events[0:2].[createdAt,message]' \
        --output table
done

echo ""
echo "=========================================="
echo "If tasks are STILL failing:"
echo "=========================================="
echo "Check VPC endpoint for CloudWatch Logs:"
echo "  aws ec2 describe-vpc-endpoints --filters 'Name=service-name,Values=*logs*' --region $AWS_REGION --query 'VpcEndpoints[*].[VpcEndpointId,State]' --output table"
echo ""

