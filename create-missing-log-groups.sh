#!/bin/bash
# Create missing log groups

set -e

export AWS_REGION="eu-west-3"
export AWS_PROFILE="reply-sso"
export MSYS_NO_PATHCONV=1

echo "=========================================="
echo "Creating Missing Log Groups"
echo "=========================================="
echo ""

# Create the missing log groups
for agent in validator archivist; do
    LOG_GROUP="/ecs/ca-a2a-${agent}"
    
    echo "Creating $LOG_GROUP..."
    
    aws logs create-log-group \
        --log-group-name "$LOG_GROUP" \
        --region $AWS_REGION 2>&1 || echo "  (Already exists)"
    
    # Set retention policy
    aws logs put-retention-policy \
        --log-group-name "$LOG_GROUP" \
        --retention-in-days 7 \
        --region $AWS_REGION
    
    echo "  ✓ Created $LOG_GROUP"
done

echo ""
echo "=========================================="
echo "Verifying all log groups exist..."
echo "=========================================="
aws logs describe-log-groups \
    --log-group-name-prefix "/ecs/ca-a2a" \
    --region $AWS_REGION \
    --query 'logGroups[*].logGroupName' \
    --output table

echo ""
echo "=========================================="
echo "Restarting services..."
echo "=========================================="
for service in validator archivist; do
    echo "  Restarting $service..."
    aws ecs update-service \
        --cluster ca-a2a-cluster \
        --service $service \
        --force-new-deployment \
        --region $AWS_REGION \
        --output text > /dev/null
    echo "    ✓ Deployment triggered"
done

echo ""
echo "Waiting 90 seconds for tasks to start..."
sleep 90

echo ""
echo "=========================================="
echo "Service Status"
echo "=========================================="
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services extractor validator archivist \
    --region $AWS_REGION \
    --query 'services[*].[serviceName,runningCount,desiredCount]' \
    --output table

echo ""
echo "Latest events:"
for service in extractor validator archivist; do
    echo ""
    echo "=== $service ==="
    aws ecs describe-services \
        --cluster ca-a2a-cluster \
        --services $service \
        --region $AWS_REGION \
        --query 'services[0].events[0].message' \
        --output text
done

echo ""
echo "=========================================="
echo "Done! Check if runningCount = desiredCount"
echo "=========================================="

