#!/bin/bash
# Check current status and wait for stabilization

set -e

export AWS_REGION="eu-west-3"
export AWS_PROFILE="reply-sso"

echo "=========================================="
echo "Checking Service Status"
echo "=========================================="
echo ""

# Check status 3 times with delays
for i in 1 2 3; do
    echo "Check #${i} - $(date +%H:%M:%S)"
    aws ecs describe-services \
        --cluster ca-a2a-cluster \
        --services extractor validator archivist \
        --region $AWS_REGION \
        --query 'services[*].[serviceName,runningCount,desiredCount,pendingCount]' \
        --output table
    
    if [ $i -lt 3 ]; then
        echo ""
        echo "Waiting 30 seconds..."
        sleep 30
        echo ""
    fi
done

echo ""
echo "=========================================="
echo "Latest Events for Each Service"
echo "=========================================="

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
echo "Summary"
echo "=========================================="
FINAL_STATUS=$(aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services extractor validator archivist \
    --region $AWS_REGION \
    --query 'services[*].[serviceName,runningCount,desiredCount]' \
    --output text)

echo "$FINAL_STATUS"
echo ""

# Check if all services are healthy
if echo "$FINAL_STATUS" | grep -q "2.*2"; then
    echo "✓ Services are starting to stabilize!"
else
    echo "⚠ Services still stabilizing..."
    echo ""
    echo "If extractor still at 0, check its events:"
    echo "  aws ecs describe-services --cluster ca-a2a-cluster --services extractor --region $AWS_REGION --query 'services[0].events[0:3]'"
fi

