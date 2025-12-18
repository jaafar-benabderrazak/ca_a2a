#!/bin/bash
# Complete ECS Fix - Verify IAM and Force Restart

set -e

export AWS_REGION="eu-west-3"
export AWS_PROFILE="reply-sso"

echo "=========================================="
echo "Complete ECS Service Fix"
echo "=========================================="
echo ""

# Step 1: Verify IAM policy attachment
echo "[1/5] Verifying IAM policy attachment..."
ATTACHED_POLICIES=$(aws iam list-attached-role-policies \
    --role-name ca-a2a-ecs-execution-role \
    --region $AWS_REGION \
    --profile $AWS_PROFILE \
    --query 'AttachedPolicies[*].PolicyName' \
    --output text)

echo "Attached policies: $ATTACHED_POLICIES"

if [[ $ATTACHED_POLICIES == *"ca-a2a-secrets-manager-policy"* ]]; then
    echo "✓ Secrets Manager policy is attached"
else
    echo "✗ Secrets Manager policy NOT attached - running fix..."
    ./fix-iam-permissions.sh
fi

echo ""

# Step 2: Verify VPC endpoints are available
echo "[2/5] Verifying VPC endpoints..."
ENDPOINT_STATUS=$(aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=vpc-086392a3eed899f72" "Name=service-name,Values=*secretsmanager*" \
    --region $AWS_REGION \
    --profile $AWS_PROFILE \
    --query 'VpcEndpoints[0].State' \
    --output text)

echo "Secrets Manager endpoint status: $ENDPOINT_STATUS"

if [ "$ENDPOINT_STATUS" != "available" ]; then
    echo "✗ VPC endpoints not ready - they may still be provisioning"
    echo "  Run: aws ec2 describe-vpc-endpoints --filters 'Name=vpc-id,Values=vpc-086392a3eed899f72' --region $AWS_REGION --query 'VpcEndpoints[*].[ServiceName,State]' --output table"
    exit 1
fi

echo "✓ VPC endpoints are available"
echo ""

# Step 3: Wait for IAM propagation
echo "[3/5] Waiting 60 seconds for IAM changes to fully propagate..."
sleep 60

# Step 4: Stop all running/failed tasks
echo "[4/5] Stopping all tasks to force fresh start..."
for service in orchestrator extractor validator archivist; do
    echo "  Stopping tasks for ${service}..."
    TASK_ARNS=$(aws ecs list-tasks \
        --cluster ca-a2a-cluster \
        --service-name ${service} \
        --region $AWS_REGION \
        --profile $AWS_PROFILE \
        --query 'taskArns' \
        --output text)
    
    if [ -n "$TASK_ARNS" ]; then
        for task in $TASK_ARNS; do
            aws ecs stop-task \
                --cluster ca-a2a-cluster \
                --task ${task} \
                --region $AWS_REGION \
                --profile $AWS_PROFILE \
                --output text > /dev/null
        done
        echo "    ✓ Stopped tasks for ${service}"
    else
        echo "    ℹ No running tasks for ${service}"
    fi
done

echo ""

# Step 5: Force new deployment for all services
echo "[5/5] Forcing new deployment for all services..."
for service in orchestrator extractor validator archivist; do
    echo "  Deploying ${service}..."
    aws ecs update-service \
        --cluster ca-a2a-cluster \
        --service ${service} \
        --force-new-deployment \
        --region $AWS_REGION \
        --profile $AWS_PROFILE \
        --output text > /dev/null
    echo "    ✓ Deployment triggered for ${service}"
done

echo ""
echo "=========================================="
echo "Waiting 90 seconds for tasks to start..."
echo "=========================================="
sleep 90

# Check final status
echo ""
echo "=========================================="
echo "Final Status Check"
echo "=========================================="
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator extractor validator archivist \
    --region $AWS_REGION \
    --profile $AWS_PROFILE \
    --query 'services[*].[serviceName,runningCount,desiredCount]' \
    --output table

echo ""
echo "Checking latest events for each service..."
for service in orchestrator extractor validator archivist; do
    echo ""
    echo "=== ${service} latest event ==="
    aws ecs describe-services \
        --cluster ca-a2a-cluster \
        --services ${service} \
        --region $AWS_REGION \
        --profile $AWS_PROFILE \
        --query 'services[0].events[0].message' \
        --output text
done

echo ""
echo "=========================================="
echo "If tasks are still failing, check task logs:"
echo "aws logs tail /ecs/ca-a2a-extractor --follow --region $AWS_REGION"
echo "=========================================="

