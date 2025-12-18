#!/bin/bash
set -e

# Fix ECS Task Connectivity to AWS Secrets Manager
# This script fixes the security group and restarts tasks

export AWS_REGION="eu-west-3"
export SG_ID="sg-0d0535244d17de853"
export CLUSTER="ca-a2a-cluster"

echo "=========================================="
echo "Fix ECS Task Connectivity"
echo "=========================================="
echo ""

# Step 1: Check current security group outbound rules
echo "Step 1: Checking security group outbound rules..."
aws ec2 describe-security-groups \
    --group-ids ${SG_ID} \
    --region ${AWS_REGION} \
    --query 'SecurityGroups[0].IpPermissionsEgress' \
    --output json

echo ""

# Step 2: Add outbound HTTPS rule if needed
echo "Step 2: Adding outbound HTTPS rule (if not exists)..."
aws ec2 authorize-security-group-egress \
    --group-id ${SG_ID} \
    --protocol tcp \
    --port 443 \
    --cidr 0.0.0.0/0 \
    --region ${AWS_REGION} 2>&1 || echo "Rule may already exist"

echo ""

# Step 3: Also ensure DNS is allowed (port 53 UDP)
echo "Step 3: Adding outbound DNS rule (if not exists)..."
aws ec2 authorize-security-group-egress \
    --group-id ${SG_ID} \
    --protocol udp \
    --port 53 \
    --cidr 0.0.0.0/0 \
    --region ${AWS_REGION} 2>&1 || echo "Rule may already exist"

echo ""

# Step 4: Stop all failed tasks to force restart
echo "Step 4: Stopping all failed tasks..."
for service in extractor validator archivist; do
    echo "  Stopping tasks for ${service}..."
    TASK_ARNS=$(aws ecs list-tasks \
        --cluster ${CLUSTER} \
        --service-name ${service} \
        --region ${AWS_REGION} \
        --query 'taskArns' \
        --output text)

    if [ -n "$TASK_ARNS" ]; then
        for task in $TASK_ARNS; do
            aws ecs stop-task \
                --cluster ${CLUSTER} \
                --task ${task} \
                --region ${AWS_REGION} \
                --output text > /dev/null
        done
        echo "  ✓ Stopped tasks for ${service}"
    else
        echo "  ℹ No tasks to stop for ${service}"
    fi
done

echo ""
echo "Step 5: Waiting 30 seconds for new tasks to start..."
sleep 30

echo ""
echo "Step 6: Checking service status..."
aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services extractor validator archivist \
    --region ${AWS_REGION} \
    --query 'services[*].[serviceName,runningCount,desiredCount]' \
    --output table

echo ""
echo "Step 7: Checking latest events..."
for service in extractor validator archivist; do
    echo ""
    echo "=== ${service} events ==="
    aws ecs describe-services \
        --cluster ${CLUSTER} \
        --services ${service} \
        --region ${AWS_REGION} \
        --query 'services[0].events[0:2].[createdAt,message]' \
        --output table
done

echo ""
echo "=========================================="
echo "If tasks are still not running, check:"
echo "1. VPC endpoints for Secrets Manager"
echo "2. Route tables for public subnets"
echo "3. Task definition secrets configuration"
echo "=========================================="
