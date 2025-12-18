#!/bin/bash
# Diagnose and fix CloudWatch Logs VPC endpoint connectivity

set -e

export AWS_REGION="eu-west-3"
export AWS_PROFILE="reply-sso"

# Fix Git Bash on Windows path conversion
export MSYS_NO_PATHCONV=1

echo "=========================================="
echo "CloudWatch Logs VPC Endpoint Diagnostics"
echo "=========================================="
echo ""

# Step 1: Check task definition log configuration
echo "[1/5] Checking task definition log configuration..."
for agent in validator archivist; do
    echo "  Checking ca-a2a-${agent}..."
    LOG_CONFIG=$(aws ecs describe-task-definition \
        --task-definition ca-a2a-${agent} \
        --region $AWS_REGION \
        --query 'taskDefinition.containerDefinitions[0].logConfiguration.options' \
        --output json)
    echo "    Log config: $LOG_CONFIG"
done

echo ""

# Step 2: List actual log groups
echo "[2/5] Listing actual CloudWatch log groups..."
aws logs describe-log-groups \
    --log-group-name-prefix "/ecs/ca-a2a" \
    --region $AWS_REGION \
    --query 'logGroups[*].logGroupName' \
    --output table

echo ""

# Step 3: Check CloudWatch Logs VPC endpoint configuration
echo "[3/5] Checking CloudWatch Logs VPC endpoint..."
aws ec2 describe-vpc-endpoints \
    --filters "Name=service-name,Values=*logs*" \
    --region $AWS_REGION \
    --query 'VpcEndpoints[0].[VpcEndpointId,State,SubnetIds,SecurityGroupIds]' \
    --output table

echo ""

# Step 4: Verify VPC endpoint security group allows inbound
echo "[4/5] Checking VPC endpoint security group..."
LOGS_VPC_SG=$(aws ec2 describe-vpc-endpoints \
    --filters "Name=service-name,Values=*logs*" \
    --region $AWS_REGION \
    --query 'VpcEndpoints[0].Groups[0].GroupId' \
    --output text)

echo "CloudWatch Logs VPC endpoint uses security group: $LOGS_VPC_SG"

# Check if it allows HTTPS inbound from VPC
HTTPS_INBOUND=$(aws ec2 describe-security-groups \
    --group-ids $LOGS_VPC_SG \
    --region $AWS_REGION \
    --query 'SecurityGroups[0].IpPermissions[?ToPort==`443`]' \
    --output json)

echo "HTTPS inbound rules: $HTTPS_INBOUND"

if [[ $HTTPS_INBOUND == "[]" ]]; then
    echo "  ⚠ No HTTPS inbound rule - adding it..."
    aws ec2 authorize-security-group-ingress \
        --group-id $LOGS_VPC_SG \
        --protocol tcp \
        --port 443 \
        --cidr 10.0.0.0/16 \
        --region $AWS_REGION
    echo "  ✓ Added HTTPS inbound from VPC"
else
    echo "  ✓ HTTPS inbound rule exists"
fi

echo ""

# Step 5: Recreate log groups with explicit permissions
echo "[5/5] Recreating log groups to ensure they exist..."
for agent in orchestrator extractor validator archivist; do
    LOG_GROUP="/ecs/ca-a2a-${agent}"
    
    # Delete and recreate to ensure clean state
    aws logs delete-log-group \
        --log-group-name $LOG_GROUP \
        --region $AWS_REGION 2>&1 || echo "  (Group didn't exist)"
    
    aws logs create-log-group \
        --log-group-name $LOG_GROUP \
        --region $AWS_REGION
    
    # Set retention
    aws logs put-retention-policy \
        --log-group-name $LOG_GROUP \
        --retention-in-days 7 \
        --region $AWS_REGION
    
    echo "  ✓ Recreated $LOG_GROUP"
done

echo ""
echo "=========================================="
echo "Waiting 30 seconds for propagation..."
echo "=========================================="
sleep 30

# Force restart
echo ""
echo "=========================================="
echo "Forcing service restart..."
echo "=========================================="
for service in extractor validator archivist; do
    aws ecs update-service \
        --cluster ca-a2a-cluster \
        --service $service \
        --force-new-deployment \
        --region $AWS_REGION \
        --output text > /dev/null
    echo "  ✓ Restarted $service"
done

echo ""
echo "Waiting 90 seconds for tasks to start..."
sleep 90

# Check status
echo ""
echo "=========================================="
echo "Final Status"
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
echo "If STILL failing, the issue may be:"
echo "1. Task definitions have wrong log group names"
echo "2. ECS execution role lacks CloudWatch Logs permissions"
echo "3. Private DNS resolution not working for VPC endpoint"
echo "=========================================="

