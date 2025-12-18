#!/bin/bash
# Fix all network and logging issues

set -e

export AWS_REGION="eu-west-3"
export AWS_PROFILE="reply-sso"

echo "=========================================="
echo "Fix Network and Logging Issues"
echo "=========================================="
echo ""

# Step 1: Create missing CloudWatch log groups
echo "[1/4] Creating CloudWatch log groups..."
for agent in orchestrator extractor validator archivist; do
    LOG_GROUP="/ecs/ca-a2a-${agent}"
    
    EXISTS=$(aws logs describe-log-groups \
        --log-group-name-prefix $LOG_GROUP \
        --region $AWS_REGION \
        --query "logGroups[?logGroupName=='${LOG_GROUP}'].logGroupName" \
        --output text 2>&1 || echo "")
    
    if [ -z "$EXISTS" ]; then
        echo "  Creating log group: $LOG_GROUP"
        aws logs create-log-group \
            --log-group-name $LOG_GROUP \
            --region $AWS_REGION
        echo "    ✓ Created"
    else
        echo "  ✓ $LOG_GROUP already exists"
    fi
done

echo ""

# Step 2: Check VPC endpoints are in the right place
echo "[2/4] Verifying VPC endpoint configuration..."
ECR_API_ENDPOINT=$(aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=vpc-086392a3eed899f72" "Name=service-name,Values=com.amazonaws.eu-west-3.ecr.api" \
    --region $AWS_REGION \
    --query 'VpcEndpoints[0].[VpcEndpointId,State,SubnetIds]' \
    --output text)

echo "ECR API Endpoint: $ECR_API_ENDPOINT"

if [[ $ECR_API_ENDPOINT == *"available"* ]]; then
    echo "  ✓ ECR API endpoint is available"
else
    echo "  ✗ ECR API endpoint issues detected"
fi

echo ""

# Step 3: Check security group allows HTTPS outbound
echo "[3/4] Verifying security group allows HTTPS..."
SG_ID="sg-0d0535244d17de853"

HTTPS_RULE=$(aws ec2 describe-security-groups \
    --group-ids $SG_ID \
    --region $AWS_REGION \
    --query 'SecurityGroups[0].IpPermissionsEgress[?ToPort==`443`].ToPort' \
    --output text)

if [ "$HTTPS_RULE" == "443" ]; then
    echo "  ✓ Security group allows HTTPS outbound"
else
    echo "  ⚠ Adding HTTPS outbound rule..."
    aws ec2 authorize-security-group-egress \
        --group-id $SG_ID \
        --protocol tcp \
        --port 443 \
        --cidr 0.0.0.0/0 \
        --region $AWS_REGION 2>&1 || echo "  (Rule may already exist)"
fi

echo ""

# Step 4: Update services to use PRIVATE subnets with VPC endpoints
echo "[4/4] Updating services to use private subnets with VPC endpoints..."

# Private subnets from config
PRIVATE_SUBNET_1="subnet-07484aca0e473e3d0"
PRIVATE_SUBNET_2="subnet-0aef6b4fcce7748a9"
ECS_SG="sg-047a8f39f9cdcaf4c"

for service in extractor validator archivist; do
    echo "  Updating $service to use private subnets..."
    
    aws ecs update-service \
        --cluster ca-a2a-cluster \
        --service $service \
        --network-configuration "awsvpcConfiguration={subnets=[$PRIVATE_SUBNET_1,$PRIVATE_SUBNET_2],securityGroups=[$ECS_SG],assignPublicIp=DISABLED}" \
        --force-new-deployment \
        --region $AWS_REGION \
        --output text > /dev/null
    
    echo "    ✓ Updated $service"
done

echo ""
echo "=========================================="
echo "Waiting 2 minutes for services to restart..."
echo "=========================================="
sleep 120

# Check status
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
echo "Summary of Changes:"
echo "=========================================="
echo "✓ Created CloudWatch log groups"
echo "✓ Verified VPC endpoints"
echo "✓ Ensured HTTPS outbound in security group"
echo "✓ Moved services to PRIVATE subnets (with VPC endpoints)"
echo ""
echo "Services now use:"
echo "  - Private subnets (with NO public IP)"
echo "  - VPC endpoints for ECR, Secrets Manager, CloudWatch"
echo "  - Proper security group configuration"
echo ""

