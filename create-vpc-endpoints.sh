#!/bin/bash
set -e

# Create VPC Endpoints for ECS Tasks in Private Subnets
# This allows tasks to access AWS Secrets Manager, ECR, CloudWatch Logs, and S3

# Load configuration
if [ -f "ca-a2a-config.env" ]; then
    source ca-a2a-config.env
fi

export AWS_REGION="${AWS_REGION:-eu-west-3}"
export VPC_ID="${VPC_ID:-vpc-086392a3eed899f72}"
export PRIVATE_SUBNET_1="${PRIVATE_SUBNET_1:-subnet-07484aca0e473e3d0}"
export PRIVATE_SUBNET_2="${PRIVATE_SUBNET_2:-subnet-0aef6b4fcce7748a9}"
export ECS_SG="${ECS_SG:-sg-047a8f39f9cdcaf4c}"
export PROJECT_NAME="${PROJECT_NAME:-ca-a2a}"

echo "========================================"
echo "Create VPC Endpoints for ECS Tasks"
echo "========================================"
echo "Region: $AWS_REGION"
echo "VPC: $VPC_ID"
echo ""

# Get route table IDs for private subnets
echo "[1/5] Finding route tables for private subnets..."
ROUTE_TABLE_1=$(aws ec2 describe-route-tables \
    --filters "Name=association.subnet-id,Values=$PRIVATE_SUBNET_1" \
    --region $AWS_REGION \
    --query 'RouteTables[0].RouteTableId' \
    --output text)

ROUTE_TABLE_2=$(aws ec2 describe-route-tables \
    --filters "Name=association.subnet-id,Values=$PRIVATE_SUBNET_2" \
    --region $AWS_REGION \
    --query 'RouteTables[0].RouteTableId' \
    --output text)

if [ -z "$ROUTE_TABLE_1" ] || [ "$ROUTE_TABLE_1" = "None" ]; then
    echo "  Error: Could not find route table for subnet $PRIVATE_SUBNET_1"
    exit 1
fi

if [ -z "$ROUTE_TABLE_2" ] || [ "$ROUTE_TABLE_2" = "None" ]; then
    echo "  Error: Could not find route table for subnet $PRIVATE_SUBNET_2"
    exit 1
fi

echo "  Route table 1: $ROUTE_TABLE_1"
echo "  Route table 2: $ROUTE_TABLE_2"
echo ""

# Check if security group allows HTTPS from VPC
echo "[2/5] Setting up security group for VPC endpoints..."
NEEDS_HTTPS_RULE=true
SG_RULES=$(aws ec2 describe-security-groups \
    --group-ids $ECS_SG \
    --region $AWS_REGION \
    --query 'SecurityGroups[0].IpPermissions' \
    --output json)

if echo "$SG_RULES" | grep -q '"FromPort": 443'; then
    NEEDS_HTTPS_RULE=false
fi

if [ "$NEEDS_HTTPS_RULE" = true ]; then
    echo "  Adding HTTPS ingress rule to security group..."
    aws ec2 authorize-security-group-ingress \
        --group-id $ECS_SG \
        --protocol tcp \
        --port 443 \
        --cidr "10.0.0.0/16" \
        --region $AWS_REGION 2>&1 | grep -v "already exists" || true
    echo "  ✓ HTTPS rule added"
else
    echo "  ✓ HTTPS rule already exists"
fi
echo ""

# Create Secrets Manager endpoint
echo "[3/5] Creating VPC endpoints..."

# Check if Secrets Manager endpoint exists
SECRETS_ENDPOINT=$(aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=com.amazonaws.$AWS_REGION.secretsmanager" \
    --region $AWS_REGION \
    --query 'VpcEndpoints[0].VpcEndpointId' \
    --output text)

if [ -z "$SECRETS_ENDPOINT" ] || [ "$SECRETS_ENDPOINT" = "None" ]; then
    echo "  Creating Secrets Manager endpoint..."
    SECRETS_ENDPOINT=$(aws ec2 create-vpc-endpoint \
        --vpc-id $VPC_ID \
        --service-name "com.amazonaws.$AWS_REGION.secretsmanager" \
        --vpc-endpoint-type Interface \
        --subnet-ids $PRIVATE_SUBNET_1 $PRIVATE_SUBNET_2 \
        --security-group-ids $ECS_SG \
        --region $AWS_REGION \
        --query 'VpcEndpoint.VpcEndpointId' \
        --output text)
    echo "  ✓ Created Secrets Manager endpoint: $SECRETS_ENDPOINT"
else
    echo "  ✓ Secrets Manager endpoint already exists: $SECRETS_ENDPOINT"
fi

# Create ECR API endpoint
ECR_API_ENDPOINT=$(aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=com.amazonaws.$AWS_REGION.ecr.api" \
    --region $AWS_REGION \
    --query 'VpcEndpoints[0].VpcEndpointId' \
    --output text)

if [ -z "$ECR_API_ENDPOINT" ] || [ "$ECR_API_ENDPOINT" = "None" ]; then
    echo "  Creating ECR API endpoint..."
    ECR_API_ENDPOINT=$(aws ec2 create-vpc-endpoint \
        --vpc-id $VPC_ID \
        --service-name "com.amazonaws.$AWS_REGION.ecr.api" \
        --vpc-endpoint-type Interface \
        --subnet-ids $PRIVATE_SUBNET_1 $PRIVATE_SUBNET_2 \
        --security-group-ids $ECS_SG \
        --region $AWS_REGION \
        --query 'VpcEndpoint.VpcEndpointId' \
        --output text)
    echo "  ✓ Created ECR API endpoint: $ECR_API_ENDPOINT"
else
    echo "  ✓ ECR API endpoint already exists: $ECR_API_ENDPOINT"
fi

# Create ECR DKR endpoint
ECR_DKR_ENDPOINT=$(aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=com.amazonaws.$AWS_REGION.ecr.dkr" \
    --region $AWS_REGION \
    --query 'VpcEndpoints[0].VpcEndpointId' \
    --output text)

if [ -z "$ECR_DKR_ENDPOINT" ] || [ "$ECR_DKR_ENDPOINT" = "None" ]; then
    echo "  Creating ECR DKR endpoint..."
    ECR_DKR_ENDPOINT=$(aws ec2 create-vpc-endpoint \
        --vpc-id $VPC_ID \
        --service-name "com.amazonaws.$AWS_REGION.ecr.dkr" \
        --vpc-endpoint-type Interface \
        --subnet-ids $PRIVATE_SUBNET_1 $PRIVATE_SUBNET_2 \
        --security-group-ids $ECS_SG \
        --region $AWS_REGION \
        --query 'VpcEndpoint.VpcEndpointId' \
        --output text)
    echo "  ✓ Created ECR DKR endpoint: $ECR_DKR_ENDPOINT"
else
    echo "  ✓ ECR DKR endpoint already exists: $ECR_DKR_ENDPOINT"
fi

# Create CloudWatch Logs endpoint
LOGS_ENDPOINT=$(aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=com.amazonaws.$AWS_REGION.logs" \
    --region $AWS_REGION \
    --query 'VpcEndpoints[0].VpcEndpointId' \
    --output text)

if [ -z "$LOGS_ENDPOINT" ] || [ "$LOGS_ENDPOINT" = "None" ]; then
    echo "  Creating CloudWatch Logs endpoint..."
    LOGS_ENDPOINT=$(aws ec2 create-vpc-endpoint \
        --vpc-id $VPC_ID \
        --service-name "com.amazonaws.$AWS_REGION.logs" \
        --vpc-endpoint-type Interface \
        --subnet-ids $PRIVATE_SUBNET_1 $PRIVATE_SUBNET_2 \
        --security-group-ids $ECS_SG \
        --region $AWS_REGION \
        --query 'VpcEndpoint.VpcEndpointId' \
        --output text)
    echo "  ✓ Created CloudWatch Logs endpoint: $LOGS_ENDPOINT"
else
    echo "  ✓ CloudWatch Logs endpoint already exists: $LOGS_ENDPOINT"
fi

# Create S3 Gateway endpoint (optional but recommended)
S3_ENDPOINT=$(aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=com.amazonaws.$AWS_REGION.s3" \
    --region $AWS_REGION \
    --query 'VpcEndpoints[0].VpcEndpointId' \
    --output text)

if [ -z "$S3_ENDPOINT" ] || [ "$S3_ENDPOINT" = "None" ]; then
    echo "  Creating S3 Gateway endpoint..."
    S3_ENDPOINT=$(aws ec2 create-vpc-endpoint \
        --vpc-id $VPC_ID \
        --service-name "com.amazonaws.$AWS_REGION.s3" \
        --vpc-endpoint-type Gateway \
        --route-table-ids $ROUTE_TABLE_1 $ROUTE_TABLE_2 \
        --region $AWS_REGION \
        --query 'VpcEndpoint.VpcEndpointId' \
        --output text)
    echo "  ✓ Created S3 Gateway endpoint: $S3_ENDPOINT"
else
    echo "  ✓ S3 Gateway endpoint already exists: $S3_ENDPOINT"
fi

echo ""

# Wait for interface endpoints to be available
echo "[4/5] Waiting for interface endpoints to be available..."
for endpoint in $SECRETS_ENDPOINT $ECR_API_ENDPOINT $ECR_DKR_ENDPOINT $LOGS_ENDPOINT; do
    if [ -n "$endpoint" ] && [ "$endpoint" != "None" ]; then
        echo "  Waiting for endpoint $endpoint..."
        MAX_ATTEMPTS=30
        ATTEMPT=0
        while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
            STATE=$(aws ec2 describe-vpc-endpoints \
                --vpc-endpoint-ids $endpoint \
                --region $AWS_REGION \
                --query 'VpcEndpoints[0].State' \
                --output text)
            
            if [ "$STATE" = "available" ]; then
                echo "    ✓ Endpoint $endpoint is available"
                break
            elif [ "$STATE" = "failed" ] || [ "$STATE" = "deleted" ]; then
                echo "    ✗ Endpoint $endpoint is in state: $STATE"
                break
            else
                ATTEMPT=$((ATTEMPT + 1))
                echo "    ... State: $STATE (attempt $ATTEMPT/$MAX_ATTEMPTS)"
                sleep 10
            fi
        done
        
        if [ $ATTEMPT -eq $MAX_ATTEMPTS ]; then
            echo "    ⚠ Endpoint $endpoint did not become available within timeout"
        fi
    fi
done

echo ""

# Verify endpoints
echo "[5/5] Verifying VPC endpoints..."
aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --region $AWS_REGION \
    --query 'VpcEndpoints[*].[VpcEndpointId,ServiceName,State]' \
    --output table

echo ""
echo "========================================"
echo "VPC Endpoints Created Successfully!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Wait 2-3 minutes for endpoints to fully propagate"
echo "2. Restart ECS tasks to pick up the new endpoints:"
echo "   ./fix-ecs-connectivity.sh"
echo ""
echo "Or manually restart services:"
echo "   aws ecs update-service --cluster ca-a2a-cluster --service extractor --force-new-deployment --region $AWS_REGION"
echo "   aws ecs update-service --cluster ca-a2a-cluster --service validator --force-new-deployment --region $AWS_REGION"
echo "   aws ecs update-service --cluster ca-a2a-cluster --service archivist --force-new-deployment --region $AWS_REGION"
echo ""

