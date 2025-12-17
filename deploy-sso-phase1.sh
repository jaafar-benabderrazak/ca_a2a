#!/bin/bash
###############################################################################
# Phase 1: Infrastructure Deployment (No Docker Required)
# Creates AWS infrastructure that can be accessed via SSO
# Region: eu-west-3
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

###############################################################################
# Configuration
###############################################################################

export AWS_REGION="eu-west-3"
export AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text 2>/dev/null)}"
export PROJECT_NAME="ca-a2a"
export ENVIRONMENT="${ENVIRONMENT:-prod}"

# Database Configuration
export DB_NAME="documents_db"
export DB_USERNAME="postgres"
export DB_PASSWORD="${DB_PASSWORD:-$(openssl rand -base64 32 | tr -d '/+=')}"
export DB_INSTANCE_CLASS="db.t3.medium"

# S3 Configuration
export S3_BUCKET="${PROJECT_NAME}-documents-${AWS_ACCOUNT_ID}"

# Network Configuration
export VPC_CIDR="10.0.0.0/16"
export PUBLIC_SUBNET_1_CIDR="10.0.1.0/24"
export PUBLIC_SUBNET_2_CIDR="10.0.2.0/24"
export PRIVATE_SUBNET_1_CIDR="10.0.10.0/24"
export PRIVATE_SUBNET_2_CIDR="10.0.20.0/24"

# Agent Ports
export ORCHESTRATOR_PORT=8001
export EXTRACTOR_PORT=8002
export VALIDATOR_PORT=8003
export ARCHIVIST_PORT=8004

###############################################################################
# Check Prerequisites
###############################################################################

log_info "Checking AWS credentials..."
if ! aws sts get-caller-identity &> /dev/null; then
    log_error "AWS credentials not configured"
    log_info "Please run: aws sso login --profile <your-profile>"
    exit 1
fi

log_info "Deploying to region: ${AWS_REGION}"
log_info "AWS Account: ${AWS_ACCOUNT_ID}"

###############################################################################
# Phase 1: Infrastructure Only
###############################################################################

log_info "========================================"
log_info "Phase 1: Infrastructure Deployment"
log_info "========================================"

# Create VPC
log_info "Creating VPC..."
VPC_ID=$(aws ec2 create-vpc \
    --cidr-block ${VPC_CIDR} \
    --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=${PROJECT_NAME}-vpc}]" \
    --region ${AWS_REGION} \
    --query 'Vpc.VpcId' --output text 2>/dev/null || \
    aws ec2 describe-vpcs \
        --filters "Name=tag:Name,Values=${PROJECT_NAME}-vpc" \
        --region ${AWS_REGION} \
        --query 'Vpcs[0].VpcId' --output text)

log_info "VPC: ${VPC_ID}"

# Enable DNS
aws ec2 modify-vpc-attribute --vpc-id ${VPC_ID} --enable-dns-support --region ${AWS_REGION}
aws ec2 modify-vpc-attribute --vpc-id ${VPC_ID} --enable-dns-hostnames --region ${AWS_REGION}

# Create Internet Gateway
log_info "Creating Internet Gateway..."
IGW_ID=$(aws ec2 create-internet-gateway \
    --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=${PROJECT_NAME}-igw}]" \
    --region ${AWS_REGION} \
    --query 'InternetGateway.InternetGatewayId' --output text 2>/dev/null || \
    aws ec2 describe-internet-gateways \
        --filters "Name=tag:Name,Values=${PROJECT_NAME}-igw" \
        --region ${AWS_REGION} \
        --query 'InternetGateways[0].InternetGatewayId' --output text)

aws ec2 attach-internet-gateway --vpc-id ${VPC_ID} --internet-gateway-id ${IGW_ID} --region ${AWS_REGION} 2>/dev/null || true

# Get availability zones
AZ1=$(aws ec2 describe-availability-zones --region ${AWS_REGION} --query 'AvailabilityZones[0].ZoneName' --output text)
AZ2=$(aws ec2 describe-availability-zones --region ${AWS_REGION} --query 'AvailabilityZones[1].ZoneName' --output text)

# Create Subnets
log_info "Creating subnets..."
PUBLIC_SUBNET_1=$(aws ec2 create-subnet \
    --vpc-id ${VPC_ID} \
    --cidr-block ${PUBLIC_SUBNET_1_CIDR} \
    --availability-zone ${AZ1} \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-public-1}]" \
    --region ${AWS_REGION} \
    --query 'Subnet.SubnetId' --output text 2>/dev/null || \
    aws ec2 describe-subnets \
        --filters "Name=tag:Name,Values=${PROJECT_NAME}-public-1" \
        --region ${AWS_REGION} \
        --query 'Subnets[0].SubnetId' --output text)

PUBLIC_SUBNET_2=$(aws ec2 create-subnet \
    --vpc-id ${VPC_ID} \
    --cidr-block ${PUBLIC_SUBNET_2_CIDR} \
    --availability-zone ${AZ2} \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-public-2}]" \
    --region ${AWS_REGION} \
    --query 'Subnet.SubnetId' --output text 2>/dev/null || \
    aws ec2 describe-subnets \
        --filters "Name=tag:Name,Values=${PROJECT_NAME}-public-2" \
        --region ${AWS_REGION} \
        --query 'Subnets[0].SubnetId' --output text)

PRIVATE_SUBNET_1=$(aws ec2 create-subnet \
    --vpc-id ${VPC_ID} \
    --cidr-block ${PRIVATE_SUBNET_1_CIDR} \
    --availability-zone ${AZ1} \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-private-1}]" \
    --region ${AWS_REGION} \
    --query 'Subnet.SubnetId' --output text 2>/dev/null || \
    aws ec2 describe-subnets \
        --filters "Name=tag:Name,Values=${PROJECT_NAME}-private-1" \
        --region ${AWS_REGION} \
        --query 'Subnets[0].SubnetId' --output text)

PRIVATE_SUBNET_2=$(aws ec2 create-subnet \
    --vpc-id ${VPC_ID} \
    --cidr-block ${PRIVATE_SUBNET_2_CIDR} \
    --availability-zone ${AZ2} \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-private-2}]" \
    --region ${AWS_REGION} \
    --query 'Subnet.SubnetId' --output text 2>/dev/null || \
    aws ec2 describe-subnets \
        --filters "Name=tag:Name,Values=${PROJECT_NAME}-private-2" \
        --region ${AWS_REGION} \
        --query 'Subnets[0].SubnetId' --output text)

# Create NAT Gateway
log_info "Creating NAT Gateway..."
EIP_ID=$(aws ec2 allocate-address --domain vpc --region ${AWS_REGION} --query 'AllocationId' --output text 2>/dev/null)

NAT_GW=$(aws ec2 create-nat-gateway \
    --subnet-id ${PUBLIC_SUBNET_1} \
    --allocation-id ${EIP_ID} \
    --tag-specifications "ResourceType=natgateway,Tags=[{Key=Name,Value=${PROJECT_NAME}-nat}]" \
    --region ${AWS_REGION} \
    --query 'NatGateway.NatGatewayId' --output text 2>/dev/null || \
    aws ec2 describe-nat-gateways \
        --filter "Name=tag:Name,Values=${PROJECT_NAME}-nat" "Name=state,Values=available" \
        --region ${AWS_REGION} \
        --query 'NatGateways[0].NatGatewayId' --output text)

if [ "$NAT_GW" != "None" ] && [ ! -z "$NAT_GW" ]; then
    log_info "Waiting for NAT Gateway to be available..."
    aws ec2 wait nat-gateway-available --nat-gateway-ids ${NAT_GW} --region ${AWS_REGION}
fi

# Create Route Tables
log_info "Creating route tables..."
PUBLIC_RT=$(aws ec2 create-route-table \
    --vpc-id ${VPC_ID} \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${PROJECT_NAME}-public-rt}]" \
    --region ${AWS_REGION} \
    --query 'RouteTable.RouteTableId' --output text 2>/dev/null || \
    aws ec2 describe-route-tables \
        --filters "Name=tag:Name,Values=${PROJECT_NAME}-public-rt" \
        --region ${AWS_REGION} \
        --query 'RouteTables[0].RouteTableId' --output text)

aws ec2 create-route --route-table-id ${PUBLIC_RT} --destination-cidr-block 0.0.0.0/0 --gateway-id ${IGW_ID} --region ${AWS_REGION} 2>/dev/null || true
aws ec2 associate-route-table --subnet-id ${PUBLIC_SUBNET_1} --route-table-id ${PUBLIC_RT} --region ${AWS_REGION} 2>/dev/null || true
aws ec2 associate-route-table --subnet-id ${PUBLIC_SUBNET_2} --route-table-id ${PUBLIC_RT} --region ${AWS_REGION} 2>/dev/null || true

PRIVATE_RT=$(aws ec2 create-route-table \
    --vpc-id ${VPC_ID} \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${PROJECT_NAME}-private-rt}]" \
    --region ${AWS_REGION} \
    --query 'RouteTable.RouteTableId' --output text 2>/dev/null || \
    aws ec2 describe-route-tables \
        --filters "Name=tag:Name,Values=${PROJECT_NAME}-private-rt" \
        --region ${AWS_REGION} \
        --query 'RouteTables[0].RouteTableId' --output text)

if [ "$NAT_GW" != "None" ] && [ ! -z "$NAT_GW" ]; then
    aws ec2 create-route --route-table-id ${PRIVATE_RT} --destination-cidr-block 0.0.0.0/0 --nat-gateway-id ${NAT_GW} --region ${AWS_REGION} 2>/dev/null || true
fi
aws ec2 associate-route-table --subnet-id ${PRIVATE_SUBNET_1} --route-table-id ${PRIVATE_RT} --region ${AWS_REGION} 2>/dev/null || true
aws ec2 associate-route-table --subnet-id ${PRIVATE_SUBNET_2} --route-table-id ${PRIVATE_RT} --region ${AWS_REGION} 2>/dev/null || true

# Create Security Groups
log_info "Creating security groups..."
ALB_SG=$(aws ec2 create-security-group \
    --group-name ${PROJECT_NAME}-alb-sg \
    --description "Security group for ALB" \
    --vpc-id ${VPC_ID} \
    --region ${AWS_REGION} \
    --query 'GroupId' --output text 2>/dev/null || \
    aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=${PROJECT_NAME}-alb-sg" \
        --region ${AWS_REGION} \
        --query 'SecurityGroups[0].GroupId' --output text)

aws ec2 authorize-security-group-ingress --group-id ${ALB_SG} --protocol tcp --port 80 --cidr 0.0.0.0/0 --region ${AWS_REGION} 2>/dev/null || true
aws ec2 authorize-security-group-ingress --group-id ${ALB_SG} --protocol tcp --port 443 --cidr 0.0.0.0/0 --region ${AWS_REGION} 2>/dev/null || true

ECS_SG=$(aws ec2 create-security-group \
    --group-name ${PROJECT_NAME}-ecs-sg \
    --description "Security group for ECS tasks" \
    --vpc-id ${VPC_ID} \
    --region ${AWS_REGION} \
    --query 'GroupId' --output text 2>/dev/null || \
    aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=${PROJECT_NAME}-ecs-sg" \
        --region ${AWS_REGION} \
        --query 'SecurityGroups[0].GroupId' --output text)

aws ec2 authorize-security-group-ingress --group-id ${ECS_SG} --protocol -1 --source-group ${ECS_SG} --region ${AWS_REGION} 2>/dev/null || true
aws ec2 authorize-security-group-ingress --group-id ${ECS_SG} --protocol tcp --port 8000-8999 --source-group ${ALB_SG} --region ${AWS_REGION} 2>/dev/null || true

RDS_SG=$(aws ec2 create-security-group \
    --group-name ${PROJECT_NAME}-rds-sg \
    --description "Security group for RDS" \
    --vpc-id ${VPC_ID} \
    --region ${AWS_REGION} \
    --query 'GroupId' --output text 2>/dev/null || \
    aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=${PROJECT_NAME}-rds-sg" \
        --region ${AWS_REGION} \
        --query 'SecurityGroups[0].GroupId' --output text)

aws ec2 authorize-security-group-ingress --group-id ${RDS_SG} --protocol tcp --port 5432 --source-group ${ECS_SG} --region ${AWS_REGION} 2>/dev/null || true

# Create S3 Bucket
log_info "Creating S3 bucket..."
aws s3 mb "s3://${S3_BUCKET}" --region ${AWS_REGION} 2>/dev/null || log_warn "S3 bucket may already exist"

aws s3api put-bucket-versioning --bucket ${S3_BUCKET} --versioning-configuration Status=Enabled --region ${AWS_REGION} 2>/dev/null || true

aws s3api put-bucket-encryption \
    --bucket ${S3_BUCKET} \
    --server-side-encryption-configuration '{
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            }
        }]
    }' --region ${AWS_REGION} 2>/dev/null || true

aws s3api put-public-access-block \
    --bucket ${S3_BUCKET} \
    --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
    --region ${AWS_REGION} 2>/dev/null || true

# Create Secrets
log_info "Creating secrets..."
aws secretsmanager create-secret \
    --name ${PROJECT_NAME}/db-password \
    --secret-string "${DB_PASSWORD}" \
    --region ${AWS_REGION} 2>/dev/null || \
aws secretsmanager update-secret \
    --secret-id ${PROJECT_NAME}/db-password \
    --secret-string "${DB_PASSWORD}" \
    --region ${AWS_REGION}

# Create RDS
log_info "Creating RDS database..."
aws rds create-db-subnet-group \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --db-subnet-group-description "Subnet group for ${PROJECT_NAME}" \
    --subnet-ids ${PRIVATE_SUBNET_1} ${PRIVATE_SUBNET_2} \
    --region ${AWS_REGION} 2>/dev/null || log_warn "DB subnet group may already exist"

aws rds create-db-instance \
    --db-instance-identifier ${PROJECT_NAME}-postgres \
    --db-instance-class ${DB_INSTANCE_CLASS} \
    --engine postgres \
    --engine-version 15.4 \
    --master-username ${DB_USERNAME} \
    --master-user-password "${DB_PASSWORD}" \
    --allocated-storage 20 \
    --storage-type gp3 \
    --vpc-security-group-ids ${RDS_SG} \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --backup-retention-period 7 \
    --storage-encrypted \
    --db-name ${DB_NAME} \
    --no-publicly-accessible \
    --region ${AWS_REGION} 2>/dev/null || log_warn "RDS instance may already exist"

log_info "Waiting for RDS to be available (this takes 5-10 minutes)..."
aws rds wait db-instance-available --db-instance-identifier ${PROJECT_NAME}-postgres --region ${AWS_REGION} 2>/dev/null || true

RDS_ENDPOINT=$(aws rds describe-db-instances \
    --db-instance-identifier ${PROJECT_NAME}-postgres \
    --region ${AWS_REGION} \
    --query 'DBInstances[0].Endpoint.Address' --output text)

# Create ECR Repositories
log_info "Creating ECR repositories..."
for agent in orchestrator extractor validator archivist; do
    aws ecr create-repository \
        --repository-name ${PROJECT_NAME}/${agent} \
        --region ${AWS_REGION} 2>/dev/null || log_warn "ECR repo ${agent} may already exist"
done

# Create IAM Roles
log_info "Creating IAM roles..."
cat > /tmp/trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role \
    --role-name ${PROJECT_NAME}-ecs-execution-role \
    --assume-role-policy-document file:///tmp/trust-policy.json \
    2>/dev/null || log_warn "Execution role may already exist"

aws iam attach-role-policy \
    --role-name ${PROJECT_NAME}-ecs-execution-role \
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy 2>/dev/null || true

aws iam create-role \
    --role-name ${PROJECT_NAME}-ecs-task-role \
    --assume-role-policy-document file:///tmp/trust-policy.json \
    2>/dev/null || log_warn "Task role may already exist"

cat > /tmp/task-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:DeleteObject"],
      "Resource": ["arn:aws:s3:::${S3_BUCKET}/*", "arn:aws:s3:::${S3_BUCKET}"]
    },
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/*"
    }
  ]
}
EOF

aws iam put-role-policy \
    --role-name ${PROJECT_NAME}-ecs-task-role \
    --policy-name ${PROJECT_NAME}-task-policy \
    --policy-document file:///tmp/task-policy.json 2>/dev/null || true

# Create ECS Cluster
log_info "Creating ECS cluster..."
aws ecs create-cluster \
    --cluster-name ${PROJECT_NAME}-cluster \
    --capacity-providers FARGATE FARGATE_SPOT \
    --region ${AWS_REGION} 2>/dev/null || log_warn "ECS cluster may already exist"

aws ecs update-cluster-settings \
    --cluster ${PROJECT_NAME}-cluster \
    --settings name=containerInsights,value=enabled \
    --region ${AWS_REGION} 2>/dev/null || true

# Create CloudWatch Log Groups
log_info "Creating CloudWatch log groups..."
for agent in orchestrator extractor validator archivist; do
    aws logs create-log-group \
        --log-group-name /ecs/${PROJECT_NAME}-$agent \
        --region ${AWS_REGION} 2>/dev/null || true

    aws logs put-retention-policy \
        --log-group-name /ecs/${PROJECT_NAME}-$agent \
        --retention-in-days 7 \
        --region ${AWS_REGION} 2>/dev/null || true
done

# Create ALB
log_info "Creating Application Load Balancer..."
ALB_ARN=$(aws elbv2 create-load-balancer \
    --name ${PROJECT_NAME}-alb \
    --subnets ${PUBLIC_SUBNET_1} ${PUBLIC_SUBNET_2} \
    --security-groups ${ALB_SG} \
    --scheme internet-facing \
    --type application \
    --region ${AWS_REGION} \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || \
    aws elbv2 describe-load-balancers \
        --names ${PROJECT_NAME}-alb \
        --region ${AWS_REGION} \
        --query 'LoadBalancers[0].LoadBalancerArn' --output text)

TG_ARN=$(aws elbv2 create-target-group \
    --name ${PROJECT_NAME}-orch-tg \
    --protocol HTTP \
    --port ${ORCHESTRATOR_PORT} \
    --vpc-id ${VPC_ID} \
    --target-type ip \
    --health-check-path /health \
    --health-check-interval-seconds 30 \
    --matcher HttpCode=200 \
    --region ${AWS_REGION} \
    --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null || \
    aws elbv2 describe-target-groups \
        --names ${PROJECT_NAME}-orch-tg \
        --region ${AWS_REGION} \
        --query 'TargetGroups[0].TargetGroupArn' --output text)

aws elbv2 create-listener \
    --load-balancer-arn ${ALB_ARN} \
    --protocol HTTP \
    --port 80 \
    --default-actions Type=forward,TargetGroupArn=${TG_ARN} \
    --region ${AWS_REGION} 2>/dev/null || true

ALB_DNS=$(aws elbv2 describe-load-balancers \
    --load-balancer-arns ${ALB_ARN} \
    --region ${AWS_REGION} \
    --query 'LoadBalancers[0].DNSName' --output text)

# Create Service Discovery
log_info "Creating service discovery..."
NAMESPACE_ID=$(aws servicediscovery create-private-dns-namespace \
    --name local \
    --vpc ${VPC_ID} \
    --description "Service discovery for ${PROJECT_NAME}" \
    --region ${AWS_REGION} \
    --query 'OperationId' --output text 2>/dev/null)

if [ "$NAMESPACE_ID" != "None" ] && [ ! -z "$NAMESPACE_ID" ]; then
    sleep 30
fi

NAMESPACE_ID=$(aws servicediscovery list-namespaces \
    --region ${AWS_REGION} \
    --query "Namespaces[?Name=='local'].Id" --output text)

for agent in extractor validator archivist; do
    aws servicediscovery create-service \
        --name ${agent} \
        --namespace-id ${NAMESPACE_ID} \
        --dns-config "NamespaceId=${NAMESPACE_ID},DnsRecords=[{Type=A,TTL=60}]" \
        --health-check-custom-config FailureThreshold=1 \
        --region ${AWS_REGION} 2>/dev/null || true
done

# Save configuration
cat > /tmp/${PROJECT_NAME}-config.env <<EOF
export AWS_REGION="${AWS_REGION}"
export AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID}"
export PROJECT_NAME="${PROJECT_NAME}"
export VPC_ID="${VPC_ID}"
export PUBLIC_SUBNET_1="${PUBLIC_SUBNET_1}"
export PUBLIC_SUBNET_2="${PUBLIC_SUBNET_2}"
export PRIVATE_SUBNET_1="${PRIVATE_SUBNET_1}"
export PRIVATE_SUBNET_2="${PRIVATE_SUBNET_2}"
export ALB_SG="${ALB_SG}"
export ECS_SG="${ECS_SG}"
export RDS_SG="${RDS_SG}"
export S3_BUCKET="${S3_BUCKET}"
export RDS_ENDPOINT="${RDS_ENDPOINT}"
export DB_PASSWORD="${DB_PASSWORD}"
export ALB_ARN="${ALB_ARN}"
export TG_ARN="${TG_ARN}"
export ALB_DNS="${ALB_DNS}"
export NAMESPACE_ID="${NAMESPACE_ID}"
EOF

log_info "========================================"
log_info "Phase 1 Complete!"
log_info "========================================"
echo ""
log_info "Infrastructure created successfully:"
echo "  • VPC: ${VPC_ID}"
echo "  • RDS Endpoint: ${RDS_ENDPOINT}"
echo "  • S3 Bucket: ${S3_BUCKET}"
echo "  • ALB DNS: ${ALB_DNS}"
echo ""
log_info "Configuration saved to: /tmp/${PROJECT_NAME}-config.env"
echo ""
log_info "Next Steps:"
echo "  1. On your local machine (with Docker), run: ./deploy-sso-phase2.sh"
echo "  2. This will build and push Docker images to ECR"
echo "  3. Then deploy ECS services"
echo ""
log_info "Or manually:"
echo "  aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
echo ""
