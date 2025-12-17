#!/bin/bash
###############################################################################
# CA A2A - Simple One-Command Deployment
# Deploys the complete multi-agent pipeline to AWS
###############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }
log_step() { echo -e "\n${BLUE}▸${NC} $1\n"; }

###############################################################################
# Banner
###############################################################################

echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   CA A2A Multi-Agent Pipeline Deployment                 ║
║   Simple One-Command AWS Deployment                      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

###############################################################################
# Configuration
###############################################################################

# Load .env if exists
if [ -f ".env" ]; then
    log_info "Loading configuration from .env"
    export $(cat .env | grep -v '^#' | xargs)
fi

# Default configuration
export AWS_REGION="${AWS_REGION:-eu-west-3}"
export PROJECT_NAME="${PROJECT_NAME:-ca-a2a}"
export ENVIRONMENT="${ENVIRONMENT:-prod}"
export DB_PASSWORD="${DB_PASSWORD:-$(openssl rand -base64 32 | tr -d '/+=')}"

log_info "Region: ${AWS_REGION}"
log_info "Project: ${PROJECT_NAME}"

###############################################################################
# Prerequisite Check
###############################################################################

log_step "Checking prerequisites..."

ERRORS=0

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    log_error "AWS CLI not found"
    echo "  Install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
    ERRORS=$((ERRORS + 1))
else
    log_info "AWS CLI found: $(aws --version 2>&1 | head -1)"
fi

# Check AWS credentials
if ! aws sts get-caller-identity &> /dev/null; then
    log_error "AWS credentials not configured"
    echo ""
    echo "  Run one of:"
    echo "    aws sso login --profile <your-profile>"
    echo "    aws configure"
    echo ""
    ERRORS=$((ERRORS + 1))
else
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    log_info "AWS Account: ${AWS_ACCOUNT_ID}"
fi

# Check Docker
DOCKER_AVAILABLE=false
if command -v docker &> /dev/null && docker ps &> /dev/null 2>&1; then
    DOCKER_AVAILABLE=true
    log_info "Docker found and running"
else
    log_warn "Docker not available"
    echo "  Will deploy infrastructure only (Phase 1)"
    echo "  You'll need Docker later for Phase 2"
fi

# Check jq (optional)
if command -v jq &> /dev/null; then
    log_info "jq found (optional but helpful)"
fi

if [ $ERRORS -gt 0 ]; then
    echo ""
    log_error "Please fix the errors above and try again"
    exit 1
fi

echo ""
read -p "Continue with deployment? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Deployment cancelled"
    exit 0
fi

###############################################################################
# Deployment Strategy
###############################################################################

if [ "$DOCKER_AVAILABLE" = true ]; then
    log_step "Full deployment (Infrastructure + Docker images + ECS services)"
    DEPLOYMENT_MODE="full"
else
    log_step "Infrastructure-only deployment (Phase 1)"
    log_warn "You'll need to run Phase 2 later on a machine with Docker"
    DEPLOYMENT_MODE="infra-only"
fi

###############################################################################
# Phase 1: Infrastructure
###############################################################################

log_step "Phase 1: Creating AWS Infrastructure..."

# Source the phase 1 script
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export S3_BUCKET="${PROJECT_NAME}-documents-${AWS_ACCOUNT_ID}"
export DB_NAME="documents_db"
export DB_USERNAME="postgres"
export DB_INSTANCE_CLASS="db.t3.medium"
export VPC_CIDR="10.0.0.0/16"
export ORCHESTRATOR_PORT=8001
export EXTRACTOR_PORT=8002
export VALIDATOR_PORT=8003
export ARCHIVIST_PORT=8004

log_info "Creating VPC and networking..."

# Create VPC
VPC_ID=$(aws ec2 create-vpc \
    --cidr-block ${VPC_CIDR} \
    --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=${PROJECT_NAME}-vpc}]" \
    --region ${AWS_REGION} \
    --query 'Vpc.VpcId' --output text 2>/dev/null || \
    aws ec2 describe-vpcs \
        --filters "Name=tag:Name,Values=${PROJECT_NAME}-vpc" \
        --region ${AWS_REGION} \
        --query 'Vpcs[0].VpcId' --output text)

aws ec2 modify-vpc-attribute --vpc-id ${VPC_ID} --enable-dns-support --region ${AWS_REGION} 2>/dev/null
aws ec2 modify-vpc-attribute --vpc-id ${VPC_ID} --enable-dns-hostnames --region ${AWS_REGION} 2>/dev/null

# Create Internet Gateway
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
PUBLIC_SUBNET_1=$(aws ec2 create-subnet \
    --vpc-id ${VPC_ID} --cidr-block 10.0.1.0/24 --availability-zone ${AZ1} \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-public-1}]" \
    --region ${AWS_REGION} --query 'Subnet.SubnetId' --output text 2>/dev/null || \
    aws ec2 describe-subnets --filters "Name=tag:Name,Values=${PROJECT_NAME}-public-1" \
        --region ${AWS_REGION} --query 'Subnets[0].SubnetId' --output text)

PUBLIC_SUBNET_2=$(aws ec2 create-subnet \
    --vpc-id ${VPC_ID} --cidr-block 10.0.2.0/24 --availability-zone ${AZ2} \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-public-2}]" \
    --region ${AWS_REGION} --query 'Subnet.SubnetId' --output text 2>/dev/null || \
    aws ec2 describe-subnets --filters "Name=tag:Name,Values=${PROJECT_NAME}-public-2" \
        --region ${AWS_REGION} --query 'Subnets[0].SubnetId' --output text)

PRIVATE_SUBNET_1=$(aws ec2 create-subnet \
    --vpc-id ${VPC_ID} --cidr-block 10.0.10.0/24 --availability-zone ${AZ1} \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-private-1}]" \
    --region ${AWS_REGION} --query 'Subnet.SubnetId' --output text 2>/dev/null || \
    aws ec2 describe-subnets --filters "Name=tag:Name,Values=${PROJECT_NAME}-private-1" \
        --region ${AWS_REGION} --query 'Subnets[0].SubnetId' --output text)

PRIVATE_SUBNET_2=$(aws ec2 create-subnet \
    --vpc-id ${VPC_ID} --cidr-block 10.0.20.0/24 --availability-zone ${AZ2} \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-private-2}]" \
    --region ${AWS_REGION} --query 'Subnet.SubnetId' --output text 2>/dev/null || \
    aws ec2 describe-subnets --filters "Name=tag:Name,Values=${PROJECT_NAME}-private-2" \
        --region ${AWS_REGION} --query 'Subnets[0].SubnetId' --output text)

log_info "Subnets created"

# Create NAT Gateway
log_info "Creating NAT Gateway (this takes a few minutes)..."
EIP_ID=$(aws ec2 allocate-address --domain vpc --region ${AWS_REGION} --query 'AllocationId' --output text 2>/dev/null)
NAT_GW=$(aws ec2 create-nat-gateway \
    --subnet-id ${PUBLIC_SUBNET_1} --allocation-id ${EIP_ID} \
    --tag-specifications "ResourceType=natgateway,Tags=[{Key=Name,Value=${PROJECT_NAME}-nat}]" \
    --region ${AWS_REGION} --query 'NatGateway.NatGatewayId' --output text 2>/dev/null || \
    aws ec2 describe-nat-gateways --filter "Name=tag:Name,Values=${PROJECT_NAME}-nat" "Name=state,Values=available" \
        --region ${AWS_REGION} --query 'NatGateways[0].NatGatewayId' --output text)

if [ "$NAT_GW" != "None" ] && [ ! -z "$NAT_GW" ]; then
    aws ec2 wait nat-gateway-available --nat-gateway-ids ${NAT_GW} --region ${AWS_REGION}
fi

# Create Route Tables
PUBLIC_RT=$(aws ec2 create-route-table --vpc-id ${VPC_ID} \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${PROJECT_NAME}-public-rt}]" \
    --region ${AWS_REGION} --query 'RouteTable.RouteTableId' --output text 2>/dev/null || \
    aws ec2 describe-route-tables --filters "Name=tag:Name,Values=${PROJECT_NAME}-public-rt" \
        --region ${AWS_REGION} --query 'RouteTables[0].RouteTableId' --output text)

aws ec2 create-route --route-table-id ${PUBLIC_RT} --destination-cidr-block 0.0.0.0/0 --gateway-id ${IGW_ID} --region ${AWS_REGION} 2>/dev/null || true
aws ec2 associate-route-table --subnet-id ${PUBLIC_SUBNET_1} --route-table-id ${PUBLIC_RT} --region ${AWS_REGION} 2>/dev/null || true
aws ec2 associate-route-table --subnet-id ${PUBLIC_SUBNET_2} --route-table-id ${PUBLIC_RT} --region ${AWS_REGION} 2>/dev/null || true

PRIVATE_RT=$(aws ec2 create-route-table --vpc-id ${VPC_ID} \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${PROJECT_NAME}-private-rt}]" \
    --region ${AWS_REGION} --query 'RouteTable.RouteTableId' --output text 2>/dev/null || \
    aws ec2 describe-route-tables --filters "Name=tag:Name,Values=${PROJECT_NAME}-private-rt" \
        --region ${AWS_REGION} --query 'RouteTables[0].RouteTableId' --output text)

if [ "$NAT_GW" != "None" ] && [ ! -z "$NAT_GW" ]; then
    aws ec2 create-route --route-table-id ${PRIVATE_RT} --destination-cidr-block 0.0.0.0/0 --nat-gateway-id ${NAT_GW} --region ${AWS_REGION} 2>/dev/null || true
fi
aws ec2 associate-route-table --subnet-id ${PRIVATE_SUBNET_1} --route-table-id ${PRIVATE_RT} --region ${AWS_REGION} 2>/dev/null || true
aws ec2 associate-route-table --subnet-id ${PRIVATE_SUBNET_2} --route-table-id ${PRIVATE_RT} --region ${AWS_REGION} 2>/dev/null || true

log_info "VPC and networking complete"

# Create Security Groups
log_info "Creating security groups..."
ALB_SG=$(aws ec2 create-security-group --group-name ${PROJECT_NAME}-alb-sg --description "ALB security group" \
    --vpc-id ${VPC_ID} --region ${AWS_REGION} --query 'GroupId' --output text 2>/dev/null || \
    aws ec2 describe-security-groups --filters "Name=group-name,Values=${PROJECT_NAME}-alb-sg" \
        --region ${AWS_REGION} --query 'SecurityGroups[0].GroupId' --output text)

aws ec2 authorize-security-group-ingress --group-id ${ALB_SG} --protocol tcp --port 80 --cidr 0.0.0.0/0 --region ${AWS_REGION} 2>/dev/null || true
aws ec2 authorize-security-group-ingress --group-id ${ALB_SG} --protocol tcp --port 443 --cidr 0.0.0.0/0 --region ${AWS_REGION} 2>/dev/null || true

ECS_SG=$(aws ec2 create-security-group --group-name ${PROJECT_NAME}-ecs-sg --description "ECS security group" \
    --vpc-id ${VPC_ID} --region ${AWS_REGION} --query 'GroupId' --output text 2>/dev/null || \
    aws ec2 describe-security-groups --filters "Name=group-name,Values=${PROJECT_NAME}-ecs-sg" \
        --region ${AWS_REGION} --query 'SecurityGroups[0].GroupId' --output text)

aws ec2 authorize-security-group-ingress --group-id ${ECS_SG} --protocol -1 --source-group ${ECS_SG} --region ${AWS_REGION} 2>/dev/null || true
aws ec2 authorize-security-group-ingress --group-id ${ECS_SG} --protocol tcp --port 8000-8999 --source-group ${ALB_SG} --region ${AWS_REGION} 2>/dev/null || true

RDS_SG=$(aws ec2 create-security-group --group-name ${PROJECT_NAME}-rds-sg --description "RDS security group" \
    --vpc-id ${VPC_ID} --region ${AWS_REGION} --query 'GroupId' --output text 2>/dev/null || \
    aws ec2 describe-security-groups --filters "Name=group-name,Values=${PROJECT_NAME}-rds-sg" \
        --region ${AWS_REGION} --query 'SecurityGroups[0].GroupId' --output text)

aws ec2 authorize-security-group-ingress --group-id ${RDS_SG} --protocol tcp --port 5432 --source-group ${ECS_SG} --region ${AWS_REGION} 2>/dev/null || true

# Create S3 Bucket
log_info "Creating S3 bucket..."
aws s3 mb "s3://${S3_BUCKET}" --region ${AWS_REGION} 2>/dev/null || true
aws s3api put-bucket-versioning --bucket ${S3_BUCKET} --versioning-configuration Status=Enabled --region ${AWS_REGION} 2>/dev/null || true
aws s3api put-bucket-encryption --bucket ${S3_BUCKET} \
    --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}' \
    --region ${AWS_REGION} 2>/dev/null || true
aws s3api put-public-access-block --bucket ${S3_BUCKET} \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
    --region ${AWS_REGION} 2>/dev/null || true

# Create Secrets
log_info "Creating secrets..."
aws secretsmanager create-secret --name ${PROJECT_NAME}/db-password --secret-string "${DB_PASSWORD}" \
    --region ${AWS_REGION} 2>/dev/null || \
aws secretsmanager update-secret --secret-id ${PROJECT_NAME}/db-password --secret-string "${DB_PASSWORD}" \
    --region ${AWS_REGION}

# Create RDS
log_info "Creating RDS database (this takes 5-10 minutes)..."
aws rds create-db-subnet-group --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --db-subnet-group-description "DB subnet group" \
    --subnet-ids ${PRIVATE_SUBNET_1} ${PRIVATE_SUBNET_2} --region ${AWS_REGION} 2>/dev/null || true

aws rds create-db-instance \
    --db-instance-identifier ${PROJECT_NAME}-postgres \
    --db-instance-class ${DB_INSTANCE_CLASS} --engine postgres --engine-version 15.4 \
    --master-username ${DB_USERNAME} --master-user-password "${DB_PASSWORD}" \
    --allocated-storage 20 --storage-type gp3 --vpc-security-group-ids ${RDS_SG} \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet --backup-retention-period 7 \
    --storage-encrypted --db-name ${DB_NAME} --no-publicly-accessible \
    --region ${AWS_REGION} 2>/dev/null || true

aws rds wait db-instance-available --db-instance-identifier ${PROJECT_NAME}-postgres --region ${AWS_REGION} 2>/dev/null || true

RDS_ENDPOINT=$(aws rds describe-db-instances --db-instance-identifier ${PROJECT_NAME}-postgres \
    --region ${AWS_REGION} --query 'DBInstances[0].Endpoint.Address' --output text)

log_info "RDS created: ${RDS_ENDPOINT}"

# Create ECR, IAM, ECS Cluster, ALB, CloudWatch, Service Discovery
log_info "Creating remaining AWS resources..."

# ECR
for agent in orchestrator extractor validator archivist; do
    aws ecr create-repository --repository-name ${PROJECT_NAME}/${agent} --region ${AWS_REGION} 2>/dev/null || true
done

# IAM Roles
cat > /tmp/trust-policy.json <<EOF
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
EOF

aws iam create-role --role-name ${PROJECT_NAME}-ecs-execution-role --assume-role-policy-document file:///tmp/trust-policy.json 2>/dev/null || true
aws iam attach-role-policy --role-name ${PROJECT_NAME}-ecs-execution-role \
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy 2>/dev/null || true

aws iam create-role --role-name ${PROJECT_NAME}-ecs-task-role --assume-role-policy-document file:///tmp/trust-policy.json 2>/dev/null || true

cat > /tmp/task-policy.json <<EOF
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"], "Resource": ["arn:aws:s3:::${S3_BUCKET}/*", "arn:aws:s3:::${S3_BUCKET}"]},
  {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/*"}
]}
EOF
aws iam put-role-policy --role-name ${PROJECT_NAME}-ecs-task-role --policy-name ${PROJECT_NAME}-task-policy \
    --policy-document file:///tmp/task-policy.json 2>/dev/null || true

# ECS Cluster
aws ecs create-cluster --cluster-name ${PROJECT_NAME}-cluster --capacity-providers FARGATE FARGATE_SPOT --region ${AWS_REGION} 2>/dev/null || true
aws ecs update-cluster-settings --cluster ${PROJECT_NAME}-cluster --settings name=containerInsights,value=enabled --region ${AWS_REGION} 2>/dev/null || true

# CloudWatch
for agent in orchestrator extractor validator archivist; do
    aws logs create-log-group --log-group-name /ecs/${PROJECT_NAME}-$agent --region ${AWS_REGION} 2>/dev/null || true
    aws logs put-retention-policy --log-group-name /ecs/${PROJECT_NAME}-$agent --retention-in-days 7 --region ${AWS_REGION} 2>/dev/null || true
done

# ALB
ALB_ARN=$(aws elbv2 create-load-balancer --name ${PROJECT_NAME}-alb \
    --subnets ${PUBLIC_SUBNET_1} ${PUBLIC_SUBNET_2} --security-groups ${ALB_SG} \
    --scheme internet-facing --type application --region ${AWS_REGION} \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || \
    aws elbv2 describe-load-balancers --names ${PROJECT_NAME}-alb --region ${AWS_REGION} \
        --query 'LoadBalancers[0].LoadBalancerArn' --output text)

TG_ARN=$(aws elbv2 create-target-group --name ${PROJECT_NAME}-orch-tg --protocol HTTP --port ${ORCHESTRATOR_PORT} \
    --vpc-id ${VPC_ID} --target-type ip --health-check-path /health --health-check-interval-seconds 30 \
    --matcher HttpCode=200 --region ${AWS_REGION} --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null || \
    aws elbv2 describe-target-groups --names ${PROJECT_NAME}-orch-tg --region ${AWS_REGION} \
        --query 'TargetGroups[0].TargetGroupArn' --output text)

aws elbv2 create-listener --load-balancer-arn ${ALB_ARN} --protocol HTTP --port 80 \
    --default-actions Type=forward,TargetGroupArn=${TG_ARN} --region ${AWS_REGION} 2>/dev/null || true

ALB_DNS=$(aws elbv2 describe-load-balancers --load-balancer-arns ${ALB_ARN} --region ${AWS_REGION} \
    --query 'LoadBalancers[0].DNSName' --output text)

# Service Discovery
NAMESPACE_ID=$(aws servicediscovery create-private-dns-namespace --name local --vpc ${VPC_ID} \
    --description "Service discovery" --region ${AWS_REGION} --query 'OperationId' --output text 2>/dev/null)
[ ! -z "$NAMESPACE_ID" ] && sleep 30
NAMESPACE_ID=$(aws servicediscovery list-namespaces --region ${AWS_REGION} --query "Namespaces[?Name=='local'].Id" --output text)

for agent in extractor validator archivist; do
    aws servicediscovery create-service --name ${agent} --namespace-id ${NAMESPACE_ID} \
        --dns-config "NamespaceId=${NAMESPACE_ID},DnsRecords=[{Type=A,TTL=60}]" \
        --health-check-custom-config FailureThreshold=1 --region ${AWS_REGION} 2>/dev/null || true
done

log_info "Infrastructure deployment complete!"

# Save configuration
cat > deployment-config.txt <<EOF
AWS_REGION=${AWS_REGION}
AWS_ACCOUNT_ID=${AWS_ACCOUNT_ID}
PROJECT_NAME=${PROJECT_NAME}
VPC_ID=${VPC_ID}
PRIVATE_SUBNET_1=${PRIVATE_SUBNET_1}
PRIVATE_SUBNET_2=${PRIVATE_SUBNET_2}
ECS_SG=${ECS_SG}
TG_ARN=${TG_ARN}
RDS_ENDPOINT=${RDS_ENDPOINT}
S3_BUCKET=${S3_BUCKET}
ALB_DNS=${ALB_DNS}
NAMESPACE_ID=${NAMESPACE_ID}
EOF

###############################################################################
# Phase 2: Docker and ECS (if Docker available)
###############################################################################

if [ "$DEPLOYMENT_MODE" = "full" ]; then
    log_step "Phase 2: Building and deploying containers..."

    # Login to ECR
    log_info "Logging in to ECR..."
    aws ecr get-login-password --region ${AWS_REGION} | \
        docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

    # Build and push images
    for agent in orchestrator extractor validator archivist; do
        log_info "Building ${agent}..."

        case $agent in
            orchestrator) PORT=8001 ;;
            extractor) PORT=8002 ;;
            validator) PORT=8003 ;;
            archivist) PORT=8004 ;;
        esac

        IMAGE_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}/${agent}:latest"

        cat > Dockerfile.${agent} <<EOF
FROM python:3.9-slim
WORKDIR /app
RUN apt-get update && apt-get install -y gcc postgresql-client libpq-dev curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
RUN useradd -m -u 1000 agent && chown -R agent:agent /app
USER agent
HEALTHCHECK --interval=30s --timeout=10s CMD curl -f http://localhost:${PORT}/health || exit 1
CMD ["python", "${agent}_agent.py"]
EOF

        docker build -q -f Dockerfile.${agent} -t ${IMAGE_URI} . && \
        docker push -q ${IMAGE_URI}
        log_info "${agent} deployed to ECR"
    done

    # Register task definitions and create services
    log_info "Deploying ECS services..."

    # This would continue with task definition registration and service creation
    # Using simplified inline approach for brevity
    source deploy-sso-phase2.sh
fi

###############################################################################
# Summary
###############################################################################

echo ""
log_step "Deployment Complete!"
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                   Deployment Summary                      ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  🌍 Region:        ${AWS_REGION}"
echo "  🏗️  VPC:           ${VPC_ID}"
echo "  🗄️  Database:      ${RDS_ENDPOINT}"
echo "  📦 S3 Bucket:     ${S3_BUCKET}"
echo "  🌐 Load Balancer: http://${ALB_DNS}"
echo ""

if [ "$DEPLOYMENT_MODE" = "full" ]; then
    echo -e "${GREEN}✓ Full deployment complete${NC}"
    echo ""
    echo "Test your deployment:"
    echo "  curl http://${ALB_DNS}/health"
    echo ""
    echo "View logs:"
    echo "  aws logs tail /ecs/${PROJECT_NAME}-orchestrator --follow --region ${AWS_REGION}"
else
    echo -e "${YELLOW}⚠ Phase 1 complete - Phase 2 required${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. On a machine with Docker, run:"
    echo "     ./deploy-sso-phase2.sh"
    echo "  2. Or manually build and push Docker images"
fi

echo ""
echo "Configuration saved to: deployment-config.txt"
echo ""
