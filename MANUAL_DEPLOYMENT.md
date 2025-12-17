# Manual AWS Deployment Guide - No Git Required

Complete guide to deploy the CA A2A Multi-Agent Pipeline to AWS using only AWS CLI commands, without requiring git access.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Deployment Steps](#deployment-steps)
4. [Configuration](#configuration)
5. [Verification](#verification)
6. [Management](#management)
7. [Cleanup](#cleanup)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Tools

```bash
# AWS CLI v2
aws --version
# AWS CLI 2.x required

# Docker
docker --version
# Docker 20.x+ required

# jq (JSON processor)
jq --version

# curl
curl --version
```

### Install Prerequisites (if missing)

**AWS CLI v2:**
```bash
# Linux
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# macOS
brew install awscli
```

**Docker:**
```bash
# Linux (Ubuntu/Debian)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# macOS
brew install --cask docker
```

**jq:**
```bash
# Linux
sudo apt-get install -y jq

# macOS
brew install jq
```

### AWS Account Setup

1. **Create AWS Account** (if you don't have one)
   - Go to https://aws.amazon.com/
   - Sign up for a new account

2. **Configure AWS CLI:**
```bash
aws configure
```

Enter your:
- AWS Access Key ID
- AWS Secret Access Key
- Default region (e.g., `us-east-1`)
- Default output format: `json`

3. **Verify credentials:**
```bash
aws sts get-caller-identity
```

Expected output:
```json
{
    "UserId": "AIDAXXXXXXXXXX",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/your-user"
}
```

---

## Quick Start

### Step 1: Prepare Deployment Files

You need the following files from the CA A2A project on your local machine:

```
ca_a2a/
├── deploy-manual.sh          # Main deployment script
├── requirements.txt           # Python dependencies
├── *.py                      # All Python agent files
│   ├── a2a_protocol.py
│   ├── mcp_protocol.py
│   ├── agent_card.py
│   ├── base_agent.py
│   ├── orchestrator_agent.py
│   ├── extractor_agent.py
│   ├── validator_agent.py
│   ├── archivist_agent.py
│   ├── config.py
│   ├── utils.py
│   ├── init_db.py
│   └── pydantic_models.py
└── .env.example              # Environment template
```

**Transfer these files to your deployment machine** (no git needed):
- USB drive
- SCP/SFTP
- Cloud storage download
- Direct copy from archive

### Step 2: Configure Environment

```bash
cd ca_a2a

# Set your AWS region
export AWS_REGION="us-east-1"  # Change to your preferred region

# Optional: Set custom database password (otherwise auto-generated)
export DB_PASSWORD="YourSecurePassword123!"

# Optional: Set environment name
export ENVIRONMENT="prod"
```

### Step 3: Run Deployment

```bash
# Make script executable
chmod +x deploy-manual.sh

# Run full deployment
./deploy-manual.sh
```

The script will:
1. ✓ Check prerequisites
2. ✓ Create VPC and networking (subnets, gateways, route tables)
3. ✓ Create security groups
4. ✓ Create S3 bucket for documents
5. ✓ Store secrets in AWS Secrets Manager
6. ✓ Create RDS PostgreSQL database
7. ✓ Create ECR repositories
8. ✓ Build and push Docker images
9. ✓ Create IAM roles
10. ✓ Create ECS cluster
11. ✓ Setup service discovery (AWS Cloud Map)
12. ✓ Create Application Load Balancer
13. ✓ Create CloudWatch log groups
14. ✓ Register ECS task definitions
15. ✓ Deploy ECS services

**Deployment time:** ~15-20 minutes

---

## Deployment Steps (Detailed)

### Phase 1: Network Infrastructure

#### Create VPC
```bash
VPC_ID=$(aws ec2 create-vpc \
    --cidr-block 10.0.0.0/16 \
    --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=ca-a2a-vpc}]' \
    --region us-east-1 \
    --query 'Vpc.VpcId' --output text)

echo "VPC created: $VPC_ID"
```

#### Enable DNS Support
```bash
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-support
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames
```

#### Create Internet Gateway
```bash
IGW_ID=$(aws ec2 create-internet-gateway \
    --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=ca-a2a-igw}]' \
    --query 'InternetGateway.InternetGatewayId' --output text)

aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID
```

#### Create Subnets
```bash
# Public Subnet 1 (AZ 1)
PUBLIC_SUBNET_1=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block 10.0.1.0/24 \
    --availability-zone us-east-1a \
    --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=ca-a2a-public-1}]' \
    --query 'Subnet.SubnetId' --output text)

# Public Subnet 2 (AZ 2)
PUBLIC_SUBNET_2=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block 10.0.2.0/24 \
    --availability-zone us-east-1b \
    --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=ca-a2a-public-2}]' \
    --query 'Subnet.SubnetId' --output text)

# Private Subnet 1 (AZ 1)
PRIVATE_SUBNET_1=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block 10.0.10.0/24 \
    --availability-zone us-east-1a \
    --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=ca-a2a-private-1}]' \
    --query 'Subnet.SubnetId' --output text)

# Private Subnet 2 (AZ 2)
PRIVATE_SUBNET_2=$(aws ec2 create-subnet \
    --vpc-id $VPC_ID \
    --cidr-block 10.0.20.0/24 \
    --availability-zone us-east-1b \
    --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=ca-a2a-private-2}]' \
    --query 'Subnet.SubnetId' --output text)
```

#### Create NAT Gateway
```bash
# Allocate Elastic IP
EIP_ID=$(aws ec2 allocate-address --domain vpc --query 'AllocationId' --output text)

# Create NAT Gateway in public subnet
NAT_GW=$(aws ec2 create-nat-gateway \
    --subnet-id $PUBLIC_SUBNET_1 \
    --allocation-id $EIP_ID \
    --tag-specifications 'ResourceType=natgateway,Tags=[{Key=Name,Value=ca-a2a-nat}]' \
    --query 'NatGateway.NatGatewayId' --output text)

# Wait for NAT Gateway
echo "Waiting for NAT Gateway..."
aws ec2 wait nat-gateway-available --nat-gateway-ids $NAT_GW
```

#### Create Route Tables
```bash
# Public route table
PUBLIC_RT=$(aws ec2 create-route-table \
    --vpc-id $VPC_ID \
    --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=ca-a2a-public-rt}]' \
    --query 'RouteTable.RouteTableId' --output text)

# Add route to internet gateway
aws ec2 create-route \
    --route-table-id $PUBLIC_RT \
    --destination-cidr-block 0.0.0.0/0 \
    --gateway-id $IGW_ID

# Associate public subnets
aws ec2 associate-route-table --subnet-id $PUBLIC_SUBNET_1 --route-table-id $PUBLIC_RT
aws ec2 associate-route-table --subnet-id $PUBLIC_SUBNET_2 --route-table-id $PUBLIC_RT

# Private route table
PRIVATE_RT=$(aws ec2 create-route-table \
    --vpc-id $VPC_ID \
    --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=ca-a2a-private-rt}]' \
    --query 'RouteTable.RouteTableId' --output text)

# Add route to NAT gateway
aws ec2 create-route \
    --route-table-id $PRIVATE_RT \
    --destination-cidr-block 0.0.0.0/0 \
    --nat-gateway-id $NAT_GW

# Associate private subnets
aws ec2 associate-route-table --subnet-id $PRIVATE_SUBNET_1 --route-table-id $PRIVATE_RT
aws ec2 associate-route-table --subnet-id $PRIVATE_SUBNET_2 --route-table-id $PRIVATE_RT
```

### Phase 2: Security Groups

```bash
# ALB Security Group
ALB_SG=$(aws ec2 create-security-group \
    --group-name ca-a2a-alb-sg \
    --description "Security group for ALB" \
    --vpc-id $VPC_ID \
    --query 'GroupId' --output text)

# Allow HTTP
aws ec2 authorize-security-group-ingress \
    --group-id $ALB_SG \
    --protocol tcp \
    --port 80 \
    --cidr 0.0.0.0/0

# Allow HTTPS
aws ec2 authorize-security-group-ingress \
    --group-id $ALB_SG \
    --protocol tcp \
    --port 443 \
    --cidr 0.0.0.0/0

# ECS Tasks Security Group
ECS_SG=$(aws ec2 create-security-group \
    --group-name ca-a2a-ecs-sg \
    --description "Security group for ECS tasks" \
    --vpc-id $VPC_ID \
    --query 'GroupId' --output text)

# Allow inter-agent communication
aws ec2 authorize-security-group-ingress \
    --group-id $ECS_SG \
    --protocol -1 \
    --source-group $ECS_SG

# Allow traffic from ALB
aws ec2 authorize-security-group-ingress \
    --group-id $ECS_SG \
    --protocol tcp \
    --port 8000-8999 \
    --source-group $ALB_SG

# RDS Security Group
RDS_SG=$(aws ec2 create-security-group \
    --group-name ca-a2a-rds-sg \
    --description "Security group for RDS" \
    --vpc-id $VPC_ID \
    --query 'GroupId' --output text)

# Allow PostgreSQL from ECS tasks
aws ec2 authorize-security-group-ingress \
    --group-id $RDS_SG \
    --protocol tcp \
    --port 5432 \
    --source-group $ECS_SG
```

### Phase 3: S3 and Secrets

```bash
# Get AWS Account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Create S3 bucket
S3_BUCKET="ca-a2a-documents-${AWS_ACCOUNT_ID}"
aws s3 mb "s3://${S3_BUCKET}" --region us-east-1

# Enable versioning
aws s3api put-bucket-versioning \
    --bucket $S3_BUCKET \
    --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \
    --bucket $S3_BUCKET \
    --server-side-encryption-configuration '{
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            }
        }]
    }'

# Block public access
aws s3api put-public-access-block \
    --bucket $S3_BUCKET \
    --public-access-block-configuration \
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Create database password secret
DB_PASSWORD="$(openssl rand -base64 32)"
aws secretsmanager create-secret \
    --name ca-a2a/db-password \
    --secret-string "$DB_PASSWORD"
```

### Phase 4: RDS Database

```bash
# Create DB subnet group
aws rds create-db-subnet-group \
    --db-subnet-group-name ca-a2a-db-subnet \
    --db-subnet-group-description "Subnet group for ca-a2a" \
    --subnet-ids $PRIVATE_SUBNET_1 $PRIVATE_SUBNET_2

# Create RDS instance
aws rds create-db-instance \
    --db-instance-identifier ca-a2a-postgres \
    --db-instance-class db.t3.medium \
    --engine postgres \
    --engine-version 15.4 \
    --master-username postgres \
    --master-user-password "$DB_PASSWORD" \
    --allocated-storage 20 \
    --storage-type gp3 \
    --vpc-security-group-ids $RDS_SG \
    --db-subnet-group-name ca-a2a-db-subnet \
    --backup-retention-period 7 \
    --storage-encrypted \
    --db-name documents_db \
    --no-publicly-accessible

# Wait for RDS (takes 5-10 minutes)
echo "Waiting for RDS to be available..."
aws rds wait db-instance-available --db-instance-identifier ca-a2a-postgres

# Get RDS endpoint
RDS_ENDPOINT=$(aws rds describe-db-instances \
    --db-instance-identifier ca-a2a-postgres \
    --query 'DBInstances[0].Endpoint.Address' --output text)

echo "RDS Endpoint: $RDS_ENDPOINT"
```

### Phase 5: Container Registry

```bash
# Create ECR repositories
for agent in orchestrator extractor validator archivist; do
    aws ecr create-repository --repository-name ca-a2a/$agent
done

# Login to ECR
aws ecr get-login-password --region us-east-1 | \
    docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com
```

### Phase 6: Build and Push Images

```bash
# Build and push each agent
for agent in orchestrator extractor validator archivist; do
    echo "Building $agent..."

    # Determine port
    case $agent in
        orchestrator) PORT=8001 ;;
        extractor) PORT=8002 ;;
        validator) PORT=8003 ;;
        archivist) PORT=8004 ;;
    esac

    # Create Dockerfile
    cat > Dockerfile.$agent <<EOF
FROM python:3.9-slim
WORKDIR /app
RUN apt-get update && apt-get install -y gcc postgresql-client libpq-dev curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
RUN useradd -m -u 1000 agent && chown -R agent:agent /app
USER agent
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:${PORT}/health || exit 1
CMD ["python", "${agent}_agent.py"]
EOF

    # Build
    IMAGE_URI="${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/${agent}:latest"
    docker build -f Dockerfile.$agent -t $IMAGE_URI .

    # Push
    docker push $IMAGE_URI

    echo "$agent pushed ✓"
done
```

### Phase 7: IAM Roles

```bash
# Trust policy for ECS tasks
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

# ECS Task Execution Role
aws iam create-role \
    --role-name ca-a2a-ecs-execution-role \
    --assume-role-policy-document file:///tmp/trust-policy.json

aws iam attach-role-policy \
    --role-name ca-a2a-ecs-execution-role \
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

# ECS Task Role (application permissions)
aws iam create-role \
    --role-name ca-a2a-ecs-task-role \
    --assume-role-policy-document file:///tmp/trust-policy.json

# Task policy (S3 + Secrets Manager)
cat > /tmp/task-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::${S3_BUCKET}/*",
        "arn:aws:s3:::${S3_BUCKET}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:us-east-1:${AWS_ACCOUNT_ID}:secret:ca-a2a/*"
    }
  ]
}
EOF

aws iam put-role-policy \
    --role-name ca-a2a-ecs-task-role \
    --policy-name ca-a2a-task-policy \
    --policy-document file:///tmp/task-policy.json
```

### Phase 8: ECS Cluster

```bash
# Create cluster
aws ecs create-cluster \
    --cluster-name ca-a2a-cluster \
    --capacity-providers FARGATE FARGATE_SPOT

# Enable Container Insights
aws ecs update-cluster-settings \
    --cluster ca-a2a-cluster \
    --settings name=containerInsights,value=enabled
```

### Phase 9: Service Discovery

```bash
# Create private DNS namespace
NAMESPACE_ID=$(aws servicediscovery create-private-dns-namespace \
    --name local \
    --vpc $VPC_ID \
    --description "Service discovery for ca-a2a" \
    --query 'OperationId' --output text)

# Wait for namespace
sleep 30
NAMESPACE_ID=$(aws servicediscovery list-namespaces \
    --query "Namespaces[?Name=='local'].Id" --output text)

# Create service discovery services
for agent in extractor validator archivist; do
    aws servicediscovery create-service \
        --name $agent \
        --namespace-id $NAMESPACE_ID \
        --dns-config "NamespaceId=${NAMESPACE_ID},DnsRecords=[{Type=A,TTL=60}]" \
        --health-check-custom-config FailureThreshold=1
done
```

### Phase 10: Application Load Balancer

```bash
# Create ALB
ALB_ARN=$(aws elbv2 create-load-balancer \
    --name ca-a2a-alb \
    --subnets $PUBLIC_SUBNET_1 $PUBLIC_SUBNET_2 \
    --security-groups $ALB_SG \
    --scheme internet-facing \
    --type application \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text)

# Create target group
TG_ARN=$(aws elbv2 create-target-group \
    --name ca-a2a-orch-tg \
    --protocol HTTP \
    --port 8001 \
    --vpc-id $VPC_ID \
    --target-type ip \
    --health-check-path /health \
    --health-check-interval-seconds 30 \
    --matcher HttpCode=200 \
    --query 'TargetGroups[0].TargetGroupArn' --output text)

# Create listener
aws elbv2 create-listener \
    --load-balancer-arn $ALB_ARN \
    --protocol HTTP \
    --port 80 \
    --default-actions Type=forward,TargetGroupArn=$TG_ARN

# Get ALB DNS
ALB_DNS=$(aws elbv2 describe-load-balancers \
    --load-balancer-arns $ALB_ARN \
    --query 'LoadBalancers[0].DNSName' --output text)

echo "ALB DNS: http://$ALB_DNS"
```

### Phase 11: CloudWatch Logs

```bash
# Create log groups
for agent in orchestrator extractor validator archivist; do
    aws logs create-log-group --log-group-name /ecs/ca-a2a-$agent
    aws logs put-retention-policy \
        --log-group-name /ecs/ca-a2a-$agent \
        --retention-in-days 7
done
```

### Phase 12: ECS Task Definitions & Services

See `deploy-manual.sh` for full task definition examples.

```bash
# Register task definitions
aws ecs register-task-definition --cli-input-json file:///tmp/orchestrator-task.json
aws ecs register-task-definition --cli-input-json file:///tmp/extractor-task.json
aws ecs register-task-definition --cli-input-json file:///tmp/validator-task.json
aws ecs register-task-definition --cli-input-json file:///tmp/archivist-task.json

# Create ECS services
aws ecs create-service \
    --cluster ca-a2a-cluster \
    --service-name orchestrator \
    --task-definition ca-a2a-orchestrator \
    --desired-count 2 \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[$PRIVATE_SUBNET_1,$PRIVATE_SUBNET_2],securityGroups=[$ECS_SG]}" \
    --load-balancers "targetGroupArn=$TG_ARN,containerName=orchestrator,containerPort=8001" \
    --health-check-grace-period-seconds 60
```

---

## Configuration

### Environment Variables

All configuration is stored in `/tmp/network-config.env`:

```bash
# Source configuration
source /tmp/network-config.env

# Available variables:
echo $VPC_ID
echo $RDS_ENDPOINT
echo $S3_BUCKET
echo $ALB_DNS
```

### Custom Configuration

Edit `deploy-manual.sh` to customize:

```bash
# At the top of the script
export AWS_REGION="eu-west-1"          # Change region
export DB_INSTANCE_CLASS="db.t3.small" # Change DB size
export VPC_CIDR="172.16.0.0/16"        # Change VPC CIDR
```

---

## Verification

### 1. Check ECS Services

```bash
aws ecs list-services --cluster ca-a2a-cluster

aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator extractor validator archivist
```

### 2. Test Health Endpoints

```bash
# Get ALB DNS
ALB_DNS=$(aws elbv2 describe-load-balancers \
    --names ca-a2a-alb \
    --query 'LoadBalancers[0].DNSName' --output text)

# Test orchestrator health
curl http://$ALB_DNS/health

# Expected: {"status": "healthy"}

# Test orchestrator status
curl http://$ALB_DNS/status

# Test agent card
curl http://$ALB_DNS/card | jq
```

### 3. Check Logs

```bash
# View orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator --follow

# View extractor logs
aws logs tail /ecs/ca-a2a-extractor --follow

# Search for errors
aws logs filter-log-events \
    --log-group-name /ecs/ca-a2a-orchestrator \
    --filter-pattern "ERROR"
```

### 4. Test Document Processing

```bash
# Upload test document to S3
echo "Test document content" > test.pdf
aws s3 cp test.pdf s3://$S3_BUCKET/test.pdf

# Process document
curl -X POST http://$ALB_DNS/process \
    -H "Content-Type: application/json" \
    -d '{"document_path": "s3://'$S3_BUCKET'/test.pdf"}'
```

---

## Management

### Update Docker Images

```bash
# Rebuild and push new image
docker build -f Dockerfile.orchestrator -t \
    ${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/orchestrator:latest .
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/orchestrator:latest

# Force new deployment
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service orchestrator \
    --force-new-deployment
```

### Scale Services

```bash
# Scale up orchestrator
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service orchestrator \
    --desired-count 4

# Scale down
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service orchestrator \
    --desired-count 1
```

### View Metrics

```bash
# CPU utilization
aws cloudwatch get-metric-statistics \
    --namespace AWS/ECS \
    --metric-name CPUUtilization \
    --dimensions Name=ServiceName,Value=orchestrator Name=ClusterName,Value=ca-a2a-cluster \
    --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 300 \
    --statistics Average

# Memory utilization
aws cloudwatch get-metric-statistics \
    --namespace AWS/ECS \
    --metric-name MemoryUtilization \
    --dimensions Name=ServiceName,Value=orchestrator Name=ClusterName,Value=ca-a2a-cluster \
    --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 300 \
    --statistics Average
```

---

## Cleanup

### Delete Everything

```bash
#!/bin/bash
# cleanup.sh - Remove all AWS resources

AWS_REGION="us-east-1"
PROJECT_NAME="ca-a2a"

# Delete ECS services
for service in orchestrator extractor validator archivist; do
    aws ecs update-service \
        --cluster ${PROJECT_NAME}-cluster \
        --service $service \
        --desired-count 0 \
        --region $AWS_REGION

    aws ecs delete-service \
        --cluster ${PROJECT_NAME}-cluster \
        --service $service \
        --force \
        --region $AWS_REGION
done

# Delete ECS cluster
aws ecs delete-cluster --cluster ${PROJECT_NAME}-cluster --region $AWS_REGION

# Delete ALB
ALB_ARN=$(aws elbv2 describe-load-balancers --names ${PROJECT_NAME}-alb --query 'LoadBalancers[0].LoadBalancerArn' --output text --region $AWS_REGION)
TG_ARN=$(aws elbv2 describe-target-groups --names ${PROJECT_NAME}-orch-tg --query 'TargetGroups[0].TargetGroupArn' --output text --region $AWS_REGION)

aws elbv2 delete-load-balancer --load-balancer-arn $ALB_ARN --region $AWS_REGION
sleep 30
aws elbv2 delete-target-group --target-group-arn $TG_ARN --region $AWS_REGION

# Delete RDS
aws rds delete-db-instance \
    --db-instance-identifier ${PROJECT_NAME}-postgres \
    --skip-final-snapshot \
    --region $AWS_REGION

# Delete S3 bucket
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
S3_BUCKET="${PROJECT_NAME}-documents-${AWS_ACCOUNT_ID}"
aws s3 rb "s3://${S3_BUCKET}" --force --region $AWS_REGION

# Delete ECR repositories
for agent in orchestrator extractor validator archivist; do
    aws ecr delete-repository \
        --repository-name ${PROJECT_NAME}/$agent \
        --force \
        --region $AWS_REGION
done

# Delete service discovery
NAMESPACE_ID=$(aws servicediscovery list-namespaces --query "Namespaces[?Name=='local'].Id" --output text --region $AWS_REGION)
for agent in extractor validator archivist; do
    SERVICE_ID=$(aws servicediscovery list-services --query "Services[?Name=='$agent'].Id" --output text --region $AWS_REGION)
    aws servicediscovery delete-service --id $SERVICE_ID --region $AWS_REGION
done
aws servicediscovery delete-namespace --id $NAMESPACE_ID --region $AWS_REGION

# Delete VPC (wait for dependencies to be deleted first)
echo "Waiting for resources to be deleted..."
sleep 120

VPC_ID=$(aws ec2 describe-vpcs --filters "Name=tag:Name,Values=${PROJECT_NAME}-vpc" --query 'Vpcs[0].VpcId' --output text --region $AWS_REGION)

# Delete NAT Gateway
NAT_GW=$(aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$VPC_ID" --query 'NatGateways[0].NatGatewayId' --output text --region $AWS_REGION)
aws ec2 delete-nat-gateway --nat-gateway-id $NAT_GW --region $AWS_REGION

# Release Elastic IP
sleep 30
EIP_ID=$(aws ec2 describe-addresses --filters "Name=domain,Values=vpc" --query 'Addresses[0].AllocationId' --output text --region $AWS_REGION)
aws ec2 release-address --allocation-id $EIP_ID --region $AWS_REGION

# Delete Security Groups
for sg in ${PROJECT_NAME}-alb-sg ${PROJECT_NAME}-ecs-sg ${PROJECT_NAME}-rds-sg; do
    SG_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$sg" --query 'SecurityGroups[0].GroupId' --output text --region $AWS_REGION)
    aws ec2 delete-security-group --group-id $SG_ID --region $AWS_REGION
done

# Delete VPC
aws ec2 delete-vpc --vpc-id $VPC_ID --region $AWS_REGION

echo "Cleanup complete!"
```

---

## Troubleshooting

### Issue: ECS Tasks Failing to Start

**Check task logs:**
```bash
aws ecs describe-tasks \
    --cluster ca-a2a-cluster \
    --tasks $(aws ecs list-tasks --cluster ca-a2a-cluster --service-name orchestrator --query 'taskArns[0]' --output text)
```

**Check CloudWatch logs:**
```bash
aws logs tail /ecs/ca-a2a-orchestrator --follow
```

### Issue: Cannot Connect to RDS

**Test from ECS task:**
```bash
# Get task ID
TASK_ID=$(aws ecs list-tasks --cluster ca-a2a-cluster --service-name orchestrator --query 'taskArns[0]' --output text)

# Enable ECS Exec (if not already enabled)
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service orchestrator \
    --enable-execute-command

# Execute command in container
aws ecs execute-command \
    --cluster ca-a2a-cluster \
    --task $TASK_ID \
    --container orchestrator \
    --interactive \
    --command "/bin/bash"

# Inside container, test connection:
apt-get update && apt-get install -y postgresql-client
psql -h $RDS_ENDPOINT -U postgres -d documents_db
```

### Issue: Service Discovery Not Working

**Check service discovery:**
```bash
# List services
aws servicediscovery list-services

# Check instances
aws servicediscovery list-instances \
    --service-id <service-id>

# DNS lookup from ECS task
nslookup extractor.local
```

### Issue: High Costs

**Check costs:**
```bash
# Get current month costs
aws ce get-cost-and-usage \
    --time-period Start=$(date +%Y-%m-01),End=$(date +%Y-%m-%d) \
    --granularity MONTHLY \
    --metrics UnblendedCost \
    --group-by Type=SERVICE
```

**Cost optimization:**
1. Use Fargate Spot for non-critical tasks
2. Scale down to 1 task per service
3. Use smaller RDS instance (db.t3.small)
4. Enable S3 lifecycle policies

---

## Cost Estimate

**Monthly costs (us-east-1):**

| Service | Configuration | Cost |
|---------|--------------|------|
| ECS Fargate | 8 tasks × 0.5 vCPU × 1GB × 730h | ~$60 |
| RDS PostgreSQL | db.t3.medium, 20GB | $50 |
| ALB | 1 ALB + data | $20 |
| NAT Gateway | Data transfer | $35 |
| S3 | 100GB storage | $3 |
| CloudWatch Logs | 10GB | $5 |
| **Total** | | **~$173/month** |

**To reduce costs:**
- Use 1 task per service: **-$30**
- Use db.t3.small: **-$25**
- Remove NAT (use VPC endpoints): **-$35**
- **New total: ~$83/month**

---

## Next Steps

1. **Initialize Database:**
   - Connect to ECS task
   - Run `python init_db.py init`

2. **Upload Test Documents:**
   ```bash
   aws s3 cp test-documents/ s3://$S3_BUCKET/test/ --recursive
   ```

3. **Set up Monitoring:**
   - Create CloudWatch dashboards
   - Set up alarms for errors
   - Enable X-Ray tracing

4. **Add HTTPS:**
   - Request ACM certificate
   - Add HTTPS listener to ALB

5. **Set up CI/CD:**
   - Create deployment pipeline
   - Automate image builds

---

## Support

- **AWS Documentation:** https://docs.aws.amazon.com/
- **ECS Best Practices:** https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/
- **Cost Calculator:** https://calculator.aws/

---

**Version:** 1.0.0
**Last Updated:** December 2025
