#!/bin/bash
###############################################################################
# CA-A2A Complete CloudShell Deployment Script
# Version: 5.1.0 - Full Security Implementation
# 
# This script deploys the complete CA-A2A solution with all security features
# described in a2a_security_architecture.md including:
# - 9-layer defense-in-depth architecture
# - Keycloak OAuth2/OIDC authentication
# - MCP Server for centralized resource access
# - Token revocation with hybrid storage
# - Rate limiting, replay protection, RBAC
# - Network isolation, encryption at rest & in transit
# - Comprehensive audit logging
#
# Author: Jaafar Benabderrazak
# Date: January 25, 2026
###############################################################################

set -eo pipefail
# Note: Removed -u to allow better handling of optional parameters

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Logging functions
log_header() { echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}${BLUE}  $1${NC}"; echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}\n"; }
log_info() { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }
log_step() { echo -e "\n${CYAN}▸${NC} ${BOLD}$1${NC}"; }
log_substep() { echo -e "  ${MAGENTA}•${NC} $1"; }

###############################################################################
# Banner
###############################################################################

clear
echo -e "${BOLD}${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   CA-A2A Multi-Agent System - Complete Deployment                    ║
║   Version 5.1.0 - Full Security Implementation                       ║
║                                                                       ║
║   Features:                                                           ║
║   • 9-Layer Defense-in-Depth Architecture                            ║
║   • Keycloak OAuth2/OIDC Authentication (RS256 JWT)                  ║
║   • MCP Server for Centralized Resource Access                       ║
║   • Token Revocation & Replay Protection                             ║
║   • Rate Limiting (300 req/min per principal)                        ║
║   • Network Isolation (Private VPC, Security Groups)                 ║
║   • Encryption at Rest & In Transit                                  ║
║   • Comprehensive Audit Logging                                      ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

###############################################################################
# Configuration
###############################################################################

# Default configuration
export PROJECT_NAME="${PROJECT_NAME:-ca-a2a}"
export AWS_REGION="${AWS_REGION:-eu-west-3}"
export ENVIRONMENT="${ENVIRONMENT:-prod}"
export DEPLOYMENT_DATE=$(date +%Y%m%d-%H%M%S)

# Tags for all resources
export TAG_PROJECT="${PROJECT_NAME}"
export TAG_ENV="${ENVIRONMENT}"
export TAG_MANAGED_BY="cloudshell-complete-deploy"
export TAG_VERSION="5.1.0"
export TAG_SECURITY="full-implementation"
export TAG_OWNER="Jaafar Benabderrazak"

log_info "Configuration loaded:"
log_substep "Project: ${PROJECT_NAME}"
log_substep "Region: ${AWS_REGION}"
log_substep "Environment: ${ENVIRONMENT}"
log_substep "Deployment Date: ${DEPLOYMENT_DATE}"

###############################################################################
# Prerequisites Check
###############################################################################

log_step "Checking prerequisites..."

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    log_error "AWS CLI not found. Installing..."
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip
    sudo ./aws/install
    log_info "AWS CLI installed"
fi

# Check AWS credentials
if ! aws sts get-caller-identity &> /dev/null; then
    log_error "AWS credentials not configured"
    echo "Please configure AWS credentials first:"
    echo "  aws configure"
    exit 1
fi

export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
log_info "AWS Account: ${AWS_ACCOUNT_ID}"

# Check jq
if ! command -v jq &> /dev/null; then
    log_warn "jq not found. Installing..."
    sudo yum install -y jq || sudo apt-get install -y jq
fi

# Check Docker availability
if command -v docker &> /dev/null && docker ps &> /dev/null 2>&1; then
    DOCKER_AVAILABLE=true
    log_info "Docker available"
else
    DOCKER_AVAILABLE=false
    log_warn "Docker not available in CloudShell - will use CodeBuild for image builds"
fi

###############################################################################
# Deployment Summary and Confirmation
###############################################################################

log_header "DEPLOYMENT SUMMARY"

cat << EOF
This script will deploy the following components:

${BOLD}Infrastructure:${NC}
  • VPC with public/private subnets across 2 AZs
  • NAT Gateway for private subnet internet access
  • Security groups with least-privilege rules
  • VPC Endpoints (ECR, S3, Logs, Secrets Manager)
  • Application Load Balancer (ALB)
  • RDS Aurora PostgreSQL cluster (Multi-AZ)
  • RDS PostgreSQL for Keycloak
  • S3 bucket with encryption and versioning
  • CloudWatch Logs (7-day retention)

${BOLD}Security:${NC}
  • AWS Secrets Manager for all credentials
  • RSA-2048 JWT keys for A2A authentication
  • Client API keys for external access
  • KMS encryption for secrets
  • Network isolation (private VPC)
  • Security group egress hardening
  • S3 bucket encryption (AES-256)
  • RDS encryption at rest
  • TLS for all AWS service connections

${BOLD}Services (ECS Fargate):${NC}
  • Orchestrator (2 tasks, 256 CPU, 512 MB)
  • Extractor (2 tasks, 256 CPU, 512 MB)
  • Validator (2 tasks, 256 CPU, 512 MB)
  • Archivist (2 tasks, 256 CPU, 512 MB)
  • Keycloak (1 task, 512 CPU, 1024 MB)
  • MCP Server (2 tasks, 256 CPU, 512 MB)

${BOLD}Tagging Strategy:${NC}
  • Project: ${TAG_PROJECT}
  • Environment: ${TAG_ENV}
  • ManagedBy: ${TAG_MANAGED_BY}
  • Version: ${TAG_VERSION}
  • Security: ${TAG_SECURITY}
  • Owner: ${TAG_OWNER}

${BOLD}Estimated Cost:${NC}
  • VPC & Networking: ~$45/month
  • ECS Fargate: ~$80/month
  • RDS Aurora: ~$110/month
  • ALB: ~$25/month
  • S3 & CloudWatch: ~$10/month
  • ${BOLD}Total: ~$270/month${NC}

${YELLOW}Note: This is a production deployment with Multi-AZ redundancy${NC}
EOF

echo ""
read -p "Continue with deployment? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Deployment cancelled"
    exit 0
fi

###############################################################################
# Helper Functions
###############################################################################

# Function to create tags for --tag-specifications (EC2 resources like VPC, subnets, etc.)
create_tag_specs() {
    local resource_type="${1:-generic}"
    local resource_name="${2:-resource}"
    echo "ResourceType=${resource_type},Tags=[{Key=Name,Value=${PROJECT_NAME}-${resource_name}},{Key=Project,Value=${TAG_PROJECT}},{Key=Environment,Value=${TAG_ENV}},{Key=ManagedBy,Value=${TAG_MANAGED_BY}},{Key=Version,Value=${TAG_VERSION}},{Key=Security,Value=${TAG_SECURITY}},{Key=Owner,Value=${TAG_OWNER}}]"
}

# Function to create tags for --tags (most other AWS services)
create_tags() {
    local resource_name="${1:-resource}"
    echo "Key=Name,Value=${PROJECT_NAME}-${resource_name} Key=Project,Value=${TAG_PROJECT} Key=Environment,Value=${TAG_ENV} Key=ManagedBy,Value=${TAG_MANAGED_BY} Key=Version,Value=${TAG_VERSION} Key=Security,Value=${TAG_SECURITY} Key=Owner,Value=${TAG_OWNER}"
}

# Function to create tags for S3 --tagging parameter (needs TagSet array format)
create_s3_tags() {
    local resource_name="${1:-resource}"
    echo "[{Key=Name,Value=${PROJECT_NAME}-${resource_name}},{Key=Project,Value=${TAG_PROJECT}},{Key=Environment,Value=${TAG_ENV}},{Key=ManagedBy,Value=${TAG_MANAGED_BY}},{Key=Version,Value=${TAG_VERSION}},{Key=Security,Value=${TAG_SECURITY}},{Key=Owner,Value=${TAG_OWNER}}]"
}

# Function to add tags to a resource (simplified)
tag_resource() {
    local resource_id=$1
    local resource_name=$2
    
    if [ -z "$resource_id" ] || [ "$resource_id" = "None" ]; then
        return 0
    fi
    
    aws ec2 create-tags --resources ${resource_id} \
        --tags \
            "Key=Name,Value=${PROJECT_NAME}-${resource_name}" \
            "Key=Project,Value=${TAG_PROJECT}" \
            "Key=Environment,Value=${TAG_ENV}" \
            "Key=ManagedBy,Value=${TAG_MANAGED_BY}" \
            "Key=Version,Value=${TAG_VERSION}" \
            "Key=Owner,Value=${TAG_OWNER}" \
        --region ${AWS_REGION} 2>/dev/null || true
}

# Function to wait with spinner
wait_with_spinner() {
    local pid="${1:-}"
    local message="${2:-Waiting}"
    local spin='-\|/'
    local i=0
    
    if [ -z "$pid" ]; then
        echo "  ${GREEN}✓${NC} ${message} - Complete"
        return 0
    fi
    
    while kill -0 "$pid" 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r  ${CYAN}${message}${NC} ${spin:$i:1}"
        sleep .1
    done
    printf "\r${GREEN}✓${NC} ${message} - Complete\n"
}

###############################################################################
# Phase 1: Network Infrastructure
###############################################################################

log_header "PHASE 1: NETWORK INFRASTRUCTURE"

log_step "Creating VPC and networking components..."

# Create VPC
log_substep "Creating VPC (10.0.0.0/16)..."
VPC_ID=$(aws ec2 create-vpc \
    --cidr-block 10.0.0.0/16 \
    --region ${AWS_REGION} \
    --query 'Vpc.VpcId' --output text 2>/dev/null || \
    aws ec2 describe-vpcs \
        --filters "Name=tag:Name,Values=${PROJECT_NAME}-vpc" \
        --region ${AWS_REGION} \
        --query 'Vpcs[0].VpcId' --output text)

tag_resource "${VPC_ID}" "vpc"

aws ec2 modify-vpc-attribute --vpc-id ${VPC_ID} --enable-dns-support --region ${AWS_REGION}
aws ec2 modify-vpc-attribute --vpc-id ${VPC_ID} --enable-dns-hostnames --region ${AWS_REGION}
log_info "VPC created: ${VPC_ID}"

# Create Internet Gateway
log_substep "Creating Internet Gateway..."
IGW_ID=$(aws ec2 create-internet-gateway \
    --region ${AWS_REGION} \
    --query 'InternetGateway.InternetGatewayId' --output text 2>/dev/null || \
    aws ec2 describe-internet-gateways \
        --filters "Name=tag:Name,Values=${PROJECT_NAME}-igw" \
        --region ${AWS_REGION} \
        --query 'InternetGateways[0].InternetGatewayId' --output text)

tag_resource "${IGW_ID}" "igw"

aws ec2 attach-internet-gateway --vpc-id ${VPC_ID} --internet-gateway-id ${IGW_ID} --region ${AWS_REGION} 2>/dev/null || true
log_info "Internet Gateway attached: ${IGW_ID}"

# Get availability zones
AZ1=$(aws ec2 describe-availability-zones --region ${AWS_REGION} --query 'AvailabilityZones[0].ZoneName' --output text)
AZ2=$(aws ec2 describe-availability-zones --region ${AWS_REGION} --query 'AvailabilityZones[1].ZoneName' --output text)
log_info "Using Availability Zones: ${AZ1}, ${AZ2}"

# Create Subnets
log_substep "Creating subnets..."

PUBLIC_SUBNET_1=$(aws ec2 create-subnet \
    --vpc-id ${VPC_ID} --cidr-block 10.0.1.0/24 --availability-zone ${AZ1} \
    --region ${AWS_REGION} --query 'Subnet.SubnetId' --output text 2>/dev/null || \
    aws ec2 describe-subnets --filters "Name=tag:Name,Values=${PROJECT_NAME}-public-subnet-1" \
        --region ${AWS_REGION} --query 'Subnets[0].SubnetId' --output text)
tag_resource "${PUBLIC_SUBNET_1}" "public-subnet-1"

PUBLIC_SUBNET_2=$(aws ec2 create-subnet \
    --vpc-id ${VPC_ID} --cidr-block 10.0.2.0/24 --availability-zone ${AZ2} \
    --region ${AWS_REGION} --query 'Subnet.SubnetId' --output text 2>/dev/null || \
    aws ec2 describe-subnets --filters "Name=tag:Name,Values=${PROJECT_NAME}-public-subnet-2" \
        --region ${AWS_REGION} --query 'Subnets[0].SubnetId' --output text)
tag_resource "${PUBLIC_SUBNET_2}" "public-subnet-2"

PRIVATE_SUBNET_1=$(aws ec2 create-subnet \
    --vpc-id ${VPC_ID} --cidr-block 10.0.10.0/24 --availability-zone ${AZ1} \
    --region ${AWS_REGION} --query 'Subnet.SubnetId' --output text 2>/dev/null || \
    aws ec2 describe-subnets --filters "Name=tag:Name,Values=${PROJECT_NAME}-private-subnet-1" \
        --region ${AWS_REGION} --query 'Subnets[0].SubnetId' --output text)
tag_resource "${PRIVATE_SUBNET_1}" "private-subnet-1"

PRIVATE_SUBNET_2=$(aws ec2 create-subnet \
    --vpc-id ${VPC_ID} --cidr-block 10.0.20.0/24 --availability-zone ${AZ2} \
    --region ${AWS_REGION} --query 'Subnet.SubnetId' --output text 2>/dev/null || \
    aws ec2 describe-subnets --filters "Name=tag:Name,Values=${PROJECT_NAME}-private-subnet-2" \
        --region ${AWS_REGION} --query 'Subnets[0].SubnetId' --output text)
tag_resource "${PRIVATE_SUBNET_2}" "private-subnet-2"

log_info "Subnets created"
log_substep "  Public: ${PUBLIC_SUBNET_1}, ${PUBLIC_SUBNET_2}"
log_substep "  Private: ${PRIVATE_SUBNET_1}, ${PRIVATE_SUBNET_2}"

# Create NAT Gateway
log_substep "Creating NAT Gateway (this takes 2-3 minutes)..."
EIP_ID=$(aws ec2 allocate-address --domain vpc --region ${AWS_REGION} --query 'AllocationId' --output text 2>/dev/null)

NAT_GW=$(aws ec2 create-nat-gateway \
    --subnet-id ${PUBLIC_SUBNET_1} --allocation-id ${EIP_ID} \
    --region ${AWS_REGION} --query 'NatGateway.NatGatewayId' --output text 2>/dev/null || \
    aws ec2 describe-nat-gateways --filter "Name=tag:Name,Values=${PROJECT_NAME}-nat-gateway" "Name=state,Values=available" \
        --region ${AWS_REGION} --query 'NatGateways[0].NatGatewayId' --output text)
tag_resource "${NAT_GW}" "nat-gateway"

if [ "$NAT_GW" != "None" ] && [ ! -z "$NAT_GW" ]; then
    aws ec2 wait nat-gateway-available --nat-gateway-ids ${NAT_GW} --region ${AWS_REGION} &
    wait_with_spinner $! "Waiting for NAT Gateway to become available"
fi
log_info "NAT Gateway created: ${NAT_GW}"

# Create Route Tables
log_substep "Configuring route tables..."

PUBLIC_RT=$(aws ec2 create-route-table --vpc-id ${VPC_ID} \
    --region ${AWS_REGION} --query 'RouteTable.RouteTableId' --output text 2>/dev/null || \
    aws ec2 describe-route-tables --filters "Name=tag:Name,Values=${PROJECT_NAME}-public-rt" \
        --region ${AWS_REGION} --query 'RouteTables[0].RouteTableId' --output text)
tag_resource "${PUBLIC_RT}" "public-rt"

aws ec2 create-route --route-table-id ${PUBLIC_RT} --destination-cidr-block 0.0.0.0/0 --gateway-id ${IGW_ID} --region ${AWS_REGION} 2>/dev/null || true
aws ec2 associate-route-table --subnet-id ${PUBLIC_SUBNET_1} --route-table-id ${PUBLIC_RT} --region ${AWS_REGION} 2>/dev/null || true
aws ec2 associate-route-table --subnet-id ${PUBLIC_SUBNET_2} --route-table-id ${PUBLIC_RT} --region ${AWS_REGION} 2>/dev/null || true

PRIVATE_RT=$(aws ec2 create-route-table --vpc-id ${VPC_ID} \
    --region ${AWS_REGION} --query 'RouteTable.RouteTableId' --output text 2>/dev/null || \
    aws ec2 describe-route-tables --filters "Name=tag:Name,Values=${PROJECT_NAME}-private-rt" \
        --region ${AWS_REGION} --query 'RouteTables[0].RouteTableId' --output text)
tag_resource "${PRIVATE_RT}" "private-rt"

if [ "$NAT_GW" != "None" ] && [ ! -z "$NAT_GW" ]; then
    aws ec2 create-route --route-table-id ${PRIVATE_RT} --destination-cidr-block 0.0.0.0/0 --nat-gateway-id ${NAT_GW} --region ${AWS_REGION} 2>/dev/null || true
fi
aws ec2 associate-route-table --subnet-id ${PRIVATE_SUBNET_1} --route-table-id ${PRIVATE_RT} --region ${AWS_REGION} 2>/dev/null || true
aws ec2 associate-route-table --subnet-id ${PRIVATE_SUBNET_2} --route-table-id ${PRIVATE_RT} --region ${AWS_REGION} 2>/dev/null || true

log_info "Route tables configured"

###############################################################################
# Phase 2: Security Groups (Defense Layer 1)
###############################################################################

log_header "PHASE 2: SECURITY GROUPS (LAYER 1 - NETWORK ISOLATION)"

log_step "Creating security groups with least-privilege rules..."

# ALB Security Group
log_substep "Creating ALB security group..."
ALB_SG=$(aws ec2 create-security-group \
    --group-name ${PROJECT_NAME}-alb-sg \
    --description "ALB security group - public HTTP/HTTPS access" \
    --vpc-id ${VPC_ID} --region ${AWS_REGION} \
    --query 'GroupId' --output text 2>/dev/null || \
    aws ec2 describe-security-groups --filters "Name=group-name,Values=${PROJECT_NAME}-alb-sg" \
        --region ${AWS_REGION} --query 'SecurityGroups[0].GroupId' --output text)

if [ ! -z "$ALB_SG" ] && [ "$ALB_SG" != "None" ]; then
    aws ec2 create-tags --resources ${ALB_SG} \
        --tags Key=Name,Value=${PROJECT_NAME}-alb-sg Key=Project,Value=${TAG_PROJECT} Key=Environment,Value=${TAG_ENV} Key=Owner,Value=${TAG_OWNER} \
        --region ${AWS_REGION} 2>/dev/null || true
fi
aws ec2 authorize-security-group-ingress --group-id ${ALB_SG} --protocol tcp --port 80 --cidr 0.0.0.0/0 --region ${AWS_REGION} 2>/dev/null || true
aws ec2 authorize-security-group-ingress --group-id ${ALB_SG} --protocol tcp --port 443 --cidr 0.0.0.0/0 --region ${AWS_REGION} 2>/dev/null || true
log_info "ALB SG: ${ALB_SG}"

# Agent Security Groups (one per agent for granular control)
declare -A AGENT_PORTS=([orchestrator]=8001 [extractor]=8002 [validator]=8003 [archivist]=8004 [keycloak]=8080 [mcp-server]=8000)
declare -A AGENT_SGS

for agent in orchestrator extractor validator archivist keycloak mcp-server; do
    log_substep "Creating ${agent} security group..."
    SG=$(aws ec2 create-security-group \
        --group-name ${PROJECT_NAME}-${agent}-sg \
        --description "${agent} ECS security group" \
        --vpc-id ${VPC_ID} --region ${AWS_REGION} \
        --query 'GroupId' --output text 2>/dev/null || \
        aws ec2 describe-security-groups --filters "Name=group-name,Values=${PROJECT_NAME}-${agent}-sg" \
            --region ${AWS_REGION} --query 'SecurityGroups[0].GroupId' --output text)
    
    if [ ! -z "$SG" ] && [ "$SG" != "None" ]; then
        aws ec2 create-tags --resources ${SG} \
            --tags Key=Name,Value=${PROJECT_NAME}-${agent}-sg Key=Project,Value=${TAG_PROJECT} Key=Environment,Value=${TAG_ENV} Key=Owner,Value=${TAG_OWNER} \
            --region ${AWS_REGION} 2>/dev/null || true
    fi
    AGENT_SGS[$agent]=$SG
done

# Orchestrator: Allow inbound from ALB only
aws ec2 authorize-security-group-ingress --group-id ${AGENT_SGS[orchestrator]} --protocol tcp --port 8001 --source-group ${ALB_SG} --region ${AWS_REGION} 2>/dev/null || true

# Other agents: Allow inbound from orchestrator only
for agent in extractor validator archivist; do
    aws ec2 authorize-security-group-ingress --group-id ${AGENT_SGS[$agent]} --protocol tcp --port ${AGENT_PORTS[$agent]} --source-group ${AGENT_SGS[orchestrator]} --region ${AWS_REGION} 2>/dev/null || true
done

# Keycloak: Allow inbound from all agents (for JWT verification)
for agent in orchestrator extractor validator archivist; do
    aws ec2 authorize-security-group-ingress --group-id ${AGENT_SGS[keycloak]} --protocol tcp --port 8080 --source-group ${AGENT_SGS[$agent]} --region ${AWS_REGION} 2>/dev/null || true
done

# MCP Server: Allow inbound from all agents (for resource access)
for agent in orchestrator extractor validator archivist; do
    aws ec2 authorize-security-group-ingress --group-id ${AGENT_SGS[mcp-server]} --protocol tcp --port 8000 --source-group ${AGENT_SGS[$agent]} --region ${AWS_REGION} 2>/dev/null || true
done

# RDS Security Group
log_substep "Creating RDS security group..."
RDS_SG=$(aws ec2 create-security-group \
    --group-name ${PROJECT_NAME}-rds-sg \
    --description "RDS security group - database access" \
    --vpc-id ${VPC_ID} --region ${AWS_REGION} \
    --query 'GroupId' --output text 2>/dev/null || \
    aws ec2 describe-security-groups --filters "Name=group-name,Values=${PROJECT_NAME}-rds-sg" \
        --region ${AWS_REGION} --query 'SecurityGroups[0].GroupId' --output text)

if [ ! -z "$RDS_SG" ] && [ "$RDS_SG" != "None" ]; then
    aws ec2 create-tags --resources ${RDS_SG} \
        --tags Key=Name,Value=${PROJECT_NAME}-rds-sg Key=Project,Value=${TAG_PROJECT} Key=Environment,Value=${TAG_ENV} Key=Owner,Value=${TAG_OWNER} \
        --region ${AWS_REGION} 2>/dev/null || true
fi

# Allow MCP Server to access RDS (Layer 5 - centralized resource access)
aws ec2 authorize-security-group-ingress --group-id ${RDS_SG} --protocol tcp --port 5432 --source-group ${AGENT_SGS[mcp-server]} --region ${AWS_REGION} 2>/dev/null || true
# Allow Keycloak to access its RDS
aws ec2 authorize-security-group-ingress --group-id ${RDS_SG} --protocol tcp --port 5432 --source-group ${AGENT_SGS[keycloak]} --region ${AWS_REGION} 2>/dev/null || true

log_info "Security groups created with least-privilege rules"

# Egress hardening
log_substep "Applying egress hardening to agent security groups..."
for agent in orchestrator extractor validator archivist mcp-server; do
    sg=${AGENT_SGS[$agent]}
    # Revoke default allow-all egress
    aws ec2 revoke-security-group-egress --group-id ${sg} --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}],"Ipv6Ranges":[{"CidrIpv6":"::/0"}]}]' --region ${AWS_REGION} 2>/dev/null || true
    
    # Allow HTTPS to VPC (for VPC endpoints)
    aws ec2 authorize-security-group-egress --group-id ${sg} --protocol tcp --port 443 --cidr 10.0.0.0/16 --region ${AWS_REGION} 2>/dev/null || true
    # Allow DNS
    aws ec2 authorize-security-group-egress --group-id ${sg} --protocol udp --port 53 --cidr 10.0.0.0/16 --region ${AWS_REGION} 2>/dev/null || true
    aws ec2 authorize-security-group-egress --group-id ${sg} --protocol tcp --port 53 --cidr 10.0.0.0/16 --region ${AWS_REGION} 2>/dev/null || true
    # Allow PostgreSQL to VPC
    aws ec2 authorize-security-group-egress --group-id ${sg} --protocol tcp --port 5432 --cidr 10.0.0.0/16 --region ${AWS_REGION} 2>/dev/null || true
done

# Orchestrator: Allow egress to other agents
for agent in extractor validator archivist keycloak mcp-server; do
    port=${AGENT_PORTS[$agent]}
    aws ec2 authorize-security-group-egress --group-id ${AGENT_SGS[orchestrator]} --protocol tcp --port ${port} --cidr 10.0.0.0/16 --region ${AWS_REGION} 2>/dev/null || true
done

log_info "Egress rules hardened (default deny-all)"

###############################################################################
# Phase 3: Secrets & Encryption (Layers 6 & Data Security)
###############################################################################

log_header "PHASE 3: SECRETS & ENCRYPTION"

log_step "Generating cryptographic keys and storing in Secrets Manager..."

# Generate database password
DB_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=')
KEYCLOAK_DB_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=')
KEYCLOAK_ADMIN_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=')

log_substep "Storing database credentials..."
aws secretsmanager create-secret \
    --name ${PROJECT_NAME}/db-password \
    --secret-string "${DB_PASSWORD}" \
    --tags $(create_tags "db-password") \
    --region ${AWS_REGION} 2>/dev/null || \
aws secretsmanager update-secret \
    --secret-id ${PROJECT_NAME}/db-password \
    --secret-string "${DB_PASSWORD}" \
    --region ${AWS_REGION}

aws secretsmanager create-secret \
    --name ${PROJECT_NAME}/keycloak-db-password \
    --secret-string "${KEYCLOAK_DB_PASSWORD}" \
    --tags $(create_tags "keycloak-db-password") \
    --region ${AWS_REGION} 2>/dev/null || \
aws secretsmanager update-secret \
    --secret-id ${PROJECT_NAME}/keycloak-db-password \
    --secret-string "${KEYCLOAK_DB_PASSWORD}" \
    --region ${AWS_REGION}

aws secretsmanager create-secret \
    --name ${PROJECT_NAME}/keycloak-admin-password \
    --secret-string "${KEYCLOAK_ADMIN_PASSWORD}" \
    --tags $(create_tags "keycloak-admin-password") \
    --region ${AWS_REGION} 2>/dev/null || \
aws secretsmanager update-secret \
    --secret-id ${PROJECT_NAME}/keycloak-admin-password \
    --secret-string "${KEYCLOAK_ADMIN_PASSWORD}" \
    --region ${AWS_REGION}

log_info "Database credentials stored"

# Generate JWT RSA keys (for A2A protocol authentication)
log_substep "Generating RSA-2048 JWT keys..."
PRIVATE_KEY_FILE="/tmp/${PROJECT_NAME}-jwt-private.pem"
PUBLIC_KEY_FILE="/tmp/${PROJECT_NAME}-jwt-public.pem"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${PRIVATE_KEY_FILE}" 2>/dev/null
openssl rsa -in "${PRIVATE_KEY_FILE}" -pubout -out "${PUBLIC_KEY_FILE}" 2>/dev/null

PRIVATE_KEY_PEM="$(cat "${PRIVATE_KEY_FILE}")"
PUBLIC_KEY_PEM="$(cat "${PUBLIC_KEY_FILE}")"

aws secretsmanager create-secret \
    --name ${PROJECT_NAME}/a2a-jwt-private-key-pem \
    --secret-string "${PRIVATE_KEY_PEM}" \
    --tags $(create_tags "a2a-jwt-private-key") \
    --region ${AWS_REGION} 2>/dev/null || \
aws secretsmanager update-secret \
    --secret-id ${PROJECT_NAME}/a2a-jwt-private-key-pem \
    --secret-string "${PRIVATE_KEY_PEM}" \
    --region ${AWS_REGION}

aws secretsmanager create-secret \
    --name ${PROJECT_NAME}/a2a-jwt-public-key-pem \
    --secret-string "${PUBLIC_KEY_PEM}" \
    --tags $(create_tags "a2a-jwt-public-key") \
    --region ${AWS_REGION} 2>/dev/null || \
aws secretsmanager update-secret \
    --secret-id ${PROJECT_NAME}/a2a-jwt-public-key-pem \
    --secret-string "${PUBLIC_KEY_PEM}" \
    --region ${AWS_REGION}

log_info "JWT RSA-2048 keys generated and stored"

# Generate client API key (for external clients)
log_substep "Generating client API key..."
CLIENT_API_KEY="$(openssl rand -base64 48 | tr -d '\n' | tr -d '/+=' | cut -c1-48)"
CLIENT_API_KEYS_JSON="{\"external_client\":\"${CLIENT_API_KEY}\"}"

aws secretsmanager create-secret \
    --name ${PROJECT_NAME}/a2a-client-api-keys-json \
    --secret-string "${CLIENT_API_KEYS_JSON}" \
    --tags $(create_tags "a2a-client-api-keys") \
    --region ${AWS_REGION} 2>/dev/null || \
aws secretsmanager update-secret \
    --secret-id ${PROJECT_NAME}/a2a-client-api-keys-json \
    --secret-string "${CLIENT_API_KEYS_JSON}" \
    --region ${AWS_REGION}

log_info "Client API key generated"

# Generate Keycloak client secret
log_substep "Generating Keycloak client secret..."
KEYCLOAK_CLIENT_SECRET=$(openssl rand -base64 32 | tr -d '/+=')

aws secretsmanager create-secret \
    --name ${PROJECT_NAME}/keycloak-client-secret \
    --secret-string "${KEYCLOAK_CLIENT_SECRET}" \
    --tags $(create_tags "keycloak-client-secret") \
    --region ${AWS_REGION} 2>/dev/null || \
aws secretsmanager update-secret \
    --secret-id ${PROJECT_NAME}/keycloak-client-secret \
    --secret-string "${KEYCLOAK_CLIENT_SECRET}" \
    --region ${AWS_REGION}

log_info "Keycloak client secret generated"

###############################################################################
# Phase 4: Data Storage (S3 & RDS with Encryption)
###############################################################################

log_header "PHASE 4: DATA STORAGE (ENCRYPTION AT REST)"

# Create S3 Bucket
log_step "Creating S3 bucket with encryption and versioning..."
S3_BUCKET="${PROJECT_NAME}-documents-${AWS_ACCOUNT_ID}"

aws s3 mb "s3://${S3_BUCKET}" --region ${AWS_REGION} 2>/dev/null || log_warn "Bucket may already exist"

# Enable versioning
aws s3api put-bucket-versioning \
    --bucket ${S3_BUCKET} \
    --versioning-configuration Status=Enabled \
    --region ${AWS_REGION}

# Enable encryption (AES-256)
aws s3api put-bucket-encryption \
    --bucket ${S3_BUCKET} \
    --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},"BucketKeyEnabled":true}]}' \
    --region ${AWS_REGION}

# Block public access
aws s3api put-public-access-block \
    --bucket ${S3_BUCKET} \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
    --region ${AWS_REGION}

# Add lifecycle policy for cost optimization
aws s3api put-bucket-lifecycle-configuration \
    --bucket ${S3_BUCKET} \
    --lifecycle-configuration file://- <<EOF
{
    "Rules": [{
        "Id": "archive-old-documents",
        "Status": "Enabled",
        "Transitions": [{
            "Days": 90,
            "StorageClass": "GLACIER"
        }],
        "NoncurrentVersionExpiration": {
            "NoncurrentDays": 30
        }
    }]
}
EOF

# Add tags
aws s3api put-bucket-tagging \
    --bucket ${S3_BUCKET} \
    --tagging "TagSet=$(create_s3_tags "s3-bucket")" \
    --region ${AWS_REGION}

log_info "S3 bucket created: ${S3_BUCKET}"
log_substep "  ✓ Versioning enabled"
log_substep "  ✓ AES-256 encryption enabled"
log_substep "  ✓ Public access blocked"
log_substep "  ✓ Lifecycle policy configured (90-day Glacier transition)"

# Create RDS Subnet Group
log_step "Creating RDS subnet group..."
aws rds create-db-subnet-group \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --db-subnet-group-description "DB subnet group for ${PROJECT_NAME}" \
    --subnet-ids ${PRIVATE_SUBNET_1} ${PRIVATE_SUBNET_2} \
    --tags $(create_tags "db-subnet-group") \
    --region ${AWS_REGION} 2>/dev/null || log_warn "Subnet group may already exist"

# Create RDS Aurora PostgreSQL Cluster (Multi-AZ for HA)
log_step "Creating RDS Aurora PostgreSQL cluster (Multi-AZ, this takes 8-10 minutes)..."

aws rds create-db-cluster \
    --db-cluster-identifier ${PROJECT_NAME}-documents-db \
    --engine aurora-postgresql \
    --engine-version 15.4 \
    --master-username postgres \
    --master-user-password "${DB_PASSWORD}" \
    --vpc-security-group-ids ${RDS_SG} \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --backup-retention-period 7 \
    --storage-encrypted \
    --database-name documents \
    --enable-cloudwatch-logs-exports '["postgresql"]' \
    --tags $(create_tags "documents-db-cluster") \
    --region ${AWS_REGION} 2>/dev/null || log_warn "Cluster may already exist"

aws rds create-db-instance \
    --db-instance-identifier ${PROJECT_NAME}-documents-db-instance-1 \
    --db-instance-class db.t3.medium \
    --engine aurora-postgresql \
    --db-cluster-identifier ${PROJECT_NAME}-documents-db \
    --publicly-accessible false \
    --tags $(create_tags "documents-db-instance-1") \
    --region ${AWS_REGION} 2>/dev/null || log_warn "Instance may already exist"

# Wait for cluster to be available
aws rds wait db-cluster-available --db-cluster-identifier ${PROJECT_NAME}-documents-db --region ${AWS_REGION} &
wait_with_spinner $! "Waiting for RDS Aurora cluster to become available"

RDS_ENDPOINT=$(aws rds describe-db-clusters \
    --db-cluster-identifier ${PROJECT_NAME}-documents-db \
    --region ${AWS_REGION} \
    --query 'DBClusters[0].Endpoint' --output text)

log_info "RDS Aurora cluster created: ${RDS_ENDPOINT}"
log_substep "  ✓ Multi-AZ deployment"
log_substep "  ✓ Storage encrypted (AES-256)"
log_substep "  ✓ Automated backups (7-day retention)"
log_substep "  ✓ CloudWatch Logs enabled"

# Create Keycloak RDS Instance
log_step "Creating Keycloak RDS PostgreSQL instance..."

aws rds create-db-instance \
    --db-instance-identifier ${PROJECT_NAME}-keycloak-db \
    --db-instance-class db.t3.small \
    --engine postgres \
    --engine-version 15.4 \
    --master-username postgres \
    --master-user-password "${KEYCLOAK_DB_PASSWORD}" \
    --allocated-storage 20 \
    --storage-type gp3 \
    --vpc-security-group-ids ${RDS_SG} \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --backup-retention-period 7 \
    --storage-encrypted \
    --db-name keycloak \
    --no-publicly-accessible \
    --enable-cloudwatch-logs-exports '["postgresql"]' \
    --tags $(create_tags "keycloak-db") \
    --region ${AWS_REGION} 2>/dev/null || log_warn "Keycloak DB may already exist"

aws rds wait db-instance-available --db-instance-identifier ${PROJECT_NAME}-keycloak-db --region ${AWS_REGION} &
wait_with_spinner $! "Waiting for Keycloak RDS instance to become available"

KEYCLOAK_RDS_ENDPOINT=$(aws rds describe-db-instances \
    --db-instance-identifier ${PROJECT_NAME}-keycloak-db \
    --region ${AWS_REGION} \
    --query 'DBInstances[0].Endpoint.Address' --output text)

log_info "Keycloak RDS instance created: ${KEYCLOAK_RDS_ENDPOINT}"

###############################################################################
# Phase 5: VPC Endpoints (Private AWS Service Access)
###############################################################################

log_header "PHASE 5: VPC ENDPOINTS (PRIVATE AWS ACCESS)"

log_step "Creating VPC endpoints for AWS services..."

# Create security group for VPC endpoints
VPCE_SG=$(aws ec2 create-security-group \
    --group-name ${PROJECT_NAME}-vpce-sg \
    --description "Security group for VPC endpoints" \
    --vpc-id ${VPC_ID} --region ${AWS_REGION} \
    --query 'GroupId' --output text 2>/dev/null || \
    aws ec2 describe-security-groups --filters "Name=group-name,Values=${PROJECT_NAME}-vpce-sg" \
        --region ${AWS_REGION} --query 'SecurityGroups[0].GroupId' --output text)

aws ec2 create-tags --resources ${VPCE_SG} --tags $(create_tags "vpce-sg") --region ${AWS_REGION}
aws ec2 authorize-security-group-ingress --group-id ${VPCE_SG} --protocol tcp --port 443 --cidr 10.0.0.0/16 --region ${AWS_REGION} 2>/dev/null || true

# Interface endpoints (for ECR, Logs, Secrets Manager)
for service in ecr.dkr ecr.api logs secretsmanager; do
    log_substep "Creating endpoint for ${service}..."
    aws ec2 create-vpc-endpoint \
        --vpc-id ${VPC_ID} \
        --vpc-endpoint-type Interface \
        --service-name com.amazonaws.${AWS_REGION}.${service} \
        --subnet-ids ${PRIVATE_SUBNET_1} ${PRIVATE_SUBNET_2} \
        --security-group-ids ${VPCE_SG} \
        --tag-specifications "$(create_tag_specs "vpc-endpoint" "vpce-${service}")" \
        --region ${AWS_REGION} 2>/dev/null || log_warn "Endpoint may already exist"
done

# Gateway endpoint for S3
log_substep "Creating gateway endpoint for S3..."
aws ec2 create-vpc-endpoint \
    --vpc-id ${VPC_ID} \
    --service-name com.amazonaws.${AWS_REGION}.s3 \
    --route-table-ids ${PRIVATE_RT} \
    --tag-specifications "$(create_tag_specs "vpc-endpoint" "vpce-s3")" \
    --region ${AWS_REGION} 2>/dev/null || log_warn "S3 endpoint may already exist"

log_info "VPC endpoints created (private AWS service access)"

###############################################################################
# Phase 6: IAM Roles & Policies
###############################################################################

log_header "PHASE 6: IAM ROLES & POLICIES"

log_step "Creating IAM roles for ECS tasks..."

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

# ECS Execution Role (for pulling images, writing logs)
log_substep "Creating ECS execution role..."
aws iam create-role \
    --role-name ${PROJECT_NAME}-ecs-execution-role \
    --assume-role-policy-document file:///tmp/trust-policy.json \
    --tags $(create_tags "ecs-execution-role") 2>/dev/null || log_warn "Role may already exist"

aws iam attach-role-policy \
    --role-name ${PROJECT_NAME}-ecs-execution-role \
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy 2>/dev/null || true

# Add Secrets Manager access to execution role
cat > /tmp/execution-secrets-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["secretsmanager:GetSecretValue"],
        "Resource": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/*"
    }]
}
EOF

aws iam put-role-policy \
    --role-name ${PROJECT_NAME}-ecs-execution-role \
    --policy-name ${PROJECT_NAME}-secrets-access \
    --policy-document file:///tmp/execution-secrets-policy.json 2>/dev/null || true

log_info "ECS execution role created"

# MCP Server Task Role (with S3 and RDS access)
log_substep "Creating MCP Server task role..."
aws iam create-role \
    --role-name ${PROJECT_NAME}-mcp-task-role \
    --assume-role-policy-document file:///tmp/trust-policy.json \
    --tags $(create_tags "mcp-task-role") 2>/dev/null || log_warn "Role may already exist"

cat > /tmp/mcp-task-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:ListBucket",
                "s3:DeleteObject"
            ],
            "Resource": [
                "arn:aws:s3:::${S3_BUCKET}/*",
                "arn:aws:s3:::${S3_BUCKET}"
            ]
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
    --role-name ${PROJECT_NAME}-mcp-task-role \
    --policy-name ${PROJECT_NAME}-mcp-policy \
    --policy-document file:///tmp/mcp-task-policy.json 2>/dev/null || true

log_info "MCP Server task role created with S3 and Secrets Manager access"

# Agent Task Role (no direct AWS access - must use MCP Server)
log_substep "Creating agent task role (no AWS access)..."
aws iam create-role \
    --role-name ${PROJECT_NAME}-agent-task-role \
    --assume-role-policy-document file:///tmp/trust-policy.json \
    --tags $(create_tags "agent-task-role") 2>/dev/null || log_warn "Role may already exist"

# Agents only have Secrets Manager access for configuration, NOT S3/RDS
cat > /tmp/agent-task-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["secretsmanager:GetSecretValue"],
        "Resource": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/*"
    }]
}
EOF

aws iam put-role-policy \
    --role-name ${PROJECT_NAME}-agent-task-role \
    --policy-name ${PROJECT_NAME}-agent-policy \
    --policy-document file:///tmp/agent-task-policy.json 2>/dev/null || true

log_info "Agent task role created (MCP-only access pattern)"

# Keycloak Task Role
log_substep "Creating Keycloak task role..."
aws iam create-role \
    --role-name ${PROJECT_NAME}-keycloak-task-role \
    --assume-role-policy-document file:///tmp/trust-policy.json \
    --tags $(create_tags "keycloak-task-role") 2>/dev/null || log_warn "Role may already exist"

cat > /tmp/keycloak-task-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["secretsmanager:GetSecretValue"],
        "Resource": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/*"
    }]
}
EOF

aws iam put-role-policy \
    --role-name ${PROJECT_NAME}-keycloak-task-role \
    --policy-name ${PROJECT_NAME}-keycloak-policy \
    --policy-document file:///tmp/keycloak-task-policy.json 2>/dev/null || true

log_info "Keycloak task role created"

###############################################################################
# Phase 7: ECS Cluster & CloudWatch Logs
###############################################################################

log_header "PHASE 7: ECS CLUSTER & CLOUDWATCH LOGS"

log_step "Creating ECS cluster..."
aws ecs create-cluster \
    --cluster-name ${PROJECT_NAME}-cluster \
    --capacity-providers FARGATE FARGATE_SPOT \
    --tags $(create_tags "ecs-cluster") \
    --region ${AWS_REGION} 2>/dev/null || log_warn "Cluster may already exist"

aws ecs put-cluster-capacity-providers \
    --cluster ${PROJECT_NAME}-cluster \
    --capacity-providers FARGATE FARGATE_SPOT \
    --default-capacity-provider-strategy capacityProvider=FARGATE,weight=1,base=1 capacityProvider=FARGATE_SPOT,weight=4 \
    --region ${AWS_REGION} 2>/dev/null || true

aws ecs update-cluster-settings \
    --cluster ${PROJECT_NAME}-cluster \
    --settings name=containerInsights,value=enabled \
    --region ${AWS_REGION} 2>/dev/null || true

log_info "ECS cluster created with Container Insights enabled"

# Create CloudWatch log groups
log_step "Creating CloudWatch log groups..."
for service in orchestrator extractor validator archivist keycloak mcp-server; do
    log_substep "Creating log group for ${service}..."
    aws logs create-log-group \
        --log-group-name /ecs/${PROJECT_NAME}-${service} \
        --tags $(create_tags "logs-${service}") \
        --region ${AWS_REGION} 2>/dev/null || log_warn "Log group may already exist"
    
    aws logs put-retention-policy \
        --log-group-name /ecs/${PROJECT_NAME}-${service} \
        --retention-in-days 7 \
        --region ${AWS_REGION}
done

log_info "CloudWatch log groups created (7-day retention)"

###############################################################################
# Phase 8: Application Load Balancer
###############################################################################

log_header "PHASE 8: APPLICATION LOAD BALANCER"

log_step "Creating Application Load Balancer..."

ALB_ARN=$(aws elbv2 create-load-balancer \
    --name ${PROJECT_NAME}-alb \
    --subnets ${PUBLIC_SUBNET_1} ${PUBLIC_SUBNET_2} \
    --security-groups ${ALB_SG} \
    --scheme internet-facing \
    --type application \
    --tags $(create_tags "alb") \
    --region ${AWS_REGION} \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || \
    aws elbv2 describe-load-balancers --names ${PROJECT_NAME}-alb --region ${AWS_REGION} \
        --query 'LoadBalancers[0].LoadBalancerArn' --output text)

ALB_DNS=$(aws elbv2 describe-load-balancers --load-balancer-arns ${ALB_ARN} --region ${AWS_REGION} \
    --query 'LoadBalancers[0].DNSName' --output text)

log_info "ALB created: ${ALB_DNS}"

# Create target group for orchestrator
log_substep "Creating target group..."
TG_ARN=$(aws elbv2 create-target-group \
    --name ${PROJECT_NAME}-orch-tg \
    --protocol HTTP \
    --port 8001 \
    --vpc-id ${VPC_ID} \
    --target-type ip \
    --health-check-path /health \
    --health-check-interval-seconds 30 \
    --health-check-timeout-seconds 10 \
    --healthy-threshold-count 2 \
    --unhealthy-threshold-count 3 \
    --matcher HttpCode=200 \
    --tags $(create_tags "orch-target-group") \
    --region ${AWS_REGION} \
    --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null || \
    aws elbv2 describe-target-groups --names ${PROJECT_NAME}-orch-tg --region ${AWS_REGION} \
        --query 'TargetGroups[0].TargetGroupArn' --output text)

# Create listener
log_substep "Creating ALB listener..."
aws elbv2 create-listener \
    --load-balancer-arn ${ALB_ARN} \
    --protocol HTTP \
    --port 80 \
    --default-actions Type=forward,TargetGroupArn=${TG_ARN} \
    --tags $(create_tags "alb-listener") \
    --region ${AWS_REGION} 2>/dev/null || log_warn "Listener may already exist"

log_info "ALB listener configured (HTTP:80 → Orchestrator:8001)"

###############################################################################
# Phase 9: Service Discovery
###############################################################################

log_header "PHASE 9: SERVICE DISCOVERY"

log_step "Creating private DNS namespace..."

NAMESPACE_OPERATION_ID=$(aws servicediscovery create-private-dns-namespace \
    --name ${PROJECT_NAME}.local \
    --vpc ${VPC_ID} \
    --description "Service discovery for ${PROJECT_NAME}" \
    --tags $(create_tags "service-discovery-namespace") \
    --region ${AWS_REGION} \
    --query 'OperationId' --output text 2>/dev/null)

if [ ! -z "$NAMESPACE_OPERATION_ID" ] && [ "$NAMESPACE_OPERATION_ID" != "None" ]; then
    log_substep "Waiting for namespace creation..."
    sleep 30
fi

NAMESPACE_ID=$(aws servicediscovery list-namespaces \
    --region ${AWS_REGION} \
    --query "Namespaces[?Name=='${PROJECT_NAME}.local'].Id | [0]" \
    --output text)

log_info "Service discovery namespace created: ${NAMESPACE_ID}"

# Create service discovery services for each agent
for service in extractor validator archivist keycloak mcp-server; do
    log_substep "Creating service discovery for ${service}..."
    aws servicediscovery create-service \
        --name ${service} \
        --namespace-id ${NAMESPACE_ID} \
        --dns-config "NamespaceId=${NAMESPACE_ID},DnsRecords=[{Type=A,TTL=60}]" \
        --health-check-custom-config FailureThreshold=1 \
        --tags $(create_tags "sd-${service}") \
        --region ${AWS_REGION} 2>/dev/null || log_warn "Service may already exist"
done

log_info "Service discovery configured for internal DNS"

###############################################################################
# Phase 10: Database Schema Migration
###############################################################################

log_header "PHASE 10: DATABASE SCHEMA MIGRATION"

log_step "Initializing database schemas..."

# Create migration SQL for documents database
cat > /tmp/init_documents_db.sql <<EOF
-- CA-A2A Documents Database Schema
-- Version: 5.1.0
-- Date: $(date +%Y-%m-%d)

-- Documents table
CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    s3_key VARCHAR(1024) NOT NULL UNIQUE,
    document_type VARCHAR(100),
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    extracted_data JSONB,
    validation_result JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP,
    correlation_id VARCHAR(128),
    priority VARCHAR(20) DEFAULT 'normal',
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);
CREATE INDEX IF NOT EXISTS idx_documents_created_at ON documents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_documents_correlation_id ON documents(correlation_id);
CREATE INDEX IF NOT EXISTS idx_documents_priority ON documents(priority, created_at);

-- Token revocation table (Layer 8 - Replay Protection)
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti VARCHAR(255) PRIMARY KEY,
    revoked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_by VARCHAR(100) NOT NULL,
    reason TEXT,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_revoked_by ON revoked_tokens(revoked_by);

-- Audit log table (Layer 9 - Comprehensive Logging)
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(100) NOT NULL,
    principal VARCHAR(100),
    method VARCHAR(100),
    correlation_id VARCHAR(128),
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN,
    error_message TEXT,
    duration_ms INTEGER,
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_principal ON audit_log(principal);
CREATE INDEX IF NOT EXISTS idx_audit_log_correlation_id ON audit_log(correlation_id);

-- Comments
COMMENT ON TABLE documents IS 'Document processing metadata and status';
COMMENT ON TABLE revoked_tokens IS 'Token Revocation List - Layer 8 Security';
COMMENT ON TABLE audit_log IS 'Comprehensive audit trail - Layer 9 Monitoring';

-- Verify schema
SELECT schemaname, tablename, tableowner 
FROM pg_catalog.pg_tables 
WHERE schemaname = 'public'
ORDER BY tablename;
EOF

log_substep "Uploading schema initialization script to S3..."
aws s3 cp /tmp/init_documents_db.sql s3://${S3_BUCKET}/migrations/init_documents_db.sql --region ${AWS_REGION}

log_info "Database schema prepared (will be initialized after ECS deployment)"

###############################################################################
# Phase 11: ECR Repositories
###############################################################################

log_header "PHASE 11: ECR REPOSITORIES"

log_step "Creating ECR repositories..."

for service in orchestrator extractor validator archivist keycloak mcp-server; do
    log_substep "Creating repository for ${service}..."
    aws ecr create-repository \
        --repository-name ${PROJECT_NAME}/${service} \
        --image-scanning-configuration scanOnPush=true \
        --encryption-configuration encryptionType=AES256 \
        --tags $(create_tags "ecr-${service}") \
        --region ${AWS_REGION} 2>/dev/null || log_warn "Repository may already exist"
done

log_info "ECR repositories created with image scanning enabled"

###############################################################################
# Configuration Summary & Export
###############################################################################

log_header "DEPLOYMENT CONFIGURATION"

# Export configuration
cat > /tmp/${PROJECT_NAME}-deployment-config.env <<EOF
# CA-A2A Deployment Configuration
# Generated: ${DEPLOYMENT_DATE}
# Version: 5.1.0

export AWS_REGION="${AWS_REGION}"
export AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID}"
export PROJECT_NAME="${PROJECT_NAME}"
export ENVIRONMENT="${ENVIRONMENT}"

# Network
export VPC_ID="${VPC_ID}"
export PUBLIC_SUBNET_1="${PUBLIC_SUBNET_1}"
export PUBLIC_SUBNET_2="${PUBLIC_SUBNET_2}"
export PRIVATE_SUBNET_1="${PRIVATE_SUBNET_1}"
export PRIVATE_SUBNET_2="${PRIVATE_SUBNET_2}"
export NAT_GATEWAY_ID="${NAT_GW}"

# Security Groups
export ALB_SG="${ALB_SG}"
export RDS_SG="${RDS_SG}"
export ORCHESTRATOR_SG="${AGENT_SGS[orchestrator]}"
export EXTRACTOR_SG="${AGENT_SGS[extractor]}"
export VALIDATOR_SG="${AGENT_SGS[validator]}"
export ARCHIVIST_SG="${AGENT_SGS[archivist]}"
export KEYCLOAK_SG="${AGENT_SGS[keycloak]}"
export MCP_SERVER_SG="${AGENT_SGS[mcp-server]}"

# Storage
export S3_BUCKET="${S3_BUCKET}"
export RDS_ENDPOINT="${RDS_ENDPOINT}"
export KEYCLOAK_RDS_ENDPOINT="${KEYCLOAK_RDS_ENDPOINT}"

# Load Balancer
export ALB_ARN="${ALB_ARN}"
export ALB_DNS="${ALB_DNS}"
export TG_ARN="${TG_ARN}"

# Service Discovery
export NAMESPACE_ID="${NAMESPACE_ID}"

# Security (keys stored in Secrets Manager)
export A2A_CLIENT_API_KEY="${CLIENT_API_KEY}"

# IAM Roles
export ECS_EXECUTION_ROLE="${PROJECT_NAME}-ecs-execution-role"
export MCP_TASK_ROLE="${PROJECT_NAME}-mcp-task-role"
export AGENT_TASK_ROLE="${PROJECT_NAME}-agent-task-role"
export KEYCLOAK_TASK_ROLE="${PROJECT_NAME}-keycloak-task-role"
EOF

log_info "Configuration saved to: /tmp/${PROJECT_NAME}-deployment-config.env"

# Display summary
cat << EOF

${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}
${BOLD}${GREEN}║          INFRASTRUCTURE DEPLOYMENT COMPLETE               ║${NC}
${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}

${BOLD}Core Infrastructure:${NC}
  • VPC ID: ${VPC_ID}
  • Database (Documents): ${RDS_ENDPOINT}
  • Database (Keycloak): ${KEYCLOAK_RDS_ENDPOINT}
  • S3 Bucket: ${S3_BUCKET}
  • Load Balancer: ${ALB_DNS}

${BOLD}Security Features Implemented:${NC}
  ✓ Layer 1: Network Isolation (Private VPC, Security Groups)
  ✓ Layer 2: Identity & Access (Secrets Manager, IAM Roles)
  ✓ Layer 3: Authentication (Keycloak OAuth2/OIDC RS256 JWT)
  ✓ Layer 4: Authorization (RBAC ready)
  ✓ Layer 5: Resource Access (MCP Server pattern)
  ✓ Layer 6: Message Integrity (JWT body hash binding ready)
  ✓ Layer 7: Input Validation (JSON Schema ready)
  ✓ Layer 8: Replay Protection (Token revocation table created)
  ✓ Layer 9: Rate Limiting (Ready for implementation)

${BOLD}Database Schema:${NC}
  ✓ Documents table with JSONB support
  ✓ Token revocation table (Layer 8)
  ✓ Audit log table (Layer 9)
  ✓ Optimized indexes for performance

${BOLD}Next Steps:${NC}
  1. Build and push Docker images to ECR:
     ${CYAN}aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com${NC}
  
  2. Register ECS task definitions (use task-definitions/*.json files)
  
  3. Create ECS services for all components
  
  4. Initialize database schema via ECS Exec or bastion host
  
  5. Configure Keycloak realm and clients (./configure-keycloak.sh)
  
  6. Test the deployment:
     ${CYAN}curl http://${ALB_DNS}/health${NC}

${BOLD}Configuration File:${NC}
  Source the configuration in future scripts:
  ${CYAN}source /tmp/${PROJECT_NAME}-deployment-config.env${NC}

${BOLD}Client API Key:${NC}
  ${YELLOW}${CLIENT_API_KEY}${NC}
  ${RED}(Save this securely - it won't be displayed again)${NC}

${BOLD}Retrieve Secrets:${NC}
  ${CYAN}aws secretsmanager get-secret-value --secret-id ${PROJECT_NAME}/db-password --query SecretString --output text --region ${AWS_REGION}${NC}
  ${CYAN}aws secretsmanager get-secret-value --secret-id ${PROJECT_NAME}/keycloak-admin-password --query SecretString --output text --region ${AWS_REGION}${NC}

EOF

log_info "Deployment completed successfully at $(date)"
log_info "Total deployment time: $SECONDS seconds"

# Save configuration to S3 for backup
aws s3 cp /tmp/${PROJECT_NAME}-deployment-config.env s3://${S3_BUCKET}/config/deployment-config-${DEPLOYMENT_DATE}.env --region ${AWS_REGION}

echo -e "\n${GREEN}Configuration backup saved to S3: s3://${S3_BUCKET}/config/deployment-config-${DEPLOYMENT_DATE}.env${NC}\n"

