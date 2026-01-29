#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# CA-A2A CDK Quick Start for AWS Cloud Shell
# Version: 2.0.0 - Improved deployment with conflict handling
# ══════════════════════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                       ║"
echo "║       CA-A2A AWS CDK Deployment - Quick Start v2.0                   ║"
echo "║                                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

cd "$(dirname "$0")"

# Configuration
PROJECT_NAME="${PROJECT_NAME:-ca-a2a}"
ENVIRONMENT="${ENVIRONMENT:-prod}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-west-3}}"

echo -e "${CYAN}Configuration:${NC}"
echo "  Project:     ${PROJECT_NAME}"
echo "  Environment: ${ENVIRONMENT}"
echo "  Region:      ${REGION}"
echo ""

# Check if CDK is installed
if ! command -v cdk &> /dev/null; then
    echo -e "${RED}✗ AWS CDK not found!${NC}"
    echo "  Installing CDK..."
    npm install -g aws-cdk
fi

echo -e "${GREEN}✓${NC} AWS CDK version: $(cdk --version)"

# Install Python dependencies
echo -e "\n${CYAN}▸${NC} Installing Python dependencies..."
python3 -m pip install -r requirements.txt --user --quiet 2>/dev/null || \
    python3 -m pip install -r requirements.txt --quiet
echo -e "${GREEN}✓${NC} Dependencies installed"

# Get AWS account info
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo -e "\n${CYAN}AWS Account:${NC} ${ACCOUNT_ID}"
echo -e "${CYAN}AWS Region:${NC}  ${REGION}"

# Check if CDK is bootstrapped
echo -e "\n${CYAN}▸${NC} Checking CDK bootstrap status..."
BOOTSTRAP_STACK=$(aws cloudformation describe-stacks \
    --stack-name CDKToolkit \
    --region $REGION \
    --query 'Stacks[0].StackStatus' \
    --output text 2>/dev/null || echo "NOT_FOUND")

if [ "$BOOTSTRAP_STACK" == "NOT_FOUND" ]; then
    echo -e "${YELLOW}⚠${NC} CDK not bootstrapped. Bootstrapping now..."
    cdk bootstrap aws://$ACCOUNT_ID/$REGION --require-approval never
    echo -e "${GREEN}✓${NC} CDK bootstrapped"
else
    echo -e "${GREEN}✓${NC} CDK already bootstrapped (status: ${BOOTSTRAP_STACK})"
fi

# Check for existing resources that might conflict
echo -e "\n${CYAN}▸${NC} Checking for existing resources..."

EXISTING_VPC=$(aws ec2 describe-vpcs --region $REGION \
    --filters "Name=tag:Project,Values=${PROJECT_NAME}" \
    --query 'Vpcs[0].VpcId' --output text 2>/dev/null || echo "None")

EXISTING_CLUSTER=$(aws ecs describe-clusters --region $REGION \
    --clusters ${PROJECT_NAME}-cluster \
    --query 'clusters[?status==`ACTIVE`].clusterName' --output text 2>/dev/null || echo "")

# Build context arguments
CONTEXT_ARGS=""
if [ "$EXISTING_VPC" != "None" ] && [ -n "$EXISTING_VPC" ]; then
    echo -e "${YELLOW}⚠${NC} Found existing VPC: ${EXISTING_VPC}"
    CONTEXT_ARGS="$CONTEXT_ARGS -c existing_vpc_id=${EXISTING_VPC}"
fi

if [ -n "$EXISTING_CLUSTER" ]; then
    echo -e "${YELLOW}⚠${NC} Found existing ECS cluster: ${EXISTING_CLUSTER}"
    CONTEXT_ARGS="$CONTEXT_ARGS -c existing_cluster_name=${EXISTING_CLUSTER}"
fi

# Check for existing secrets
EXISTING_SECRETS=$(aws secretsmanager list-secrets --region $REGION \
    --filters Key=name,Values=${PROJECT_NAME}/ \
    --query 'SecretList[*].Name' --output text 2>/dev/null || echo "")

if [ -n "$EXISTING_SECRETS" ]; then
    echo -e "${YELLOW}⚠${NC} Found existing secrets (CDK will create new ones with unique names)"
fi

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}                         DEPLOYMENT OPTIONS                            ${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  1. ${BOLD}cdk diff${NC}    - Preview changes"
echo "  2. ${BOLD}cdk deploy${NC}  - Deploy infrastructure"
echo "  3. ${BOLD}cdk destroy${NC} - Destroy infrastructure"
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════════════${NC}"
echo ""

# Parse command line argument
ACTION="${1:-deploy}"

case $ACTION in
    diff)
        echo -e "${CYAN}▸${NC} Running cdk diff..."
        cdk diff \
            -c project_name=${PROJECT_NAME} \
            -c environment=${ENVIRONMENT} \
            -c region=${REGION} \
            $CONTEXT_ARGS
        ;;
    deploy)
        echo -e "${CYAN}▸${NC} Starting deployment... (This takes 15-20 minutes)"
        echo ""
        
        cdk deploy \
            -c project_name=${PROJECT_NAME} \
            -c environment=${ENVIRONMENT} \
            -c region=${REGION} \
            $CONTEXT_ARGS \
            --require-approval never \
            --outputs-file outputs.json
        
        echo ""
        echo -e "${BOLD}${GREEN}"
        echo "╔═══════════════════════════════════════════════════════════════════════╗"
        echo "║                                                                       ║"
        echo "║                    ✅ Deployment Complete!                            ║"
        echo "║                                                                       ║"
        echo "╚═══════════════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        
        if [ -f outputs.json ]; then
            echo -e "${CYAN}Stack Outputs:${NC}"
            cat outputs.json | python3 -m json.tool 2>/dev/null || cat outputs.json
        fi
        
        echo ""
        echo -e "${BOLD}Next Steps:${NC}"
        echo "  1. Build and push Docker images to ECR"
        echo "  2. Create ECS task definitions"
        echo "  3. Deploy ECS services"
        echo ""
        echo "  Run: ./deploy-services.sh"
        ;;
    destroy)
        echo -e "${YELLOW}⚠${NC} Destroying infrastructure..."
        echo -e "${RED}This will delete all resources!${NC}"
        echo ""
        
        cdk destroy \
            -c project_name=${PROJECT_NAME} \
            -c environment=${ENVIRONMENT} \
            -c region=${REGION} \
            $CONTEXT_ARGS \
            --force
        
        echo -e "${GREEN}✓${NC} Infrastructure destroyed"
        ;;
    *)
        echo -e "${RED}Unknown action: ${ACTION}${NC}"
        echo "Usage: $0 [diff|deploy|destroy]"
        exit 1
        ;;
esac
