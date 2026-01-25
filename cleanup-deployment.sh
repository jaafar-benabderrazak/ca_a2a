#!/bin/bash

###############################################################################
# CA-A2A Deployment Cleanup Script
# 
# This script deletes ALL resources created by cloudshell-complete-deploy.sh
# Use this to start fresh with a clean slate
#
# Usage: ./cleanup-deployment.sh [--force]
###############################################################################

set -e

# Configuration
PROJECT_NAME="ca-a2a"
AWS_REGION="${AWS_REGION:-eu-west-3}"
ENVIRONMENT="${ENVIRONMENT:-prod}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Helper functions
log_info() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_step() {
    echo -e "\n${BLUE}▸${NC} ${BOLD}$1${NC}"
}

log_substep() {
    echo -e "  ${BLUE}•${NC} $1"
}

# Display banner
echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                       ║"
echo "║   CA-A2A Deployment Cleanup Script                                   ║"
echo "║   This will DELETE ALL deployed resources                            ║"
echo "║                                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

# Configuration summary
echo "${BOLD}Configuration:${NC}"
echo "  • Project: ${PROJECT_NAME}"
echo "  • Region: ${AWS_REGION}"
echo "  • Environment: ${ENVIRONMENT}"
echo ""

# Confirmation unless --force flag is used
if [ "$1" != "--force" ]; then
    echo -e "${YELLOW}${BOLD}WARNING:${NC} This will delete:"
    echo "  • VPC and all networking (subnets, NAT gateway, IGW)"
    echo "  • Security Groups"
    echo "  • RDS databases (Aurora cluster and Keycloak DB)"
    echo "  • S3 bucket and all contents"
    echo "  • ECS cluster and all services"
    echo "  • Application Load Balancer"
    echo "  • All secrets from Secrets Manager"
    echo "  • CloudWatch log groups"
    echo "  • ECR repositories"
    echo "  • IAM roles"
    echo ""
    read -p "Are you sure you want to continue? (type 'yes' to confirm): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Cleanup cancelled."
        exit 0
    fi
fi

###############################################################################
# Phase 1: ECS Services and Tasks
###############################################################################

log_step "Phase 1: Deleting ECS services and tasks..."

CLUSTER_NAME="${PROJECT_NAME}-cluster"
if aws ecs describe-clusters --clusters ${CLUSTER_NAME} --region ${AWS_REGION} --query 'clusters[0].clusterName' --output text 2>/dev/null | grep -q "${CLUSTER_NAME}"; then
    
    log_substep "Stopping and deleting ECS services..."
    SERVICES=$(aws ecs list-services --cluster ${CLUSTER_NAME} --region ${AWS_REGION} --query 'serviceArns[*]' --output text 2>/dev/null || echo "")
    
    for service_arn in $SERVICES; do
        service_name=$(basename $service_arn)
        log_substep "Deleting service: ${service_name}"
        aws ecs update-service --cluster ${CLUSTER_NAME} --service ${service_name} --desired-count 0 --region ${AWS_REGION} 2>/dev/null || true
        aws ecs delete-service --cluster ${CLUSTER_NAME} --service ${service_name} --force --region ${AWS_REGION} 2>/dev/null || true
    done
    
    log_substep "Waiting for services to delete..."
    sleep 10
    
    log_substep "Deleting ECS cluster..."
    aws ecs delete-cluster --cluster ${CLUSTER_NAME} --region ${AWS_REGION} 2>/dev/null || true
    log_info "ECS resources deleted"
else
    log_warn "ECS cluster not found, skipping"
fi

###############################################################################
# Phase 2: Load Balancer and Target Groups
###############################################################################

log_step "Phase 2: Deleting Application Load Balancer..."

ALB_ARN=$(aws elbv2 describe-load-balancers --names ${PROJECT_NAME}-alb --region ${AWS_REGION} --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || echo "None")

if [ "$ALB_ARN" != "None" ] && [ ! -z "$ALB_ARN" ]; then
    log_substep "Deleting listeners..."
    LISTENER_ARNS=$(aws elbv2 describe-listeners --load-balancer-arn ${ALB_ARN} --region ${AWS_REGION} --query 'Listeners[*].ListenerArn' --output text 2>/dev/null || echo "")
    for listener in $LISTENER_ARNS; do
        aws elbv2 delete-listener --listener-arn $listener --region ${AWS_REGION} 2>/dev/null || true
    done
    
    log_substep "Deleting ALB..."
    aws elbv2 delete-load-balancer --load-balancer-arn ${ALB_ARN} --region ${AWS_REGION} 2>/dev/null || true
    
    log_substep "Waiting for ALB to delete..."
    sleep 10
    log_info "ALB deleted"
else
    log_warn "ALB not found, skipping"
fi

log_substep "Deleting target groups..."
TG_ARNS=$(aws elbv2 describe-target-groups --region ${AWS_REGION} --query "TargetGroups[?starts_with(TargetGroupName, '${PROJECT_NAME}')].TargetGroupArn" --output text 2>/dev/null || echo "")
for tg in $TG_ARNS; do
    aws elbv2 delete-target-group --target-group-arn $tg --region ${AWS_REGION} 2>/dev/null || true
done

###############################################################################
# Phase 3: RDS Databases
###############################################################################

log_step "Phase 3: Deleting RDS databases..."

log_substep "Deleting Aurora cluster..."
aws rds delete-db-cluster --db-cluster-identifier ${PROJECT_NAME}-documents-db --skip-final-snapshot --region ${AWS_REGION} 2>/dev/null || log_warn "Aurora cluster not found"

log_substep "Deleting Keycloak database..."
aws rds delete-db-instance --db-instance-identifier ${PROJECT_NAME}-keycloak-db --skip-final-snapshot --region ${AWS_REGION} 2>/dev/null || log_warn "Keycloak DB not found"

log_substep "Waiting for databases to delete (this may take a few minutes)..."
sleep 30

log_substep "Deleting DB subnet group..."
aws rds delete-db-subnet-group --db-subnet-group-name ${PROJECT_NAME}-db-subnet-group --region ${AWS_REGION} 2>/dev/null || log_warn "DB subnet group not found"

log_info "RDS resources deleted"

###############################################################################
# Phase 4: S3 Bucket
###############################################################################

log_step "Phase 4: Deleting S3 bucket..."

S3_BUCKET="${PROJECT_NAME}-documents-${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"

if aws s3 ls s3://${S3_BUCKET} --region ${AWS_REGION} 2>/dev/null; then
    log_substep "Emptying bucket..."
    aws s3 rm s3://${S3_BUCKET} --recursive --region ${AWS_REGION} 2>/dev/null || true
    
    log_substep "Deleting bucket..."
    aws s3api delete-bucket --bucket ${S3_BUCKET} --region ${AWS_REGION} 2>/dev/null || true
    log_info "S3 bucket deleted"
else
    log_warn "S3 bucket not found, skipping"
fi

###############################################################################
# Phase 5: VPC and Networking (Most Complex)
###############################################################################

log_step "Phase 5: Deleting VPC and networking..."

# Find VPC
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=tag:Name,Values=${PROJECT_NAME}-vpc" --region ${AWS_REGION} --query 'Vpcs[0].VpcId' --output text 2>/dev/null || echo "None")

if [ "$VPC_ID" = "None" ] || [ -z "$VPC_ID" ]; then
    log_warn "VPC not found, skipping network cleanup"
else
    log_info "Found VPC: ${VPC_ID}"
    
    # Delete NAT Gateways
    log_substep "Deleting NAT Gateways..."
    NAT_GW_IDS=$(aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=${VPC_ID}" "Name=state,Values=available,pending" --query 'NatGateways[*].NatGatewayId' --output text --region ${AWS_REGION} 2>/dev/null || echo "")
    for nat in $NAT_GW_IDS; do
        log_substep "  Deleting NAT Gateway: $nat"
        aws ec2 delete-nat-gateway --nat-gateway-id $nat --region ${AWS_REGION} 2>/dev/null || true
    done
    
    if [ ! -z "$NAT_GW_IDS" ]; then
        log_substep "Waiting 60 seconds for NAT Gateways to delete..."
        sleep 60
    fi
    
    # Release Elastic IPs
    log_substep "Releasing Elastic IPs..."
    EIP_ALLOC_IDS=$(aws ec2 describe-addresses --filters "Name=domain,Values=vpc" --query 'Addresses[*].AllocationId' --output text --region ${AWS_REGION} 2>/dev/null || echo "")
    for eip in $EIP_ALLOC_IDS; do
        aws ec2 release-address --allocation-id $eip --region ${AWS_REGION} 2>/dev/null || true
    done
    
    # Delete VPC Endpoints
    log_substep "Deleting VPC endpoints..."
    VPCE_IDS=$(aws ec2 describe-vpc-endpoints --filters "Name=vpc-id,Values=${VPC_ID}" --query 'VpcEndpoints[*].VpcEndpointId' --output text --region ${AWS_REGION} 2>/dev/null || echo "")
    for vpce in $VPCE_IDS; do
        aws ec2 delete-vpc-endpoints --vpc-endpoint-ids $vpce --region ${AWS_REGION} 2>/dev/null || true
    done
    
    if [ ! -z "$VPCE_IDS" ]; then
        sleep 10
    fi
    
    # Delete Network Interfaces
    log_substep "Deleting network interfaces..."
    ENI_IDS=$(aws ec2 describe-network-interfaces --filters "Name=vpc-id,Values=${VPC_ID}" --query 'NetworkInterfaces[*].NetworkInterfaceId' --output text --region ${AWS_REGION} 2>/dev/null || echo "")
    for eni in $ENI_IDS; do
        aws ec2 delete-network-interface --network-interface-id $eni --region ${AWS_REGION} 2>/dev/null || true
    done
    
    # Delete Subnets
    log_substep "Deleting subnets..."
    SUBNET_IDS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=${VPC_ID}" --query 'Subnets[*].SubnetId' --output text --region ${AWS_REGION} 2>/dev/null || echo "")
    for subnet in $SUBNET_IDS; do
        aws ec2 delete-subnet --subnet-id $subnet --region ${AWS_REGION} 2>/dev/null || true
    done
    
    # Delete Route Tables (except main)
    log_substep "Deleting route tables..."
    RT_IDS=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=${VPC_ID}" --query 'RouteTables[?Associations[0].Main==`false`].RouteTableId' --output text --region ${AWS_REGION} 2>/dev/null || echo "")
    for rt in $RT_IDS; do
        # Disassociate first
        ASSOC_IDS=$(aws ec2 describe-route-tables --route-table-ids $rt --query 'RouteTables[0].Associations[*].RouteTableAssociationId' --output text --region ${AWS_REGION} 2>/dev/null || echo "")
        for assoc in $ASSOC_IDS; do
            aws ec2 disassociate-route-table --association-id $assoc --region ${AWS_REGION} 2>/dev/null || true
        done
        aws ec2 delete-route-table --route-table-id $rt --region ${AWS_REGION} 2>/dev/null || true
    done
    
    # Delete Internet Gateway
    log_substep "Deleting Internet Gateway..."
    IGW_ID=$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=${VPC_ID}" --query 'InternetGateways[0].InternetGatewayId' --output text --region ${AWS_REGION} 2>/dev/null || echo "None")
    if [ "$IGW_ID" != "None" ] && [ ! -z "$IGW_ID" ]; then
        aws ec2 detach-internet-gateway --internet-gateway-id ${IGW_ID} --vpc-id ${VPC_ID} --region ${AWS_REGION} 2>/dev/null || true
        aws ec2 delete-internet-gateway --internet-gateway-id ${IGW_ID} --region ${AWS_REGION} 2>/dev/null || true
    fi
    
    # Delete Security Groups (after everything else)
    log_substep "Deleting security groups..."
    sleep 5  # Wait a bit for dependencies to clear
    SG_IDS=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=${VPC_ID}" --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text --region ${AWS_REGION} 2>/dev/null || echo "")
    for sg in $SG_IDS; do
        aws ec2 delete-security-group --group-id $sg --region ${AWS_REGION} 2>/dev/null || true
    done
    
    # Delete VPC
    log_substep "Deleting VPC..."
    aws ec2 delete-vpc --vpc-id ${VPC_ID} --region ${AWS_REGION} 2>/dev/null || log_warn "VPC deletion failed (may have remaining dependencies)"
    
    log_info "VPC and networking deleted"
fi

###############################################################################
# Phase 6: Secrets Manager
###############################################################################

log_step "Phase 6: Deleting secrets from Secrets Manager..."

SECRETS=(
    "${PROJECT_NAME}/db-password"
    "${PROJECT_NAME}/keycloak-db-password"
    "${PROJECT_NAME}/keycloak-admin-password"
    "${PROJECT_NAME}/a2a-jwt-private-key-pem"
    "${PROJECT_NAME}/a2a-jwt-public-key-pem"
    "${PROJECT_NAME}/a2a-client-api-keys-json"
    "${PROJECT_NAME}/keycloak-client-secret"
)

for secret in "${SECRETS[@]}"; do
    log_substep "Deleting secret: $secret"
    aws secretsmanager delete-secret --secret-id "$secret" --force-delete-without-recovery --region ${AWS_REGION} 2>/dev/null || log_warn "  Secret not found or already deleted"
done

log_info "Secrets deleted"

###############################################################################
# Phase 7: CloudWatch Logs
###############################################################################

log_step "Phase 7: Deleting CloudWatch log groups..."

LOG_GROUPS=$(aws logs describe-log-groups --log-group-name-prefix "/ecs/${PROJECT_NAME}" --region ${AWS_REGION} --query 'logGroups[*].logGroupName' --output text 2>/dev/null || echo "")

for log_group in $LOG_GROUPS; do
    log_substep "Deleting log group: $log_group"
    aws logs delete-log-group --log-group-name "$log_group" --region ${AWS_REGION} 2>/dev/null || true
done

log_info "CloudWatch logs deleted"

###############################################################################
# Phase 8: ECR Repositories
###############################################################################

log_step "Phase 8: Deleting ECR repositories..."

SERVICES="orchestrator extractor validator archivist keycloak mcp-server"

for service in $SERVICES; do
    REPO_NAME="${PROJECT_NAME}-${service}"
    log_substep "Deleting repository: $REPO_NAME"
    aws ecr delete-repository --repository-name $REPO_NAME --force --region ${AWS_REGION} 2>/dev/null || log_warn "  Repository not found"
done

log_info "ECR repositories deleted"

###############################################################################
# Phase 9: IAM Roles and Policies
###############################################################################

log_step "Phase 9: Deleting IAM roles..."

ROLES=(
    "${PROJECT_NAME}-ecs-execution-role"
    "${PROJECT_NAME}-mcp-task-role"
    "${PROJECT_NAME}-agent-task-role"
    "${PROJECT_NAME}-keycloak-task-role"
)

for role in "${ROLES[@]}"; do
    log_substep "Deleting role: $role"
    
    # Detach managed policies
    ATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[*].PolicyArn' --output text 2>/dev/null || echo "")
    for policy_arn in $ATTACHED_POLICIES; do
        aws iam detach-role-policy --role-name "$role" --policy-arn "$policy_arn" 2>/dev/null || true
    done
    
    # Delete inline policies
    INLINE_POLICIES=$(aws iam list-role-policies --role-name "$role" --query 'PolicyNames[*]' --output text 2>/dev/null || echo "")
    for policy_name in $INLINE_POLICIES; do
        aws iam delete-role-policy --role-name "$role" --policy-name "$policy_name" 2>/dev/null || true
    done
    
    # Delete role
    aws iam delete-role --role-name "$role" 2>/dev/null || log_warn "  Role not found or already deleted"
done

log_info "IAM roles deleted"

###############################################################################
# Phase 10: Service Discovery
###############################################################################

log_step "Phase 10: Deleting Service Discovery resources..."

NAMESPACE_ID=$(aws servicediscovery list-namespaces --region ${AWS_REGION} --query "Namespaces[?Name=='${PROJECT_NAME}.local'].Id" --output text 2>/dev/null || echo "")

if [ ! -z "$NAMESPACE_ID" ]; then
    # Delete services first
    SERVICE_IDS=$(aws servicediscovery list-services --region ${AWS_REGION} --query 'Services[*].Id' --output text 2>/dev/null || echo "")
    for svc_id in $SERVICE_IDS; do
        log_substep "Deleting service discovery service: $svc_id"
        aws servicediscovery delete-service --id $svc_id --region ${AWS_REGION} 2>/dev/null || true
    done
    
    sleep 5
    
    # Delete namespace
    log_substep "Deleting namespace: ${PROJECT_NAME}.local"
    aws servicediscovery delete-namespace --id $NAMESPACE_ID --region ${AWS_REGION} 2>/dev/null || log_warn "Namespace deletion failed"
    
    log_info "Service Discovery resources deleted"
else
    log_warn "Service Discovery namespace not found, skipping"
fi

###############################################################################
# Completion
###############################################################################

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                       ║"
echo "║   ✅ Cleanup Complete!                                                ║"
echo "║                                                                       ║"
echo "║   All resources have been deleted.                                    ║"
echo "║   You can now run: ./cloudshell-complete-deploy.sh                   ║"
echo "║                                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

