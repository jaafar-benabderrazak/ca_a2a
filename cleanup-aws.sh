#!/bin/bash
###############################################################################
# AWS Cleanup Script - Remove All CA A2A Resources
# WARNING: This will delete all deployed resources
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

AWS_REGION="${AWS_REGION:-us-east-1}"
PROJECT_NAME="ca-a2a"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Confirmation
echo -e "${RED}WARNING: This will delete ALL ${PROJECT_NAME} resources!${NC}"
echo "Region: $AWS_REGION"
echo "Account: $AWS_ACCOUNT_ID"
echo ""
read -p "Are you sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    log_info "Cleanup cancelled"
    exit 0
fi

log_info "Starting cleanup..."

# 1. Delete ECS Services
log_info "Deleting ECS services..."
for service in orchestrator extractor validator archivist; do
    log_info "Scaling down $service to 0..."
    aws ecs update-service \
        --cluster ${PROJECT_NAME}-cluster \
        --service $service \
        --desired-count 0 \
        --region $AWS_REGION 2>/dev/null || log_warn "Service $service not found"

    log_info "Deleting $service service..."
    aws ecs delete-service \
        --cluster ${PROJECT_NAME}-cluster \
        --service $service \
        --force \
        --region $AWS_REGION 2>/dev/null || log_warn "Service $service already deleted"
done

# Wait for services to be deleted
log_info "Waiting for services to drain..."
sleep 30

# 2. Delete ECS Cluster
log_info "Deleting ECS cluster..."
aws ecs delete-cluster \
    --cluster ${PROJECT_NAME}-cluster \
    --region $AWS_REGION 2>/dev/null || log_warn "Cluster already deleted"

# 3. Delete Load Balancer
log_info "Deleting Application Load Balancer..."
ALB_ARN=$(aws elbv2 describe-load-balancers \
    --names ${PROJECT_NAME}-alb \
    --query 'LoadBalancers[0].LoadBalancerArn' \
    --output text \
    --region $AWS_REGION 2>/dev/null)

if [ "$ALB_ARN" != "None" ] && [ ! -z "$ALB_ARN" ]; then
    aws elbv2 delete-load-balancer \
        --load-balancer-arn $ALB_ARN \
        --region $AWS_REGION
    log_info "Waiting for ALB to be deleted..."
    sleep 60
fi

# Delete Target Group
TG_ARN=$(aws elbv2 describe-target-groups \
    --names ${PROJECT_NAME}-orch-tg \
    --query 'TargetGroups[0].TargetGroupArn' \
    --output text \
    --region $AWS_REGION 2>/dev/null)

if [ "$TG_ARN" != "None" ] && [ ! -z "$TG_ARN" ]; then
    aws elbv2 delete-target-group \
        --target-group-arn $TG_ARN \
        --region $AWS_REGION 2>/dev/null || log_warn "Target group already deleted"
fi

# 4. Delete RDS Database
log_info "Deleting RDS database..."
aws rds delete-db-instance \
    --db-instance-identifier ${PROJECT_NAME}-postgres \
    --skip-final-snapshot \
    --region $AWS_REGION 2>/dev/null || log_warn "RDS instance not found"

# Delete DB Subnet Group
aws rds delete-db-subnet-group \
    --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
    --region $AWS_REGION 2>/dev/null || log_warn "DB subnet group already deleted"

# 5. Empty and Delete S3 Bucket
log_info "Emptying S3 bucket..."
S3_BUCKET="${PROJECT_NAME}-documents-${AWS_ACCOUNT_ID}"
aws s3 rm "s3://${S3_BUCKET}" --recursive --region $AWS_REGION 2>/dev/null || log_warn "S3 bucket not found"

log_info "Deleting S3 bucket..."
aws s3 rb "s3://${S3_BUCKET}" --region $AWS_REGION 2>/dev/null || log_warn "S3 bucket already deleted"

# 6. Delete ECR Repositories
log_info "Deleting ECR repositories..."
for agent in orchestrator extractor validator archivist; do
    aws ecr delete-repository \
        --repository-name ${PROJECT_NAME}/$agent \
        --force \
        --region $AWS_REGION 2>/dev/null || log_warn "ECR repo $agent not found"
done

# 7. Delete Service Discovery
log_info "Deleting service discovery..."
NAMESPACE_ID=$(aws servicediscovery list-namespaces \
    --query "Namespaces[?Name=='local'].Id" \
    --output text \
    --region $AWS_REGION 2>/dev/null)

if [ "$NAMESPACE_ID" != "None" ] && [ ! -z "$NAMESPACE_ID" ]; then
    for agent in extractor validator archivist; do
        SERVICE_ID=$(aws servicediscovery list-services \
            --filters "Name=NAMESPACE_ID,Values=$NAMESPACE_ID" \
            --query "Services[?Name=='$agent'].Id" \
            --output text \
            --region $AWS_REGION 2>/dev/null)

        if [ "$SERVICE_ID" != "None" ] && [ ! -z "$SERVICE_ID" ]; then
            aws servicediscovery delete-service \
                --id $SERVICE_ID \
                --region $AWS_REGION 2>/dev/null || log_warn "Service $agent already deleted"
        fi
    done

    aws servicediscovery delete-namespace \
        --id $NAMESPACE_ID \
        --region $AWS_REGION 2>/dev/null || log_warn "Namespace already deleted"
fi

# 8. Delete CloudWatch Log Groups
log_info "Deleting CloudWatch log groups..."
for agent in orchestrator extractor validator archivist; do
    aws logs delete-log-group \
        --log-group-name /ecs/${PROJECT_NAME}-$agent \
        --region $AWS_REGION 2>/dev/null || log_warn "Log group $agent not found"
done

# 9. Delete Secrets
log_info "Deleting secrets..."
aws secretsmanager delete-secret \
    --secret-id ${PROJECT_NAME}/db-password \
    --force-delete-without-recovery \
    --region $AWS_REGION 2>/dev/null || log_warn "Secret not found"

# 10. Delete IAM Roles
log_info "Deleting IAM roles..."

# Detach and delete execution role
aws iam detach-role-policy \
    --role-name ${PROJECT_NAME}-ecs-execution-role \
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy \
    2>/dev/null || log_warn "Execution role policy already detached"

aws iam delete-role \
    --role-name ${PROJECT_NAME}-ecs-execution-role \
    2>/dev/null || log_warn "Execution role already deleted"

# Delete task role
aws iam delete-role-policy \
    --role-name ${PROJECT_NAME}-ecs-task-role \
    --policy-name ${PROJECT_NAME}-task-policy \
    2>/dev/null || log_warn "Task role policy already deleted"

aws iam delete-role \
    --role-name ${PROJECT_NAME}-ecs-task-role \
    2>/dev/null || log_warn "Task role already deleted"

# Wait for resources to be fully deleted
log_info "Waiting for resources to be fully deleted (120s)..."
sleep 120

# 11. Delete VPC and Networking
log_info "Deleting VPC resources..."

VPC_ID=$(aws ec2 describe-vpcs \
    --filters "Name=tag:Name,Values=${PROJECT_NAME}-vpc" \
    --query 'Vpcs[0].VpcId' \
    --output text \
    --region $AWS_REGION 2>/dev/null)

if [ "$VPC_ID" != "None" ] && [ ! -z "$VPC_ID" ]; then
    # Delete NAT Gateway
    NAT_GW=$(aws ec2 describe-nat-gateways \
        --filter "Name=vpc-id,Values=$VPC_ID" "Name=state,Values=available" \
        --query 'NatGateways[0].NatGatewayId' \
        --output text \
        --region $AWS_REGION 2>/dev/null)

    if [ "$NAT_GW" != "None" ] && [ ! -z "$NAT_GW" ]; then
        log_info "Deleting NAT Gateway..."
        aws ec2 delete-nat-gateway \
            --nat-gateway-id $NAT_GW \
            --region $AWS_REGION

        # Get associated EIP
        EIP_ID=$(aws ec2 describe-nat-gateways \
            --nat-gateway-ids $NAT_GW \
            --query 'NatGateways[0].NatGatewayAddresses[0].AllocationId' \
            --output text \
            --region $AWS_REGION)

        log_info "Waiting for NAT Gateway to be deleted..."
        sleep 60

        # Release EIP
        if [ "$EIP_ID" != "None" ] && [ ! -z "$EIP_ID" ]; then
            aws ec2 release-address \
                --allocation-id $EIP_ID \
                --region $AWS_REGION 2>/dev/null || log_warn "EIP already released"
        fi
    fi

    # Delete Security Groups
    log_info "Deleting security groups..."
    for sg_name in ${PROJECT_NAME}-alb-sg ${PROJECT_NAME}-ecs-sg ${PROJECT_NAME}-rds-sg; do
        SG_ID=$(aws ec2 describe-security-groups \
            --filters "Name=group-name,Values=$sg_name" "Name=vpc-id,Values=$VPC_ID" \
            --query 'SecurityGroups[0].GroupId' \
            --output text \
            --region $AWS_REGION 2>/dev/null)

        if [ "$SG_ID" != "None" ] && [ ! -z "$SG_ID" ]; then
            aws ec2 delete-security-group \
                --group-id $SG_ID \
                --region $AWS_REGION 2>/dev/null || log_warn "SG $sg_name already deleted"
        fi
    done

    # Delete Subnets
    log_info "Deleting subnets..."
    SUBNETS=$(aws ec2 describe-subnets \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --query 'Subnets[].SubnetId' \
        --output text \
        --region $AWS_REGION)

    for subnet in $SUBNETS; do
        aws ec2 delete-subnet \
            --subnet-id $subnet \
            --region $AWS_REGION 2>/dev/null || log_warn "Subnet $subnet already deleted"
    done

    # Delete Route Tables (except main)
    log_info "Deleting route tables..."
    ROUTE_TABLES=$(aws ec2 describe-route-tables \
        --filters "Name=vpc-id,Values=$VPC_ID" \
        --query 'RouteTables[?Associations[0].Main!=`true`].RouteTableId' \
        --output text \
        --region $AWS_REGION)

    for rt in $ROUTE_TABLES; do
        # Disassociate from subnets first
        ASSOCIATIONS=$(aws ec2 describe-route-tables \
            --route-table-ids $rt \
            --query 'RouteTables[0].Associations[?!Main].RouteTableAssociationId' \
            --output text \
            --region $AWS_REGION)

        for assoc in $ASSOCIATIONS; do
            aws ec2 disassociate-route-table \
                --association-id $assoc \
                --region $AWS_REGION 2>/dev/null
        done

        aws ec2 delete-route-table \
            --route-table-id $rt \
            --region $AWS_REGION 2>/dev/null || log_warn "Route table $rt already deleted"
    done

    # Detach and Delete Internet Gateway
    log_info "Deleting Internet Gateway..."
    IGW_ID=$(aws ec2 describe-internet-gateways \
        --filters "Name=attachment.vpc-id,Values=$VPC_ID" \
        --query 'InternetGateways[0].InternetGatewayId' \
        --output text \
        --region $AWS_REGION 2>/dev/null)

    if [ "$IGW_ID" != "None" ] && [ ! -z "$IGW_ID" ]; then
        aws ec2 detach-internet-gateway \
            --internet-gateway-id $IGW_ID \
            --vpc-id $VPC_ID \
            --region $AWS_REGION 2>/dev/null

        aws ec2 delete-internet-gateway \
            --internet-gateway-id $IGW_ID \
            --region $AWS_REGION 2>/dev/null || log_warn "IGW already deleted"
    fi

    # Delete VPC
    log_info "Deleting VPC..."
    aws ec2 delete-vpc \
        --vpc-id $VPC_ID \
        --region $AWS_REGION 2>/dev/null || log_warn "VPC already deleted"
fi

log_info "Cleanup complete! ✓"
log_info "All ${PROJECT_NAME} resources have been deleted."
