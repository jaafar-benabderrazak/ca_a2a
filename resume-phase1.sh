#!/bin/bash
###############################################################################
# Resume Phase 1 - Continue from ALB creation
###############################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

export AWS_REGION="eu-west-3"
export PROJECT_NAME="ca-a2a"
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
export ORCHESTRATOR_PORT=8001

log_info "Resuming Phase 1 deployment..."
log_info "Region: ${AWS_REGION}"
log_info "Account: ${AWS_ACCOUNT_ID}"

# Get existing resource IDs
log_info "Fetching existing resource IDs..."

VPC_ID=$(aws ec2 describe-vpcs \
    --filters "Name=tag:Name,Values=${PROJECT_NAME}-vpc" \
    --region ${AWS_REGION} \
    --query 'Vpcs[0].VpcId' --output text)

PUBLIC_SUBNET_1=$(aws ec2 describe-subnets \
    --filters "Name=tag:Name,Values=${PROJECT_NAME}-public-1" \
    --region ${AWS_REGION} \
    --query 'Subnets[0].SubnetId' --output text)

PUBLIC_SUBNET_2=$(aws ec2 describe-subnets \
    --filters "Name=tag:Name,Values=${PROJECT_NAME}-public-2" \
    --region ${AWS_REGION} \
    --query 'Subnets[0].SubnetId' --output text)

PRIVATE_SUBNET_1=$(aws ec2 describe-subnets \
    --filters "Name=tag:Name,Values=${PROJECT_NAME}-private-1" \
    --region ${AWS_REGION} \
    --query 'Subnets[0].SubnetId' --output text)

PRIVATE_SUBNET_2=$(aws ec2 describe-subnets \
    --filters "Name=tag:Name,Values=${PROJECT_NAME}-private-2" \
    --region ${AWS_REGION} \
    --query 'Subnets[0].SubnetId' --output text)

ALB_SG=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=${PROJECT_NAME}-alb-sg" \
    --region ${AWS_REGION} \
    --query 'SecurityGroups[0].GroupId' --output text)

ECS_SG=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=${PROJECT_NAME}-ecs-sg" \
    --region ${AWS_REGION} \
    --query 'SecurityGroups[0].GroupId' --output text)

log_info "Found existing resources:"
log_info "  VPC: ${VPC_ID}"
log_info "  Public Subnets: ${PUBLIC_SUBNET_1}, ${PUBLIC_SUBNET_2}"
log_info "  Private Subnets: ${PRIVATE_SUBNET_1}, ${PRIVATE_SUBNET_2}"
log_info "  Security Groups: ${ALB_SG}, ${ECS_SG}"

# Check if RDS is ready
log_info "Checking RDS status..."
RDS_STATUS=$(aws rds describe-db-instances \
    --db-instance-identifier ${PROJECT_NAME}-postgres \
    --region ${AWS_REGION} \
    --query 'DBInstances[0].DBInstanceStatus' --output text 2>/dev/null || echo "not-found")

if [ "$RDS_STATUS" != "available" ]; then
    log_warn "RDS status: ${RDS_STATUS}"
    log_info "Waiting for RDS to be available..."
    aws rds wait db-instance-available \
        --db-instance-identifier ${PROJECT_NAME}-postgres \
        --region ${AWS_REGION}
fi

RDS_ENDPOINT=$(aws rds describe-db-instances \
    --db-instance-identifier ${PROJECT_NAME}-postgres \
    --region ${AWS_REGION} \
    --query 'DBInstances[0].Endpoint.Address' --output text)

log_info "RDS available: ${RDS_ENDPOINT}"

# Create or get ALB
log_info "Creating Application Load Balancer..."

ALB_ARN=$(aws elbv2 describe-load-balancers \
    --names ${PROJECT_NAME}-alb \
    --region ${AWS_REGION} \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || echo "not-found")

if [ "$ALB_ARN" = "not-found" ] || [ -z "$ALB_ARN" ]; then
    log_info "Creating new ALB..."
    ALB_ARN=$(aws elbv2 create-load-balancer \
        --name ${PROJECT_NAME}-alb \
        --subnets ${PUBLIC_SUBNET_1} ${PUBLIC_SUBNET_2} \
        --security-groups ${ALB_SG} \
        --scheme internet-facing \
        --type application \
        --region ${AWS_REGION} \
        --query 'LoadBalancers[0].LoadBalancerArn' --output text)

    log_info "Waiting for ALB to be active..."
    aws elbv2 wait load-balancer-available \
        --load-balancer-arns ${ALB_ARN} \
        --region ${AWS_REGION}
else
    log_info "ALB already exists: ${ALB_ARN}"
fi

# Create or get Target Group
log_info "Creating target group..."

TG_ARN=$(aws elbv2 describe-target-groups \
    --names ${PROJECT_NAME}-orch-tg \
    --region ${AWS_REGION} \
    --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null || echo "not-found")

if [ "$TG_ARN" = "not-found" ] || [ -z "$TG_ARN" ]; then
    log_info "Creating new target group..."
    TG_ARN=$(aws elbv2 create-target-group \
        --name ${PROJECT_NAME}-orch-tg \
        --protocol HTTP \
        --port ${ORCHESTRATOR_PORT} \
        --vpc-id ${VPC_ID} \
        --target-type ip \
        --health-check-path /health \
        --health-check-interval-seconds 30 \
        --health-check-timeout-seconds 5 \
        --healthy-threshold-count 2 \
        --unhealthy-threshold-count 3 \
        --matcher HttpCode=200 \
        --region ${AWS_REGION} \
        --query 'TargetGroups[0].TargetGroupArn' --output text)
else
    log_info "Target group already exists: ${TG_ARN}"
fi

# Create or get Listener
log_info "Creating ALB listener..."

LISTENER_ARN=$(aws elbv2 describe-listeners \
    --load-balancer-arn ${ALB_ARN} \
    --region ${AWS_REGION} \
    --query 'Listeners[0].ListenerArn' --output text 2>/dev/null || echo "not-found")

if [ "$LISTENER_ARN" = "not-found" ] || [ -z "$LISTENER_ARN" ]; then
    log_info "Creating new listener..."
    aws elbv2 create-listener \
        --load-balancer-arn ${ALB_ARN} \
        --protocol HTTP \
        --port 80 \
        --default-actions Type=forward,TargetGroupArn=${TG_ARN} \
        --region ${AWS_REGION} >/dev/null
else
    log_info "Listener already exists"
fi

# Get ALB DNS
ALB_DNS=$(aws elbv2 describe-load-balancers \
    --load-balancer-arns ${ALB_ARN} \
    --region ${AWS_REGION} \
    --query 'LoadBalancers[0].DNSName' --output text)

log_info "ALB DNS: ${ALB_DNS}"

# Create Service Discovery
log_info "Creating service discovery..."

NAMESPACE_ID=$(aws servicediscovery list-namespaces \
    --region ${AWS_REGION} \
    --query "Namespaces[?Name=='local'].Id" --output text)

if [ -z "$NAMESPACE_ID" ] || [ "$NAMESPACE_ID" = "None" ]; then
    log_info "Creating service discovery namespace..."
    OPERATION_ID=$(aws servicediscovery create-private-dns-namespace \
        --name local \
        --vpc ${VPC_ID} \
        --description "Service discovery for ${PROJECT_NAME}" \
        --region ${AWS_REGION} \
        --query 'OperationId' --output text)

    log_info "Waiting for namespace creation..."
    sleep 30

    NAMESPACE_ID=$(aws servicediscovery list-namespaces \
        --region ${AWS_REGION} \
        --query "Namespaces[?Name=='local'].Id" --output text)
fi

log_info "Service discovery namespace: ${NAMESPACE_ID}"

# Create service discovery services
for agent in extractor validator archivist; do
    SERVICE_ID=$(aws servicediscovery list-services \
        --region ${AWS_REGION} \
        --query "Services[?Name=='${agent}'].Id" --output text)

    if [ -z "$SERVICE_ID" ] || [ "$SERVICE_ID" = "None" ]; then
        log_info "Creating service discovery for ${agent}..."
        aws servicediscovery create-service \
            --name ${agent} \
            --namespace-id ${NAMESPACE_ID} \
            --dns-config "NamespaceId=${NAMESPACE_ID},DnsRecords=[{Type=A,TTL=60}]" \
            --health-check-custom-config FailureThreshold=1 \
            --region ${AWS_REGION} >/dev/null
    else
        log_info "Service discovery for ${agent} already exists"
    fi
done

# Get S3 bucket
S3_BUCKET="${PROJECT_NAME}-documents-${AWS_ACCOUNT_ID}"

# Get database password
DB_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id ${PROJECT_NAME}/db-password \
    --region ${AWS_REGION} \
    --query 'SecretString' --output text)

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
export S3_BUCKET="${S3_BUCKET}"
export RDS_ENDPOINT="${RDS_ENDPOINT}"
export DB_PASSWORD="${DB_PASSWORD}"
export ALB_ARN="${ALB_ARN}"
export TG_ARN="${TG_ARN}"
export ALB_DNS="${ALB_DNS}"
export NAMESPACE_ID="${NAMESPACE_ID}"
EOF

# Also save in current directory
cp /tmp/${PROJECT_NAME}-config.env ./ca-a2a-config.env

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
log_info "Configuration saved to:"
echo "  • /tmp/${PROJECT_NAME}-config.env"
echo "  • ./ca-a2a-config.env"
echo ""
log_info "Next Steps:"
echo "  1. Run Phase 2 to deploy containers:"
echo "     AWS_PROFILE=reply-sso ./deploy-sso-phase2.sh"
echo ""
