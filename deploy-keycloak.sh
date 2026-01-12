#!/bin/bash
set -e

REGION="eu-west-3"
PROJECT_NAME="ca-a2a"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-$(openssl rand -base64 32 | tr -d '/+=')}"

echo "============================================"
echo "KEYCLOAK DEPLOYMENT FOR CA-A2A"
echo "============================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Step 1: Create Keycloak admin password secret
log_info "Creating Keycloak admin password secret..."
aws secretsmanager create-secret \
    --name ${PROJECT_NAME}/keycloak-admin-password \
    --secret-string "${KEYCLOAK_ADMIN_PASSWORD}" \
    --region ${REGION} 2>/dev/null || \
aws secretsmanager update-secret \
    --secret-id ${PROJECT_NAME}/keycloak-admin-password \
    --secret-string "${KEYCLOAK_ADMIN_PASSWORD}" \
    --region ${REGION}

log_info "Admin password stored in Secrets Manager: ${PROJECT_NAME}/keycloak-admin-password"

# Step 2: Create Keycloak database
log_info "Creating Keycloak database in RDS..."
DB_ENDPOINT=$(aws rds describe-db-clusters \
    --region ${REGION} \
    --db-cluster-identifier documents-db \
    --query 'DBClusters[0].Endpoint' \
    --output text 2>/dev/null || echo "")

if [ -z "$DB_ENDPOINT" ]; then
    log_error "RDS cluster not found. Please deploy the main infrastructure first."
    exit 1
fi

log_info "RDS endpoint: $DB_ENDPOINT"

# Create database via SQL (requires bastion or ECS task)
cat > /tmp/create-keycloak-db.sql <<EOF
-- Create Keycloak database
CREATE DATABASE keycloak;
-- Create dedicated user (optional, using postgres for simplicity)
-- CREATE USER keycloak WITH PASSWORD 'secure_password';
-- GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;
EOF

log_info "To create Keycloak database, run:"
log_info "  aws rds execute-statement --resource-arn <cluster-arn> --secret-arn <secret-arn> --sql \"CREATE DATABASE IF NOT EXISTS keycloak;\""
log_info "  OR connect via psql and run: CREATE DATABASE keycloak;"

# Step 3: Create CloudWatch log group
log_info "Creating CloudWatch log group..."
aws logs create-log-group \
    --log-group-name /ecs/${PROJECT_NAME}-keycloak \
    --region ${REGION} 2>/dev/null || log_warn "Log group already exists"

aws logs put-retention-policy \
    --log-group-name /ecs/${PROJECT_NAME}-keycloak \
    --retention-in-days 30 \
    --region ${REGION}

# Step 4: Get VPC and subnet information
log_info "Retrieving VPC and subnet information..."
VPC_ID=$(aws ec2 describe-vpcs \
    --filters "Name=tag:Name,Values=${PROJECT_NAME}-vpc" \
    --query 'Vpcs[0].VpcId' \
    --output text \
    --region ${REGION})

PRIVATE_SUBNET_1=$(aws ec2 describe-subnets \
    --filters "Name=tag:Name,Values=${PROJECT_NAME}-private-subnet-1" \
    --query 'Subnets[0].SubnetId' \
    --output text \
    --region ${REGION})

PRIVATE_SUBNET_2=$(aws ec2 describe-subnets \
    --filters "Name=tag:Name,Values=${PROJECT_NAME}-private-subnet-2" \
    --query 'Subnets[0].SubnetId' \
    --output text \
    --region ${REGION})

log_info "VPC ID: $VPC_ID"
log_info "Private Subnets: $PRIVATE_SUBNET_1, $PRIVATE_SUBNET_2"

# Step 5: Create security group for Keycloak
log_info "Creating security group for Keycloak..."
KEYCLOAK_SG=$(aws ec2 create-security-group \
    --group-name ${PROJECT_NAME}-keycloak-sg \
    --description "Security group for Keycloak" \
    --vpc-id ${VPC_ID} \
    --region ${REGION} \
    --query 'GroupId' \
    --output text 2>/dev/null || \
    aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=${PROJECT_NAME}-keycloak-sg" \
        --query 'SecurityGroups[0].GroupId' \
        --output text \
        --region ${REGION})

log_info "Keycloak Security Group: $KEYCLOAK_SG"

# Allow inbound from agent security groups
log_info "Configuring security group rules..."
for AGENT in orchestrator extractor validator archivist; do
    AGENT_SG=$(aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=${PROJECT_NAME}-${AGENT}-sg" \
        --query 'SecurityGroups[0].GroupId' \
        --output text \
        --region ${REGION} 2>/dev/null || echo "")
    
    if [ ! -z "$AGENT_SG" ]; then
        aws ec2 authorize-security-group-ingress \
            --group-id ${KEYCLOAK_SG} \
            --protocol tcp \
            --port 8080 \
            --source-group ${AGENT_SG} \
            --region ${REGION} 2>/dev/null || log_warn "Rule already exists for $AGENT"
        log_info "  Allowed inbound from $AGENT ($AGENT_SG)"
    fi
done

# Allow outbound to RDS
RDS_SG=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=${PROJECT_NAME}-rds-sg" \
    --query 'SecurityGroups[0].GroupId' \
    --output text \
    --region ${REGION} 2>/dev/null || echo "")

if [ ! -z "$RDS_SG" ]; then
    aws ec2 authorize-security-group-egress \
        --group-id ${KEYCLOAK_SG} \
        --protocol tcp \
        --port 5432 \
        --destination-group ${RDS_SG} \
        --region ${REGION} 2>/dev/null || log_warn "Egress rule to RDS already exists"
    
    # Allow RDS to accept connections from Keycloak
    aws ec2 authorize-security-group-ingress \
        --group-id ${RDS_SG} \
        --protocol tcp \
        --port 5432 \
        --source-group ${KEYCLOAK_SG} \
        --region ${REGION} 2>/dev/null || log_warn "RDS ingress rule already exists"
fi

# Step 6: Register task definition
log_info "Registering Keycloak ECS task definition..."
aws ecs register-task-definition \
    --cli-input-json file://task-definitions/keycloak-task.json \
    --region ${REGION}

# Step 7: Create service discovery for Keycloak
log_info "Creating service discovery for Keycloak..."
NAMESPACE_ID=$(aws servicediscovery list-namespaces \
    --filters Name=Name,Values=${PROJECT_NAME}.local \
    --query 'Namespaces[0].Id' \
    --output text \
    --region ${REGION})

KEYCLOAK_SERVICE_DISCOVERY=$(aws servicediscovery create-service \
    --name keycloak \
    --namespace-id ${NAMESPACE_ID} \
    --dns-config "NamespaceId=${NAMESPACE_ID},DnsRecords=[{Type=A,TTL=60}]" \
    --health-check-custom-config FailureThreshold=1 \
    --region ${REGION} \
    --query 'Service.Id' \
    --output text 2>/dev/null || \
    aws servicediscovery list-services \
        --filters Name=NAMESPACE_ID,Values=${NAMESPACE_ID} \
        --query "Services[?Name=='keycloak'].Id" \
        --output text \
        --region ${REGION})

log_info "Service Discovery: $KEYCLOAK_SERVICE_DISCOVERY"

# Step 8: Create ECS service
log_info "Creating Keycloak ECS service..."
aws ecs create-service \
    --cluster ${PROJECT_NAME}-cluster \
    --service-name keycloak \
    --task-definition ${PROJECT_NAME}-keycloak \
    --desired-count 1 \
    --launch-type FARGATE \
    --platform-version LATEST \
    --network-configuration "awsvpcConfiguration={subnets=[$PRIVATE_SUBNET_1,$PRIVATE_SUBNET_2],securityGroups=[$KEYCLOAK_SG],assignPublicIp=DISABLED}" \
    --service-registries "registryArn=arn:aws:servicediscovery:${REGION}:555043101106:service/${KEYCLOAK_SERVICE_DISCOVERY}" \
    --enable-execute-command \
    --region ${REGION} 2>/dev/null || log_warn "Service may already exist. Updating..."

# If service exists, update it
aws ecs update-service \
    --cluster ${PROJECT_NAME}-cluster \
    --service keycloak \
    --task-definition ${PROJECT_NAME}-keycloak \
    --force-new-deployment \
    --region ${REGION} 2>/dev/null || true

# Step 9: Wait for service to become stable
log_info "Waiting for Keycloak service to become stable (this may take 2-3 minutes)..."
aws ecs wait services-stable \
    --cluster ${PROJECT_NAME}-cluster \
    --services keycloak \
    --region ${REGION}

log_info "Keycloak service is now running!"

# Step 10: Display connection information
echo ""
echo "============================================"
echo "KEYCLOAK DEPLOYMENT COMPLETE"
echo "============================================"
echo ""
echo "Keycloak Admin Console:"
echo "  Internal URL: http://keycloak.${PROJECT_NAME}.local:8080"
echo "  Admin Username: admin"
echo "  Admin Password: (stored in Secrets Manager: ${PROJECT_NAME}/keycloak-admin-password)"
echo ""
echo "To retrieve admin password:"
echo "  aws secretsmanager get-secret-value --secret-id ${PROJECT_NAME}/keycloak-admin-password --query SecretString --output text --region ${REGION}"
echo ""
echo "Next steps:"
echo "  1. Run ./configure-keycloak.sh to setup realm and clients"
echo "  2. Update agent task definitions to use Keycloak authentication"
echo "  3. Test authentication with test-keycloak-auth.sh"
echo ""
echo "To access Keycloak admin console from CloudShell:"
echo "  1. Use ECS Exec to port-forward:"
echo "     aws ecs execute-command --cluster ${PROJECT_NAME}-cluster --task <task-id> --container keycloak --interactive --command \"/bin/bash\""
echo "  2. Or create a bastion host / ALB for external access"
echo ""

