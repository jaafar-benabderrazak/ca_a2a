#!/bin/bash
###############################################################################
# Manual AWS Deployment Script - No Git Required
# Deploys CA A2A Multi-Agent Pipeline to AWS using only AWS CLI
###############################################################################

set -e  # Exit on error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

###############################################################################
# Configuration - Update these values
###############################################################################

export AWS_REGION="${AWS_REGION:-us-east-1}"
export AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
export PROJECT_NAME="ca-a2a"
export ENVIRONMENT="${ENVIRONMENT:-prod}"

# Database Configuration
export DB_NAME="documents_db"
export DB_USERNAME="postgres"
export DB_PASSWORD="${DB_PASSWORD:-$(openssl rand -base64 32)}"  # Generate random if not set
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
# Functions
###############################################################################

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install it first."
        exit 1
    fi

    # Check jq
    if ! command -v jq &> /dev/null; then
        log_warn "jq is not installed. Installing..."
        sudo apt-get install -y jq || brew install jq
    fi

    # Verify AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured. Run 'aws configure' first."
        exit 1
    fi

    log_info "Prerequisites check passed ✓"
}

create_vpc_network() {
    log_info "Creating VPC and network infrastructure..."

    # Create VPC
    VPC_ID=$(aws ec2 create-vpc \
        --cidr-block ${VPC_CIDR} \
        --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=${PROJECT_NAME}-vpc}]" \
        --region ${AWS_REGION} \
        --query 'Vpc.VpcId' --output text)

    log_info "VPC created: ${VPC_ID}"

    # Enable DNS
    aws ec2 modify-vpc-attribute --vpc-id ${VPC_ID} --enable-dns-support
    aws ec2 modify-vpc-attribute --vpc-id ${VPC_ID} --enable-dns-hostnames

    # Create Internet Gateway
    IGW_ID=$(aws ec2 create-internet-gateway \
        --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=${PROJECT_NAME}-igw}]" \
        --region ${AWS_REGION} \
        --query 'InternetGateway.InternetGatewayId' --output text)

    aws ec2 attach-internet-gateway --vpc-id ${VPC_ID} --internet-gateway-id ${IGW_ID} --region ${AWS_REGION}
    log_info "Internet Gateway created: ${IGW_ID}"

    # Get availability zones
    AZ1=$(aws ec2 describe-availability-zones --region ${AWS_REGION} --query 'AvailabilityZones[0].ZoneName' --output text)
    AZ2=$(aws ec2 describe-availability-zones --region ${AWS_REGION} --query 'AvailabilityZones[1].ZoneName' --output text)

    # Create Public Subnets
    PUBLIC_SUBNET_1=$(aws ec2 create-subnet \
        --vpc-id ${VPC_ID} \
        --cidr-block ${PUBLIC_SUBNET_1_CIDR} \
        --availability-zone ${AZ1} \
        --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-public-1}]" \
        --region ${AWS_REGION} \
        --query 'Subnet.SubnetId' --output text)

    PUBLIC_SUBNET_2=$(aws ec2 create-subnet \
        --vpc-id ${VPC_ID} \
        --cidr-block ${PUBLIC_SUBNET_2_CIDR} \
        --availability-zone ${AZ2} \
        --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-public-2}]" \
        --region ${AWS_REGION} \
        --query 'Subnet.SubnetId' --output text)

    # Create Private Subnets
    PRIVATE_SUBNET_1=$(aws ec2 create-subnet \
        --vpc-id ${VPC_ID} \
        --cidr-block ${PRIVATE_SUBNET_1_CIDR} \
        --availability-zone ${AZ1} \
        --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-private-1}]" \
        --region ${AWS_REGION} \
        --query 'Subnet.SubnetId' --output text)

    PRIVATE_SUBNET_2=$(aws ec2 create-subnet \
        --vpc-id ${VPC_ID} \
        --cidr-block ${PRIVATE_SUBNET_2_CIDR} \
        --availability-zone ${AZ2} \
        --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${PROJECT_NAME}-private-2}]" \
        --region ${AWS_REGION} \
        --query 'Subnet.SubnetId' --output text)

    log_info "Subnets created"

    # Create Route Tables
    PUBLIC_RT=$(aws ec2 create-route-table \
        --vpc-id ${VPC_ID} \
        --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${PROJECT_NAME}-public-rt}]" \
        --region ${AWS_REGION} \
        --query 'RouteTable.RouteTableId' --output text)

    aws ec2 create-route --route-table-id ${PUBLIC_RT} --destination-cidr-block 0.0.0.0/0 --gateway-id ${IGW_ID} --region ${AWS_REGION}
    aws ec2 associate-route-table --subnet-id ${PUBLIC_SUBNET_1} --route-table-id ${PUBLIC_RT} --region ${AWS_REGION}
    aws ec2 associate-route-table --subnet-id ${PUBLIC_SUBNET_2} --route-table-id ${PUBLIC_RT} --region ${AWS_REGION}

    # Create NAT Gateway for private subnets
    EIP_ID=$(aws ec2 allocate-address --domain vpc --region ${AWS_REGION} --query 'AllocationId' --output text)
    NAT_GW=$(aws ec2 create-nat-gateway \
        --subnet-id ${PUBLIC_SUBNET_1} \
        --allocation-id ${EIP_ID} \
        --tag-specifications "ResourceType=natgateway,Tags=[{Key=Name,Value=${PROJECT_NAME}-nat}]" \
        --region ${AWS_REGION} \
        --query 'NatGateway.NatGatewayId' --output text)

    log_info "Waiting for NAT Gateway to be available..."
    aws ec2 wait nat-gateway-available --nat-gateway-ids ${NAT_GW} --region ${AWS_REGION}

    PRIVATE_RT=$(aws ec2 create-route-table \
        --vpc-id ${VPC_ID} \
        --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${PROJECT_NAME}-private-rt}]" \
        --region ${AWS_REGION} \
        --query 'RouteTable.RouteTableId' --output text)

    aws ec2 create-route --route-table-id ${PRIVATE_RT} --destination-cidr-block 0.0.0.0/0 --nat-gateway-id ${NAT_GW} --region ${AWS_REGION}
    aws ec2 associate-route-table --subnet-id ${PRIVATE_SUBNET_1} --route-table-id ${PRIVATE_RT} --region ${AWS_REGION}
    aws ec2 associate-route-table --subnet-id ${PRIVATE_SUBNET_2} --route-table-id ${PRIVATE_RT} --region ${AWS_REGION}

    # Save network IDs to file
    cat > /tmp/network-config.env <<EOF
export VPC_ID=${VPC_ID}
export IGW_ID=${IGW_ID}
export PUBLIC_SUBNET_1=${PUBLIC_SUBNET_1}
export PUBLIC_SUBNET_2=${PUBLIC_SUBNET_2}
export PRIVATE_SUBNET_1=${PRIVATE_SUBNET_1}
export PRIVATE_SUBNET_2=${PRIVATE_SUBNET_2}
export NAT_GW=${NAT_GW}
EOF

    source /tmp/network-config.env
    log_info "Network infrastructure created ✓"
}

create_security_groups() {
    log_info "Creating security groups..."

    # ALB Security Group
    ALB_SG=$(aws ec2 create-security-group \
        --group-name ${PROJECT_NAME}-alb-sg \
        --description "Security group for ALB" \
        --vpc-id ${VPC_ID} \
        --region ${AWS_REGION} \
        --query 'GroupId' --output text)

    aws ec2 authorize-security-group-ingress \
        --group-id ${ALB_SG} \
        --protocol tcp \
        --port 80 \
        --cidr 0.0.0.0/0 \
        --region ${AWS_REGION}

    aws ec2 authorize-security-group-ingress \
        --group-id ${ALB_SG} \
        --protocol tcp \
        --port 443 \
        --cidr 0.0.0.0/0 \
        --region ${AWS_REGION}

    # Per-agent ECS Security Groups (least privilege)
    ORCHESTRATOR_SG=$(aws ec2 create-security-group \
        --group-name ${PROJECT_NAME}-orchestrator-sg \
        --description "Orchestrator ECS security group" \
        --vpc-id ${VPC_ID} \
        --region ${AWS_REGION} \
        --query 'GroupId' --output text)

    EXTRACTOR_SG=$(aws ec2 create-security-group \
        --group-name ${PROJECT_NAME}-extractor-sg \
        --description "Extractor ECS security group" \
        --vpc-id ${VPC_ID} \
        --region ${AWS_REGION} \
        --query 'GroupId' --output text)

    VALIDATOR_SG=$(aws ec2 create-security-group \
        --group-name ${PROJECT_NAME}-validator-sg \
        --description "Validator ECS security group" \
        --vpc-id ${VPC_ID} \
        --region ${AWS_REGION} \
        --query 'GroupId' --output text)

    ARCHIVIST_SG=$(aws ec2 create-security-group \
        --group-name ${PROJECT_NAME}-archivist-sg \
        --description "Archivist ECS security group" \
        --vpc-id ${VPC_ID} \
        --region ${AWS_REGION} \
        --query 'GroupId' --output text)

    # Ingress rules
    aws ec2 authorize-security-group-ingress \
        --group-id ${ORCHESTRATOR_SG} \
        --protocol tcp \
        --port ${ORCHESTRATOR_PORT} \
        --source-group ${ALB_SG} \
        --region ${AWS_REGION}

    aws ec2 authorize-security-group-ingress \
        --group-id ${EXTRACTOR_SG} \
        --protocol tcp \
        --port ${EXTRACTOR_PORT} \
        --source-group ${ORCHESTRATOR_SG} \
        --region ${AWS_REGION}

    aws ec2 authorize-security-group-ingress \
        --group-id ${VALIDATOR_SG} \
        --protocol tcp \
        --port ${VALIDATOR_PORT} \
        --source-group ${ORCHESTRATOR_SG} \
        --region ${AWS_REGION}

    aws ec2 authorize-security-group-ingress \
        --group-id ${ARCHIVIST_SG} \
        --protocol tcp \
        --port ${ARCHIVIST_PORT} \
        --source-group ${ORCHESTRATOR_SG} \
        --region ${AWS_REGION}

    # RDS Security Group
    RDS_SG=$(aws ec2 create-security-group \
        --group-name ${PROJECT_NAME}-rds-sg \
        --description "Security group for RDS" \
        --vpc-id ${VPC_ID} \
        --region ${AWS_REGION} \
        --query 'GroupId' --output text)

    # DB access only from agents
    aws ec2 authorize-security-group-ingress \
        --group-id ${RDS_SG} \
        --protocol tcp \
        --port 5432 \
        --source-group ${ORCHESTRATOR_SG} \
        --region ${AWS_REGION}

    aws ec2 authorize-security-group-ingress \
        --group-id ${RDS_SG} \
        --protocol tcp \
        --port 5432 \
        --source-group ${EXTRACTOR_SG} \
        --region ${AWS_REGION}

    aws ec2 authorize-security-group-ingress \
        --group-id ${RDS_SG} \
        --protocol tcp \
        --port 5432 \
        --source-group ${VALIDATOR_SG} \
        --region ${AWS_REGION}

    aws ec2 authorize-security-group-ingress \
        --group-id ${RDS_SG} \
        --protocol tcp \
        --port 5432 \
        --source-group ${ARCHIVIST_SG} \
        --region ${AWS_REGION}

    # Egress hardening (best-effort): revoke default allow-all and only allow VPC-internal HTTPS + DNS + required ports.
    for sg in ${ORCHESTRATOR_SG} ${EXTRACTOR_SG} ${VALIDATOR_SG} ${ARCHIVIST_SG}; do
        aws ec2 revoke-security-group-egress \
            --group-id ${sg} \
            --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' \
            --region ${AWS_REGION} 2>/dev/null || true

        aws ec2 authorize-security-group-egress \
            --group-id ${sg} --protocol tcp --port 443 --cidr ${VPC_CIDR} --region ${AWS_REGION} 2>/dev/null || true
        aws ec2 authorize-security-group-egress \
            --group-id ${sg} --protocol udp --port 53 --cidr ${VPC_CIDR} --region ${AWS_REGION} 2>/dev/null || true
        aws ec2 authorize-security-group-egress \
            --group-id ${sg} --protocol tcp --port 53 --cidr ${VPC_CIDR} --region ${AWS_REGION} 2>/dev/null || true
        aws ec2 authorize-security-group-egress \
            --group-id ${sg} --protocol tcp --port 5432 --cidr ${VPC_CIDR} --region ${AWS_REGION} 2>/dev/null || true
    done

    aws ec2 authorize-security-group-egress \
        --group-id ${ORCHESTRATOR_SG} --protocol tcp --port ${EXTRACTOR_PORT} --cidr ${VPC_CIDR} --region ${AWS_REGION} 2>/dev/null || true
    aws ec2 authorize-security-group-egress \
        --group-id ${ORCHESTRATOR_SG} --protocol tcp --port ${VALIDATOR_PORT} --cidr ${VPC_CIDR} --region ${AWS_REGION} 2>/dev/null || true
    aws ec2 authorize-security-group-egress \
        --group-id ${ORCHESTRATOR_SG} --protocol tcp --port ${ARCHIVIST_PORT} --cidr ${VPC_CIDR} --region ${AWS_REGION} 2>/dev/null || true

    # Save security group IDs
    cat >> /tmp/network-config.env <<EOF
export ALB_SG=${ALB_SG}
export RDS_SG=${RDS_SG}
export ORCHESTRATOR_SG=${ORCHESTRATOR_SG}
export EXTRACTOR_SG=${EXTRACTOR_SG}
export VALIDATOR_SG=${VALIDATOR_SG}
export ARCHIVIST_SG=${ARCHIVIST_SG}
EOF

    source /tmp/network-config.env
    log_info "Security groups created ✓"
}

create_s3_bucket() {
    log_info "Creating S3 bucket..."

    if aws s3 ls "s3://${S3_BUCKET}" 2>&1 | grep -q 'NoSuchBucket'; then
        aws s3 mb "s3://${S3_BUCKET}" --region ${AWS_REGION}

        # Enable versioning
        aws s3api put-bucket-versioning \
            --bucket ${S3_BUCKET} \
            --versioning-configuration Status=Enabled

        # Enable encryption
        aws s3api put-bucket-encryption \
            --bucket ${S3_BUCKET} \
            --server-side-encryption-configuration '{
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    },
                    "BucketKeyEnabled": true
                }]
            }'

        # Block public access
        aws s3api put-public-access-block \
            --bucket ${S3_BUCKET} \
            --public-access-block-configuration \
                "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

        log_info "S3 bucket created: ${S3_BUCKET} ✓"
    else
        log_warn "S3 bucket already exists: ${S3_BUCKET}"
    fi
}

create_secrets() {
    log_info "Creating secrets in AWS Secrets Manager..."

    # Database password
    aws secretsmanager create-secret \
        --name ${PROJECT_NAME}/db-password \
        --secret-string "${DB_PASSWORD}" \
        --region ${AWS_REGION} 2>/dev/null || \
    aws secretsmanager update-secret \
        --secret-id ${PROJECT_NAME}/db-password \
        --secret-string "${DB_PASSWORD}" \
        --region ${AWS_REGION}

    log_info "Secrets created ✓"
}

create_a2a_security_secrets() {
    log_info "Creating A2A security secrets (JWT keys + client API key)..."

    # Toggle: default ON for this deployment script
    export A2A_REQUIRE_AUTH="${A2A_REQUIRE_AUTH:-true}"

    # Generate RSA keypair (PEM) for RS256 JWT (orchestrator signs, other agents verify)
    TMPDIR="/tmp"
    PRIVATE_KEY_FILE="${TMPDIR}/${PROJECT_NAME}-a2a-jwt-private.pem"
    PUBLIC_KEY_FILE="${TMPDIR}/${PROJECT_NAME}-a2a-jwt-public.pem"

    if ! command -v openssl &> /dev/null; then
        log_error "openssl is required to generate JWT keys"
        exit 1
    fi

    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${PRIVATE_KEY_FILE}" > /dev/null 2>&1
    openssl rsa -in "${PRIVATE_KEY_FILE}" -pubout -out "${PUBLIC_KEY_FILE}" > /dev/null 2>&1

    PRIVATE_KEY_PEM="$(cat "${PRIVATE_KEY_FILE}")"
    PUBLIC_KEY_PEM="$(cat "${PUBLIC_KEY_FILE}")"

    # External client API key (used to call orchestrator via ALB)
    CLIENT_API_KEY="$(openssl rand -base64 48 | tr -d '\n' | tr -d '/+=' | cut -c1-48)"
    CLIENT_API_KEYS_JSON="{\"external_client\":\"${CLIENT_API_KEY}\"}"

    # Store in Secrets Manager (as plain strings)
    aws secretsmanager create-secret \
        --name ${PROJECT_NAME}/a2a-jwt-private-key-pem \
        --secret-string "${PRIVATE_KEY_PEM}" \
        --region ${AWS_REGION} 2>/dev/null || \
    aws secretsmanager update-secret \
        --secret-id ${PROJECT_NAME}/a2a-jwt-private-key-pem \
        --secret-string "${PRIVATE_KEY_PEM}" \
        --region ${AWS_REGION}

    aws secretsmanager create-secret \
        --name ${PROJECT_NAME}/a2a-jwt-public-key-pem \
        --secret-string "${PUBLIC_KEY_PEM}" \
        --region ${AWS_REGION} 2>/dev/null || \
    aws secretsmanager update-secret \
        --secret-id ${PROJECT_NAME}/a2a-jwt-public-key-pem \
        --secret-string "${PUBLIC_KEY_PEM}" \
        --region ${AWS_REGION}

    aws secretsmanager create-secret \
        --name ${PROJECT_NAME}/a2a-client-api-keys-json \
        --secret-string "${CLIENT_API_KEYS_JSON}" \
        --region ${AWS_REGION} 2>/dev/null || \
    aws secretsmanager update-secret \
        --secret-id ${PROJECT_NAME}/a2a-client-api-keys-json \
        --secret-string "${CLIENT_API_KEYS_JSON}" \
        --region ${AWS_REGION}

    # Persist for summary (do not print the key here; it will be in /tmp/network-config.env)
    cat >> /tmp/network-config.env <<EOF
export A2A_REQUIRE_AUTH=${A2A_REQUIRE_AUTH}
export A2A_CLIENT_API_KEY=${CLIENT_API_KEY}
EOF

    log_info "A2A security secrets created ✓"
}

create_service_connect_mtls() {
    # Toggle: default OFF unless explicitly enabled (ACM PCA can be costly/controlled)
    if [ "${SERVICE_CONNECT_ENABLE_MTLS:-false}" != "true" ]; then
        log_warn "Service Connect mTLS not enabled (set SERVICE_CONNECT_ENABLE_MTLS=true to enable)"
        return 0
    fi

    log_info "Creating ECS Service Connect mTLS resources (ACM PCA + KMS)..."

    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is required"
        exit 1
    fi
    if ! command -v openssl &> /dev/null; then
        log_error "openssl is required"
        exit 1
    fi

    # 1) KMS key (for Service Connect TLS)
    SERVICE_CONNECT_TLS_KMS_KEY_ARN=$(aws kms create-key \
        --description "${PROJECT_NAME} ECS Service Connect TLS" \
        --region ${AWS_REGION} \
        --query 'KeyMetadata.Arn' --output text 2>/dev/null || echo "")

    if [ -n "${SERVICE_CONNECT_TLS_KMS_KEY_ARN}" ]; then
        aws kms create-alias \
            --alias-name alias/${PROJECT_NAME}-service-connect-tls \
            --target-key-id ${SERVICE_CONNECT_TLS_KMS_KEY_ARN} \
            --region ${AWS_REGION} 2>/dev/null || true
        log_info "KMS key created: ${SERVICE_CONNECT_TLS_KMS_KEY_ARN}"
    else
        log_warn "Could not create KMS key (it may already exist)."
    fi

    # 2) ACM PCA root CA
    CA_CONFIG_FILE="/tmp/${PROJECT_NAME}-pca-config.json"
    cat > ${CA_CONFIG_FILE} <<EOF
{
  "KeyAlgorithm": "RSA_2048",
  "SigningAlgorithm": "SHA256WITHRSA",
  "Subject": {
    "Country": "FR",
    "Organization": "${PROJECT_NAME}",
    "OrganizationalUnit": "service-connect",
    "CommonName": "${PROJECT_NAME}-service-connect-root-ca"
  }
}
EOF

    SERVICE_CONNECT_TLS_PCA_ARN=$(aws acm-pca create-certificate-authority \
        --certificate-authority-configuration file://${CA_CONFIG_FILE} \
        --certificate-authority-type ROOT \
        --idempotency-token ${PROJECT_NAME}-service-connect \
        --region ${AWS_REGION} \
        --query 'CertificateAuthorityArn' --output text 2>/dev/null || echo "")

    if [ -z "${SERVICE_CONNECT_TLS_PCA_ARN}" ]; then
        # If create failed, try to find an existing CA by common name
        log_warn "Could not create PCA (it may already exist or be blocked by org policy)."
        log_warn "If you already have a PCA ARN, export SERVICE_CONNECT_TLS_PCA_ARN and SERVICE_CONNECT_TLS_KMS_KEY_ARN before running."
        return 0
    fi

    log_info "PCA created: ${SERVICE_CONNECT_TLS_PCA_ARN}"

    # Activate CA: issue and import the CA certificate
    CSR_FILE="/tmp/${PROJECT_NAME}-pca.csr"
    CERT_FILE="/tmp/${PROJECT_NAME}-pca-cert.pem"
    CERT_CHAIN_FILE="/tmp/${PROJECT_NAME}-pca-chain.pem"

    aws acm-pca get-certificate-authority-csr \
        --certificate-authority-arn ${SERVICE_CONNECT_TLS_PCA_ARN} \
        --region ${AWS_REGION} \
        --output text > ${CSR_FILE}

    # Issue certificate for the CA itself (long-lived)
    CERT_ARN=$(aws acm-pca issue-certificate \
        --certificate-authority-arn ${SERVICE_CONNECT_TLS_PCA_ARN} \
        --csr fileb://${CSR_FILE} \
        --signing-algorithm SHA256WITHRSA \
        --template-arn arn:aws:acm-pca:::template/RootCACertificate/V1 \
        --validity Value=3650,Type=DAYS \
        --region ${AWS_REGION} \
        --query 'CertificateArn' --output text)

    # Wait a bit for issuance
    sleep 10

    aws acm-pca get-certificate \
        --certificate-authority-arn ${SERVICE_CONNECT_TLS_PCA_ARN} \
        --certificate-arn ${CERT_ARN} \
        --region ${AWS_REGION} \
        --query 'Certificate' --output text > ${CERT_FILE}

    aws acm-pca get-certificate \
        --certificate-authority-arn ${SERVICE_CONNECT_TLS_PCA_ARN} \
        --certificate-arn ${CERT_ARN} \
        --region ${AWS_REGION} \
        --query 'CertificateChain' --output text > ${CERT_CHAIN_FILE} 2>/dev/null || true

    aws acm-pca import-certificate-authority-certificate \
        --certificate-authority-arn ${SERVICE_CONNECT_TLS_PCA_ARN} \
        --certificate fileb://${CERT_FILE} \
        --certificate-chain fileb://${CERT_CHAIN_FILE} \
        --region ${AWS_REGION} 2>/dev/null || \
    aws acm-pca import-certificate-authority-certificate \
        --certificate-authority-arn ${SERVICE_CONNECT_TLS_PCA_ARN} \
        --certificate fileb://${CERT_FILE} \
        --region ${AWS_REGION}

    aws acm-pca update-certificate-authority \
        --certificate-authority-arn ${SERVICE_CONNECT_TLS_PCA_ARN} \
        --status ACTIVE \
        --region ${AWS_REGION} 2>/dev/null || true

    # Persist for later phases / service creation
    cat >> /tmp/network-config.env <<EOF
export SERVICE_CONNECT_TLS_PCA_ARN=${SERVICE_CONNECT_TLS_PCA_ARN}
export SERVICE_CONNECT_TLS_KMS_KEY_ARN=${SERVICE_CONNECT_TLS_KMS_KEY_ARN}
EOF

    log_info "Service Connect mTLS resources ready ✓"
}

create_rds_database() {
    log_info "Creating RDS PostgreSQL database..."

    # Create DB subnet group
    aws rds create-db-subnet-group \
        --db-subnet-group-name ${PROJECT_NAME}-db-subnet \
        --db-subnet-group-description "Subnet group for ${PROJECT_NAME}" \
        --subnet-ids ${PRIVATE_SUBNET_1} ${PRIVATE_SUBNET_2} \
        --region ${AWS_REGION} 2>/dev/null || log_warn "DB subnet group already exists"

    # Create RDS instance
    RDS_ENDPOINT=$(aws rds create-db-instance \
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
        --region ${AWS_REGION} \
        --query 'DBInstance.Endpoint.Address' --output text 2>/dev/null)

    if [ $? -ne 0 ]; then
        log_warn "RDS instance may already exist, fetching endpoint..."
        RDS_ENDPOINT=$(aws rds describe-db-instances \
            --db-instance-identifier ${PROJECT_NAME}-postgres \
            --region ${AWS_REGION} \
            --query 'DBInstances[0].Endpoint.Address' --output text)
    fi

    log_info "Waiting for RDS to be available (this may take 5-10 minutes)..."
    aws rds wait db-instance-available \
        --db-instance-identifier ${PROJECT_NAME}-postgres \
        --region ${AWS_REGION}

    # Get final endpoint
    RDS_ENDPOINT=$(aws rds describe-db-instances \
        --db-instance-identifier ${PROJECT_NAME}-postgres \
        --region ${AWS_REGION} \
        --query 'DBInstances[0].Endpoint.Address' --output text)

    cat >> /tmp/network-config.env <<EOF
export RDS_ENDPOINT=${RDS_ENDPOINT}
EOF

    source /tmp/network-config.env
    log_info "RDS database created: ${RDS_ENDPOINT} ✓"
}

create_ecr_repositories() {
    log_info "Creating ECR repositories..."

    for agent in orchestrator extractor validator archivist; do
        aws ecr create-repository \
            --repository-name ${PROJECT_NAME}/${agent} \
            --region ${AWS_REGION} 2>/dev/null || log_warn "ECR repository ${agent} already exists"
    done

    log_info "ECR repositories created ✓"
}

build_and_push_images() {
    log_info "Building and pushing Docker images..."

    # Login to ECR
    aws ecr get-login-password --region ${AWS_REGION} | \
        docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

    # Build and push each agent
    for agent in orchestrator extractor validator archivist; do
        log_info "Building ${agent}..."

        AGENT_SCRIPT="${agent}_agent.py"
        IMAGE_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}/${agent}:latest"

        # Create agent-specific Dockerfile
        cat > Dockerfile.${agent} <<EOF
FROM python:3.9-slim
WORKDIR /app
RUN apt-get update && apt-get install -y gcc postgresql-client libpq-dev curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py ./
RUN useradd -m -u 1000 agent && chown -R agent:agent /app
USER agent
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 CMD curl -f http://localhost:${!agent^^_PORT}/health || exit 1
CMD ["python", "${AGENT_SCRIPT}"]
EOF

        docker build -f Dockerfile.${agent} -t ${IMAGE_URI} .
        docker push ${IMAGE_URI}

        log_info "${agent} image pushed ✓"
    done

    log_info "All images built and pushed ✓"
}

create_iam_roles() {
    log_info "Creating IAM roles..."

    # ECS Task Execution Role
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
        --region ${AWS_REGION} 2>/dev/null || log_warn "Execution role already exists"

    aws iam attach-role-policy \
        --role-name ${PROJECT_NAME}-ecs-execution-role \
        --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

    # ECS Task Role (for application permissions)
    aws iam create-role \
        --role-name ${PROJECT_NAME}-ecs-task-role \
        --assume-role-policy-document file:///tmp/trust-policy.json \
        --region ${AWS_REGION} 2>/dev/null || log_warn "Task role already exists"

    # S3 access policy
    cat > /tmp/task-policy.json <<EOF
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
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/*"
    }
  ]
}
EOF

    aws iam put-role-policy \
        --role-name ${PROJECT_NAME}-ecs-task-role \
        --policy-name ${PROJECT_NAME}-task-policy \
        --policy-document file:///tmp/task-policy.json

    # Optional: permissions for ECS Service Connect mTLS (ACM PCA + KMS)
    if [ -n "${SERVICE_CONNECT_TLS_PCA_ARN}" ] && [ -n "${SERVICE_CONNECT_TLS_KMS_KEY_ARN}" ]; then
        cat > /tmp/service-connect-tls-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "acm-pca:DescribeCertificateAuthority",
        "acm-pca:GetCertificateAuthorityCertificate",
        "acm-pca:IssueCertificate",
        "acm-pca:GetCertificate"
      ],
      "Resource": "${SERVICE_CONNECT_TLS_PCA_ARN}"
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:DescribeKey"
      ],
      "Resource": "${SERVICE_CONNECT_TLS_KMS_KEY_ARN}"
    }
  ]
}
EOF

        aws iam put-role-policy \
            --role-name ${PROJECT_NAME}-ecs-task-role \
            --policy-name ${PROJECT_NAME}-service-connect-tls-policy \
            --policy-document file:///tmp/service-connect-tls-policy.json 2>/dev/null || true

        log_info "Attached Service Connect mTLS policy to task role ✓"
    fi

    log_info "IAM roles created ✓"
}

create_ecs_cluster() {
    log_info "Creating ECS cluster..."

    aws ecs create-cluster \
        --cluster-name ${PROJECT_NAME}-cluster \
        --capacity-providers FARGATE FARGATE_SPOT \
        --region ${AWS_REGION} 2>/dev/null || log_warn "ECS cluster already exists"

    # Enable Container Insights
    aws ecs update-cluster-settings \
        --cluster ${PROJECT_NAME}-cluster \
        --settings name=containerInsights,value=enabled \
        --region ${AWS_REGION}

    log_info "ECS cluster created ✓"
}

create_service_discovery() {
    log_info "Creating service discovery namespace..."

    NAMESPACE_ID=$(aws servicediscovery create-private-dns-namespace \
        --name local \
        --vpc ${VPC_ID} \
        --description "Service discovery for ${PROJECT_NAME}" \
        --region ${AWS_REGION} \
        --query 'OperationId' --output text 2>/dev/null)

    if [ $? -eq 0 ]; then
        # Wait for namespace creation
        sleep 30
        NAMESPACE_ID=$(aws servicediscovery list-namespaces \
            --region ${AWS_REGION} \
            --query "Namespaces[?Name=='local'].Id" --output text)
    else
        log_warn "Namespace may already exist"
        NAMESPACE_ID=$(aws servicediscovery list-namespaces \
            --region ${AWS_REGION} \
            --query "Namespaces[?Name=='local'].Id" --output text)
    fi

    # Create services for each agent (except orchestrator which uses ALB)
    for agent in extractor validator archivist; do
        aws servicediscovery create-service \
            --name ${agent} \
            --namespace-id ${NAMESPACE_ID} \
            --dns-config "NamespaceId=${NAMESPACE_ID},DnsRecords=[{Type=A,TTL=60}]" \
            --health-check-custom-config FailureThreshold=1 \
            --region ${AWS_REGION} 2>/dev/null || log_warn "Service ${agent} already exists"
    done

    cat >> /tmp/network-config.env <<EOF
export NAMESPACE_ID=${NAMESPACE_ID}
EOF

    source /tmp/network-config.env
    log_info "Service discovery created ✓"
}

create_alb() {
    log_info "Creating Application Load Balancer..."

    ALB_ARN=$(aws elbv2 create-load-balancer \
        --name ${PROJECT_NAME}-alb \
        --subnets ${PUBLIC_SUBNET_1} ${PUBLIC_SUBNET_2} \
        --security-groups ${ALB_SG} \
        --scheme internet-facing \
        --type application \
        --region ${AWS_REGION} \
        --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null)

    if [ $? -ne 0 ]; then
        log_warn "ALB may already exist, fetching ARN..."
        ALB_ARN=$(aws elbv2 describe-load-balancers \
            --names ${PROJECT_NAME}-alb \
            --region ${AWS_REGION} \
            --query 'LoadBalancers[0].LoadBalancerArn' --output text)
    fi

    # Create target group for orchestrator
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
        --query 'TargetGroups[0].TargetGroupArn' --output text 2>/dev/null)

    if [ $? -ne 0 ]; then
        log_warn "Target group may already exist"
        TG_ARN=$(aws elbv2 describe-target-groups \
            --names ${PROJECT_NAME}-orch-tg \
            --region ${AWS_REGION} \
            --query 'TargetGroups[0].TargetGroupArn' --output text)
    fi

    # Create listener
    aws elbv2 create-listener \
        --load-balancer-arn ${ALB_ARN} \
        --protocol HTTP \
        --port 80 \
        --default-actions Type=forward,TargetGroupArn=${TG_ARN} \
        --region ${AWS_REGION} 2>/dev/null || log_warn "Listener already exists"

    # Get ALB DNS name
    ALB_DNS=$(aws elbv2 describe-load-balancers \
        --load-balancer-arns ${ALB_ARN} \
        --region ${AWS_REGION} \
        --query 'LoadBalancers[0].DNSName' --output text)

    cat >> /tmp/network-config.env <<EOF
export ALB_ARN=${ALB_ARN}
export TG_ARN=${TG_ARN}
export ALB_DNS=${ALB_DNS}
EOF

    source /tmp/network-config.env
    log_info "ALB created: ${ALB_DNS} ✓"
}

create_cloudwatch_logs() {
    log_info "Creating CloudWatch log groups..."

    for agent in orchestrator extractor validator archivist; do
        aws logs create-log-group \
            --log-group-name /ecs/${PROJECT_NAME}-${agent} \
            --region ${AWS_REGION} 2>/dev/null || log_warn "Log group ${agent} already exists"

        # Set retention to 7 days
        aws logs put-retention-policy \
            --log-group-name /ecs/${PROJECT_NAME}-${agent} \
            --retention-in-days 7 \
            --region ${AWS_REGION}
    done

    log_info "CloudWatch log groups created ✓"
}

register_task_definitions() {
    log_info "Registering ECS task definitions..."

    EXEC_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${PROJECT_NAME}-ecs-execution-role"
    TASK_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${PROJECT_NAME}-ecs-task-role"

    # Orchestrator task definition
    cat > /tmp/orchestrator-task.json <<EOF
{
  "family": "${PROJECT_NAME}-orchestrator",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "${EXEC_ROLE_ARN}",
  "taskRoleArn": "${TASK_ROLE_ARN}",
  "containerDefinitions": [{
    "name": "orchestrator",
    "image": "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}/orchestrator:latest",
    "portMappings": [{"containerPort": ${ORCHESTRATOR_PORT}, "protocol": "tcp", "name": "http"}],
    "environment": [
      {"name": "ORCHESTRATOR_HOST", "value": "0.0.0.0"},
      {"name": "ORCHESTRATOR_PORT", "value": "${ORCHESTRATOR_PORT}"},
      {"name": "EXTRACTOR_HOST", "value": "extractor.local"},
      {"name": "EXTRACTOR_PORT", "value": "${EXTRACTOR_PORT}"},
      {"name": "VALIDATOR_HOST", "value": "validator.local"},
      {"name": "VALIDATOR_PORT", "value": "${VALIDATOR_PORT}"},
      {"name": "ARCHIVIST_HOST", "value": "archivist.local"},
      {"name": "ARCHIVIST_PORT", "value": "${ARCHIVIST_PORT}"},
      {"name": "POSTGRES_HOST", "value": "${RDS_ENDPOINT}"},
      {"name": "POSTGRES_DB", "value": "${DB_NAME}"},
      {"name": "POSTGRES_USER", "value": "${DB_USERNAME}"},
      {"name": "POSTGRES_PORT", "value": "5432"},
      {"name": "S3_BUCKET_NAME", "value": "${S3_BUCKET}"},
      {"name": "AWS_REGION", "value": "${AWS_REGION}"},
      {"name": "A2A_REQUIRE_AUTH", "value": "${A2A_REQUIRE_AUTH}"},
      {"name": "A2A_RBAC_POLICY_JSON", "value": "{\"allow\":{\"external_client\":[\"process_document\",\"process_batch\",\"get_task_status\",\"list_pending_documents\",\"discover_agents\",\"get_agent_registry\"]},\"deny\":{}}"},
      {"name": "A2A_JWT_ISSUER", "value": "ca-a2a"},
      {"name": "A2A_JWT_ALG", "value": "RS256"}
    ],
    "secrets": [
      {"name": "POSTGRES_PASSWORD", "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/db-password"},
      {"name": "A2A_JWT_PRIVATE_KEY_PEM", "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/a2a-jwt-private-key-pem"},
      {"name": "A2A_JWT_PUBLIC_KEY_PEM", "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/a2a-jwt-public-key-pem"},
      {"name": "A2A_API_KEYS_JSON", "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/a2a-client-api-keys-json"}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/${PROJECT_NAME}-orchestrator",
        "awslogs-region": "${AWS_REGION}",
        "awslogs-stream-prefix": "ecs"
      }
    },
    "healthCheck": {
      "command": ["CMD-SHELL", "curl -f http://localhost:${ORCHESTRATOR_PORT}/health || exit 1"],
      "interval": 30,
      "timeout": 5,
      "retries": 3,
      "startPeriod": 60
    }
  }]
}
EOF

    aws ecs register-task-definition \
        --cli-input-json file:///tmp/orchestrator-task.json \
        --region ${AWS_REGION}

    # Create task definitions for other agents
    for agent in extractor validator archivist; do
        PORT_VAR="${agent^^}_PORT"
        PORT=${!PORT_VAR}

        cat > /tmp/${agent}-task.json <<EOF
{
  "family": "${PROJECT_NAME}-${agent}",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "${EXEC_ROLE_ARN}",
  "taskRoleArn": "${TASK_ROLE_ARN}",
  "containerDefinitions": [{
    "name": "${agent}",
    "image": "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}/${agent}:latest",
    "portMappings": [{"containerPort": ${PORT}, "protocol": "tcp", "name": "http"}],
    "environment": [
      {"name": "${agent^^}_HOST", "value": "0.0.0.0"},
      {"name": "${agent^^}_PORT", "value": "${PORT}"},
      {"name": "POSTGRES_HOST", "value": "${RDS_ENDPOINT}"},
      {"name": "POSTGRES_DB", "value": "${DB_NAME}"},
      {"name": "POSTGRES_USER", "value": "${DB_USERNAME}"},
      {"name": "POSTGRES_PORT", "value": "5432"},
      {"name": "S3_BUCKET_NAME", "value": "${S3_BUCKET}"},
      {"name": "AWS_REGION", "value": "${AWS_REGION}"},
      {"name": "A2A_REQUIRE_AUTH", "value": "${A2A_REQUIRE_AUTH}"},
      {"name": "A2A_RBAC_POLICY_JSON", "value": "{\"allow\":{\"orchestrator\":[\"*\"]},\"deny\":{}}"},
      {"name": "A2A_JWT_ISSUER", "value": "ca-a2a"},
      {"name": "A2A_JWT_ALG", "value": "RS256"}
    ],
    "secrets": [
      {"name": "POSTGRES_PASSWORD", "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/db-password"},
      {"name": "A2A_JWT_PUBLIC_KEY_PEM", "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/a2a-jwt-public-key-pem"}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/${PROJECT_NAME}-${agent}",
        "awslogs-region": "${AWS_REGION}",
        "awslogs-stream-prefix": "ecs"
      }
    },
    "healthCheck": {
      "command": ["CMD-SHELL", "curl -f http://localhost:${PORT}/health || exit 1"],
      "interval": 30,
      "timeout": 5,
      "retries": 3,
      "startPeriod": 60
    }
  }]
}
EOF

        aws ecs register-task-definition \
            --cli-input-json file:///tmp/${agent}-task.json \
            --region ${AWS_REGION}
    done

    log_info "Task definitions registered ✓"
}

create_ecs_services() {
    log_info "Creating ECS services..."

    # Create orchestrator service with ALB
    # Service Connect / mTLS configuration (optional TLS if SERVICE_CONNECT_TLS_* env vars are set)
    # Note: mTLS requires ACM PCA + KMS; if not provided, Service Connect still provides a proxy + discovery.
    SC_TLS_FRAGMENT=""
    if [ -n "${SERVICE_CONNECT_TLS_PCA_ARN}" ] && [ -n "${SERVICE_CONNECT_TLS_KMS_KEY_ARN}" ]; then
        SC_TLS_FRAGMENT=",\"tls\":{\"issuerCertificateAuthority\":{\"awsPcaAuthorityArn\":\"${SERVICE_CONNECT_TLS_PCA_ARN}\"},\"kmsKey\":\"${SERVICE_CONNECT_TLS_KMS_KEY_ARN}\",\"roleArn\":\"${TASK_ROLE_ARN}\"}"
    fi

    aws ecs create-service \
        --cluster ${PROJECT_NAME}-cluster \
        --service-name orchestrator \
        --task-definition ${PROJECT_NAME}-orchestrator \
        --desired-count 2 \
        --launch-type FARGATE \
        --platform-version LATEST \
        --network-configuration "awsvpcConfiguration={subnets=[${PRIVATE_SUBNET_1},${PRIVATE_SUBNET_2}],securityGroups=[${ORCHESTRATOR_SG}],assignPublicIp=DISABLED}" \
        --load-balancers "targetGroupArn=${TG_ARN},containerName=orchestrator,containerPort=${ORCHESTRATOR_PORT}" \
        --health-check-grace-period-seconds 60 \
        --service-connect-configuration "{\"enabled\":true,\"namespace\":\"local\",\"services\":[{\"portName\":\"http\",\"discoveryName\":\"orchestrator\",\"clientAliases\":[{\"port\":${ORCHESTRATOR_PORT},\"dnsName\":\"orchestrator\"}]${SC_TLS_FRAGMENT}}]}" \
        --region ${AWS_REGION} 2>/dev/null || log_warn "Orchestrator service already exists"

    # Create other agent services with service discovery
    for agent in extractor validator archivist; do
        SERVICE_REGISTRY_ARN=$(aws servicediscovery list-services \
            --region ${AWS_REGION} \
            --query "Services[?Name=='${agent}'].Arn" --output text)

        # Select per-agent security group
        case $agent in
            extractor) SG=${EXTRACTOR_SG} ;;
            validator) SG=${VALIDATOR_SG} ;;
            archivist) SG=${ARCHIVIST_SG} ;;
        esac
        # Select port for Service Connect client alias
        case $agent in
            extractor) PORT=${EXTRACTOR_PORT} ;;
            validator) PORT=${VALIDATOR_PORT} ;;
            archivist) PORT=${ARCHIVIST_PORT} ;;
        esac

        aws ecs create-service \
            --cluster ${PROJECT_NAME}-cluster \
            --service-name ${agent} \
            --task-definition ${PROJECT_NAME}-${agent} \
            --desired-count 2 \
            --launch-type FARGATE \
            --platform-version LATEST \
            --network-configuration "awsvpcConfiguration={subnets=[${PRIVATE_SUBNET_1},${PRIVATE_SUBNET_2}],securityGroups=[${SG}],assignPublicIp=DISABLED}" \
            --service-registries "registryArn=${SERVICE_REGISTRY_ARN}" \
            --service-connect-configuration "{\"enabled\":true,\"namespace\":\"local\",\"services\":[{\"portName\":\"http\",\"discoveryName\":\"${agent}\",\"clientAliases\":[{\"port\":${PORT},\"dnsName\":\"${agent}\"}]${SC_TLS_FRAGMENT}}]}" \
            --region ${AWS_REGION} 2>/dev/null || log_warn "${agent} service already exists"
    done

    log_info "ECS services created ✓"
}

initialize_database() {
    log_info "Database initialization..."
    log_warn "You need to run 'python init_db.py init' from an ECS task or EC2 instance with access to RDS"
    log_info "Database endpoint: ${RDS_ENDPOINT}"
}

print_summary() {
    log_info "=================================="
    log_info "Deployment Complete!"
    log_info "=================================="
    echo ""
    log_info "Application Load Balancer: http://${ALB_DNS}"
    log_info "S3 Bucket: ${S3_BUCKET}"
    log_info "RDS Endpoint: ${RDS_ENDPOINT}"
    log_info "Database Name: ${DB_NAME}"
    log_info "Database User: ${DB_USERNAME}"
    echo ""
    log_info "Test the deployment:"
    echo "  curl http://${ALB_DNS}/health"
    echo "  curl http://${ALB_DNS}/status"
    echo ""
    log_info "View logs:"
    echo "  aws logs tail /ecs/${PROJECT_NAME}-orchestrator --follow --region ${AWS_REGION}"
    echo ""
    log_info "Next steps:"
    echo "  1. Initialize the database (see init_db.py)"
    echo "  2. Upload test documents to S3"
    echo "  3. Process documents via the API"
    echo ""
    log_info "Configuration saved to: /tmp/network-config.env"
}

###############################################################################
# Main Deployment Flow
###############################################################################

main() {
    log_info "Starting AWS deployment for ${PROJECT_NAME}..."
    log_info "Region: ${AWS_REGION}"
    log_info "Account: ${AWS_ACCOUNT_ID}"

    check_prerequisites

    # Infrastructure
    create_vpc_network
    create_security_groups
    create_s3_bucket
    create_secrets
    create_a2a_security_secrets
    create_service_connect_mtls
    create_rds_database

    # Container Setup
    create_ecr_repositories
    build_and_push_images

    # ECS Setup
    create_iam_roles
    create_ecs_cluster
    create_service_discovery
    create_alb
    create_cloudwatch_logs
    register_task_definitions
    create_ecs_services

    # Finalize
    initialize_database
    print_summary

    log_info "Deployment script completed successfully! ✓"
}

# Run main function
main "$@"
