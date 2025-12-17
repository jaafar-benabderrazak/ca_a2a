#!/bin/bash
###############################################################################
# Phase 2: Docker Images and ECS Services Deployment
# Run this on your LOCAL MACHINE with Docker installed
# Requires: AWS SSO configured, Docker running
###############################################################################

set -e

# Disable path conversion for Git Bash on Windows
export MSYS_NO_PATHCONV=1

# Create temp directory for task definitions
TASK_DEF_DIR="./task-definitions"
mkdir -p ${TASK_DEF_DIR}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

###############################################################################
# Load Configuration
###############################################################################

if [ -f "/tmp/ca-a2a-config.env" ]; then
    source /tmp/ca-a2a-config.env
    log_info "Loaded configuration from /tmp/ca-a2a-config.env"
elif [ -f "ca-a2a-config.env" ]; then
    source ca-a2a-config.env
    log_info "Loaded configuration from ca-a2a-config.env"
else
    log_error "Configuration file not found!"
    log_info "Please ensure Phase 1 completed successfully"
    log_info "Or manually set these variables:"
    echo "  export AWS_REGION='eu-west-3'"
    echo "  export AWS_ACCOUNT_ID='your-account-id'"
    echo "  export PROJECT_NAME='ca-a2a'"
    exit 1
fi

# Default values if not set
export AWS_REGION="${AWS_REGION:-eu-west-3}"
export PROJECT_NAME="${PROJECT_NAME:-ca-a2a}"

###############################################################################
# Check Prerequisites
###############################################################################

log_info "Checking prerequisites..."

# Check Docker
if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed or not in PATH"
    exit 1
fi

# Check Docker daemon
if ! docker ps &> /dev/null; then
    log_error "Docker daemon is not running"
    exit 1
fi

# Check AWS credentials
if ! aws sts get-caller-identity &> /dev/null; then
    log_error "AWS credentials not configured"
    log_info "Please run: aws sso login"
    exit 1
fi

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

log_info "Prerequisites check passed ✓"
log_info "AWS Account: ${AWS_ACCOUNT_ID}"
log_info "Region: ${AWS_REGION}"

###############################################################################
# Build and Push Docker Images
###############################################################################

log_info "========================================"
log_info "Phase 2: Building Docker Images"
log_info "========================================"

# Login to ECR
log_info "Logging in to ECR..."
aws ecr get-login-password --region ${AWS_REGION} | \
    docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Build and push each agent
for agent in orchestrator extractor validator archivist; do
    log_info "Building ${agent}..."

    # Determine port
    case $agent in
        orchestrator) PORT=8001 ;;
        extractor) PORT=8002 ;;
        validator) PORT=8003 ;;
        archivist) PORT=8004 ;;
    esac

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
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:${PORT}/health || exit 1
CMD ["python", "${AGENT_SCRIPT}"]
EOF

    # Build
    docker build -f Dockerfile.${agent} -t ${IMAGE_URI} .

    # Push
    log_info "Pushing ${agent} to ECR..."
    docker push ${IMAGE_URI}

    log_info "${agent} image pushed ✓"
done

###############################################################################
# Register ECS Task Definitions
###############################################################################

log_info "========================================"
log_info "Registering ECS Task Definitions"
log_info "========================================"

EXEC_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${PROJECT_NAME}-ecs-execution-role"
TASK_ROLE_ARN="arn:aws:iam::${AWS_ACCOUNT_ID}:role/${PROJECT_NAME}-ecs-task-role"

# Orchestrator task definition
cat > ${TASK_DEF_DIR}/orchestrator-task.json <<EOF
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
    "portMappings": [{"containerPort": 8001, "protocol": "tcp"}],
    "environment": [
      {"name": "ORCHESTRATOR_HOST", "value": "0.0.0.0"},
      {"name": "ORCHESTRATOR_PORT", "value": "8001"},
      {"name": "EXTRACTOR_HOST", "value": "extractor.local"},
      {"name": "EXTRACTOR_PORT", "value": "8002"},
      {"name": "VALIDATOR_HOST", "value": "validator.local"},
      {"name": "VALIDATOR_PORT", "value": "8003"},
      {"name": "ARCHIVIST_HOST", "value": "archivist.local"},
      {"name": "ARCHIVIST_PORT", "value": "8004"},
      {"name": "POSTGRES_HOST", "value": "${RDS_ENDPOINT}"},
      {"name": "POSTGRES_DB", "value": "documents_db"},
      {"name": "POSTGRES_USER", "value": "postgres"},
      {"name": "POSTGRES_PORT", "value": "5432"},
      {"name": "S3_BUCKET_NAME", "value": "${S3_BUCKET}"},
      {"name": "AWS_REGION", "value": "${AWS_REGION}"}
    ],
    "secrets": [
      {"name": "POSTGRES_PASSWORD", "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/db-password"}
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
      "command": ["CMD-SHELL", "curl -f http://localhost:8001/health || exit 1"],
      "interval": 30,
      "timeout": 5,
      "retries": 3,
      "startPeriod": 60
    }
  }]
}
EOF

aws ecs register-task-definition \
    --cli-input-json file://${TASK_DEF_DIR}/orchestrator-task.json \
    --region ${AWS_REGION}

# Create task definitions for other agents
for agent in extractor validator archivist; do
    PORT_VAR="${agent^^}_PORT"
    case $agent in
        extractor) PORT=8002 ;;
        validator) PORT=8003 ;;
        archivist) PORT=8004 ;;
    esac

    cat > ${TASK_DEF_DIR}/${agent}-task.json <<EOF
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
    "portMappings": [{"containerPort": ${PORT}, "protocol": "tcp"}],
    "environment": [
      {"name": "${agent^^}_HOST", "value": "0.0.0.0"},
      {"name": "${agent^^}_PORT", "value": "${PORT}"},
      {"name": "POSTGRES_HOST", "value": "${RDS_ENDPOINT}"},
      {"name": "POSTGRES_DB", "value": "documents_db"},
      {"name": "POSTGRES_USER", "value": "postgres"},
      {"name": "POSTGRES_PORT", "value": "5432"},
      {"name": "S3_BUCKET_NAME", "value": "${S3_BUCKET}"},
      {"name": "AWS_REGION", "value": "${AWS_REGION}"}
    ],
    "secrets": [
      {"name": "POSTGRES_PASSWORD", "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${PROJECT_NAME}/db-password"}
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
        --cli-input-json file://${TASK_DEF_DIR}/${agent}-task.json \
        --region ${AWS_REGION}
done

###############################################################################
# Create ECS Services
###############################################################################

log_info "========================================"
log_info "Creating ECS Services"
log_info "========================================"

# Create orchestrator service with ALB
log_info "Creating orchestrator service..."
aws ecs create-service \
    --cluster ${PROJECT_NAME}-cluster \
    --service-name orchestrator \
    --task-definition ${PROJECT_NAME}-orchestrator \
    --desired-count 2 \
    --launch-type FARGATE \
    --platform-version LATEST \
    --network-configuration "awsvpcConfiguration={subnets=[${PRIVATE_SUBNET_1},${PRIVATE_SUBNET_2}],securityGroups=[${ECS_SG}],assignPublicIp=DISABLED}" \
    --load-balancers "targetGroupArn=${TG_ARN},containerName=orchestrator,containerPort=8001" \
    --health-check-grace-period-seconds 60 \
    --region ${AWS_REGION} 2>/dev/null || log_warn "Orchestrator service may already exist"

# Create other agent services with service discovery
for agent in extractor validator archivist; do
    log_info "Creating ${agent} service..."

    SERVICE_REGISTRY_ARN=$(aws servicediscovery list-services \
        --region ${AWS_REGION} \
        --query "Services[?Name=='${agent}'].Arn" --output text)

    aws ecs create-service \
        --cluster ${PROJECT_NAME}-cluster \
        --service-name ${agent} \
        --task-definition ${PROJECT_NAME}-${agent} \
        --desired-count 2 \
        --launch-type FARGATE \
        --platform-version LATEST \
        --network-configuration "awsvpcConfiguration={subnets=[${PRIVATE_SUBNET_1},${PRIVATE_SUBNET_2}],securityGroups=[${ECS_SG}],assignPublicIp=DISABLED}" \
        --service-registries "registryArn=${SERVICE_REGISTRY_ARN}" \
        --region ${AWS_REGION} 2>/dev/null || log_warn "${agent} service may already exist"
done

###############################################################################
# Summary
###############################################################################

log_info "========================================"
log_info "Deployment Complete!"
log_info "========================================"
echo ""
log_info "Application Load Balancer: http://${ALB_DNS}"
log_info "S3 Bucket: ${S3_BUCKET}"
log_info "RDS Endpoint: ${RDS_ENDPOINT}"
echo ""
log_info "Test the deployment:"
echo "  curl http://${ALB_DNS}/health"
echo "  curl http://${ALB_DNS}/status"
echo "  curl http://${ALB_DNS}/card | jq"
echo ""
log_info "View logs:"
echo "  aws logs tail /ecs/${PROJECT_NAME}-orchestrator --follow --region ${AWS_REGION}"
echo ""
log_info "Check ECS services:"
echo "  aws ecs describe-services --cluster ${PROJECT_NAME}-cluster --services orchestrator extractor validator archivist --region ${AWS_REGION}"
echo ""
