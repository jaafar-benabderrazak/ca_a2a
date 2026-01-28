#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# CA-A2A ECS Services Deployment Script
# Deploys Docker containers to ECS after CDK infrastructure is ready
# ══════════════════════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║       CA-A2A ECS Services Deployment                                  ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Configuration
PROJECT="${PROJECT_NAME:-ca-a2a}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-west-3}}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo -e "${CYAN}Configuration:${NC}"
echo "  Project:  ${PROJECT}"
echo "  Region:   ${REGION}"
echo "  Account:  ${ACCOUNT_ID}"
echo ""

# Check if CDK outputs exist
if [ -f outputs.json ]; then
    echo -e "${GREEN}✓${NC} Found CDK outputs"
    
    # Parse outputs
    CLUSTER_NAME=$(cat outputs.json | python3 -c "import sys,json; d=json.load(sys.stdin); k=list(d.keys())[0]; print(d[k].get('EcsClusterName',''))" 2>/dev/null || echo "")
    ECS_SG_ID=$(cat outputs.json | python3 -c "import sys,json; d=json.load(sys.stdin); k=list(d.keys())[0]; print(d[k].get('EcsServicesSecurityGroupId',''))" 2>/dev/null || echo "")
    TASK_EXEC_ROLE=$(cat outputs.json | python3 -c "import sys,json; d=json.load(sys.stdin); k=list(d.keys())[0]; print(d[k].get('TaskExecutionRoleArn',''))" 2>/dev/null || echo "")
    TASK_ROLE=$(cat outputs.json | python3 -c "import sys,json; d=json.load(sys.stdin); k=list(d.keys())[0]; print(d[k].get('TaskRoleArn',''))" 2>/dev/null || echo "")
    ALB_ARN=$(cat outputs.json | python3 -c "import sys,json; d=json.load(sys.stdin); k=list(d.keys())[0]; print(d[k].get('AlbArn',''))" 2>/dev/null || echo "")
    VPC_ID=$(cat outputs.json | python3 -c "import sys,json; d=json.load(sys.stdin); k=list(d.keys())[0]; print(d[k].get('VpcId',''))" 2>/dev/null || echo "")
else
    echo -e "${YELLOW}⚠${NC} No outputs.json found, looking up resources..."
    
    CLUSTER_NAME="${PROJECT}-cluster"
    VPC_ID=$(aws ec2 describe-vpcs --region $REGION \
        --filters "Name=tag:Project,Values=${PROJECT}" \
        --query 'Vpcs[0].VpcId' --output text 2>/dev/null || echo "")
    
    ECS_SG_ID=$(aws ec2 describe-security-groups --region $REGION \
        --filters "Name=group-name,Values=${PROJECT}-ecs-services-sg" \
        --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "")
    
    TASK_EXEC_ROLE=$(aws iam get-role --role-name ${PROJECT}-ecs-task-execution-role \
        --query 'Role.Arn' --output text 2>/dev/null || echo "")
    
    TASK_ROLE=$(aws iam get-role --role-name ${PROJECT}-ecs-task-role \
        --query 'Role.Arn' --output text 2>/dev/null || echo "")
    
    ALB_ARN=$(aws elbv2 describe-load-balancers --region $REGION \
        --names ${PROJECT}-alb \
        --query 'LoadBalancers[0].LoadBalancerArn' --output text 2>/dev/null || echo "")
fi

# Validate required resources
if [ -z "$CLUSTER_NAME" ] || [ -z "$VPC_ID" ]; then
    echo -e "${RED}✗ Required infrastructure not found. Run CDK deploy first.${NC}"
    exit 1
fi

echo -e "\n${CYAN}Infrastructure:${NC}"
echo "  Cluster:    ${CLUSTER_NAME}"
echo "  VPC:        ${VPC_ID}"
echo "  ECS SG:     ${ECS_SG_ID}"
echo "  Exec Role:  ${TASK_EXEC_ROLE}"
echo ""

# Get private subnets
PRIVATE_SUBNETS=$(aws ec2 describe-subnets --region $REGION \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Name,Values=*Private*" \
    --query 'Subnets[*].SubnetId' --output text | tr '\t' ',')

if [ -z "$PRIVATE_SUBNETS" ]; then
    echo -e "${RED}✗ No private subnets found${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Private subnets: ${PRIVATE_SUBNETS}"

# Login to ECR
echo -e "\n${CYAN}▸${NC} Logging into ECR..."
aws ecr get-login-password --region $REGION | \
    docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com
echo -e "${GREEN}✓${NC} ECR login successful"

# Build and push images
SERVICES="orchestrator extractor validator archivist mcp-server"
cd ..  # Go to project root

for SERVICE in $SERVICES; do
    echo -e "\n${CYAN}▸${NC} Building ${SERVICE}..."
    
    if [ -d "$SERVICE" ]; then
        # Build
        docker build -t ${PROJECT}/${SERVICE}:latest ./${SERVICE}
        
        # Tag
        docker tag ${PROJECT}/${SERVICE}:latest \
            ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PROJECT}/${SERVICE}:latest
        
        # Push
        docker push ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PROJECT}/${SERVICE}:latest
        
        echo -e "${GREEN}✓${NC} ${SERVICE} pushed to ECR"
    else
        echo -e "${YELLOW}⚠${NC} Directory ${SERVICE} not found, skipping"
    fi
done

# Create/Update ECS Task Definitions and Services
echo -e "\n${CYAN}▸${NC} Creating ECS task definitions and services..."

# Service configurations: name, port, cpu, memory
declare -A SERVICE_CONFIG=(
    ["orchestrator"]="8001 256 512"
    ["extractor"]="8002 256 512"
    ["validator"]="8003 256 512"
    ["archivist"]="8004 256 512"
    ["mcp-server"]="8000 256 512"
)

for SERVICE in $SERVICES; do
    CONFIG=(${SERVICE_CONFIG[$SERVICE]})
    PORT=${CONFIG[0]}
    CPU=${CONFIG[1]}
    MEMORY=${CONFIG[2]}
    
    echo -e "\n${CYAN}▸${NC} Deploying ${SERVICE} (port: ${PORT})..."
    
    # Create task definition
    TASK_DEF=$(cat <<EOF
{
    "family": "${PROJECT}-${SERVICE}",
    "networkMode": "awsvpc",
    "requiresCompatibilities": ["FARGATE"],
    "cpu": "${CPU}",
    "memory": "${MEMORY}",
    "executionRoleArn": "${TASK_EXEC_ROLE}",
    "taskRoleArn": "${TASK_ROLE}",
    "containerDefinitions": [{
        "name": "${SERVICE}",
        "image": "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PROJECT}/${SERVICE}:latest",
        "essential": true,
        "portMappings": [{
            "containerPort": ${PORT},
            "protocol": "tcp"
        }],
        "environment": [
            {"name": "AWS_REGION", "value": "${REGION}"},
            {"name": "SERVICE_NAME", "value": "${SERVICE}"},
            {"name": "A2A_REQUIRE_AUTH", "value": "false"}
        ],
        "logConfiguration": {
            "logDriver": "awslogs",
            "options": {
                "awslogs-group": "/ecs/${PROJECT}/${SERVICE}",
                "awslogs-region": "${REGION}",
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
)
    
    # Register task definition
    echo "$TASK_DEF" > /tmp/task-def-${SERVICE}.json
    aws ecs register-task-definition --cli-input-json file:///tmp/task-def-${SERVICE}.json --region $REGION > /dev/null
    echo -e "${GREEN}✓${NC} Task definition registered"
    
    # Check if service exists
    SERVICE_EXISTS=$(aws ecs describe-services --cluster $CLUSTER_NAME --services $SERVICE --region $REGION \
        --query 'services[?status==`ACTIVE`].serviceName' --output text 2>/dev/null || echo "")
    
    if [ -n "$SERVICE_EXISTS" ]; then
        # Update existing service
        aws ecs update-service \
            --cluster $CLUSTER_NAME \
            --service $SERVICE \
            --task-definition ${PROJECT}-${SERVICE} \
            --force-new-deployment \
            --region $REGION > /dev/null
        echo -e "${GREEN}✓${NC} Service ${SERVICE} updated"
    else
        # Create new service
        aws ecs create-service \
            --cluster $CLUSTER_NAME \
            --service-name $SERVICE \
            --task-definition ${PROJECT}-${SERVICE} \
            --desired-count 1 \
            --launch-type FARGATE \
            --network-configuration "awsvpcConfiguration={subnets=[${PRIVATE_SUBNETS}],securityGroups=[${ECS_SG_ID}],assignPublicIp=DISABLED}" \
            --region $REGION > /dev/null
        echo -e "${GREEN}✓${NC} Service ${SERVICE} created"
    fi
done

echo -e "\n${BOLD}${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                                                                       ║"
echo "║                    ✅ Services Deployed!                              ║"
echo "║                                                                       ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo "Check service status:"
echo "  aws ecs describe-services --cluster ${CLUSTER_NAME} --services orchestrator extractor validator archivist mcp-server --region ${REGION} --query 'services[*].{Name:serviceName,Running:runningCount,Desired:desiredCount}' --output table"
echo ""
echo "View logs:"
echo "  aws logs tail /ecs/${PROJECT}/orchestrator --since 5m --region ${REGION}"

