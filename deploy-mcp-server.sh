#!/bin/bash
# Deploy MCP Server to AWS ECS
# This script builds, pushes, and deploys the MCP HTTP server to ECS Fargate

set -e

# Configuration
PROJECT_NAME="ca-a2a"
REGION="eu-west-3"
ACCOUNT_ID="555043101106"
CLUSTER_NAME="${PROJECT_NAME}-cluster"
SERVICE_NAME="mcp-server"
TASK_FAMILY="${PROJECT_NAME}-mcp-server"
ECR_REPO="${PROJECT_NAME}/mcp-server"
IMAGE_TAG="latest"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}=====================================================================${NC}"
echo -e "${GREEN}  MCP SERVER DEPLOYMENT TO AWS ECS${NC}"
echo -e "${CYAN}=====================================================================${NC}"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo "  Account: $ACCOUNT_ID"
echo "  Region: $REGION"
echo "  Cluster: $CLUSTER_NAME"
echo "  Service: $SERVICE_NAME"
echo "  ECR Repo: $ECR_REPO"
echo ""

# Step 1: Create ECR repository if it doesn't exist
echo -e "${YELLOW}[1/9] Checking ECR repository...${NC}"
if aws ecr describe-repositories --repository-names $ECR_REPO --region $REGION 2>/dev/null; then
    echo -e "  ${GREEN}[OK] ECR repository exists${NC}"
else
    echo -e "  ${CYAN}Creating ECR repository: $ECR_REPO${NC}"
    aws ecr create-repository \
        --repository-name $ECR_REPO \
        --image-scanning-configuration scanOnPush=true \
        --encryption-configuration encryptionType=AES256 \
        --region $REGION
    echo -e "  ${GREEN}[OK] ECR repository created${NC}"
fi

# Step 2: Login to ECR
echo -e "\n${YELLOW}[2/9] Logging in to ECR...${NC}"
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com
echo -e "  ${GREEN}[OK] Logged in to ECR${NC}"

# Step 3: Build Docker image
echo -e "\n${YELLOW}[3/9] Building Docker image...${NC}"
docker build -f Dockerfile.mcp -t ${ECR_REPO}:${IMAGE_TAG} .
echo -e "  ${GREEN}[OK] Docker image built${NC}"

# Step 4: Tag image
echo -e "\n${YELLOW}[4/9] Tagging Docker image...${NC}"
ECR_IMAGE="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG}"
docker tag ${ECR_REPO}:${IMAGE_TAG} $ECR_IMAGE
echo -e "  ${GREEN}[OK] Image tagged${NC}"

# Step 5: Push to ECR
echo -e "\n${YELLOW}[5/9] Pushing image to ECR...${NC}"
docker push $ECR_IMAGE
echo -e "  ${GREEN}[OK] Image pushed to ECR${NC}"

# Step 6: Create CloudWatch log group
echo -e "\n${YELLOW}[6/9] Creating CloudWatch log group...${NC}"
aws logs create-log-group --log-group-name /ecs/${PROJECT_NAME}-mcp-server --region $REGION 2>/dev/null || \
    echo -e "  ${YELLOW}[WARN] Log group already exists${NC}"
echo -e "  ${GREEN}[OK] Log group ready${NC}"

# Step 7: Register ECS task definition
echo -e "\n${YELLOW}[7/9] Registering ECS task definition...${NC}"
TASK_DEF_ARN=$(aws ecs register-task-definition \
    --cli-input-json file://task-definitions/mcp-server-task.json \
    --region $REGION \
    --query 'taskDefinition.taskDefinitionArn' \
    --output text)
echo -e "  ${GREEN}[OK] Task definition registered: $TASK_DEF_ARN${NC}"

# Step 8: Get VPC configuration from existing orchestrator service
echo -e "\n${YELLOW}[8/9] Getting network configuration...${NC}"
NETWORK_CONFIG=$(aws ecs describe-services \
    --cluster $CLUSTER_NAME \
    --services orchestrator \
    --region $REGION \
    --query 'services[0].networkConfiguration.awsvpcConfiguration' \
    --output json)

SUBNETS=$(echo $NETWORK_CONFIG | jq -r '.subnets | join(",")')
SECURITY_GROUP=$(echo $NETWORK_CONFIG | jq -r '.securityGroups[0]')

echo "  Subnets: $SUBNETS"
echo "  Security Group: $SECURITY_GROUP"
echo -e "  ${GREEN}[OK] Network configuration retrieved${NC}"

# Step 9: Create service discovery for MCP server
echo -e "\n${YELLOW}[9/10] Creating service discovery...${NC}"

# Get namespace ID
NAMESPACE_ID=$(aws servicediscovery list-namespaces \
    --region $REGION \
    --query "Namespaces[?Name=='${PROJECT_NAME}.local'].Id | [0]" \
    --output text)

if [ "$NAMESPACE_ID" == "None" ] || [ -z "$NAMESPACE_ID" ]; then
    echo -e "  ${RED}[ERROR] Service discovery namespace not found${NC}"
    echo "  Please run deploy.sh first to create the namespace"
    exit 1
fi

echo "  Namespace ID: $NAMESPACE_ID"

# Check if service discovery already exists
SD_SERVICE_ID=$(aws servicediscovery list-services \
    --region $REGION \
    --query "Services[?Name=='mcp-server'].Id | [0]" \
    --output text)

if [ "$SD_SERVICE_ID" == "None" ] || [ -z "$SD_SERVICE_ID" ]; then
    echo -e "  ${CYAN}Creating service discovery for mcp-server...${NC}"
    SD_SERVICE_ID=$(aws servicediscovery create-service \
        --name mcp-server \
        --namespace-id $NAMESPACE_ID \
        --dns-config "NamespaceId=${NAMESPACE_ID},DnsRecords=[{Type=A,TTL=60}]" \
        --health-check-custom-config FailureThreshold=1 \
        --region $REGION \
        --query 'Service.Id' \
        --output text)
    echo -e "  ${GREEN}[OK] Service discovery created: $SD_SERVICE_ID${NC}"
else
    echo -e "  ${GREEN}[OK] Service discovery exists: $SD_SERVICE_ID${NC}"
fi

SD_SERVICE_ARN=$(aws servicediscovery get-service \
    --id $SD_SERVICE_ID \
    --region $REGION \
    --query 'Service.Arn' \
    --output text)

echo "  Service Discovery ARN: $SD_SERVICE_ARN"

# Step 10: Create or update ECS service
echo -e "\n${YELLOW}[10/10] Creating/updating ECS service...${NC}"

# Check if service exists
SERVICE_EXISTS=$(aws ecs describe-services \
    --cluster $CLUSTER_NAME \
    --services $SERVICE_NAME \
    --region $REGION \
    --query 'services[?status==`ACTIVE`] | length(@)')

if [ "$SERVICE_EXISTS" -gt 0 ]; then
    echo -e "  ${CYAN}Updating existing service...${NC}"
    aws ecs update-service \
        --cluster $CLUSTER_NAME \
        --service $SERVICE_NAME \
        --task-definition $TASK_DEF_ARN \
        --force-new-deployment \
        --region $REGION > /dev/null
    echo -e "  ${GREEN}[OK] Service updated${NC}"
else
    echo -e "  ${CYAN}Creating new service...${NC}"
    
    # Convert subnets to JSON array
    SUBNETS_ARRAY=$(echo $SUBNETS | tr ',' '\n' | jq -R -s -c 'split("\n")[:-1]')
    
    aws ecs create-service \
        --cluster $CLUSTER_NAME \
        --service-name $SERVICE_NAME \
        --task-definition $TASK_DEF_ARN \
        --desired-count 1 \
        --launch-type FARGATE \
        --platform-version LATEST \
        --network-configuration "{
            \"awsvpcConfiguration\": {
                \"subnets\": $SUBNETS_ARRAY,
                \"securityGroups\": [\"$SECURITY_GROUP\"],
                \"assignPublicIp\": \"DISABLED\"
            }
        }" \
        --service-registries "[{
            \"registryArn\": \"$SD_SERVICE_ARN\"
        }]" \
        --enable-execute-command \
        --region $REGION > /dev/null
    
    echo -e "  ${GREEN}[OK] Service created${NC}"
fi

echo ""
echo -e "${CYAN}=====================================================================${NC}"
echo -e "${GREEN}  MCP SERVER DEPLOYMENT COMPLETE${NC}"
echo -e "${CYAN}=====================================================================${NC}"
echo ""
echo -e "${YELLOW}Service Details:${NC}"
echo "  Cluster: $CLUSTER_NAME"
echo "  Service: $SERVICE_NAME"
echo "  Service Discovery: mcp-server.${PROJECT_NAME}.local:8000"
echo "  Task Definition: $TASK_DEF_ARN"
echo "  Image: $ECR_IMAGE"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Wait for service to become healthy:"
echo "     aws ecs describe-services --cluster $CLUSTER_NAME --services $SERVICE_NAME --region $REGION"
echo ""
echo "  2. Monitor logs:"
echo "     aws logs tail /ecs/${PROJECT_NAME}-mcp-server --follow --region $REGION"
echo ""
echo "  3. Verify health endpoint:"
echo "     # From within VPC (e.g., orchestrator container)"
echo "     curl http://mcp-server.${PROJECT_NAME}.local:8000/health"
echo ""
echo "  4. Update agent services to use MCP server:"
echo "     ./update-agents-use-mcp.sh"
echo ""


