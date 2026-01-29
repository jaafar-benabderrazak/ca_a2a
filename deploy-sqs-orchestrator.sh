#!/bin/bash
###############################################################################
# Deploy SQS-Enabled Orchestrator
# Rebuilds and redeploys orchestrator with automatic document processing
###############################################################################

set -e

REGION="${AWS_REGION:-eu-west-3}"
ACCOUNT_ID="${AWS_ACCOUNT_ID:-555043101106}"
CLUSTER_NAME="ca-a2a-cluster"
SERVICE_NAME="orchestrator"
ECR_REPO="ca-a2a-orchestrator"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_header() { echo -e "${CYAN}=== $1 ===${NC}"; }

log_header "DEPLOYING SQS-ENABLED ORCHESTRATOR"
echo ""

# Step 1: Verify SQS queue exists
log_info "Checking SQS queue..."
QUEUE_URL=$(aws sqs get-queue-url \
  --queue-name ca-a2a-document-processing \
  --region $REGION \
  --query 'QueueUrl' \
  --output text 2>/dev/null || echo "")

if [ -z "$QUEUE_URL" ]; then
  log_warn "SQS queue not found - creating it..."
  aws sqs create-queue \
    --queue-name ca-a2a-document-processing \
    --region $REGION
  log_info "✓ SQS queue created"
else
  log_info "✓ SQS queue found: $QUEUE_URL"
fi

# Step 2: Build Docker image
log_header "Building Docker Image"
log_info "Building orchestrator image with SQS support..."

docker build \
  -f Dockerfile.orchestrator \
  -t ${ECR_REPO}:latest \
  -t ${ECR_REPO}:sqs-enabled \
  .

log_info "✓ Docker image built"

# Step 3: Push to ECR
log_header "Pushing to ECR"

# Login to ECR
aws ecr get-login-password --region $REGION | \
  docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com

# Tag and push
docker tag ${ECR_REPO}:latest ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}:latest
docker tag ${ECR_REPO}:sqs-enabled ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}:sqs-enabled

docker push ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}:latest
docker push ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}:sqs-enabled

log_info "✓ Image pushed to ECR"

# Step 4: Update task definition with SQS environment variables
log_header "Updating Task Definition"

# Get current task definition
TASK_DEF=$(aws ecs describe-task-definition \
  --task-definition ca-a2a-orchestrator \
  --region $REGION)

# Extract and modify
NEW_TASK_DEF=$(echo "$TASK_DEF" | jq -r '.taskDefinition | {
  family: .family,
  networkMode: .networkMode,
  requiresCompatibilities: .requiresCompatibilities,
  cpu: .cpu,
  memory: .memory,
  taskRoleArn: .taskRoleArn,
  executionRoleArn: .executionRoleArn,
  containerDefinitions: [
    .containerDefinitions[0] | {
      name: .name,
      image: "'${ACCOUNT_ID}'.dkr.ecr.'${REGION}'.amazonaws.com/'${ECR_REPO}':latest",
      essential: .essential,
      portMappings: .portMappings,
      logConfiguration: .logConfiguration,
      environment: (.environment + [
        {name: "SQS_ENABLED", value: "true"},
        {name: "SQS_QUEUE_NAME", value: "ca-a2a-document-processing"},
        {name: "AWS_REGION", value: "'${REGION}'"},
        {name: "SQS_POLL_INTERVAL", value: "10"},
        {name: "SQS_MAX_MESSAGES", value: "10"},
        {name: "SQS_WAIT_TIME", value: "20"}
      ]),
      secrets: .secrets,
      healthCheck: .healthCheck
    }
  ]
}')

# Register new task definition
NEW_TASK_DEF_ARN=$(echo "$NEW_TASK_DEF" | \
  aws ecs register-task-definition \
    --cli-input-json file:///dev/stdin \
    --region $REGION \
    --query 'taskDefinition.taskDefinitionArn' \
    --output text)

log_info "✓ New task definition registered: $NEW_TASK_DEF_ARN"

# Step 5: Update IAM role with SQS permissions
log_header "Updating IAM Permissions"

TASK_ROLE_NAME=$(aws ecs describe-task-definition \
  --task-definition ca-a2a-orchestrator \
  --region $REGION \
  --query 'taskDefinition.taskRoleArn' \
  --output text | awk -F'/' '{print $NF}')

# Create SQS policy
SQS_POLICY='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl"
      ],
      "Resource": "arn:aws:sqs:'${REGION}':'${ACCOUNT_ID}':ca-a2a-document-processing"
    }
  ]
}'

# Attach inline policy
aws iam put-role-policy \
  --role-name $TASK_ROLE_NAME \
  --policy-name SQSDocumentProcessingPolicy \
  --policy-document "$SQS_POLICY" \
  --region $REGION || log_warn "Failed to update IAM policy (may already exist)"

log_info "✓ IAM permissions updated"

# Step 6: Update ECS service
log_header "Updating ECS Service"

aws ecs update-service \
  --cluster $CLUSTER_NAME \
  --service $SERVICE_NAME \
  --task-definition $NEW_TASK_DEF_ARN \
  --force-new-deployment \
  --region $REGION > /dev/null

log_info "✓ ECS service updated - deployment in progress"

# Step 7: Wait for deployment
log_header "Waiting for Deployment"

log_info "Waiting for service to stabilize (this may take 2-3 minutes)..."

aws ecs wait services-stable \
  --cluster $CLUSTER_NAME \
  --services $SERVICE_NAME \
  --region $REGION

log_info "✓ Service deployment complete"

# Step 8: Verify SQS polling
log_header "Verifying SQS Polling"

sleep 10  # Give service time to start polling

# Check recent logs
log_info "Checking logs for SQS activity..."
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 2m \
  --region $REGION \
  --filter-pattern "SQS" \
  --format short | tail -n 10

# Check service status
log_info "Checking service health..."
RUNNING_COUNT=$(aws ecs describe-services \
  --cluster $CLUSTER_NAME \
  --services $SERVICE_NAME \
  --region $REGION \
  --query 'services[0].runningCount' \
  --output text)

log_info "✓ Orchestrator running: $RUNNING_COUNT tasks"

# Test upload to trigger processing
log_header "Testing Automatic Processing"

log_info "Uploading test document to S3..."
cat > /tmp/sqs-test-invoice.txt << 'EOF'
INVOICE - SQS Test
Company: Automated Processing Test Inc.
Date: $(date +%Y-%m-%d)
Amount: €999.00
Status: Testing SQS automatic processing
EOF

TIMESTAMP=$(date +%s)
TEST_KEY="uploads/sqs-test-${TIMESTAMP}.txt"

aws s3 cp /tmp/sqs-test-invoice.txt \
  "s3://ca-a2a-documents/${TEST_KEY}" \
  --region $REGION

log_info "✓ Test document uploaded: ${TEST_KEY}"

log_info "Waiting 15 seconds for automatic processing..."
sleep 15

# Check if processing started
log_info "Checking for processing activity..."
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 30s \
  --region $REGION \
  --filter-pattern "Auto-processing" \
  --format short | tail -n 5

# Cleanup test file
rm -f /tmp/sqs-test-invoice.txt

# Summary
log_header "DEPLOYMENT COMPLETE"
echo ""
echo -e "${GREEN}✓ SQS-enabled orchestrator deployed successfully!${NC}"
echo ""
echo "Configuration:"
echo "  - SQS Queue: ca-a2a-document-processing"
echo "  - Region: $REGION"
echo "  - Poll Interval: 10 seconds"
echo "  - Max Messages: 10"
echo "  - Long Polling: 20 seconds"
echo ""
echo "Status:"
echo "  - Running Tasks: $RUNNING_COUNT"
echo "  - Task Definition: $NEW_TASK_DEF_ARN"
echo ""
echo "Next Steps:"
echo "  1. Upload documents to s3://ca-a2a-documents/uploads/"
echo "  2. Documents will be processed automatically"
echo "  3. Monitor: aws logs tail /ecs/ca-a2a-orchestrator --follow --region $REGION"
echo ""
echo "Test Command:"
echo "  aws s3 cp your-invoice.pdf s3://ca-a2a-documents/uploads/"
echo ""
