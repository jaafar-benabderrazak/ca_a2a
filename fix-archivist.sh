#!/bin/bash
# Fix Archivist - Deploy Updated Version with MCP_SERVER_URL

set -e

REGION="eu-west-3"
CLUSTER="ca-a2a-cluster"

echo "============================================================="
echo "  FIXING ARCHIVIST - ADDING MCP_SERVER_URL"
echo "============================================================="
echo ""

echo "Step 1: Register new task definition with MCP_SERVER_URL..."
TASK_DEF_JSON='{
  "family": "ca-a2a-archivist",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::555043101106:role/ca-a2a-ecs-execution-role",
  "taskRoleArn": "arn:aws:iam::555043101106:role/ca-a2a-ecs-task-role",
  "containerDefinitions": [{
    "name": "archivist",
    "image": "555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/archivist:latest",
    "portMappings": [{"containerPort": 8004, "protocol": "tcp"}],
    "environment": [
      {"name": "ARCHIVIST_HOST", "value": "0.0.0.0"},
      {"name": "ARCHIVIST_PORT", "value": "8004"},
      {"name": "POSTGRES_HOST", "value": "ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com"},
      {"name": "POSTGRES_DB", "value": "documents_db"},
      {"name": "POSTGRES_USER", "value": "postgres"},
      {"name": "POSTGRES_PORT", "value": "5432"},
      {"name": "S3_BUCKET_NAME", "value": "ca-a2a-documents-555043101106"},
      {"name": "AWS_REGION", "value": "eu-west-3"},
      {"name": "MCP_SERVER_URL", "value": "http://mcp-server.ca-a2a.local:8000"}
    ],
    "secrets": [
      {"name": "POSTGRES_PASSWORD", "valueFrom": "arn:aws:secretsmanager:eu-west-3:555043101106:secret:ca-a2a/db-password"}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/ca-a2a-archivist",
        "awslogs-region": "eu-west-3",
        "awslogs-stream-prefix": "ecs"
      }
    },
    "healthCheck": {
      "command": ["CMD-SHELL", "curl -f http://localhost:8004/health || exit 1"],
      "interval": 30,
      "timeout": 5,
      "retries": 3,
      "startPeriod": 60
    }
  }]
}'

NEW_REVISION=$(echo "$TASK_DEF_JSON" | aws ecs register-task-definition \
  --cli-input-json file:///dev/stdin \
  --region ${REGION} \
  --query 'taskDefinition.revision' \
  --output text)

echo "✓ New task definition registered: revision $NEW_REVISION"
echo ""

echo "Step 2: Force service update to use new image..."
aws ecs update-service \
  --cluster ${CLUSTER} \
  --service archivist \
  --force-new-deployment \
  --region ${REGION} \
  --query 'service.[serviceName,desiredCount,runningCount]' \
  --output table

echo ""
echo "Step 3: Waiting 30 seconds for deployment..."
sleep 30

echo ""
echo "Step 4: Checking service status..."
aws ecs describe-services \
  --cluster ${CLUSTER} \
  --services archivist \
  --region ${REGION} \
  --query 'services[0].[serviceName,desiredCount,runningCount,pendingCount]' \
  --output table

echo ""
echo "Step 5: Checking task status..."
aws ecs list-tasks \
  --cluster ${CLUSTER} \
  --service-name archivist \
  --region ${REGION} \
  --desired-status RUNNING \
  --query 'taskArns[*]' \
  --output text

echo ""
echo "Step 6: Checking logs for MCP HTTP client (wait 60s for tasks to initialize)..."
echo "Waiting 60 seconds..."
sleep 60

echo ""
aws logs tail /ecs/ca-a2a-archivist --since 2m --region ${REGION} \
  | grep -E "MCP HTTP|initialized|continuing" | tail -10

echo ""
echo "============================================================="
echo "  ARCHIVIST FIX COMPLETE"
echo "============================================================="
echo ""
echo "Verify with:"
echo "  aws ecs describe-services --cluster ca-a2a-cluster --services archivist --region eu-west-3"
echo "  aws logs tail /ecs/ca-a2a-archivist --since 5m --region eu-west-3"
echo ""

