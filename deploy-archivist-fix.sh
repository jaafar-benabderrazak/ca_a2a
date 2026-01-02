#!/bin/bash
# Deploy Archivist Fix - Add MCP_SERVER_URL and Force Deployment

set -e

REGION="eu-west-3"
CLUSTER="ca-a2a-cluster"

echo "============================================================="
echo "  DEPLOYING ARCHIVIST FIX - MCP HTTP CLIENT"
echo "============================================================="
echo ""

echo "Step 1: Registering new task definition with MCP_SERVER_URL..."

# Register new task definition
NEW_REVISION=$(aws ecs register-task-definition \
  --family ca-a2a-archivist \
  --network-mode awsvpc \
  --requires-compatibilities FARGATE \
  --cpu 512 \
  --memory 1024 \
  --execution-role-arn arn:aws:iam::555043101106:role/ca-a2a-ecs-execution-role \
  --task-role-arn arn:aws:iam::555043101106:role/ca-a2a-ecs-task-role \
  --region ${REGION} \
  --container-definitions '[
    {
      "name": "archivist",
      "image": "555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/archivist:latest",
      "portMappings": [{"containerPort": 8004, "protocol": "tcp", "name": "http"}],
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
    }
  ]' \
  --query 'taskDefinition.revision' \
  --output text)

echo "✓ New task definition registered: revision $NEW_REVISION"
echo ""

echo "Step 2: Updating service to use new task definition and force deployment..."
aws ecs update-service \
  --cluster ${CLUSTER} \
  --service archivist \
  --task-definition ca-a2a-archivist:${NEW_REVISION} \
  --force-new-deployment \
  --region ${REGION} \
  --query 'service.[serviceName,taskDefinition,desiredCount,runningCount]' \
  --output table

echo ""
echo "Step 3: Waiting 45 seconds for new tasks to start..."
sleep 45

echo ""
echo "Step 4: Checking service status..."
aws ecs describe-services \
  --cluster ${CLUSTER} \
  --services archivist \
  --region ${REGION} \
  --query 'services[0].{Service:serviceName,Desired:desiredCount,Running:runningCount,Pending:pendingCount}' \
  --output table

echo ""
echo "Step 5: Listing running tasks..."
aws ecs list-tasks \
  --cluster ${CLUSTER} \
  --service-name archivist \
  --region ${REGION} \
  --desired-status RUNNING \
  --query 'taskArns[*]' \
  --output text

echo ""
echo "Step 6: Checking logs for successful initialization (waiting 60s)..."
sleep 60

echo ""
echo "Recent archivist logs:"
aws logs tail /ecs/ca-a2a-archivist --since 3m --region ${REGION} \
  | grep -E "MCP HTTP|initialized|Schema initialization|continuing" | tail -15

echo ""
echo "============================================================="
echo "  ARCHIVIST DEPLOYMENT COMPLETE"
echo "============================================================="
echo ""
echo "Verify with:"
echo "  aws ecs describe-services --cluster ca-a2a-cluster --services archivist --region eu-west-3 --query 'services[0].[desiredCount,runningCount]'"
echo "  aws logs tail /ecs/ca-a2a-archivist --since 5m --region eu-west-3 | grep 'MCP HTTP'"
echo ""

