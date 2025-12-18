#!/bin/bash
# Diagnose Orchestrator Issues in CloudShell
# Run this to find out why the orchestrator isn't responding

export AWS_REGION=eu-west-3

echo "========================================="
echo "  ORCHESTRATOR DIAGNOSTICS"
echo "========================================="
echo ""

# Step 1: Get recent logs
echo "=== Step 1: Checking Recent Logs (last 2 minutes) ==="
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 2m \
  --region $AWS_REGION \
  --format short | tail -50

echo ""
echo ""
echo "=== Step 2: Looking for Errors/Exceptions ==="
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "ERROR" \
  --start-time $(($(date +%s) - 300))000 \
  --region $AWS_REGION \
  --query 'events[*].message' \
  --output text | tail -20

echo ""
echo ""
echo "=== Step 3: Get Running Task Info ==="
TASK_ARN=$(aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service-name orchestrator \
  --region $AWS_REGION \
  --query 'taskArns[0]' \
  --output text)

echo "Task ARN: $TASK_ARN"

aws ecs describe-tasks \
  --cluster ca-a2a-cluster \
  --tasks $TASK_ARN \
  --region $AWS_REGION \
  --query 'tasks[0].{LastStatus:lastStatus,HealthStatus:healthStatus,StartedAt:startedAt,Containers:containers[0].{Name:name,LastStatus:lastStatus,HealthStatus:healthStatus,RuntimeId:runtimeId}}' \
  --output json

echo ""
echo ""
echo "=== Step 4: Test Container Directly with ECS Exec ==="
echo "Running diagnostic command inside the container..."

# Try to get into the container and test
TASK_ID=$(echo $TASK_ARN | cut -d'/' -f3)

echo ""
echo "Task ID: $TASK_ID"
echo ""
echo "Testing if orchestrator process is running..."

aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task $TASK_ARN \
  --container orchestrator \
  --interactive \
  --command "ps aux | grep python" \
  --region $AWS_REGION

echo ""
echo ""
echo "=== Step 5: Test Local Connection Inside Container ==="
echo "Checking if port 8001 is listening..."

aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task $TASK_ARN \
  --container orchestrator \
  --interactive \
  --command "netstat -tlnp | grep 8001" \
  --region $AWS_REGION

echo ""
echo ""
echo "=== Step 6: Try Hitting Localhost from Inside Container ==="
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task $TASK_ARN \
  --container orchestrator \
  --interactive \
  --command "curl -s -m 5 http://localhost:8001/health || echo 'FAILED'" \
  --region $AWS_REGION

echo ""
echo ""
echo "========================================="
echo "  ANALYSIS"
echo "========================================="
echo ""
echo "If you see:"
echo "  - Errors about database connection → RDS issue"
echo "  - Python not running → App crashed"
echo "  - Port 8001 not listening → App not started"
echo "  - Localhost curl works but ALB doesn't → Network issue"
echo ""

