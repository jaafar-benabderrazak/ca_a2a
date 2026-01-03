#!/bin/bash
REGION="eu-west-3"

echo "Waiting 30 more seconds..."
sleep 30

echo ""
echo "=== Service Status ==="
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services archivist \
    --region ${REGION} \
    --query 'services[0].{Running:runningCount,Desired:desiredCount,Pending:pendingCount}' \
    --output table

echo ""
echo "=== Recent Full Logs (last 2 min) ==="
aws logs tail /ecs/ca-a2a-archivist --since 2m --region ${REGION} | tail -50

echo ""
echo "=== Checking Task Definitions ==="
echo "Archivist task definition image:"
aws ecs describe-task-definition \
    --task-definition ca-a2a-archivist:12 \
    --region ${REGION} \
    --query 'taskDefinition.containerDefinitions[0].image' \
    --output text

echo ""
echo "Checking MCP_SERVER_URL in task definition:"
aws ecs describe-task-definition \
    --task-definition ca-a2a-archivist:12 \
    --region ${REGION} \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`MCP_SERVER_URL`]' \
    --output json

