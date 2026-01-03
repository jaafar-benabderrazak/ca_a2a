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
echo "=== Recent Logs (last 2 minutes, all) ==="
aws logs tail /ecs/ca-a2a-archivist --since 2m --region ${REGION} | tail -40

echo ""
echo "=== Checking for stopped tasks ==="
STOPPED_TASK=$(aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --service-name archivist \
    --region ${REGION} \
    --desired-status STOPPED \
    --query 'taskArns[0]' \
    --output text)

if [ "$STOPPED_TASK" != "None" ] && [ ! -z "$STOPPED_TASK" ]; then
    echo "Stopped task reason:"
    aws ecs describe-tasks \
        --cluster ca-a2a-cluster \
        --tasks ${STOPPED_TASK} \
        --region ${REGION} \
        --query 'tasks[0].{StoppedReason:stoppedReason,Container:containers[0].{ExitCode:exitCode,Reason:reason}}' \
        --output json
fi

echo ""
echo "=== Running tasks ==="
aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --service-name archivist \
    --region ${REGION} \
    --desired-status RUNNING \
    --query 'taskArns' \
    --output json

