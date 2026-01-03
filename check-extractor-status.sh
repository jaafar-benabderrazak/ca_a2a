#!/bin/bash
REGION="eu-west-3"

echo "============================================"
echo "CHECKING EXTRACTOR STATUS"
echo "============================================"
echo ""

echo "Waiting 30 more seconds..."
sleep 30

echo ""
echo "1. Service status:"
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services extractor \
    --region ${REGION} \
    --query 'services[0].{Running:runningCount,Desired:desiredCount,Pending:pendingCount}' \
    --output table

echo ""
echo "2. Full recent logs (last 3 minutes, unfiltered):"
aws logs tail /ecs/ca-a2a-extractor --since 3m --region ${REGION} | tail -50

echo ""
echo "3. Checking for stopped tasks:"
STOPPED_TASK=$(aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --service-name extractor \
    --region ${REGION} \
    --desired-status STOPPED \
    --query 'taskArns[0]' \
    --output text)

if [ "$STOPPED_TASK" != "None" ] && [ ! -z "$STOPPED_TASK" ]; then
    echo ""
    echo "Stopped task details:"
    aws ecs describe-tasks \
        --cluster ca-a2a-cluster \
        --tasks ${STOPPED_TASK} \
        --region ${REGION} \
        --query 'tasks[0].{StoppedReason:stoppedReason,StoppedAt:stoppedAt,Container:containers[0].{Reason:reason,ExitCode:exitCode,LastStatus:lastStatus}}' \
        --output json
fi

echo ""
echo "4. Checking running tasks:"
aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --service-name extractor \
    --region ${REGION} \
    --desired-status RUNNING \
    --query 'taskArns' \
    --output json

