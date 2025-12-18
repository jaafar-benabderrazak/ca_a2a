#!/bin/bash
set -e

export AWS_REGION="eu-west-3"
export CLUSTER="ca-a2a-cluster"

echo "=========================================="
echo "Checking ECS Task Status"
echo "=========================================="
echo ""

# Wait a bit more for tasks to fully start
echo "Waiting 60 seconds for tasks to fully initialize..."
sleep 60

echo ""
echo "Step 1: Service status (running vs desired count)..."
aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services extractor validator archivist \
    --region ${AWS_REGION} \
    --query 'services[*].[serviceName,runningCount,desiredCount]' \
    --output table

echo ""
echo "Step 2: Checking individual task statuses..."
for service in extractor validator archivist; do
    echo ""
    echo "=== ${service} tasks ==="
    TASK_ARNS=$(aws ecs list-tasks \
        --cluster ${CLUSTER} \
        --service-name ${service} \
        --region ${AWS_REGION} \
        --query 'taskArns' \
        --output text)

    if [ -n "$TASK_ARNS" ]; then
        for task in $TASK_ARNS; do
            echo ""
            echo "Task: ${task##*/}"
            aws ecs describe-tasks \
                --cluster ${CLUSTER} \
                --tasks ${task} \
                --region ${AWS_REGION} \
                --query 'tasks[0].[lastStatus,healthStatus,stopCode,stoppedReason]' \
                --output table
        done
    else
        echo "No tasks found"
    fi
done

echo ""
echo "Step 3: Latest service events..."
for service in extractor validator archivist; do
    echo ""
    echo "=== ${service} latest event ==="
    aws ecs describe-services \
        --cluster ${CLUSTER} \
        --services ${service} \
        --region ${AWS_REGION} \
        --query 'services[0].events[0].message' \
        --output text
done

echo ""
echo "Step 4: Testing ALB health endpoint..."
ALB_DNS="ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
echo "Checking: http://${ALB_DNS}/health"
curl -s -m 10 "http://${ALB_DNS}/health" && echo "" || echo "Failed to reach ALB"

echo ""
echo "=========================================="
echo "Summary:"
echo "- If tasks show 'RUNNING' status: ✓ Success!"
echo "- If tasks show 'PENDING': Still starting up, wait more"
echo "- If tasks show 'STOPPED': Check stoppedReason above"
echo "=========================================="
