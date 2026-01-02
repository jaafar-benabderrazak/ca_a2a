#!/bin/bash
# Force extractor to use the new fixed image
# Run in CloudShell

set -e

REGION="eu-west-3"
CLUSTER="ca-a2a-cluster"
SERVICE="extractor"

echo "============================================"
echo "FORCE EXTRACTOR UPDATE"
echo "============================================"
echo ""

# Check current deployment
echo "1. Current deployment status:"
aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services ${SERVICE} \
    --region ${REGION} \
    --query 'services[0].deployments[*].{Status:status,Running:runningCount,Desired:desiredCount,TaskDef:taskDefinition}' \
    --output table

echo ""

# Check what image the current tasks are using
echo "2. Current task definition image:"
CURRENT_TASK_DEF=$(aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services ${SERVICE} \
    --region ${REGION} \
    --query 'services[0].taskDefinition' \
    --output text)

echo "   Task Definition: ${CURRENT_TASK_DEF}"

CURRENT_IMAGE=$(aws ecs describe-task-definition \
    --task-definition ${CURRENT_TASK_DEF} \
    --region ${REGION} \
    --query 'taskDefinition.containerDefinitions[0].image' \
    --output text)

echo "   Current Image: ${CURRENT_IMAGE}"
echo ""

# Check if :fixed image exists in ECR
echo "3. Checking for :fixed image in ECR:"
FIXED_IMAGE_EXISTS=$(aws ecr describe-images \
    --repository-name ca-a2a-extractor \
    --region ${REGION} \
    --query 'imageDetails[?imageTags!=`null` && contains(imageTags, `fixed`)].imageTags[0]' \
    --output text 2>/dev/null || echo "")

if [ -z "$FIXED_IMAGE_EXISTS" ]; then
    echo "   ❌ :fixed image NOT found in ECR!"
    echo ""
    echo "The fixed image was not pushed successfully."
    echo "Please re-run the deployment from Windows:"
    echo "  .\Deploy-WithCredentials.ps1"
    exit 1
else
    echo "   ✓ :fixed image found in ECR"
fi

echo ""

# Stop all running tasks to force restart with new image
echo "4. Stopping all running extractor tasks..."

TASK_ARNS=$(aws ecs list-tasks \
    --cluster ${CLUSTER} \
    --service-name ${SERVICE} \
    --region ${REGION} \
    --query 'taskArns[]' \
    --output text)

if [ -z "$TASK_ARNS" ]; then
    echo "   No running tasks to stop"
else
    for TASK_ARN in $TASK_ARNS; do
        echo "   Stopping task: ${TASK_ARN}"
        aws ecs stop-task \
            --cluster ${CLUSTER} \
            --task ${TASK_ARN} \
            --region ${REGION} \
            --reason "Forcing update to fixed image" > /dev/null
    done
    echo "   ✓ All tasks stopped"
fi

echo ""
echo "5. Waiting 30 seconds for new tasks to start..."
sleep 30

echo ""
echo "6. New deployment status:"
aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services ${SERVICE} \
    --region ${REGION} \
    --query 'services[0].deployments[*].{Status:status,Running:runningCount,Desired:desiredCount,TaskDef:taskDefinition}' \
    --output table

echo ""
echo "7. Verifying new tasks are using :fixed image..."

# Get new task ARNs
NEW_TASK_ARNS=$(aws ecs list-tasks \
    --cluster ${CLUSTER} \
    --service-name ${SERVICE} \
    --region ${REGION} \
    --query 'taskArns[]' \
    --output text)

if [ -z "$NEW_TASK_ARNS" ]; then
    echo "   ⚠ No tasks running yet, wait a bit longer"
else
    for TASK_ARN in $NEW_TASK_ARNS; do
        TASK_DEF=$(aws ecs describe-tasks \
            --cluster ${CLUSTER} \
            --tasks ${TASK_ARN} \
            --region ${REGION} \
            --query 'tasks[0].taskDefinitionArn' \
            --output text)
        
        IMAGE=$(aws ecs describe-task-definition \
            --task-definition ${TASK_DEF} \
            --region ${REGION} \
            --query 'taskDefinition.containerDefinitions[0].image' \
            --output text)
        
        if [[ "$IMAGE" == *":fixed"* ]]; then
            echo "   ✓ Task using :fixed image - ${TASK_ARN}"
        else
            echo "   ⚠ Task NOT using :fixed image - ${IMAGE}"
        fi
    done
fi

echo ""
echo "============================================"
echo "NEXT STEPS"
echo "============================================"
echo ""
echo "Wait 30 more seconds, then test again:"
echo "  ./test-with-real-pdf.sh"
echo ""
echo "Expected result:"
echo "  ✅ EXTRACTOR: Successfully extracted PDF content"
echo "  ✅ VALIDATOR: Called and processing"
echo "  ✅ ARCHIVIST: Called and processing"
echo ""

