#!/bin/bash
# Update extractor task definition to use the :fixed image
# Run in CloudShell

set -e

REGION="eu-west-3"
CLUSTER="ca-a2a-cluster"
SERVICE="extractor"
ACCOUNT="555043101106"
NEW_IMAGE="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a-extractor:fixed"

echo "============================================"
echo "UPDATE EXTRACTOR TO USE :fixed IMAGE"
echo "============================================"
echo ""

echo "1. Downloading current task definition..."
CURRENT_TASK_DEF=$(aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services ${SERVICE} \
    --region ${REGION} \
    --query 'services[0].taskDefinition' \
    --output text)

echo "   Current: ${CURRENT_TASK_DEF}"

aws ecs describe-task-definition \
    --task-definition ${CURRENT_TASK_DEF} \
    --region ${REGION} \
    --query 'taskDefinition' > taskdef.json

CURRENT_IMAGE=$(cat taskdef.json | jq -r '.containerDefinitions[0].image')
echo "   Current Image: ${CURRENT_IMAGE}"
echo "   New Image: ${NEW_IMAGE}"

echo ""
echo "2. Updating task definition with :fixed image..."

# Update the image and remove fields that can't be in register call
cat taskdef.json | jq --arg img "${NEW_IMAGE}" '
    .containerDefinitions[0].image = $img |
    del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy)
' > taskdef_updated.json

# Register new task definition
echo "   Registering new task definition..."
NEW_TASK_DEF=$(aws ecs register-task-definition \
    --cli-input-json file://taskdef_updated.json \
    --region ${REGION} \
    --query 'taskDefinition.taskDefinitionArn' \
    --output text)

echo "   ✓ New Task Definition: ${NEW_TASK_DEF}"

echo ""
echo "3. Updating ECS service to use new task definition..."
aws ecs update-service \
    --cluster ${CLUSTER} \
    --service ${SERVICE} \
    --task-definition ${NEW_TASK_DEF} \
    --force-new-deployment \
    --region ${REGION} > /dev/null

echo "   ✓ Service updated"

# Clean up
rm -f taskdef.json taskdef_updated.json

echo ""
echo "4. Stopping all old tasks to force immediate restart..."
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
        aws ecs stop-task \
            --cluster ${CLUSTER} \
            --task ${TASK_ARN} \
            --region ${REGION} \
            --reason "Force update to :fixed image" > /dev/null
        echo "   Stopped task"
    done
fi

echo ""
echo "5. Waiting 45 seconds for new tasks to start with :fixed image..."
sleep 45

echo ""
echo "6. Verifying new deployment..."
aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services ${SERVICE} \
    --region ${REGION} \
    --query 'services[0].deployments[*].{Status:status,Running:runningCount,Desired:desiredCount,TaskDef:taskDefinition}' \
    --output table

echo ""
echo "7. Checking new task image..."
NEW_TASK_ARNS=$(aws ecs list-tasks \
    --cluster ${CLUSTER} \
    --service-name ${SERVICE} \
    --region ${REGION} \
    --query 'taskArns[0]' \
    --output text)

if [ -z "$NEW_TASK_ARNS" ] || [ "$NEW_TASK_ARNS" == "None" ]; then
    echo "   ⚠ Tasks still starting..."
else
    TASK_DEF=$(aws ecs describe-tasks \
        --cluster ${CLUSTER} \
        --tasks ${NEW_TASK_ARNS} \
        --region ${REGION} \
        --query 'tasks[0].taskDefinitionArn' \
        --output text)
    
    IMAGE=$(aws ecs describe-task-definition \
        --task-definition ${TASK_DEF} \
        --region ${REGION} \
        --query 'taskDefinition.containerDefinitions[0].image' \
        --output text)
    
    if [[ "$IMAGE" == *":fixed"* ]]; then
        echo "   ✅ SUCCESS! Task is using :fixed image"
        echo "   Image: ${IMAGE}"
    else
        echo "   ❌ Task NOT using :fixed image"
        echo "   Image: ${IMAGE}"
    fi
fi

echo ""
echo "============================================"
echo "DEPLOYMENT COMPLETE!"
echo "============================================"
echo ""
echo "Wait 30 seconds, then test:"
echo ""
echo "TIMESTAMP=\$(date +%s)"
echo "aws s3 cp facture_acme_dec2025.pdf \\"
echo "  s3://ca-a2a-documents-555043101106/invoices/2026/01/test_\${TIMESTAMP}.pdf \\"
echo "  --region eu-west-3"
echo ""
echo "sleep 30"
echo ""
echo "aws logs tail /ecs/ca-a2a-extractor --since 2m --region eu-west-3 | grep -E 'Extracting|Extracted|ERROR' | tail -10"
echo ""

