#!/bin/bash
REGION="eu-west-3"
ACCOUNT_ID="555043101106"
TAG="native-mcp-complete-20260103000346"  # The tag we just pushed

echo "============================================"
echo "FINISHING DEPLOYMENT FROM CLOUDSHELL"
echo "============================================"
echo ""

# Update ECS task definition
echo "1. Updating ECS task definition..."
TASK_DEF=$(aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services extractor \
    --region ${REGION} \
    --query 'services[0].taskDefinition' \
    --output text)

echo "   Current task definition: $TASK_DEF"

aws ecs describe-task-definition \
    --task-definition ${TASK_DEF} \
    --region ${REGION} \
    --query 'taskDefinition' > taskdef.json

jq --arg IMG "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/extractor:${TAG}" \
    '.containerDefinitions[0].image = $IMG |
    del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy)' \
    taskdef.json > taskdef_new.json

NEW_TD=$(aws ecs register-task-definition \
    --cli-input-json file://taskdef_new.json \
    --region ${REGION} \
    --query 'taskDefinition.taskDefinitionArn' \
    --output text)

echo "   New task definition: $NEW_TD"

# Update service
echo ""
echo "2. Updating ECS service..."
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service extractor \
    --task-definition ${NEW_TD} \
    --force-new-deployment \
    --region ${REGION} > /dev/null

echo "   ✓ Service updated"

# Stop old tasks
echo ""
echo "3. Stopping old tasks..."
for TASK_ARN in $(aws ecs list-tasks --cluster ca-a2a-cluster --service-name extractor --region ${REGION} --query 'taskArns[]' --output text); do
    aws ecs stop-task --cluster ca-a2a-cluster --task ${TASK_ARN} --region ${REGION} --reason "Deploy complete fix" > /dev/null
    echo "   Stopped task"
done

echo ""
echo "4. Waiting 60 seconds for new tasks..."
sleep 60

echo ""
echo "============================================"
echo "DEPLOYMENT STATUS"
echo "============================================"
echo ""
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services extractor \
    --region ${REGION} \
    --query 'services[0].deployments[*].{Status:status,Running:runningCount,Desired:desiredCount}' \
    --output table

echo ""
echo "Recent logs (CRITICAL - should show 'Using native MCP implementation'):"
aws logs tail /ecs/ca-a2a-extractor --since 1m --region ${REGION} | grep -E "native MCP|Extractor initialized|started successfully|ERROR|IndentationError" | tail -15

rm -f taskdef.json taskdef_new.json

echo ""
echo "============================================"
echo "✓ COMPLETE!"
echo "============================================"
echo ""
echo "Next: Test with real invoice:"
echo "  TIMESTAMP=\$(date +%s)"
echo "  aws s3 cp facture_acme_dec2025.pdf s3://ca-a2a-documents-555043101106/invoices/2026/01/test_\${TIMESTAMP}.pdf --region eu-west-3"
echo "  sleep 40"
echo "  aws logs tail /ecs/ca-a2a-extractor --since 2m --region eu-west-3 | tail -30"

