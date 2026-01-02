#!/bin/bash
REGION="eu-west-3"
CLUSTER="ca-a2a-cluster"
SERVICE="archivist"
ACCOUNT_ID="555043101106"

echo "============================================"
echo "FIXING ARCHIVIST - NATIVE MCP"
echo "============================================"
echo ""

# Step 1: Check current task definition
echo "1. Checking current Archivist task definition..."
TASK_DEF=$(aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services ${SERVICE} \
    --region ${REGION} \
    --query 'services[0].taskDefinition' \
    --output text)

echo "   Current: $TASK_DEF"

aws ecs describe-task-definition \
    --task-definition ${TASK_DEF} \
    --region ${REGION} \
    --query 'taskDefinition' > archivist_taskdef.json

# Check if MCP_SERVER_URL exists
echo ""
echo "2. Checking for MCP_SERVER_URL..."
MCP_URL=$(jq -r '.containerDefinitions[0].environment[] | select(.name=="MCP_SERVER_URL") | .value' archivist_taskdef.json)

if [ ! -z "$MCP_URL" ] && [ "$MCP_URL" != "null" ]; then
    echo "   Found: MCP_SERVER_URL=$MCP_URL"
    echo "   Removing it to enable native MCP..."
    
    # Remove MCP_SERVER_URL from environment
    jq '.containerDefinitions[0].environment = [.containerDefinitions[0].environment[] | select(.name!="MCP_SERVER_URL")] |
        del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy)' \
        archivist_taskdef.json > archivist_taskdef_new.json
    
    # Register new task definition
    echo ""
    echo "3. Registering new task definition..."
    NEW_TD=$(aws ecs register-task-definition \
        --cli-input-json file://archivist_taskdef_new.json \
        --region ${REGION} \
        --query 'taskDefinition.taskDefinitionArn' \
        --output text)
    
    echo "   New task definition: $NEW_TD"
    
    # Update service
    echo ""
    echo "4. Updating ECS service..."
    aws ecs update-service \
        --cluster ${CLUSTER} \
        --service ${SERVICE} \
        --task-definition ${NEW_TD} \
        --force-new-deployment \
        --region ${REGION} > /dev/null
    
    echo "   ✓ Service updated"
    
    # Stop old tasks
    echo ""
    echo "5. Stopping old tasks..."
    for TASK_ARN in $(aws ecs list-tasks --cluster ${CLUSTER} --service-name ${SERVICE} --region ${REGION} --query 'taskArns[]' --output text); do
        aws ecs stop-task --cluster ${CLUSTER} --task ${TASK_ARN} --region ${REGION} --reason "Enable native MCP" > /dev/null
        echo "   Stopped task"
    done
    
    echo ""
    echo "6. Waiting 60 seconds for new tasks..."
    sleep 60
    
else
    echo "   MCP_SERVER_URL not found - checking if image needs update..."
    
    # Check current image
    CURRENT_IMAGE=$(jq -r '.containerDefinitions[0].image' archivist_taskdef.json)
    echo "   Current image: $CURRENT_IMAGE"
    
    # Check if we need to update to extractor's working image as reference
    echo ""
    echo "   Archivist likely needs code update. Checking if archivist_agent.py exists..."
    
    if [ -f "archivist_agent.py" ]; then
        echo "   ✓ Found archivist_agent.py"
        echo ""
        echo "Building new Archivist image with native MCP..."
        
        # Build
        TAG="native-mcp-$(date +%Y%m%d%H%M%S)"
        docker build --no-cache -t ca-a2a-archivist:${TAG} -f Dockerfile.archivist .
        
        # Login
        aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com
        
        # Tag
        docker tag ca-a2a-archivist:${TAG} ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/archivist:${TAG}
        docker tag ca-a2a-archivist:${TAG} ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/archivist:latest
        
        # Push
        docker push ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/archivist:${TAG}
        docker push ${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/archivist:latest
        
        # Update task def with new image
        jq --arg IMG "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ca-a2a/archivist:${TAG}" \
            '.containerDefinitions[0].image = $IMG |
            del(.taskDefinitionArn, .revision, .status, .requiresAttributes, .compatibilities, .registeredAt, .registeredBy)' \
            archivist_taskdef.json > archivist_taskdef_new.json
        
        NEW_TD=$(aws ecs register-task-definition \
            --cli-input-json file://archivist_taskdef_new.json \
            --region ${REGION} \
            --query 'taskDefinition.taskDefinitionArn' \
            --output text)
        
        echo "   New task definition: $NEW_TD"
        
        # Update service
        aws ecs update-service \
            --cluster ${CLUSTER} \
            --service ${SERVICE} \
            --task-definition ${NEW_TD} \
            --force-new-deployment \
            --region ${REGION} > /dev/null
        
        # Stop old tasks
        for TASK_ARN in $(aws ecs list-tasks --cluster ${CLUSTER} --service-name ${SERVICE} --region ${REGION} --query 'taskArns[]' --output text); do
            aws ecs stop-task --cluster ${CLUSTER} --task ${TASK_ARN} --region ${REGION} --reason "Native MCP update" > /dev/null
            echo "   Stopped task"
        done
        
        echo ""
        echo "Waiting 60 seconds..."
        sleep 60
    else
        echo "   ✗ archivist_agent.py not found in current directory"
        exit 1
    fi
fi

echo ""
echo "============================================"
echo "DEPLOYMENT STATUS"
echo "============================================"
echo ""

# Check service status
aws ecs describe-services \
    --cluster ${CLUSTER} \
    --services ${SERVICE} \
    --region ${REGION} \
    --query 'services[0].{Running:runningCount,Desired:desiredCount,Pending:pendingCount}' \
    --output table

echo ""
echo "Recent logs (should show native MCP, NO connection errors):"
aws logs tail /ecs/ca-a2a-archivist --since 2m --region ${REGION} | grep -E "native MCP|PostgreSQL resource|MCP context|Archivist initialized|ERROR|Cannot connect" | tail -20

rm -f archivist_taskdef.json archivist_taskdef_new.json

echo ""
echo "============================================"
echo "✓ ARCHIVIST FIX COMPLETE"
echo "============================================"
echo ""
echo "Test again with:"
echo "  ./test-full-pipeline.sh"

