#!/bin/bash
# Update all agent task definitions to use MCP server
# This script adds MCP_SERVER_URL environment variable to all agents

set -e

PROJECT_NAME="ca-a2a"
REGION="eu-west-3"
CLUSTER_NAME="${PROJECT_NAME}-cluster"
MCP_SERVER_URL="http://mcp-server.${PROJECT_NAME}.local:8000"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}=====================================================================${NC}"
echo -e "${GREEN}  UPDATE AGENTS TO USE MCP SERVER${NC}"
echo -e "${CYAN}=====================================================================${NC}"
echo ""
echo "MCP Server URL: $MCP_SERVER_URL"
echo ""

for AGENT in orchestrator extractor validator archivist; do
    echo -e "${YELLOW}Updating $AGENT...${NC}"
    
    # Read current task definition
    TASK_DEF_FILE="task-definitions/${AGENT}-task.json"
    
    if [ ! -f "$TASK_DEF_FILE" ]; then
        echo -e "  ${YELLOW}[WARN] Task definition file not found: $TASK_DEF_FILE${NC}"
        continue
    fi
    
    # Add or update MCP_SERVER_URL in environment
    python3 << EOF
import json

with open('$TASK_DEF_FILE', 'r') as f:
    task_def = json.load(f)

# Get container definition
container = task_def['containerDefinitions'][0]
env_vars = container.get('environment', [])

# Remove existing MCP_SERVER_URL if present
env_vars = [e for e in env_vars if e['name'] != 'MCP_SERVER_URL']

# Add MCP_SERVER_URL
env_vars.append({
    'name': 'MCP_SERVER_URL',
    'value': '$MCP_SERVER_URL'
})

container['environment'] = env_vars

# Write back
with open('$TASK_DEF_FILE', 'w') as f:
    json.dump(task_def, f, indent=2)

print(f"  [OK] Updated {container['name']} task definition")
EOF
    
    # Register new task definition
    TASK_DEF_ARN=$(aws ecs register-task-definition \
        --cli-input-json file://$TASK_DEF_FILE \
        --region $REGION \
        --query 'taskDefinition.taskDefinitionArn' \
        --output text)
    
    echo -e "  ${GREEN}[OK] Registered: $TASK_DEF_ARN${NC}"
    
    # Update service
    aws ecs update-service \
        --cluster $CLUSTER_NAME \
        --service $AGENT \
        --task-definition $TASK_DEF_ARN \
        --force-new-deployment \
        --region $REGION > /dev/null
    
    echo -e "  ${GREEN}[OK] Service updated, deploying new tasks${NC}"
    echo ""
done

echo -e "${GREEN}All agents updated to use MCP server!${NC}"
echo ""
echo -e "${YELLOW}Monitor deployment:${NC}"
echo "  aws ecs describe-services --cluster $CLUSTER_NAME --services orchestrator extractor validator archivist --region $REGION"
echo ""
echo -e "${YELLOW}Verify MCP connectivity:${NC}"
echo "  aws logs filter-log-events --log-group-name /ecs/${PROJECT_NAME}-orchestrator --filter-pattern 'MCP' --region $REGION"
echo ""


