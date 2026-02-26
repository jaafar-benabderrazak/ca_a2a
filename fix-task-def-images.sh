#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Fix ECS Task Definition Image URIs
# Updates image references to match the current AWS account's ECR registry
# ══════════════════════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

PROJECT="${PROJECT_NAME:-ca-a2a}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-west-3}}"
CLUSTER="${PROJECT}-cluster"

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        *) shift ;;
    esac
done

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
if [ -z "$ACCOUNT_ID" ]; then
    echo -e "${RED}Cannot get AWS account ID${NC}"
    exit 1
fi

ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

echo -e "${BOLD}${CYAN}Fix Task Definition Image URIs${NC}"
echo "  Account:  ${ACCOUNT_ID}"
echo "  Registry: ${ECR_REGISTRY}"
echo "  Region:   ${REGION}"
echo ""

SERVICES="orchestrator extractor validator archivist"

for SERVICE in $SERVICES; do
    FAMILY="${PROJECT}-${SERVICE}"
    echo -e "${CYAN}▸${NC} ${FAMILY}"

    # Get current task definition
    CURRENT_ARN=$(aws ecs describe-services \
        --cluster "$CLUSTER" \
        --services "$SERVICE" \
        --region "$REGION" \
        --query 'services[0].taskDefinition' \
        --output text 2>/dev/null)

    if [ -z "$CURRENT_ARN" ] || [ "$CURRENT_ARN" = "None" ]; then
        echo -e "  ${YELLOW}Service not found, skipping${NC}"
        continue
    fi

    # Fetch full task definition JSON
    TASKDEF_JSON=$(aws ecs describe-task-definition \
        --task-definition "$CURRENT_ARN" \
        --region "$REGION" \
        --query 'taskDefinition' 2>/dev/null)

    # Extract current image
    CURRENT_IMAGE=$(echo "$TASKDEF_JSON" | python3 -c "
import sys, json
td = json.load(sys.stdin)
print(td['containerDefinitions'][0]['image'])
" 2>/dev/null)

    CORRECT_IMAGE="${ECR_REGISTRY}/${PROJECT}/${SERVICE}:latest"

    echo -e "  Current: ${CURRENT_IMAGE}"
    echo -e "  Target:  ${CORRECT_IMAGE}"

    if [ "$CURRENT_IMAGE" = "$CORRECT_IMAGE" ]; then
        echo -e "  ${GREEN}Already correct${NC}"
        continue
    fi

    # Build new task definition with updated image, stripping ECS-added fields
    echo "$TASKDEF_JSON" | python3 -c "
import sys, json

td = json.load(sys.stdin)

# Update image
td['containerDefinitions'][0]['image'] = '${CORRECT_IMAGE}'

# Remove fields that cannot be included in register-task-definition
for key in ['taskDefinitionArn', 'revision', 'status', 'requiresAttributes',
            'compatibilities', 'registeredAt', 'registeredBy', 'deregisteredAt',
            'enableFaultInjection']:
    td.pop(key, None)

json.dump(td, sys.stdout)
" > /tmp/taskdef-fix-${SERVICE}.json 2>/dev/null

    if [ $? -ne 0 ]; then
        echo -e "  ${RED}Failed to build new task definition${NC}"
        continue
    fi

    # Register new revision
    NEW_ARN=$(aws ecs register-task-definition \
        --cli-input-json file:///tmp/taskdef-fix-${SERVICE}.json \
        --region "$REGION" \
        --query 'taskDefinition.taskDefinitionArn' \
        --output text 2>/dev/null)

    if [ -z "$NEW_ARN" ] || [ "$NEW_ARN" = "None" ]; then
        echo -e "  ${RED}Failed to register${NC}"
        continue
    fi

    echo -e "  ${GREEN}Registered: ${NEW_ARN}${NC}"

    # Update ECS service to use new revision
    aws ecs update-service \
        --cluster "$CLUSTER" \
        --service "$SERVICE" \
        --task-definition "$NEW_ARN" \
        --force-new-deployment \
        --region "$REGION" > /dev/null 2>&1

    echo -e "  ${GREEN}Service updated + redeployment triggered${NC}"
done

# Wait for stabilization
echo ""
echo -e "${CYAN}▸${NC} Waiting for services to stabilize..."
for SERVICE in $SERVICES; do
    SVC_STATUS=$(aws ecs describe-services \
        --cluster "$CLUSTER" \
        --services "$SERVICE" \
        --region "$REGION" \
        --query 'services[?status==`ACTIVE`].serviceName' \
        --output text 2>/dev/null)
    if [ -z "$SVC_STATUS" ]; then continue; fi

    echo -n "  ${SERVICE}..."
    aws ecs wait services-stable \
        --cluster "$CLUSTER" \
        --services "$SERVICE" \
        --region "$REGION" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e " ${GREEN}stable${NC}"
    else
        echo -e " ${YELLOW}timeout${NC}"
    fi
done

# Verify
echo ""
echo -e "${CYAN}▸${NC} Verifying images..."
for SERVICE in $SERVICES; do
    FAMILY="${PROJECT}-${SERVICE}"
    IMG=$(aws ecs describe-task-definition \
        --task-definition "$FAMILY" \
        --region "$REGION" \
        --query 'taskDefinition.containerDefinitions[0].image' \
        --output text 2>/dev/null)
    if echo "$IMG" | grep -q "$ACCOUNT_ID"; then
        echo -e "  ${GREEN}✓${NC} ${SERVICE}: ${IMG}"
    else
        echo -e "  ${RED}✗${NC} ${SERVICE}: ${IMG}"
    fi
done

echo ""
echo -e "${GREEN}Done. Re-run attack tests now.${NC}"
