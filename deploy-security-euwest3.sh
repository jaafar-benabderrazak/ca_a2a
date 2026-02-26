#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# CA-A2A Security Deployment — eu-west-3
# Registers security-hardened task definitions and updates running ECS services.
# No Docker build — uses existing images in ECR.
#
# Usage:
#   ./deploy-security-euwest3.sh
#   ./deploy-security-euwest3.sh --dry-run
#   ./deploy-security-euwest3.sh --wait
# ══════════════════════════════════════════════════════════════════════════════

set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

REGION="eu-west-3"
CLUSTER="ca-a2a-cluster"
DRY_RUN=false
WAIT_STABLE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)     DRY_RUN=true; shift ;;
        --wait)        WAIT_STABLE=true; shift ;;
        --region)      REGION="$2"; shift 2 ;;
        *) shift ;;
    esac
done

echo -e "${BOLD}${CYAN}"
echo "══════════════════════════════════════════════════════════════════════"
echo "  CA-A2A Security Deployment — ${REGION}"
echo "══════════════════════════════════════════════════════════════════════"
echo -e "${NC}"

if $DRY_RUN; then
    echo -e "  ${YELLOW}DRY RUN — no changes will be made${NC}"
    echo ""
fi

TASK_DEF_DIR="task-definitions"
SERVICES=("orchestrator" "extractor" "validator" "archivist")
TASK_DEF_FILES=(
    "orchestrator-task-euwest3-security.json"
    "extractor-task-euwest3-security.json"
    "validator-task-euwest3-security.json"
    "archivist-task-euwest3-security.json"
)

# ─── Validate files exist ────────────────────────────────────────────────────

echo -e "${CYAN}1. Validating task definition files${NC}"
for file in "${TASK_DEF_FILES[@]}"; do
    if [ ! -f "${TASK_DEF_DIR}/${file}" ]; then
        echo -e "  ${RED}✗${NC} Missing: ${TASK_DEF_DIR}/${file}"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} ${file}"
done
echo ""

# ─── Verify cluster exists ───────────────────────────────────────────────────

echo -e "${CYAN}2. Verifying ECS cluster${NC}"
CLUSTER_STATUS=$(aws ecs describe-clusters --clusters "$CLUSTER" --region "$REGION" \
    --query 'clusters[0].status' --output text 2>/dev/null || echo "NOT_FOUND")

if [ "$CLUSTER_STATUS" != "ACTIVE" ]; then
    echo -e "  ${RED}✗${NC} Cluster '${CLUSTER}' not found or not active (status: ${CLUSTER_STATUS})"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Cluster: ${CLUSTER} (ACTIVE)"
echo ""

# ─── Show security config diff ───────────────────────────────────────────────

echo -e "${CYAN}3. Security configuration to apply${NC}"
for i in "${!SERVICES[@]}"; do
    service="${SERVICES[$i]}"
    file="${TASK_DEF_FILES[$i]}"

    # Extract current auth setting from running task def
    CURRENT_AUTH=$(aws ecs describe-task-definition \
        --task-definition "ca-a2a-${service}" --region "$REGION" \
        --query "taskDefinition.containerDefinitions[0].environment[?name=='A2A_REQUIRE_AUTH'].value" \
        --output text 2>/dev/null || echo "not set")
    [ -z "$CURRENT_AUTH" ] && CURRENT_AUTH="not set"

    # Extract new auth setting from file
    NEW_AUTH=$(python3 -c "import json; d=json.load(open('${TASK_DEF_DIR}/${file}')); print([e['value'] for e in d['containerDefinitions'][0]['environment'] if e['name']=='A2A_REQUIRE_AUTH'][0])" 2>/dev/null || echo "?")

    if [ "$CURRENT_AUTH" == "$NEW_AUTH" ]; then
        echo -e "  ${service}: A2A_REQUIRE_AUTH ${CURRENT_AUTH} → ${NEW_AUTH} (no change)"
    else
        echo -e "  ${service}: A2A_REQUIRE_AUTH ${RED}${CURRENT_AUTH}${NC} → ${GREEN}${NEW_AUTH}${NC}"
    fi
done
echo ""

if $DRY_RUN; then
    echo -e "${YELLOW}DRY RUN complete. Use without --dry-run to apply.${NC}"
    exit 0
fi

# ─── Register task definitions ────────────────────────────────────────────────

echo -e "${CYAN}4. Registering security-hardened task definitions${NC}"
for i in "${!SERVICES[@]}"; do
    service="${SERVICES[$i]}"
    file="${TASK_DEF_FILES[$i]}"

    RESULT=$(aws ecs register-task-definition \
        --cli-input-json "file://${TASK_DEF_DIR}/${file}" \
        --region "$REGION" \
        --query 'taskDefinition.taskDefinitionArn' \
        --output text 2>&1)

    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} ${service}: registered (${RESULT})"
    else
        echo -e "  ${RED}✗${NC} ${service}: registration failed — ${RESULT}"
        exit 1
    fi
done
echo ""

# ─── Update ECS services ────────────────────────────────────────────────────

echo -e "${CYAN}5. Updating ECS services (force new deployment)${NC}"
for service in "${SERVICES[@]}"; do
    aws ecs update-service \
        --cluster "$CLUSTER" \
        --service "$service" \
        --task-definition "ca-a2a-${service}" \
        --force-new-deployment \
        --region "$REGION" > /dev/null 2>&1

    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} ${service}: deployment triggered"
    else
        echo -e "  ${RED}✗${NC} ${service}: update failed"
    fi
done
echo ""

# ─── Wait for stability (optional) ──────────────────────────────────────────

if $WAIT_STABLE; then
    echo -e "${CYAN}6. Waiting for services to stabilize (up to 10 min)...${NC}"
    for service in "${SERVICES[@]}"; do
        echo -e "  Waiting for ${service}..."
        aws ecs wait services-stable \
            --cluster "$CLUSTER" \
            --services "$service" \
            --region "$REGION" 2>/dev/null

        if [ $? -eq 0 ]; then
            echo -e "  ${GREEN}✓${NC} ${service}: stable"
        else
            echo -e "  ${YELLOW}⚠${NC} ${service}: did not stabilize within timeout"
        fi
    done
    echo ""
fi

# ─── Verify deployment ──────────────────────────────────────────────────────

echo -e "${CYAN}6. Verifying deployment${NC}"
for service in "${SERVICES[@]}"; do
    STATUS=$(aws ecs describe-services --cluster "$CLUSTER" --services "$service" --region "$REGION" \
        --query 'services[0].{Running:runningCount,Desired:desiredCount,Pending:pendingCount}' \
        --output text 2>/dev/null)

    echo -e "  ${service}: ${STATUS}"
done
echo ""

# ─── Verify security env vars on new task def ───────────────────────────────

echo -e "${CYAN}7. Verifying security configuration in registered task definitions${NC}"
for service in "${SERVICES[@]}"; do
    AUTH=$(aws ecs describe-task-definition \
        --task-definition "ca-a2a-${service}" --region "$REGION" \
        --query "taskDefinition.containerDefinitions[0].environment[?name=='A2A_REQUIRE_AUTH'].value" \
        --output text 2>/dev/null)

    RATE=$(aws ecs describe-task-definition \
        --task-definition "ca-a2a-${service}" --region "$REGION" \
        --query "taskDefinition.containerDefinitions[0].environment[?name=='A2A_ENABLE_RATE_LIMIT'].value" \
        --output text 2>/dev/null)

    HEADERS=$(aws ecs describe-task-definition \
        --task-definition "ca-a2a-${service}" --region "$REGION" \
        --query "taskDefinition.containerDefinitions[0].environment[?name=='A2A_SECURITY_HEADERS'].value" \
        --output text 2>/dev/null)

    if [ "$AUTH" == "true" ] && [ "$RATE" == "true" ] && [ "$HEADERS" == "true" ]; then
        echo -e "  ${GREEN}✓${NC} ${service}: auth=${AUTH} rate_limit=${RATE} headers=${HEADERS}"
    else
        echo -e "  ${RED}✗${NC} ${service}: auth=${AUTH:-?} rate_limit=${RATE:-?} headers=${HEADERS:-?}"
    fi
done

echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  Security deployment complete.${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Next steps:"
echo "  1. Wait ~2 min for new tasks to replace old ones"
echo "  2. Run attack tests: ./run_all_attacks_cloudshell.sh --region ${REGION}"
echo "  3. Monitor logs: aws logs tail /ecs/ca-a2a-orchestrator --since 5m --region ${REGION}"
echo ""
