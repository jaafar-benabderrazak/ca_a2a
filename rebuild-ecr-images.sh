#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# CA-A2A ECR Image Rebuild & Push Script
# Rebuilds Docker images from current source code and pushes to ECR
# Then forces ECS service redeployment to pick up new images
# ══════════════════════════════════════════════════════════════════════════════

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

echo -e "${BOLD}${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║       CA-A2A ECR Image Rebuild & Push                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Configuration ──────────────────────────────────────────────────────────
PROJECT="${PROJECT_NAME:-ca-a2a}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-west-3}}"
SKIP_PUSH=false
SKIP_DEPLOY=false
SERVICES_FILTER=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --skip-push) SKIP_PUSH=true; shift ;;
        --skip-deploy) SKIP_DEPLOY=true; shift ;;
        --service) SERVICES_FILTER="$2"; shift 2 ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --region REGION     AWS region (default: eu-west-3)"
            echo "  --skip-push         Build only, don't push to ECR"
            echo "  --skip-deploy       Push to ECR but don't force ECS redeployment"
            echo "  --service NAME      Rebuild only one service (orchestrator|extractor|validator|archivist|mcp-server)"
            echo "  --help              Show this help"
            exit 0
            ;;
        *) echo -e "${RED}Unknown option: $1${NC}"; exit 1 ;;
    esac
done

# Get AWS account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
if [ -z "$ACCOUNT_ID" ]; then
    echo -e "${RED}✗ Failed to get AWS account ID. Check AWS credentials.${NC}"
    exit 1
fi

ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

echo -e "${CYAN}Configuration:${NC}"
echo "  Project:   ${PROJECT}"
echo "  Region:    ${REGION}"
echo "  Account:   ${ACCOUNT_ID}"
echo "  Registry:  ${ECR_REGISTRY}"
echo ""

# ── Determine project root ────────────────────────────────────────────────
# Script may be run from project root or from any subdirectory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

# Verify we have the expected files
if [ ! -f "$PROJECT_ROOT/base_agent.py" ] || [ ! -f "$PROJECT_ROOT/a2a_security.py" ]; then
    echo -e "${RED}✗ Cannot find base_agent.py and a2a_security.py in $PROJECT_ROOT${NC}"
    echo "  Run this script from the project root directory."
    exit 1
fi

echo -e "${GREEN}✓${NC} Project root: ${PROJECT_ROOT}"
echo -e "${GREEN}✓${NC} base_agent.py found (with security middleware)"
echo -e "${GREEN}✓${NC} a2a_security.py found (A2ASecurityManager)"

# ── Service definitions ────────────────────────────────────────────────────
# Map: service-name -> Dockerfile -> entry-point
# All use root-level Dockerfiles that COPY *.py from project root
declare -A DOCKERFILES=(
    ["orchestrator"]="Dockerfile.orchestrator"
    ["extractor"]="Dockerfile.extractor"
    ["validator"]="Dockerfile.validator"
    ["archivist"]="Dockerfile.archivist"
    ["mcp-server"]="Dockerfile.mcp"
)

# Determine which services to build
if [ -n "$SERVICES_FILTER" ]; then
    SERVICES="$SERVICES_FILTER"
else
    SERVICES="orchestrator extractor validator archivist mcp-server"
fi

# ── Verify Dockerfiles exist ──────────────────────────────────────────────
echo ""
for SERVICE in $SERVICES; do
    DOCKERFILE="${DOCKERFILES[$SERVICE]}"
    if [ -z "$DOCKERFILE" ]; then
        echo -e "${RED}✗ Unknown service: ${SERVICE}${NC}"
        exit 1
    fi
    if [ ! -f "$PROJECT_ROOT/$DOCKERFILE" ]; then
        echo -e "${RED}✗ Dockerfile not found: ${DOCKERFILE}${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓${NC} ${SERVICE} -> ${DOCKERFILE}"
done

# ── ECR Login ──────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}▸${NC} Logging into ECR..."
aws ecr get-login-password --region $REGION | \
    docker login --username AWS --password-stdin ${ECR_REGISTRY} 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}✗ ECR login failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} ECR login successful"

# ── Ensure ECR repositories exist ─────────────────────────────────────────
echo ""
echo -e "${CYAN}▸${NC} Ensuring ECR repositories exist..."
for SERVICE in $SERVICES; do
    REPO_NAME="${PROJECT}/${SERVICE}"
    aws ecr describe-repositories --repository-names "$REPO_NAME" --region $REGION > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}  Creating repository: ${REPO_NAME}${NC}"
        aws ecr create-repository \
            --repository-name "$REPO_NAME" \
            --region $REGION \
            --image-scanning-configuration scanOnPush=true \
            --encryption-configuration encryptionType=AES256 > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo -e "${RED}✗ Failed to create repository ${REPO_NAME}${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}✓${NC} ${REPO_NAME}"
done

# ── Build, Tag, Push ──────────────────────────────────────────────────────
echo ""
BUILT=0
FAILED=0

for SERVICE in $SERVICES; do
    DOCKERFILE="${DOCKERFILES[$SERVICE]}"
    IMAGE_TAG="${ECR_REGISTRY}/${PROJECT}/${SERVICE}:latest"

    echo -e "\n${BOLD}${CYAN}── ${SERVICE} ──${NC}"

    # Build
    echo -e "${CYAN}▸${NC} Building from ${DOCKERFILE}..."
    docker build \
        -f "$PROJECT_ROOT/$DOCKERFILE" \
        -t "${PROJECT}/${SERVICE}:latest" \
        "$PROJECT_ROOT" 2>&1 | tail -5

    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        echo -e "${RED}✗ Build failed for ${SERVICE}${NC}"
        FAILED=$((FAILED + 1))
        continue
    fi
    echo -e "${GREEN}✓${NC} Built ${SERVICE}"

    if [ "$SKIP_PUSH" = true ]; then
        echo -e "${YELLOW}  Skipping push (--skip-push)${NC}"
        BUILT=$((BUILT + 1))
        continue
    fi

    # Tag
    docker tag "${PROJECT}/${SERVICE}:latest" "${IMAGE_TAG}"

    # Push
    echo -e "${CYAN}▸${NC} Pushing to ECR..."
    docker push "${IMAGE_TAG}" 2>&1 | tail -3

    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        echo -e "${RED}✗ Push failed for ${SERVICE}${NC}"
        FAILED=$((FAILED + 1))
        continue
    fi
    echo -e "${GREEN}✓${NC} Pushed ${IMAGE_TAG}"
    BUILT=$((BUILT + 1))
done

echo ""
echo -e "${CYAN}Build results:${NC} ${GREEN}${BUILT} succeeded${NC}, ${RED}${FAILED} failed${NC}"

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}✗ Some builds failed. Fix errors and retry.${NC}"
    exit 1
fi

if [ "$SKIP_PUSH" = true ]; then
    echo -e "${YELLOW}Images built locally only (--skip-push). Done.${NC}"
    exit 0
fi

# ── Force ECS Redeployment ────────────────────────────────────────────────
if [ "$SKIP_DEPLOY" = true ]; then
    echo -e "${YELLOW}Skipping ECS redeployment (--skip-deploy). Done.${NC}"
    exit 0
fi

echo ""
echo -e "${CYAN}▸${NC} Forcing ECS service redeployment..."

CLUSTER_NAME="${PROJECT}-cluster"

# Verify cluster exists
aws ecs describe-clusters --clusters "$CLUSTER_NAME" --region $REGION \
    --query 'clusters[0].status' --output text 2>/dev/null | grep -q ACTIVE
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}⚠ Cluster ${CLUSTER_NAME} not found or not active.${NC}"
    echo "  Push completed. Manually update ECS services when ready."
    exit 0
fi

DEPLOY_OK=0
DEPLOY_FAIL=0

for SERVICE in $SERVICES; do
    # Check if ECS service exists
    SVC_STATUS=$(aws ecs describe-services \
        --cluster "$CLUSTER_NAME" \
        --services "$SERVICE" \
        --region $REGION \
        --query 'services[?status==`ACTIVE`].serviceName' \
        --output text 2>/dev/null)

    if [ -z "$SVC_STATUS" ]; then
        echo -e "${YELLOW}⚠${NC} ECS service '${SERVICE}' not found, skipping redeploy"
        continue
    fi

    aws ecs update-service \
        --cluster "$CLUSTER_NAME" \
        --service "$SERVICE" \
        --force-new-deployment \
        --region $REGION > /dev/null 2>&1

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} ${SERVICE} — new deployment triggered"
        DEPLOY_OK=$((DEPLOY_OK + 1))
    else
        echo -e "${RED}✗${NC} ${SERVICE} — failed to trigger deployment"
        DEPLOY_FAIL=$((DEPLOY_FAIL + 1))
    fi
done

echo ""
echo -e "${CYAN}Deployment results:${NC} ${GREEN}${DEPLOY_OK} triggered${NC}, ${RED}${DEPLOY_FAIL} failed${NC}"

# ── Wait for stabilization (optional) ─────────────────────────────────────
if [ $DEPLOY_OK -gt 0 ]; then
    echo ""
    echo -e "${CYAN}▸${NC} Waiting for services to stabilize (up to 10 min)..."
    echo "  This ensures new containers are running with updated code."

    for SERVICE in $SERVICES; do
        SVC_STATUS=$(aws ecs describe-services \
            --cluster "$CLUSTER_NAME" \
            --services "$SERVICE" \
            --region $REGION \
            --query 'services[?status==`ACTIVE`].serviceName' \
            --output text 2>/dev/null)

        if [ -z "$SVC_STATUS" ]; then
            continue
        fi

        echo -n "  Waiting for ${SERVICE}..."
        aws ecs wait services-stable \
            --cluster "$CLUSTER_NAME" \
            --services "$SERVICE" \
            --region $REGION 2>/dev/null

        if [ $? -eq 0 ]; then
            echo -e " ${GREEN}stable${NC}"
        else
            echo -e " ${YELLOW}timeout (may still be deploying)${NC}"
        fi
    done
fi

# ── Summary ────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                    ECR Images Rebuilt & Deployed                     ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo "Verify running containers have new code:"
echo "  aws ecs describe-services --cluster ${CLUSTER_NAME} --services orchestrator extractor validator archivist mcp-server --region ${REGION} --query 'services[*].{Name:serviceName,Running:runningCount,Desired:desiredCount,TaskDef:taskDefinition}' --output table"
echo ""
echo "Check container logs:"
echo "  aws logs tail /ecs/${PROJECT}/orchestrator --since 5m --region ${REGION}"
echo ""
echo "Quick smoke test (replace ALB_DNS):"
echo "  curl -s https://ALB_DNS/health | python3 -m json.tool"
echo "  curl -s https://ALB_DNS/.well-known/agent.json | python3 -m json.tool"
echo "  curl -sI https://ALB_DNS/health | grep -i 'x-content-type\|x-frame\|strict-transport'"
