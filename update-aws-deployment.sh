#!/bin/bash
set -e

# ==========================================
# Update AWS Deployment with Skill Filtering
# Rebuilds and redeploys Docker images
# ==========================================

# Configuration
export AWS_REGION="${AWS_REGION:-eu-west-3}"
export AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-555043101106}"
export PROJECT_NAME="${PROJECT_NAME:-ca-a2a}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_section() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║     Update AWS Deployment with Skill Filtering           ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Region:      ${AWS_REGION}"
echo "Account:     ${AWS_ACCOUNT_ID}"
echo "Project:     ${PROJECT_NAME}"
echo ""

# ==========================================
# Step 1: Verify New Files
# ==========================================
log_section "Step 1: Verify New Files"

REQUIRED_FILES=(
    "skill_filter.py"
    "skill_filter_integration.py"
    "config/user_permissions.yaml"
    "SKILL_FILTERING_GUIDE.md"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        log_success "Found: $file"
    else
        echo "✗ Missing: $file"
        exit 1
    fi
done

# ==========================================
# Step 2: ECR Login
# ==========================================
log_section "Step 2: Login to ECR"

log_info "Logging into ECR..."
aws ecr get-login-password --region ${AWS_REGION} | \
    docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

if [ $? -eq 0 ]; then
    log_success "ECR login successful"
else
    echo "✗ ECR login failed"
    exit 1
fi

# ==========================================
# Step 3: Rebuild Docker Images
# ==========================================
log_section "Step 3: Rebuild Docker Images"

AGENTS=("orchestrator" "extractor" "validator" "archivist")

for agent in "${AGENTS[@]}"; do
    log_info "Building ${agent}..."

    IMAGE_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}/${agent}:latest"

    docker build -f Dockerfile.${agent} -t ${IMAGE_URI} . --quiet

    if [ $? -eq 0 ]; then
        log_success "Built ${agent}"
    else
        echo "✗ Failed to build ${agent}"
        exit 1
    fi
done

# ==========================================
# Step 4: Push Images to ECR
# ==========================================
log_section "Step 4: Push Images to ECR"

for agent in "${AGENTS[@]}"; do
    log_info "Pushing ${agent}..."

    IMAGE_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${PROJECT_NAME}/${agent}:latest"

    docker push ${IMAGE_URI} --quiet

    if [ $? -eq 0 ]; then
        log_success "Pushed ${agent}"
    else
        echo "✗ Failed to push ${agent}"
        exit 1
    fi
done

# ==========================================
# Step 5: Update ECS Services
# ==========================================
log_section "Step 5: Update ECS Services"

for agent in "${AGENTS[@]}"; do
    log_info "Updating ${agent} service..."

    aws ecs update-service \
        --cluster ${PROJECT_NAME}-cluster \
        --service ${PROJECT_NAME}-${agent} \
        --force-new-deployment \
        --region ${AWS_REGION} \
        --output text > /dev/null 2>&1

    if [ $? -eq 0 ]; then
        log_success "Triggered ${agent} update"
    else
        echo "✗ Failed to update ${agent}"
        exit 1
    fi
done

# ==========================================
# Step 6: Wait for Services to Stabilize
# ==========================================
log_section "Step 6: Wait for Services to Stabilize"

log_info "Waiting for services to update (this takes 3-5 minutes)..."
echo ""

for agent in "${AGENTS[@]}"; do
    echo -n "  Waiting for ${agent}... "

    aws ecs wait services-stable \
        --cluster ${PROJECT_NAME}-cluster \
        --services ${PROJECT_NAME}-${agent} \
        --region ${AWS_REGION} 2>/dev/null

    if [ $? -eq 0 ]; then
        log_success "Running"
    else
        echo "⚠ Timeout (check manually)"
    fi
done

# ==========================================
# Step 7: Verify Deployment
# ==========================================
log_section "Step 7: Verify Deployment"

# Get ALB URL
ALB_DNS=$(aws elbv2 describe-load-balancers \
    --region ${AWS_REGION} \
    --query "LoadBalancers[?contains(LoadBalancerName, '${PROJECT_NAME}')].DNSName" \
    --output text 2>/dev/null)

if [ -z "$ALB_DNS" ]; then
    echo "⚠ Could not find ALB URL"
else
    export ALB_URL="http://${ALB_DNS}"
    echo "ALB URL: ${ALB_URL}"
    echo ""

    log_info "Testing health endpoints..."

    for port in 8001 8002 8003 8004; do
        HEALTH=$(curl -s "${ALB_URL}:${port}/health" 2>/dev/null)
        if [ $? -eq 0 ]; then
            STATUS=$(echo $HEALTH | jq -r '.status // "unknown"' 2>/dev/null)
            AGENT=$(echo $HEALTH | jq -r '.agent // "unknown"' 2>/dev/null)
            if [ "$STATUS" = "healthy" ]; then
                log_success "${AGENT} (port ${port}): ${STATUS}"
            else
                echo "⚠ ${AGENT} (port ${port}): ${STATUS}"
            fi
        else
            echo "⚠ Port ${port}: not responding"
        fi
    done

    echo ""
    log_info "Testing skill filtering..."

    # Test permissions endpoint
    PERMS=$(curl -s "${ALB_URL}:8001/permissions" \
        -H "X-User-Category: power_user" \
        -H "X-User-ID: test_user" 2>/dev/null)

    if [ $? -eq 0 ]; then
        SKILL_COUNT=$(echo $PERMS | jq -r '.skill_count // 0' 2>/dev/null)
        if [ "$SKILL_COUNT" -gt 0 ]; then
            log_success "Skill filtering is working (${SKILL_COUNT} skills for power_user)"
        else
            echo "⚠ Skill filtering endpoint returned 0 skills"
        fi
    else
        echo "⚠ Could not test permissions endpoint"
    fi
fi

# ==========================================
# Summary
# ==========================================
log_section "Deployment Complete!"

echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                                                           ║"
echo "║              DEPLOYMENT SUCCESSFUL! ✓                     ║"
echo "║                                                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "Next Steps:"
echo ""
echo "  1. Run the demo script:"
echo "     ./demo_aws_filtering.sh"
echo ""
echo "  2. Test manually:"
echo "     export ALB_URL=\"${ALB_URL}\""
echo "     curl \${ALB_URL}:8001/permissions -H \"X-User-Category: power_user\""
echo ""
echo "  3. View logs:"
echo "     aws logs tail \"/ecs/${PROJECT_NAME}-orchestrator\" --follow --region ${AWS_REGION}"
echo ""
echo "  4. Check ECS console:"
echo "     https://console.aws.amazon.com/ecs/home?region=${AWS_REGION}#/clusters/${PROJECT_NAME}-cluster"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

exit 0
