#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# CA-A2A Security Deployment — eu-west-3
#
# Patches RUNNING task definitions with security env vars and restarts services.
# No local JSON files needed — reads current task defs from AWS, adds security
# env vars, re-registers, and forces new deployment.
#
# Usage:
#   ./deploy-security-euwest3.sh
#   ./deploy-security-euwest3.sh --dry-run
#   ./deploy-security-euwest3.sh --wait
#   ./deploy-security-euwest3.sh --region eu-west-3
# ══════════════════════════════════════════════════════════════════════════════

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

REGION="${AWS_REGION:-eu-west-3}"
CLUSTER="ca-a2a-cluster"
DRY_RUN=false
WAIT_STABLE=false
ERRORS=0

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

# Security env vars to inject into every service
SECURITY_ENVS='[
  {"name":"A2A_REQUIRE_AUTH","value":"true"},
  {"name":"A2A_USE_KEYCLOAK","value":"false"},
  {"name":"A2A_ENABLE_RATE_LIMIT","value":"true"},
  {"name":"A2A_RATE_LIMIT_PER_MINUTE","value":"300"},
  {"name":"A2A_ENABLE_REPLAY_PROTECTION","value":"true"},
  {"name":"A2A_REPLAY_TTL_SECONDS","value":"120"},
  {"name":"A2A_ENABLE_SCHEMA_VALIDATION","value":"true"},
  {"name":"A2A_AUDIT_LOGGING","value":"true"},
  {"name":"A2A_SECURITY_HEADERS","value":"true"},
  {"name":"A2A_RBAC_POLICY_JSON","value":"{\"deny\":{\"anonymous\":[\"process_document\",\"process_batch\",\"admin_*\"]},\"allow\":{\"validator\":[\"validate_document\",\"health\",\"card\",\"skills\"],\"extractor\":[\"extract_document\",\"health\",\"card\",\"skills\"],\"anonymous\":[\"health\",\"card\"],\"orchestrator\":[\"*\"],\"archivist\":[\"archive_document\",\"search_documents\",\"health\",\"card\",\"skills\"],\"admin\":[\"*\"],\"user\":[\"process_document\",\"get_task_status\",\"health\"]}}"},
  {"name":"A2A_API_KEYS_JSON","value":"{\"demo-key-001\":\"admin\",\"test-key-001\":\"user\"}"}
]'

SERVICES=("orchestrator" "extractor" "validator" "archivist")

# ─── Step 1: Verify cluster ──────────────────────────────────────────────────

echo -e "${CYAN}1. Verifying ECS cluster${NC}"
CLUSTER_STATUS=$(aws ecs describe-clusters --clusters "$CLUSTER" --region "$REGION" \
    --query 'clusters[0].status' --output text 2>/dev/null || echo "NOT_FOUND")

if [ "$CLUSTER_STATUS" != "ACTIVE" ]; then
    echo -e "  ${RED}FAIL${NC} Cluster '${CLUSTER}' not active (status: ${CLUSTER_STATUS})"
    exit 1
fi
echo -e "  ${GREEN}OK${NC} Cluster: ${CLUSTER} (ACTIVE)"
echo ""

# ─── Step 2: Show current vs target config ───────────────────────────────────

echo -e "${CYAN}2. Current security configuration${NC}"
for service in "${SERVICES[@]}"; do
    CURRENT_AUTH=$(aws ecs describe-task-definition \
        --task-definition "ca-a2a-${service}" --region "$REGION" \
        --query "taskDefinition.containerDefinitions[0].environment[?name=='A2A_REQUIRE_AUTH'].value | [0]" \
        --output text 2>/dev/null || echo "?")
    [ "$CURRENT_AUTH" = "None" ] && CURRENT_AUTH="not set"
    [ -z "$CURRENT_AUTH" ] && CURRENT_AUTH="not set"

    if [ "$CURRENT_AUTH" = "true" ]; then
        echo -e "  ${service}: A2A_REQUIRE_AUTH = ${GREEN}${CURRENT_AUTH}${NC} (already enabled)"
    else
        echo -e "  ${service}: A2A_REQUIRE_AUTH = ${RED}${CURRENT_AUTH}${NC} → will set to ${GREEN}true${NC}"
    fi
done
echo ""

if $DRY_RUN; then
    echo -e "${YELLOW}DRY RUN complete. Remove --dry-run to apply.${NC}"
    exit 0
fi

# ─── Step 3: Patch and register task definitions ─────────────────────────────

echo -e "${CYAN}3. Patching and registering task definitions${NC}"

for service in "${SERVICES[@]}"; do
    FAMILY="ca-a2a-${service}"

    echo -e "  ${service}: fetching current task definition..."

    # Write current task def and security envs to temp files (avoids quoting hell)
    TASKDEF_FILE="/tmp/ca-a2a-${service}-current.json"
    SECENV_FILE="/tmp/ca-a2a-security-envs.json"
    TMPFILE="/tmp/ca-a2a-${service}-patched.json"

    aws ecs describe-task-definition \
        --task-definition "$FAMILY" --region "$REGION" \
        --query 'taskDefinition' --output json > "$TASKDEF_FILE" 2>&1

    if [ $? -ne 0 ]; then
        echo -e "  ${RED}FAIL${NC} ${service}: could not fetch task definition"
        cat "$TASKDEF_FILE" | head -3
        ((ERRORS++))
        continue
    fi

    echo "$SECURITY_ENVS" > "$SECENV_FILE"

    # Use Python to merge security env vars — reads from files, no string embedding
    python3 -c "
import json, sys

with open('${TASKDEF_FILE}') as f:
    taskdef = json.load(f)
with open('${SECENV_FILE}') as f:
    security_envs = json.load(f)

container_defs = taskdef['containerDefinitions']

for container in container_defs:
    existing = container.get('environment', [])
    existing_names = {e['name'] for e in existing}

    for sec_env in security_envs:
        if sec_env['name'] in existing_names:
            for e in existing:
                if e['name'] == sec_env['name']:
                    e['value'] = sec_env['value']
        else:
            existing.append(sec_env)

    container['environment'] = existing

reg_input = {
    'family': taskdef['family'],
    'networkMode': taskdef.get('networkMode', 'awsvpc'),
    'requiresCompatibilities': taskdef.get('requiresCompatibilities', ['FARGATE']),
    'cpu': taskdef.get('cpu', '512'),
    'memory': taskdef.get('memory', '1024'),
    'containerDefinitions': container_defs,
}

if 'executionRoleArn' in taskdef:
    reg_input['executionRoleArn'] = taskdef['executionRoleArn']
if 'taskRoleArn' in taskdef:
    reg_input['taskRoleArn'] = taskdef['taskRoleArn']

with open('${TMPFILE}', 'w') as f:
    json.dump(reg_input, f)
" 2>&1

    if [ $? -ne 0 ]; then
        echo -e "  ${RED}FAIL${NC} ${service}: could not patch task definition"
        ((ERRORS++))
        continue
    fi

    echo -e "  ${service}: registering patched task definition..."
    REG_RESULT=$(aws ecs register-task-definition \
        --cli-input-json "file://${TMPFILE}" \
        --region "$REGION" \
        --query 'taskDefinition.taskDefinitionArn' \
        --output text 2>&1)

    if [ $? -ne 0 ]; then
        echo -e "  ${RED}FAIL${NC} ${service}: registration failed"
        echo -e "       ${REG_RESULT}"
        ((ERRORS++))
        continue
    fi

    echo -e "  ${GREEN}OK${NC} ${service}: registered ${REG_RESULT}"

    # Clean up temp files
    rm -f "$TASKDEF_FILE" "$SECENV_FILE" "$TMPFILE"
done
echo ""

if [ $ERRORS -gt 0 ]; then
    echo -e "${RED}${ERRORS} service(s) failed registration. Fix errors above before continuing.${NC}"
    exit 1
fi

# ─── Step 4: Update ECS services ────────────────────────────────────────────

echo -e "${CYAN}4. Updating ECS services (force new deployment)${NC}"
for service in "${SERVICES[@]}"; do
    UPDATE_RESULT=$(aws ecs update-service \
        --cluster "$CLUSTER" \
        --service "$service" \
        --task-definition "ca-a2a-${service}" \
        --force-new-deployment \
        --region "$REGION" \
        --query 'service.deployments[0].status' \
        --output text 2>&1)

    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}OK${NC} ${service}: deployment triggered (${UPDATE_RESULT})"
    else
        echo -e "  ${RED}FAIL${NC} ${service}: ${UPDATE_RESULT}"
        ((ERRORS++))
    fi
done
echo ""

# ─── Step 5: Verify registration ────────────────────────────────────────────

echo -e "${CYAN}5. Verifying registered task definitions${NC}"
ALL_OK=true
for service in "${SERVICES[@]}"; do
    AUTH=$(aws ecs describe-task-definition \
        --task-definition "ca-a2a-${service}" --region "$REGION" \
        --query "taskDefinition.containerDefinitions[0].environment[?name=='A2A_REQUIRE_AUTH'].value | [0]" \
        --output text 2>/dev/null)

    RATE=$(aws ecs describe-task-definition \
        --task-definition "ca-a2a-${service}" --region "$REGION" \
        --query "taskDefinition.containerDefinitions[0].environment[?name=='A2A_ENABLE_RATE_LIMIT'].value | [0]" \
        --output text 2>/dev/null)

    HEADERS=$(aws ecs describe-task-definition \
        --task-definition "ca-a2a-${service}" --region "$REGION" \
        --query "taskDefinition.containerDefinitions[0].environment[?name=='A2A_SECURITY_HEADERS'].value | [0]" \
        --output text 2>/dev/null)

    if [ "$AUTH" = "true" ] && [ "$RATE" = "true" ] && [ "$HEADERS" = "true" ]; then
        echo -e "  ${GREEN}OK${NC} ${service}: auth=${AUTH} rate_limit=${RATE} headers=${HEADERS}"
    else
        echo -e "  ${RED}FAIL${NC} ${service}: auth=${AUTH:-?} rate_limit=${RATE:-?} headers=${HEADERS:-?}"
        ALL_OK=false
    fi
done
echo ""

# ─── Step 6: Wait for stability (optional) ──────────────────────────────────

if $WAIT_STABLE; then
    echo -e "${CYAN}6. Waiting for services to stabilize (up to 10 min)...${NC}"
    for service in "${SERVICES[@]}"; do
        echo -ne "  ${service}: waiting..."
        aws ecs wait services-stable \
            --cluster "$CLUSTER" \
            --services "$service" \
            --region "$REGION" 2>/dev/null

        if [ $? -eq 0 ]; then
            echo -e "\r  ${GREEN}OK${NC} ${service}: stable                "
        else
            echo -e "\r  ${YELLOW}WARN${NC} ${service}: timeout waiting for stability"
        fi
    done
    echo ""
else
    echo -e "${YELLOW}Tip: Services need ~2 min to roll over. Use --wait to block until stable.${NC}"
    echo ""
fi

# ─── Summary ────────────────────────────────────────────────────────────────

if $ALL_OK && [ $ERRORS -eq 0 ]; then
    echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════════════════════"
    echo -e "  Security deployment complete."
    echo -e "══════════════════════════════════════════════════════════════════════${NC}"
else
    echo -e "${BOLD}${RED}══════════════════════════════════════════════════════════════════════"
    echo -e "  Deployment had errors — check output above."
    echo -e "══════════════════════════════════════════════════════════════════════${NC}"
fi

echo ""
echo "Next steps:"
echo "  1. Wait ~2 min for rolling deployment to complete"
echo "  2. Run: ./run_all_attacks_cloudshell.sh --region ${REGION}"
echo ""
