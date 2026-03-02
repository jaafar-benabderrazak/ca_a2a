#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Fix ECS Task Definitions
# 1. Updates image URIs to match current AWS account's ECR registry
# 2. Removes 'command' overrides so Dockerfile CMD is used (no S3 code download)
# 3. Injects infrastructure env vars (POSTGRES_HOST, S3_BUCKET_NAME, agent URLs)
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

# ── Discover infrastructure ────────────────────────────────────────────
echo -e "${CYAN}▸${NC} Discovering infrastructure..."

# RDS endpoint
RDS_ENDPOINT=$(aws rds describe-db-instances --region "$REGION" \
    --query 'DBInstances[?DBInstanceIdentifier==`ca-a2a-db`].Endpoint.Address' \
    --output text 2>/dev/null)
RDS_DBNAME=$(aws rds describe-db-instances --region "$REGION" \
    --query 'DBInstances[?DBInstanceIdentifier==`ca-a2a-db`].DBName' \
    --output text 2>/dev/null)
if [ -z "$RDS_ENDPOINT" ] || [ "$RDS_ENDPOINT" = "None" ]; then
    echo -e "  ${RED}Cannot find RDS instance ca-a2a-db${NC}"
    exit 1
fi

# S3 bucket
S3_BUCKET=$(aws s3api list-buckets --query 'Buckets[?contains(Name,`ca-a2a`)].Name | [0]' --output text 2>/dev/null)

# DB password secret ARN
DB_SECRET_ARN=$(aws secretsmanager list-secrets --region "$REGION" \
    --query 'SecretList[?Name==`ca-a2a/db-password`].ARN | [0]' \
    --output text 2>/dev/null)

echo -e "  RDS:      ${RDS_ENDPOINT} (db: ${RDS_DBNAME})"
echo -e "  S3:       ${S3_BUCKET}"
echo -e "  DB Secret: ${DB_SECRET_ARN}"

echo -e ""
echo -e "${BOLD}${CYAN}Fix Task Definitions${NC}"
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

    # Check current image and command
    CURRENT_CMD=$(echo "$TASKDEF_JSON" | python3 -c "
import sys, json
td = json.load(sys.stdin)
cmd = td['containerDefinitions'][0].get('command')
print(json.dumps(cmd) if cmd else 'None')
" 2>/dev/null)

    echo -e "  Image:   ${CURRENT_IMAGE}"
    echo -e "  Command: ${CURRENT_CMD}"
    echo -e "  Target:  ${CORRECT_IMAGE} (no command override)"

    # Build new task definition: fix image, remove command, inject infra env vars
    echo "$TASKDEF_JSON" | python3 -c "
import sys, json

td = json.load(sys.stdin)
cd = td['containerDefinitions'][0]

# Fix image URI to current account
cd['image'] = '${CORRECT_IMAGE}'

# Remove command override — let Dockerfile CMD run the baked-in code
cd.pop('command', None)
cd.pop('entryPoint', None)

# Build env var dict from existing values
env_map = {e['name']: e['value'] for e in cd.get('environment', [])}

# Inject infrastructure env vars (config.py reads these via os.getenv)
infra_vars = {
    'POSTGRES_HOST': '${RDS_ENDPOINT}',
    'POSTGRES_PORT': '5432',
    'POSTGRES_DB': '${RDS_DBNAME}',
    'POSTGRES_USER': 'postgres',
    'S3_BUCKET_NAME': '${S3_BUCKET}',
    'AWS_REGION': '${REGION}',
    'AWS_DEFAULT_REGION': '${REGION}',
    # Each agent binds on 0.0.0.0, not localhost
    'ORCHESTRATOR_HOST': '0.0.0.0',
    'EXTRACTOR_HOST': '0.0.0.0',
    'VALIDATOR_HOST': '0.0.0.0',
    'ARCHIVIST_HOST': '0.0.0.0',
}

# Merge: infra vars fill in missing values, don't overwrite existing
for k, v in infra_vars.items():
    if k not in env_map:
        env_map[k] = v

cd['environment'] = [{'name': k, 'value': v} for k, v in sorted(env_map.items())]

# Add DB password from Secrets Manager (if not already set)
secrets = cd.get('secrets', [])
secret_names = {s['name'] for s in secrets}
if 'POSTGRES_PASSWORD' not in secret_names and '${DB_SECRET_ARN}' != 'None':
    secrets.append({
        'name': 'POSTGRES_PASSWORD',
        'valueFrom': '${DB_SECRET_ARN}'
    })
    cd['secrets'] = secrets

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
echo -e "${CYAN}▸${NC} Verifying task definitions..."
for SERVICE in $SERVICES; do
    FAMILY="${PROJECT}-${SERVICE}"
    VERIFY=$(aws ecs describe-task-definition \
        --task-definition "$FAMILY" \
        --region "$REGION" \
        --query 'taskDefinition.containerDefinitions[0].{Image:image,Command:command}' \
        --output json 2>/dev/null)
    IMG=$(echo "$VERIFY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Image'])" 2>/dev/null)
    CMD=$(echo "$VERIFY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Command'])" 2>/dev/null)
    if echo "$IMG" | grep -q "$ACCOUNT_ID"; then
        echo -e "  ${GREEN}✓${NC} ${SERVICE}: image=${IMG}"
    else
        echo -e "  ${RED}✗${NC} ${SERVICE}: image=${IMG}"
    fi
    if [ "$CMD" = "None" ]; then
        echo -e "    ${GREEN}✓${NC} command: using Dockerfile CMD"
    else
        echo -e "    ${RED}✗${NC} command: ${CMD} (should be None)"
    fi
done

echo ""
echo -e "${GREEN}Done. Re-run attack tests now.${NC}"
