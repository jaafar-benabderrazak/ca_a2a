#!/bin/bash
set -e

REGION="eu-west-3"
PROJECT_NAME="ca-a2a"

echo "============================================"
echo "UPDATE AGENT TASK DEFINITIONS FOR KEYCLOAK"
echo "============================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Get Keycloak client secret from Secrets Manager
log_info "Retrieving Keycloak client secret..."
CLIENT_SECRET_ARN=$(aws secretsmanager describe-secret \
    --secret-id ${PROJECT_NAME}/keycloak-client-secret \
    --region ${REGION} \
    --query 'ARN' \
    --output text 2>/dev/null || echo "")

if [ -z "$CLIENT_SECRET_ARN" ]; then
    log_warn "Keycloak client secret not found. Run ./configure-keycloak.sh first."
    exit 1
fi

log_info "Client secret ARN: $CLIENT_SECRET_ARN"

# Keycloak environment variables to add
KEYCLOAK_ENV_VARS='
        {"name": "A2A_USE_KEYCLOAK", "value": "true"},
        {"name": "KEYCLOAK_URL", "value": "http://keycloak.ca-a2a.local:8080"},
        {"name": "KEYCLOAK_REALM", "value": "ca-a2a"},
        {"name": "KEYCLOAK_CLIENT_ID", "value": "ca-a2a-agents"},
        {"name": "KEYCLOAK_CACHE_TTL", "value": "3600"},'

# Function to update task definition
update_task_definition() {
    local AGENT=$1
    local TASK_FILE="task-definitions/${AGENT}-task.json"
    
    log_info "Updating task definition for $AGENT..."
    
    if [ ! -f "$TASK_FILE" ]; then
        log_warn "Task definition not found: $TASK_FILE"
        return
    fi
    
    # Backup original
    cp "$TASK_FILE" "$TASK_FILE.backup"
    
    # Use Python to add Keycloak environment variables
    python3 <<EOF
import json
import sys

# Read task definition
with open('$TASK_FILE', 'r') as f:
    task_def = json.load(f)

# Get container definition
container = task_def['containerDefinitions'][0]

# Check if Keycloak env vars already exist
env_vars = container.get('environment', [])
existing_names = {e['name'] for e in env_vars}

# Add Keycloak environment variables if not present
keycloak_vars = [
    {"name": "A2A_USE_KEYCLOAK", "value": "true"},
    {"name": "KEYCLOAK_URL", "value": "http://keycloak.ca-a2a.local:8080"},
    {"name": "KEYCLOAK_REALM", "value": "ca-a2a"},
    {"name": "KEYCLOAK_CLIENT_ID", "value": "ca-a2a-agents"},
    {"name": "KEYCLOAK_CACHE_TTL", "value": "3600"}
]

for var in keycloak_vars:
    if var['name'] not in existing_names:
        env_vars.append(var)
        print(f"  Added: {var['name']}")
    else:
        # Update existing value
        for i, e in enumerate(env_vars):
            if e['name'] == var['name']:
                env_vars[i]['value'] = var['value']
                print(f"  Updated: {var['name']}")
                break

container['environment'] = env_vars

# Add Keycloak client secret to secrets
secrets = container.get('secrets', [])
existing_secret_names = {s['name'] for s in secrets}

if 'KEYCLOAK_CLIENT_SECRET' not in existing_secret_names:
    secrets.append({
        "name": "KEYCLOAK_CLIENT_SECRET",
        "valueFrom": "$CLIENT_SECRET_ARN"
    })
    print(f"  Added secret: KEYCLOAK_CLIENT_SECRET")

container['secrets'] = secrets

# Write updated task definition
with open('$TASK_FILE', 'w') as f:
    json.dump(task_def, f, indent=2)

print("  Task definition updated successfully")
EOF
    
    # Register updated task definition
    log_info "Registering updated task definition..."
    aws ecs register-task-definition \
        --cli-input-json file://$TASK_FILE \
        --region ${REGION} > /dev/null
    
    log_info "✓ $AGENT task definition updated"
}

# Update all agent task definitions
for AGENT in orchestrator extractor validator archivist; do
    update_task_definition $AGENT
    echo ""
done

echo "============================================"
echo "TASK DEFINITIONS UPDATED"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Deploy updated agents:"
echo "     ./deploy.sh"
echo ""
echo "  2. Or update services individually:"
echo "     aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --force-new-deployment --region eu-west-3"
echo "     aws ecs update-service --cluster ca-a2a-cluster --service extractor --force-new-deployment --region eu-west-3"
echo "     aws ecs update-service --cluster ca-a2a-cluster --service validator --force-new-deployment --region eu-west-3"
echo "     aws ecs update-service --cluster ca-a2a-cluster --service archivist --force-new-deployment --region eu-west-3"
echo ""
echo "  3. Test Keycloak authentication:"
echo "     ./test-keycloak-auth.sh"
echo ""

# Optional: Ask if user wants to deploy now
read -p "Deploy updated services now? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "Deploying updated services..."
    for AGENT in orchestrator extractor validator archivist; do
        aws ecs update-service \
            --cluster ${PROJECT_NAME}-cluster \
            --service $AGENT \
            --force-new-deployment \
            --region ${REGION} > /dev/null
        log_info "  Triggered deployment for $AGENT"
    done
    
    log_info "Services are being deployed. Monitor with:"
    log_info "  aws ecs describe-services --cluster ca-a2a-cluster --services orchestrator extractor validator archivist --region eu-west-3"
fi

