#!/bin/bash
set -e

REGION="eu-west-3"
PROJECT_NAME="ca-a2a"
KEYCLOAK_URL="http://keycloak.${PROJECT_NAME}.local:8080"
REALM_NAME="ca-a2a"

echo "============================================"
echo "KEYCLOAK REALM CONFIGURATION"
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

# Get admin password from Secrets Manager
log_info "Retrieving Keycloak admin password..."
KEYCLOAK_ADMIN_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id ${PROJECT_NAME}/keycloak-admin-password \
    --query SecretString \
    --output text \
    --region ${REGION})

# This script needs to be run from within the VPC (from an ECS task or bastion)
log_info "Note: This script must be run from within the VPC (e.g., ECS task with exec enabled)"
log_info "Keycloak URL: $KEYCLOAK_URL"
echo ""

# Check if Keycloak is accessible
if ! curl -f -s "${KEYCLOAK_URL}/health/ready" > /dev/null 2>&1; then
    log_warn "Cannot reach Keycloak at $KEYCLOAK_URL"
    log_warn "Make sure you're running this from within the VPC or have VPN access"
    exit 1
fi

log_info "Keycloak is accessible!"

# Get admin access token
log_info "Authenticating as admin..."
ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -z "$ADMIN_TOKEN" ]; then
    log_warn "Failed to authenticate. Check admin password."
    exit 1
fi

log_info "Admin authentication successful!"

# Create realm
log_info "Creating realm: $REALM_NAME..."
curl -s -X POST "${KEYCLOAK_URL}/admin/realms" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"realm\": \"${REALM_NAME}\",
        \"enabled\": true,
        \"displayName\": \"CA-A2A Document Processing\",
        \"accessTokenLifespan\": 300,
        \"ssoSessionIdleTimeout\": 1800,
        \"ssoSessionMaxLifespan\": 36000,
        \"offlineSessionIdleTimeout\": 2592000,
        \"offlineSessionMaxLifespan\": 5184000,
        \"accessCodeLifespan\": 60,
        \"accessCodeLifespanUserAction\": 300,
        \"accessCodeLifespanLogin\": 1800,
        \"bruteForceProtected\": true,
        \"permanentLockout\": false,
        \"maxFailureWaitSeconds\": 900,
        \"minimumQuickLoginWaitSeconds\": 60,
        \"waitIncrementSeconds\": 60,
        \"quickLoginCheckMilliSeconds\": 1000,
        \"maxDeltaTimeSeconds\": 43200,
        \"failureFactor\": 5
    }" 2>/dev/null || log_warn "Realm may already exist"

# Create roles
log_info "Creating realm roles..."
for ROLE in admin orchestrator lambda viewer document-processor; do
    curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/roles" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"${ROLE}\", \"description\": \"Role for ${ROLE}\"}" 2>/dev/null || log_warn "Role $ROLE may already exist"
    log_info "  Created role: $ROLE"
done

# Create client for agents
log_info "Creating client: ca-a2a-agents..."
CLIENT_SECRET=$(openssl rand -base64 32 | tr -d '/+=')

curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/clients" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"clientId\": \"ca-a2a-agents\",
        \"enabled\": true,
        \"clientAuthenticatorType\": \"client-secret\",
        \"secret\": \"${CLIENT_SECRET}\",
        \"publicClient\": false,
        \"directAccessGrantsEnabled\": true,
        \"serviceAccountsEnabled\": true,
        \"authorizationServicesEnabled\": false,
        \"standardFlowEnabled\": true,
        \"implicitFlowEnabled\": false,
        \"redirectUris\": [\"*\"],
        \"webOrigins\": [\"*\"],
        \"protocol\": \"openid-connect\",
        \"attributes\": {
            \"access.token.lifespan\": \"300\",
            \"client.secret.creation.time\": \"$(date +%s)\"
        },
        \"defaultClientScopes\": [\"profile\", \"email\", \"roles\"],
        \"optionalClientScopes\": [\"address\", \"phone\"]
    }" 2>/dev/null || log_warn "Client may already exist"

# Store client secret in Secrets Manager
log_info "Storing client secret in Secrets Manager..."
aws secretsmanager create-secret \
    --name ${PROJECT_NAME}/keycloak-client-secret \
    --secret-string "${CLIENT_SECRET}" \
    --region ${REGION} 2>/dev/null || \
aws secretsmanager update-secret \
    --secret-id ${PROJECT_NAME}/keycloak-client-secret \
    --secret-string "${CLIENT_SECRET}" \
    --region ${REGION}

# Create service accounts
log_info "Creating service account users..."

# Lambda service account
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "lambda-service",
        "enabled": true,
        "emailVerified": true,
        "email": "lambda@ca-a2a.internal",
        "credentials": [{
            "type": "password",
            "value": "'"$(openssl rand -base64 24)"'",
            "temporary": false
        }]
    }' 2>/dev/null || log_warn "User lambda-service may already exist"

# Orchestrator service account
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "orchestrator-service",
        "enabled": true,
        "emailVerified": true,
        "email": "orchestrator@ca-a2a.internal",
        "credentials": [{
            "type": "password",
            "value": "'"$(openssl rand -base64 24)"'",
            "temporary": false
        }]
    }' 2>/dev/null || log_warn "User orchestrator-service may already exist"

# Admin user
ADMIN_USER_PASSWORD=$(openssl rand -base64 24)
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "admin-user",
        "enabled": true,
        "emailVerified": true,
        "email": "admin@ca-a2a.internal",
        "credentials": [{
            "type": "password",
            "value": "'"${ADMIN_USER_PASSWORD}"'",
            "temporary": false
        }]
    }' 2>/dev/null || log_warn "User admin-user may already exist"

# Store admin user password
aws secretsmanager create-secret \
    --name ${PROJECT_NAME}/keycloak-admin-user-password \
    --secret-string "${ADMIN_USER_PASSWORD}" \
    --region ${REGION} 2>/dev/null || \
aws secretsmanager update-secret \
    --secret-id ${PROJECT_NAME}/keycloak-admin-user-password \
    --secret-string "${ADMIN_USER_PASSWORD}" \
    --region ${REGION}

# Assign roles to users
log_info "Assigning roles to users..."

# Get user IDs
LAMBDA_USER_ID=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users?username=lambda-service" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    | python3 -c "import sys, json; users=json.load(sys.stdin); print(users[0]['id'] if users else '')")

ORCHESTRATOR_USER_ID=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users?username=orchestrator-service" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    | python3 -c "import sys, json; users=json.load(sys.stdin); print(users[0]['id'] if users else '')")

ADMIN_USER_ID=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users?username=admin-user" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    | python3 -c "import sys, json; users=json.load(sys.stdin); print(users[0]['id'] if users else '')")

# Get role IDs
LAMBDA_ROLE=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/roles/lambda" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}")

ORCHESTRATOR_ROLE=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/roles/orchestrator" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}")

ADMIN_ROLE=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/roles/admin" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}")

# Assign lambda role
if [ ! -z "$LAMBDA_USER_ID" ]; then
    curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users/${LAMBDA_USER_ID}/role-mappings/realm" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "[${LAMBDA_ROLE}]" 2>/dev/null || true
    log_info "  Assigned lambda role to lambda-service"
fi

# Assign orchestrator role
if [ ! -z "$ORCHESTRATOR_USER_ID" ]; then
    curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users/${ORCHESTRATOR_USER_ID}/role-mappings/realm" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "[${ORCHESTRATOR_ROLE}]" 2>/dev/null || true
    log_info "  Assigned orchestrator role to orchestrator-service"
fi

# Assign admin role
if [ ! -z "$ADMIN_USER_ID" ]; then
    curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM_NAME}/users/${ADMIN_USER_ID}/role-mappings/realm" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "[${ADMIN_ROLE}]" 2>/dev/null || true
    log_info "  Assigned admin role to admin-user"
fi

echo ""
echo "============================================"
echo "KEYCLOAK CONFIGURATION COMPLETE"
echo "============================================"
echo ""
echo "Realm: $REALM_NAME"
echo "Client ID: ca-a2a-agents"
echo "Client Secret: (stored in ${PROJECT_NAME}/keycloak-client-secret)"
echo ""
echo "Service Accounts Created:"
echo "  - lambda-service (role: lambda)"
echo "  - orchestrator-service (role: orchestrator)"
echo "  - admin-user (role: admin)"
echo ""
echo "Admin user password: (stored in ${PROJECT_NAME}/keycloak-admin-user-password)"
echo ""
echo "Token Endpoint:"
echo "  ${KEYCLOAK_URL}/realms/${REALM_NAME}/protocol/openid-connect/token"
echo ""
echo "JWKS Endpoint (for JWT validation):"
echo "  ${KEYCLOAK_URL}/realms/${REALM_NAME}/protocol/openid-connect/certs"
echo ""
echo "Next steps:"
echo "  1. Update agent task definitions with Keycloak environment variables"
echo "  2. Deploy updated agents"
echo "  3. Test authentication with test-keycloak-auth.sh"
echo ""

