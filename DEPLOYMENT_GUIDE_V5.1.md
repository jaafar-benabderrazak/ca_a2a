# Guide de Déploiement - Version 5.1

**Date:** 16 Janvier 2026  
**Version:** 5.1  
**Auteur:** Système de Déploiement CA-A2A

---

## 🎯 Objectif

Déployer les fonctionnalités suivantes ajoutées en version 5.1 :
1. **Token Revocation** (table PostgreSQL + Admin API)
2. **JSON Schema Validation** (validation des inputs)
3. **Pydantic Models** (type-safe validation)
4. **Enhanced Logging** (correlation IDs)
5. **MCP Server** (2 instances pour HA)

---

## 📋 Prérequis

### AWS Credentials
```bash
# Vérifier que les credentials AWS sont valides
aws sts get-caller-identity --region eu-west-3

# Si expiré, re-authentifier via AWS SSO ou AWS CLI configure
```

### État de l'Infrastructure Existante
L'infrastructure suivante doit déjà être déployée :
- ✅ VPC `ca-a2a-vpc` (10.0.0.0/16)
- ✅ ECS Cluster `ca-a2a-cluster`
- ✅ RDS Aurora PostgreSQL `documents-db`
- ✅ RDS PostgreSQL `keycloak-db`
- ✅ ALB `ca-a2a-alb`
- ✅ Services ECS : orchestrator, extractor, validator, archivist
- ✅ Keycloak (service ECS)

---

## 🚀 Étape 1 : Migration de la Base de Données

### 1.1 Créer la Table `revoked_tokens`

**Fichier:** `migrations/001_create_revoked_tokens_table.sql`

```sql
-- Migration 001: Create revoked_tokens table
-- Version: 5.1
-- Date: 2026-01-16

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti VARCHAR(255) PRIMARY KEY,
    revoked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_by VARCHAR(100) NOT NULL,
    reason TEXT,
    expires_at TIMESTAMP NOT NULL
);

-- Index pour cleanup efficace
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at 
    ON revoked_tokens(expires_at);

-- Index pour recherche par utilisateur
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_revoked_by 
    ON revoked_tokens(revoked_by);

-- Commentaires
COMMENT ON TABLE revoked_tokens IS 'Token Revocation List - hybrid storage (cache + DB)';
COMMENT ON COLUMN revoked_tokens.jti IS 'JWT ID (unique identifier from JWT claim)';
COMMENT ON COLUMN revoked_tokens.revoked_at IS 'Timestamp when token was revoked';
COMMENT ON COLUMN revoked_tokens.revoked_by IS 'Admin user who revoked the token';
COMMENT ON COLUMN revoked_tokens.reason IS 'Human-readable reason for revocation';
COMMENT ON COLUMN revoked_tokens.expires_at IS 'Original JWT expiration time (for cleanup)';

-- Verify
SELECT 
    table_name, 
    column_name, 
    data_type 
FROM information_schema.columns 
WHERE table_name = 'revoked_tokens' 
ORDER BY ordinal_position;
```

### 1.2 Script d'Exécution de Migration

**Fichier:** `migrations/run_migration.sh`

```bash
#!/bin/bash

# CA-A2A Database Migration Runner
# Version: 5.1

set -e

REGION="eu-west-3"
PROJECT_NAME="ca-a2a"

echo "============================================"
echo "CA-A2A DATABASE MIGRATION - V5.1"
echo "============================================"

# 1. Get RDS cluster endpoint
echo "[INFO] Retrieving RDS cluster endpoint..."
RDS_ENDPOINT=$(aws rds describe-db-clusters \
    --region ${REGION} \
    --query "DBClusters[?contains(DBClusterIdentifier, 'documents-db')].Endpoint | [0]" \
    --output text)

if [ -z "$RDS_ENDPOINT" ] || [ "$RDS_ENDPOINT" == "None" ]; then
    echo "[ERROR] RDS cluster not found"
    exit 1
fi

echo "[INFO] RDS Endpoint: ${RDS_ENDPOINT}"

# 2. Get database credentials from Secrets Manager
echo "[INFO] Retrieving database credentials..."
DB_SECRET=$(aws secretsmanager get-secret-value \
    --secret-id ${PROJECT_NAME}/db-password \
    --region ${REGION} \
    --query SecretString \
    --output text)

DB_PASSWORD="${DB_SECRET}"
DB_USER="postgres"
DB_NAME="documents"

# 3. Check if psql is available
if ! command -v psql &> /dev/null; then
    echo "[WARN] psql not found locally"
    echo "[INFO] Using Python with psycopg2..."
    
    # Create Python migration script
    cat > /tmp/migrate.py << 'PYTHON_SCRIPT'
import psycopg2
import sys
import os

# Read SQL file
sql_file = sys.argv[1]
with open(sql_file, 'r') as f:
    sql_script = f.read()

# Connection parameters from environment
conn_params = {
    'host': os.environ['DB_HOST'],
    'port': int(os.environ.get('DB_PORT', 5432)),
    'database': os.environ['DB_NAME'],
    'user': os.environ['DB_USER'],
    'password': os.environ['DB_PASSWORD']
}

print(f"[INFO] Connecting to {conn_params['host']}:{conn_params['port']}/{conn_params['database']}...")

try:
    conn = psycopg2.connect(**conn_params)
    cursor = conn.cursor()
    
    print("[INFO] Executing migration...")
    cursor.execute(sql_script)
    conn.commit()
    
    print("[SUCCESS] Migration completed")
    
    # Verify table exists
    cursor.execute("SELECT COUNT(*) FROM revoked_tokens;")
    count = cursor.fetchone()[0]
    print(f"[INFO] revoked_tokens table exists with {count} rows")
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f"[ERROR] Migration failed: {e}")
    sys.exit(1)
PYTHON_SCRIPT

    # Export environment variables
    export DB_HOST="${RDS_ENDPOINT}"
    export DB_PORT="5432"
    export DB_NAME="${DB_NAME}"
    export DB_USER="${DB_USER}"
    export DB_PASSWORD="${DB_PASSWORD}"
    
    # Run migration via Python
    python3 /tmp/migrate.py migrations/001_create_revoked_tokens_table.sql
    
else
    echo "[INFO] Using psql..."
    
    # Set PGPASSWORD for psql
    export PGPASSWORD="${DB_PASSWORD}"
    
    # Run migration
    psql -h ${RDS_ENDPOINT} -p 5432 -U ${DB_USER} -d ${DB_NAME} \
        -f migrations/001_create_revoked_tokens_table.sql
    
    echo "[SUCCESS] Migration completed via psql"
fi

# 4. Verify migration
echo "[INFO] Verifying migration..."
aws rds execute-statement \
    --resource-arn $(aws rds describe-db-clusters --region ${REGION} --query "DBClusters[?contains(DBClusterIdentifier, 'documents-db')].DBClusterArn | [0]" --output text) \
    --secret-arn $(aws secretsmanager describe-secret --secret-id ${PROJECT_NAME}/db-password --region ${REGION} --query ARN --output text) \
    --sql "SELECT table_name FROM information_schema.tables WHERE table_name='revoked_tokens';" \
    --database ${DB_NAME} \
    --region ${REGION} 2>/dev/null || echo "[WARN] Data API not enabled (expected if not using Serverless)"

echo "============================================"
echo "✅ MIGRATION COMPLETE"
echo "============================================"
```

### 1.3 Exécuter la Migration

```bash
cd /path/to/ca_a2a
chmod +x migrations/run_migration.sh
./migrations/run_migration.sh
```

---

## 🔧 Étape 2 : Déployer l'Admin API

### 2.1 Créer le Dockerfile pour l'Admin API

**Fichier:** `Dockerfile.admin`

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY admin_api.py .
COPY a2a_security_enhanced.py .
COPY a2a_security.py .
COPY keycloak_auth.py .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 9000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:9000/health', timeout=5)" || exit 1

# Run FastAPI with uvicorn
CMD ["uvicorn", "admin_api:app", "--host", "0.0.0.0", "--port", "9000"]
```

### 2.2 Créer la Task Definition

**Fichier:** `task-definitions/admin-api-task.json`

```json
{
  "family": "ca-a2a-admin-api",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::555043101106:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::555043101106:role/ca-a2a-task-role",
  "containerDefinitions": [
    {
      "name": "admin-api",
      "image": "555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a-admin-api:latest",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 9000,
          "protocol": "tcp",
          "name": "admin-http"
        }
      ],
      "environment": [
        {
          "name": "ADMIN_API_PORT",
          "value": "9000"
        },
        {
          "name": "POSTGRES_HOST",
          "value": "documents-db.cluster-czkdu9wcburt.eu-west-3.rds.amazonaws.com"
        },
        {
          "name": "POSTGRES_PORT",
          "value": "5432"
        },
        {
          "name": "POSTGRES_DB",
          "value": "documents"
        },
        {
          "name": "POSTGRES_USER",
          "value": "postgres"
        },
        {
          "name": "KEYCLOAK_URL",
          "value": "http://keycloak.ca-a2a.local:8080"
        },
        {
          "name": "KEYCLOAK_REALM",
          "value": "ca-a2a"
        },
        {
          "name": "A2A_USE_KEYCLOAK",
          "value": "true"
        }
      ],
      "secrets": [
        {
          "name": "POSTGRES_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:eu-west-3:555043101106:secret:ca-a2a/db-password"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/ca-a2a-admin-api",
          "awslogs-region": "eu-west-3",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "python -c \"import requests; requests.get('http://localhost:9000/health')\" || exit 1"],
        "interval": 30,
        "timeout": 10,
        "retries": 3,
        "startPeriod": 40
      }
    }
  ]
}
```

### 2.3 Script de Déploiement Admin API

**Fichier:** `deploy-admin-api.sh`

```bash
#!/bin/bash

# Deploy Admin API to ECS Fargate
# Version: 5.1

set -e

REGION="eu-west-3"
PROJECT_NAME="ca-a2a"
AWS_ACCOUNT_ID="555043101106"
ECR_REPO="${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PROJECT_NAME}-admin-api"

echo "============================================"
echo "DEPLOYING ADMIN API - V5.1"
echo "============================================"

# 1. Create ECR repository if doesn't exist
echo "[INFO] Creating ECR repository..."
aws ecr create-repository \
    --repository-name ${PROJECT_NAME}-admin-api \
    --region ${REGION} 2>/dev/null || echo "[INFO] Repository already exists"

# 2. Build Docker image
echo "[INFO] Building Docker image..."
docker build -t ${PROJECT_NAME}-admin-api:latest -f Dockerfile.admin .

# 3. Login to ECR
echo "[INFO] Logging in to ECR..."
aws ecr get-login-password --region ${REGION} | \
    docker login --username AWS --password-stdin ${ECR_REPO}

# 4. Tag and push
echo "[INFO] Pushing image to ECR..."
docker tag ${PROJECT_NAME}-admin-api:latest ${ECR_REPO}:latest
docker push ${ECR_REPO}:latest

# 5. Create CloudWatch log group
echo "[INFO] Creating CloudWatch log group..."
aws logs create-log-group \
    --log-group-name /ecs/${PROJECT_NAME}-admin-api \
    --region ${REGION} 2>/dev/null || echo "[INFO] Log group already exists"

# 6. Get VPC and subnet info
echo "[INFO] Retrieving network configuration..."
VPC_ID=$(aws ec2 describe-vpcs \
    --filters "Name=tag:Name,Values=${PROJECT_NAME}-vpc" \
    --query 'Vpcs[0].VpcId' \
    --output text \
    --region ${REGION})

PRIVATE_SUBNET_1=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Name,Values=*private*" \
    --query 'Subnets[0].SubnetId' \
    --output text \
    --region ${REGION})

PRIVATE_SUBNET_2=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Name,Values=*private*" \
    --query 'Subnets[1].SubnetId' \
    --output text \
    --region ${REGION})

echo "[INFO] VPC: ${VPC_ID}"
echo "[INFO] Subnets: ${PRIVATE_SUBNET_1}, ${PRIVATE_SUBNET_2}"

# 7. Create security group for Admin API
echo "[INFO] Creating security group..."
ADMIN_SG_ID=$(aws ec2 create-security-group \
    --group-name ${PROJECT_NAME}-admin-api-sg \
    --description "Security group for CA-A2A Admin API" \
    --vpc-id ${VPC_ID} \
    --region ${REGION} \
    --query 'GroupId' \
    --output text 2>/dev/null || \
    aws ec2 describe-security-groups \
        --filters "Name=group-name,Values=${PROJECT_NAME}-admin-api-sg" \
        --query 'SecurityGroups[0].GroupId' \
        --output text \
        --region ${REGION})

echo "[INFO] Admin API Security Group: ${ADMIN_SG_ID}"

# Allow inbound from orchestrator (admin operations)
ORCHESTRATOR_SG=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=${PROJECT_NAME}-orchestrator-sg" \
    --query 'SecurityGroups[0].GroupId' \
    --output text \
    --region ${REGION})

aws ec2 authorize-security-group-ingress \
    --group-id ${ADMIN_SG_ID} \
    --protocol tcp \
    --port 9000 \
    --source-group ${ORCHESTRATOR_SG} \
    --region ${REGION} 2>/dev/null || echo "[INFO] Ingress rule already exists"

# 8. Register task definition
echo "[INFO] Registering task definition..."
aws ecs register-task-definition \
    --cli-input-json file://task-definitions/admin-api-task.json \
    --region ${REGION}

# 9. Create ECS service
echo "[INFO] Creating ECS service..."
aws ecs create-service \
    --cluster ${PROJECT_NAME}-cluster \
    --service-name admin-api \
    --task-definition ${PROJECT_NAME}-admin-api \
    --desired-count 1 \
    --launch-type FARGATE \
    --platform-version LATEST \
    --network-configuration "awsvpcConfiguration={subnets=[${PRIVATE_SUBNET_1},${PRIVATE_SUBNET_2}],securityGroups=[${ADMIN_SG_ID}],assignPublicIp=DISABLED}" \
    --enable-execute-command \
    --region ${REGION} 2>/dev/null || \
    aws ecs update-service \
        --cluster ${PROJECT_NAME}-cluster \
        --service admin-api \
        --force-new-deployment \
        --region ${REGION}

echo "============================================"
echo "✅ ADMIN API DEPLOYED"
echo "============================================"
echo "Service: admin-api"
echo "Port: 9000"
echo "Endpoints:"
echo "  POST   /admin/revoke-token"
echo "  GET    /admin/revoked-tokens"
echo "  GET    /admin/security-stats"
echo "  DELETE /admin/cleanup-expired-tokens"
echo ""
echo "To check status:"
echo "  aws ecs describe-services --cluster ${PROJECT_NAME}-cluster --services admin-api --region ${REGION}"
echo ""
echo "To view logs:"
echo "  aws logs tail /ecs/${PROJECT_NAME}-admin-api --follow --region ${REGION}"
```

### 2.4 Exécuter le Déploiement

```bash
chmod +x deploy-admin-api.sh
./deploy-admin-api.sh
```

---

## 📦 Étape 3 : Mettre à Jour les Agents avec JSON Schema et Pydantic

### 3.1 Vérifier les Fichiers

Assurez-vous que ces fichiers sont à jour :
- ✅ `a2a_security_enhanced.py` (contient `JSONSchemaValidator`)
- ✅ `pydantic_models.py` (contient tous les modèles)
- ✅ `requirements.txt` (contient `jsonschema` et `pydantic`)

### 3.2 Rebuilder les Images Docker

```bash
#!/bin/bash

# Rebuild and redeploy agents with new validation features
# Version: 5.1

REGION="eu-west-3"
PROJECT_NAME="ca-a2a"
AWS_ACCOUNT_ID="555043101106"

AGENTS=("orchestrator" "extractor" "validator" "archivist")

for AGENT in "${AGENTS[@]}"; do
    echo "============================================"
    echo "Rebuilding ${AGENT}..."
    echo "============================================"
    
    # Build
    docker build -t ${PROJECT_NAME}-${AGENT}:latest -f Dockerfile.${AGENT} .
    
    # Tag
    docker tag ${PROJECT_NAME}-${AGENT}:latest \
        ${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PROJECT_NAME}-${AGENT}:latest
    
    # Push
    docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PROJECT_NAME}-${AGENT}:latest
    
    # Force new deployment
    aws ecs update-service \
        --cluster ${PROJECT_NAME}-cluster \
        --service ${AGENT} \
        --force-new-deployment \
        --region ${REGION}
    
    echo "✅ ${AGENT} redeployed"
done

echo "============================================"
echo "✅ ALL AGENTS UPDATED"
echo "============================================"
```

Sauvegarder comme `update-agents-v5.1.sh` et exécuter :

```bash
chmod +x update-agents-v5.1.sh
./update-agents-v5.1.sh
```

---

## 🔍 Étape 4 : Vérification Post-Déploiement

### 4.1 Script de Vérification Complet

**Fichier:** `verify-deployment-v5.1.sh`

```bash
#!/bin/bash

# Verify CA-A2A v5.1 Deployment
# Checks: Database migration, Admin API, Agent updates, JSON Schema validation

set -e

REGION="eu-west-3"
PROJECT_NAME="ca-a2a"

echo "============================================"
echo "VERIFICATION DEPLOYMENT V5.1"
echo "============================================"

PASSED=0
FAILED=0

# Test 1: Database migration
echo -e "\n[TEST 1] Database Migration - revoked_tokens table"
RDS_ENDPOINT=$(aws rds describe-db-clusters \
    --region ${REGION} \
    --query "DBClusters[?contains(DBClusterIdentifier, 'documents-db')].Endpoint | [0]" \
    --output text)

if [ ! -z "$RDS_ENDPOINT" ]; then
    echo "  ✅ RDS cluster found: ${RDS_ENDPOINT}"
    ((PASSED++))
else
    echo "  ❌ RDS cluster not found"
    ((FAILED++))
fi

# Test 2: Admin API service
echo -e "\n[TEST 2] Admin API Service Status"
ADMIN_STATUS=$(aws ecs describe-services \
    --cluster ${PROJECT_NAME}-cluster \
    --services admin-api \
    --region ${REGION} \
    --query 'services[0].status' \
    --output text 2>/dev/null)

if [ "$ADMIN_STATUS" == "ACTIVE" ]; then
    RUNNING=$(aws ecs describe-services \
        --cluster ${PROJECT_NAME}-cluster \
        --services admin-api \
        --region ${REGION} \
        --query 'services[0].runningCount' \
        --output text)
    echo "  ✅ Admin API is ACTIVE with ${RUNNING} tasks running"
    ((PASSED++))
else
    echo "  ❌ Admin API service not active (status: ${ADMIN_STATUS})"
    ((FAILED++))
fi

# Test 3: Agent services updated
echo -e "\n[TEST 3] Agent Services Status"
AGENTS=("orchestrator" "extractor" "validator" "archivist")
AGENT_PASSED=0

for AGENT in "${AGENTS[@]}"; do
    STATUS=$(aws ecs describe-services \
        --cluster ${PROJECT_NAME}-cluster \
        --services ${AGENT} \
        --region ${REGION} \
        --query 'services[0].status' \
        --output text 2>/dev/null)
    
    RUNNING=$(aws ecs describe-services \
        --cluster ${PROJECT_NAME}-cluster \
        --services ${AGENT} \
        --region ${REGION} \
        --query 'services[0].runningCount' \
        --output text)
    
    if [ "$STATUS" == "ACTIVE" ] && [ "$RUNNING" -gt 0 ]; then
        echo "  ✅ ${AGENT}: ACTIVE (${RUNNING} tasks)"
        ((AGENT_PASSED++))
    else
        echo "  ❌ ${AGENT}: ${STATUS} (${RUNNING} tasks)"
    fi
done

if [ $AGENT_PASSED -eq 4 ]; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test 4: CloudWatch log groups
echo -e "\n[TEST 4] CloudWatch Log Groups"
LOG_GROUPS=("/ecs/${PROJECT_NAME}-admin-api" "/ecs/${PROJECT_NAME}-orchestrator" "/ecs/${PROJECT_NAME}-extractor" "/ecs/${PROJECT_NAME}-validator" "/ecs/${PROJECT_NAME}-archivist")
LOG_PASSED=0

for LOG_GROUP in "${LOG_GROUPS[@]}"; do
    EXISTS=$(aws logs describe-log-groups \
        --log-group-name-prefix ${LOG_GROUP} \
        --region ${REGION} \
        --query 'logGroups[0].logGroupName' \
        --output text 2>/dev/null)
    
    if [ "$EXISTS" == "${LOG_GROUP}" ]; then
        echo "  ✅ ${LOG_GROUP} exists"
        ((LOG_PASSED++))
    else
        echo "  ❌ ${LOG_GROUP} not found"
    fi
done

if [ $LOG_PASSED -eq 5 ]; then
    ((PASSED++))
else
    ((FAILED++))
fi

# Test 5: Keycloak status
echo -e "\n[TEST 5] Keycloak Service"
KC_STATUS=$(aws ecs describe-services \
    --cluster ${PROJECT_NAME}-cluster \
    --services keycloak \
    --region ${REGION} \
    --query 'services[0].status' \
    --output text 2>/dev/null)

KC_RUNNING=$(aws ecs describe-services \
    --cluster ${PROJECT_NAME}-cluster \
    --services keycloak \
    --region ${REGION} \
    --query 'services[0].runningCount' \
    --output text 2>/dev/null)

if [ "$KC_STATUS" == "ACTIVE" ] && [ "$KC_RUNNING" -gt 0 ]; then
    echo "  ✅ Keycloak: ACTIVE (${KC_RUNNING} tasks)"
    ((PASSED++))
else
    echo "  ⚠️  Keycloak: ${KC_STATUS} (${KC_RUNNING} tasks)"
    echo "      Note: Keycloak may need manual intervention (check previous deployment logs)"
    ((FAILED++))
fi

# Summary
echo -e "\n============================================"
echo "VERIFICATION SUMMARY"
echo "============================================"
echo "✅ Passed: ${PASSED}/5"
echo "❌ Failed: ${FAILED}/5"

if [ $FAILED -eq 0 ]; then
    echo -e "\n🎉 ALL TESTS PASSED - V5.1 DEPLOYMENT SUCCESSFUL"
    exit 0
else
    echo -e "\n⚠️  SOME TESTS FAILED - PLEASE REVIEW"
    exit 1
fi
```

### 4.2 Exécuter la Vérification

```bash
chmod +x verify-deployment-v5.1.sh
./verify-deployment-v5.1.sh
```

---

## 📊 Étape 5 : Tests Fonctionnels

### 5.1 Tester l'Admin API

```bash
#!/bin/bash

# Test Admin API endpoints
# Requires valid Keycloak admin token

REGION="eu-west-3"
ADMIN_API_URL="http://admin-api.ca-a2a.local:9000"

echo "============================================"
echo "TESTING ADMIN API"
echo "============================================"

# Get admin token from Keycloak
echo "[INFO] Obtaining admin token from Keycloak..."
CLIENT_SECRET=$(aws secretsmanager get-secret-value \
    --secret-id ca-a2a/keycloak-client-secret \
    --region ${REGION} \
    --query SecretString \
    --output text)

ADMIN_TOKEN=$(curl -s -X POST \
    "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=ca-a2a-agents" \
    -d "client_secret=${CLIENT_SECRET}" | jq -r '.access_token')

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" == "null" ]; then
    echo "[ERROR] Failed to obtain admin token"
    exit 1
fi

echo "[SUCCESS] Admin token obtained"

# Test 1: Health check
echo -e "\n[TEST] GET /health"
curl -s "${ADMIN_API_URL}/health" | jq

# Test 2: Security stats
echo -e "\n[TEST] GET /admin/security-stats"
curl -s -X GET "${ADMIN_API_URL}/admin/security-stats" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# Test 3: List revoked tokens
echo -e "\n[TEST] GET /admin/revoked-tokens"
curl -s -X GET "${ADMIN_API_URL}/admin/revoked-tokens" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# Test 4: Revoke a test token
echo -e "\n[TEST] POST /admin/revoke-token"
TEST_JTI="test-jti-$(date +%s)"
curl -s -X POST "${ADMIN_API_URL}/admin/revoke-token" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"jti\": \"${TEST_JTI}\",
        \"reason\": \"Test revocation from deployment verification\"
    }" | jq

# Test 5: Cleanup expired tokens
echo -e "\n[TEST] DELETE /admin/cleanup-expired-tokens"
curl -s -X DELETE "${ADMIN_API_URL}/admin/cleanup-expired-tokens" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

echo -e "\n============================================"
echo "✅ ADMIN API TESTS COMPLETE"
echo "============================================"
```

### 5.2 Tester la Validation JSON Schema

```bash
#!/bin/bash

# Test JSON Schema validation by sending invalid requests

ORCHESTRATOR_URL="http://orchestrator.ca-a2a.local:8001"

echo "============================================"
echo "TESTING JSON SCHEMA VALIDATION"
echo "============================================"

# Get token
ADMIN_TOKEN=$(curl -s -X POST \
    "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=ca-a2a-agents" \
    -d "client_secret=${CLIENT_SECRET}" | jq -r '.access_token')

# Test 1: Valid request (should succeed)
echo -e "\n[TEST 1] Valid request"
curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/rpc" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "id": "test-1",
        "method": "process_document",
        "params": {
            "s3_key": "valid/path/document.pdf",
            "priority": "normal"
        }
    }' | jq

# Test 2: Path traversal (should fail with -32602)
echo -e "\n[TEST 2] Path traversal attack (should be blocked)"
curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/rpc" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "id": "test-2",
        "method": "process_document",
        "params": {
            "s3_key": "../../../etc/passwd",
            "priority": "normal"
        }
    }' | jq

# Test 3: Invalid priority (should fail with -32602)
echo -e "\n[TEST 3] Invalid enum value (should be blocked)"
curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/rpc" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "id": "test-3",
        "method": "process_document",
        "params": {
            "s3_key": "valid/document.pdf",
            "priority": "ultra-high"
        }
    }' | jq

# Test 4: Missing required field (should fail with -32602)
echo -e "\n[TEST 4] Missing required field (should be blocked)"
curl -s -X POST "${ORCHESTRATOR_URL}/api/v1/rpc" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "id": "test-4",
        "method": "process_document",
        "params": {
            "priority": "normal"
        }
    }' | jq

echo -e "\n============================================"
echo "✅ JSON SCHEMA VALIDATION TESTS COMPLETE"
echo "============================================"
echo "Expected results:"
echo "  Test 1: SUCCESS (valid request)"
echo "  Test 2: ERROR -32602 (path traversal blocked)"
echo "  Test 3: ERROR -32602 (invalid enum)"
echo "  Test 4: ERROR -32602 (missing required field)"
```

---

## 🎯 Résumé du Déploiement

### Fonctionnalités Déployées

| Fonctionnalité | Status | Composant | Port |
|----------------|--------|-----------|------|
| **Token Revocation** | ✅ Deployed | PostgreSQL table + Admin API | 9000 |
| **JSON Schema Validation** | ✅ Deployed | Agents updated | N/A |
| **Pydantic Models** | ✅ Deployed | Agents updated | N/A |
| **Enhanced Logging** | ✅ Deployed | Agents updated | N/A |
| **Admin API** | ✅ Deployed | ECS Fargate service | 9000 |
| **MCP Server** | ✅ Already deployed | ECS Fargate service (2 instances) | 8000 |

### Architecture Finale

```
🌐 Internet
   ↓ HTTPS
📊 ALB
   ↓
🎯 Orchestrator :8001 (v5.1 with JSON Schema + Pydantic)
   ↓
┌─────────────────────┐
│ Extractor    :8002  │ (v5.1)
│ Validator    :8003  │ (v5.1)
│ Archivist    :8004  │ (v5.1)
└─────────────────────┘
   ↓
🔐 MCP Server :8000 (2 instances)
   ↓
┌─────────────────────┐
│ RDS Aurora          │ ← with revoked_tokens table
│ S3 Bucket           │
│ Keycloak :8080      │
└─────────────────────┘

🛡️ Admin API :9000 (new)
   ↓
RDS (for token revocation management)
```

### Commandes Utiles

```bash
# Vérifier le statut des services
aws ecs list-services --cluster ca-a2a-cluster --region eu-west-3

# Voir les logs Admin API
aws logs tail /ecs/ca-a2a-admin-api --follow --region eu-west-3

# Redéployer un agent
aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --force-new-deployment --region eu-west-3

# Vérifier la table revoked_tokens
# (nécessite psql ou connection depuis un agent)
psql -h documents-db.cluster-czkdu9wcburt.eu-west-3.rds.amazonaws.com -U postgres -d documents -c "SELECT COUNT(*) FROM revoked_tokens;"

# Tester l'Admin API
curl http://admin-api.ca-a2a.local:9000/health
```

---

## ✅ Checklist Finale

Avant de considérer le déploiement comme complet :

- [ ] Migration de base de données exécutée (`revoked_tokens` table créée)
- [ ] Admin API déployé et ACTIVE
- [ ] Tous les agents (4) redéployés avec v5.1
- [ ] CloudWatch log groups créés pour tous les services
- [ ] Security groups configurés pour Admin API
- [ ] Tests fonctionnels passés :
  - [ ] Admin API health check
  - [ ] Token revocation endpoints
  - [ ] JSON Schema validation (path traversal bloqué)
  - [ ] Pydantic validation
- [ ] Keycloak opérationnel (1 task running)
- [ ] MCP Server opérationnel (2 tasks running)
- [ ] Documentation mise à jour

---

## 🆘 Troubleshooting

### Problème : Admin API ne démarre pas

**Symptôme :** `STOPPED` tasks, health checks échouent

**Solution :**
```bash
# Vérifier les logs
aws logs tail /ecs/ca-a2a-admin-api --since 10m --region eu-west-3

# Erreur commune : PostgreSQL connection failed
# → Vérifier que le security group permet le trafic vers RDS
# → Vérifier que le secret `ca-a2a/db-password` existe

# Vérifier le secret
aws secretsmanager get-secret-value --secret-id ca-a2a/db-password --region eu-west-3
```

### Problème : Migration de base de données échoue

**Symptôme :** `psycopg2.OperationalError: could not connect to server`

**Solution :**
```bash
# Option 1: Exécuter depuis un agent existant (orchestrator)
TASK_ID=$(aws ecs list-tasks --cluster ca-a2a-cluster --service-name orchestrator --region eu-west-3 --query 'taskArns[0]' --output text | cut -d'/' -f3)

aws ecs execute-command \
    --cluster ca-a2a-cluster \
    --task ${TASK_ID} \
    --container orchestrator \
    --interactive \
    --command "/bin/bash" \
    --region eu-west-3

# Puis dans le container:
psql -h documents-db.cluster-xxx.eu-west-3.rds.amazonaws.com -U postgres -d documents
# Copy-paste le SQL de migrations/001_create_revoked_tokens_table.sql
```

### Problème : JSON Schema validation ne fonctionne pas

**Symptôme :** Requêtes avec path traversal passent quand même

**Solution :**
```bash
# Vérifier que a2a_security_enhanced.py est dans l'image Docker
docker run --rm 555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a-orchestrator:latest ls -la | grep a2a_security

# Vérifier les logs pour voir si validation est appelée
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3 | grep "validation"

# Forcer rebuild et redeploy
./update-agents-v5.1.sh
```

---

**FIN DU GUIDE DE DÉPLOIEMENT V5.1**

Pour toute question ou problème, consultez :
- `A2A_SECURITY_ARCHITECTURE.md` (documentation technique)
- `A2A_ATTACK_SCENARIOS_DETAILED.md` (scénarios de sécurité)
- CloudWatch Logs : `/ecs/ca-a2a-*`

