# Quick Deployment Checklist - v5.1

**Execute these commands in order after AWS authentication**

## ⚠️ Prerequisites

```bash
# 1. Verify AWS credentials are valid
aws sts get-caller-identity --region eu-west-3

# 2. Navigate to project directory
cd /path/to/ca_a2a
```

---

## 🚀 Deployment Commands (Copy-Paste Ready)

### Step 1: Database Migration

```bash
# Create and run migration
chmod +x migrations/run_migration.sh
./migrations/run_migration.sh
```

### Step 2: Deploy Admin API

```bash
# Make script executable and deploy
chmod +x deploy-admin-api.sh
./deploy-admin-api.sh
```

### Step 3: Update All Agents

```bash
# Create update script
cat > update-agents-v5.1.sh << 'EOF'
#!/bin/bash
REGION="eu-west-3"
PROJECT_NAME="ca-a2a"
AWS_ACCOUNT_ID="555043101106"
AGENTS=("orchestrator" "extractor" "validator" "archivist")

# Login to ECR
aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com

for AGENT in "${AGENTS[@]}"; do
    echo "Updating ${AGENT}..."
    docker build -t ${PROJECT_NAME}-${AGENT}:latest -f Dockerfile.${AGENT} .
    docker tag ${PROJECT_NAME}-${AGENT}:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PROJECT_NAME}-${AGENT}:latest
    docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PROJECT_NAME}-${AGENT}:latest
    aws ecs update-service --cluster ${PROJECT_NAME}-cluster --service ${AGENT} --force-new-deployment --region ${REGION}
    echo "✅ ${AGENT} updated"
done
EOF

chmod +x update-agents-v5.1.sh
./update-agents-v5.1.sh
```

### Step 4: Verify Deployment

```bash
# Create and run verification script
chmod +x verify-deployment-v5.1.sh
./verify-deployment-v5.1.sh
```

### Step 5: Functional Tests

```bash
# Test Admin API
REGION="eu-west-3"
CLIENT_SECRET=$(aws secretsmanager get-secret-value --secret-id ca-a2a/keycloak-client-secret --region ${REGION} --query SecretString --output text)

ADMIN_TOKEN=$(curl -s -X POST "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=ca-a2a-agents" \
    -d "client_secret=${CLIENT_SECRET}" | jq -r '.access_token')

# Test health
curl -s "http://admin-api.ca-a2a.local:9000/health" | jq

# Test security stats
curl -s -X GET "http://admin-api.ca-a2a.local:9000/admin/security-stats" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq

# Test JSON Schema validation (should fail)
curl -s -X POST "http://orchestrator.ca-a2a.local:8001/api/v1/rpc" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":"test","method":"process_document","params":{"s3_key":"../../../etc/passwd"}}' | jq
```

---

## ✅ Expected Results

After successful deployment:

1. **Database Migration**
   ```
   ✅ MIGRATION COMPLETE
   Table 'revoked_tokens' created with 5 columns
   ```

2. **Admin API**
   ```
   ✅ ADMIN API DEPLOYED
   Service: admin-api (ACTIVE)
   Port: 9000
   ```

3. **Agent Updates**
   ```
   ✅ orchestrator redeployed
   ✅ extractor redeployed
   ✅ validator redeployed
   ✅ archivist redeployed
   ```

4. **Verification**
   ```
   ✅ Passed: 5/5
   🎉 ALL TESTS PASSED - V5.1 DEPLOYMENT SUCCESSFUL
   ```

5. **Functional Tests**
   ```
   - Health check: {"status": "healthy"}
   - Security stats: {...}
   - Path traversal: ERROR -32602 (blocked) ✅
   ```

---

## 🎯 Quick Status Check

```bash
# Check all services
aws ecs list-services --cluster ca-a2a-cluster --region eu-west-3 | grep "service/"

# Check running tasks
aws ecs list-tasks --cluster ca-a2a-cluster --region eu-west-3 --query 'taskArns[*]' --output table

# Check recent logs
aws logs tail /ecs/ca-a2a-admin-api --since 5m --region eu-west-3
aws logs tail /ecs/ca-a2a-orchestrator --since 5m --region eu-west-3
```

---

## 🆘 Quick Troubleshooting

### If Admin API fails to start:
```bash
# Check logs
aws logs tail /ecs/ca-a2a-admin-api --since 10m --region eu-west-3

# Common fix: Verify DB secret exists
aws secretsmanager get-secret-value --secret-id ca-a2a/db-password --region eu-west-3
```

### If migration fails:
```bash
# Run from orchestrator container
TASK_ID=$(aws ecs list-tasks --cluster ca-a2a-cluster --service-name orchestrator --region eu-west-3 --query 'taskArns[0]' --output text | cut -d'/' -f3)

aws ecs execute-command --cluster ca-a2a-cluster --task ${TASK_ID} --container orchestrator --interactive --command "/bin/bash" --region eu-west-3

# Then in container:
psql -h documents-db.cluster-czkdu9wcburt.eu-west-3.rds.amazonaws.com -U postgres -d documents < migrations/001_create_revoked_tokens_table.sql
```

### If agents don't update:
```bash
# Force new deployment
aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --force-new-deployment --region eu-west-3
aws ecs update-service --cluster ca-a2a-cluster --service extractor --force-new-deployment --region eu-west-3
aws ecs update-service --cluster ca-a2a-cluster --service validator --force-new-deployment --region eu-west-3
aws ecs update-service --cluster ca-a2a-cluster --service archivist --force-new-deployment --region eu-west-3
```

---

## 📊 Deployment Time Estimate

| Step | Duration | Complexity |
|------|----------|------------|
| Database Migration | 2-5 min | Low |
| Admin API Deployment | 5-10 min | Medium |
| Agent Updates | 15-20 min | Medium |
| Verification | 2-3 min | Low |
| **Total** | **25-40 min** | - |

---

## 📝 Post-Deployment

After successful deployment:

1. **Update documentation** (if needed)
2. **Notify team** of new Admin API endpoints
3. **Monitor CloudWatch** for first 24 hours
4. **Backup RDS** before any manual changes
5. **Test end-to-end** with real document processing

---

**For detailed instructions, see:** `DEPLOYMENT_GUIDE_V5.1.md`

