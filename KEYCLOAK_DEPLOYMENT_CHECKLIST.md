# Keycloak Deployment Checklist

Complete step-by-step checklist for deploying Keycloak OAuth2 authentication to AWS.

## Pre-Deployment Checklist

### ✅ Prerequisites
- [ ] CA-A2A infrastructure deployed and operational
- [ ] Access to AWS CloudShell or VPC-connected environment
- [ ] AWS CLI configured with appropriate permissions
- [ ] Git repository cloned and up to date

### ✅ Verify Current System
```bash
# Check ECS cluster is running
aws ecs describe-clusters --cluster ca-a2a-cluster --region eu-west-3

# Check all 4 agent services are healthy
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator extractor validator archivist \
    --region eu-west-3 \
    --query 'services[*].{Name:serviceName,Status:status,Running:runningCount}'

# Check RDS is available
aws rds describe-db-clusters \
    --db-cluster-identifier documents-db \
    --region eu-west-3 \
    --query 'DBClusters[0].Status'
```

---

## Phase 1: Deploy Keycloak Service (15 minutes)

### Step 1: Pull Latest Code
```bash
cd ca_a2a
git pull origin main
```

**Expected:** Latest code with Keycloak integration

### Step 2: Make Scripts Executable
```bash
chmod +x deploy-keycloak.sh
chmod +x configure-keycloak.sh
chmod +x update-agents-keycloak.sh
chmod +x test-keycloak-auth.sh
```

**Verify:**
```bash
ls -la *.sh | grep -E "(deploy-keycloak|configure-keycloak|update-agents-keycloak|test-keycloak-auth)"
```

### Step 3: Deploy Keycloak
```bash
./deploy-keycloak.sh
```

**Expected output:**
```
============================================
KEYCLOAK DEPLOYMENT COMPLETE
============================================

Keycloak Admin Console:
  Internal URL: http://keycloak.ca-a2a.local:8080
  Admin Username: admin
  Admin Password: (stored in Secrets Manager)
```

**Time:** ~5 minutes

**Verify:**
- [ ] Keycloak admin password created in Secrets Manager
- [ ] CloudWatch log group `/ecs/ca-a2a-keycloak` created
- [ ] Security group `ca-a2a-keycloak-sg` created
- [ ] ECS service `keycloak` running (1/1 tasks)
- [ ] Service discovery `keycloak.ca-a2a.local` registered

```bash
# Check Keycloak service status
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services keycloak \
    --region eu-west-3 \
    --query 'services[0].{Status:status,Running:runningCount,Desired:desiredCount}'

# Check CloudWatch logs
aws logs tail /ecs/ca-a2a-keycloak --since 10m --region eu-west-3 | grep "Keycloak.*started"
```

**Troubleshooting:**
- If service fails to start, check logs: `aws logs tail /ecs/ca-a2a-keycloak --follow --region eu-west-3`
- Common issue: Database connection - verify RDS security group allows Keycloak SG

---

## Phase 2: Configure Keycloak Realm (10 minutes)

### Step 4: Access VPC Environment

**Option A: Via ECS Exec (Recommended)**
```bash
# Get Keycloak task ID
TASK_ID=$(aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --service-name keycloak \
    --region eu-west-3 \
    --query 'taskArns[0]' \
    --output text | cut -d'/' -f3)

echo "Task ID: $TASK_ID"

# Connect to Keycloak container
aws ecs execute-command \
    --cluster ca-a2a-cluster \
    --task $TASK_ID \
    --container keycloak \
    --interactive \
    --command "/bin/bash" \
    --region eu-west-3
```

**Option B: CloudShell (if VPC accessible)**
If your CloudShell has VPC access, you can run directly from CloudShell.

### Step 5: Run Configuration Script

**Inside Keycloak container or VPC-connected environment:**
```bash
# If in Keycloak container, first install AWS CLI
yum install -y aws-cli curl

# Download configuration script
cd /tmp
curl -O https://raw.githubusercontent.com/jaafar-benabderrazak/ca_a2a/main/configure-keycloak.sh
chmod +x configure-keycloak.sh

# Run configuration
./configure-keycloak.sh
```

**Expected output:**
```
============================================
KEYCLOAK CONFIGURATION COMPLETE
============================================

Realm: ca-a2a
Client ID: ca-a2a-agents
Client Secret: (stored in ca-a2a/keycloak-client-secret)

Service Accounts Created:
  - lambda-service (role: lambda)
  - orchestrator-service (role: orchestrator)
  - admin-user (role: admin)
```

**Time:** ~3 minutes

**Verify:**
- [ ] Realm `ca-a2a` created
- [ ] Client `ca-a2a-agents` created
- [ ] 5 roles created (admin, lambda, orchestrator, document-processor, viewer)
- [ ] 3 users created with passwords in Secrets Manager
- [ ] Client secret stored in Secrets Manager

```bash
# Verify secrets (run from CloudShell)
aws secretsmanager list-secrets \
    --region eu-west-3 \
    --query 'SecretList[?contains(Name, `keycloak`)].Name'
```

**Expected:**
```
[
    "ca-a2a/keycloak-admin-password",
    "ca-a2a/keycloak-client-secret",
    "ca-a2a/keycloak-admin-user-password"
]
```

---

## Phase 3: Update Agent Services (10 minutes)

### Step 6: Update Agent Task Definitions
```bash
# Exit from Keycloak container if still connected
exit

# Return to CloudShell in ca_a2a directory
cd ca_a2a

# Run update script
./update-agents-keycloak.sh
```

**Prompt:** "Deploy updated services now? (y/n):"
- Type **`y`** to deploy immediately (recommended)
- Type **`n`** to deploy manually later

**Expected output:**
```
============================================
TASK DEFINITIONS UPDATED
============================================

Next steps:
  1. Deploy updated agents: ./deploy.sh
  OR
  2. Update services individually [commands provided]
```

**Time:** ~5 minutes

**Verify:**
- [ ] All 4 task definitions updated with Keycloak env vars
- [ ] Services redeploying (if you selected 'y')

```bash
# Check service deployments
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator extractor validator archivist \
    --region eu-west-3 \
    --query 'services[*].{Name:serviceName,Running:runningCount,Desired:desiredCount,Deployments:length(deployments)}'
```

**Wait for services to stabilize (~3-5 minutes):**
```bash
aws ecs wait services-stable \
    --cluster ca-a2a-cluster \
    --services orchestrator extractor validator archivist \
    --region eu-west-3

echo "All services are stable!"
```

---

## Phase 4: Test Authentication (5 minutes)

### Step 7: Run Authentication Test
```bash
./test-keycloak-auth.sh
```

**Expected output:**
```
============================================
KEYCLOAK AUTHENTICATION TEST COMPLETE
============================================

Summary:
  ✓ Token Endpoint: Working
  ✓ JWKS Endpoint: Accessible
  ✓ Token Issuance: Successful
  ✓ Token Refresh: Working
  ✓ Service Integration: Tested

Keycloak authentication is properly configured!
```

**Time:** ~2 minutes

**Verify:**
- [ ] Token endpoint accessible
- [ ] JWKS endpoint returns public keys
- [ ] Admin user can authenticate
- [ ] Token refresh works
- [ ] Orchestrator accepts Keycloak JWT

### Step 8: Manual Verification (Optional)

**Test token issuance:**
```bash
# Get credentials
CLIENT_SECRET=$(aws secretsmanager get-secret-value \
    --secret-id ca-a2a/keycloak-client-secret \
    --query SecretString --output text --region eu-west-3)

ADMIN_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id ca-a2a/keycloak-admin-user-password \
    --query SecretString --output text --region eu-west-3)

# Get token (requires VPC access)
curl -X POST "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=ca-a2a-agents" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "username=admin-user" \
    -d "password=$ADMIN_PASSWORD" | jq
```

**Expected:** JSON response with `access_token`, `refresh_token`, `expires_in`

---

## Phase 5: Validation & Documentation (5 minutes)

### Step 9: System Health Check

**Check all services:**
```bash
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services keycloak orchestrator extractor validator archivist \
    --region eu-west-3 \
    --query 'services[*].{Name:serviceName,Status:status,Running:runningCount,Desired:desiredCount}' \
    --output table
```

**Expected:** All services show `Running: 1, Desired: 1`

**Check CloudWatch logs:**
```bash
# Keycloak logs
aws logs tail /ecs/ca-a2a-keycloak --since 5m --region eu-west-3 | grep -i error || echo "No errors"

# Orchestrator logs (should show Keycloak initialization)
aws logs tail /ecs/ca-a2a-orchestrator --since 5m --region eu-west-3 | grep -i keycloak
```

**Expected:** Keycloak validator initialized messages in orchestrator logs

### Step 10: Document Deployment

**Record deployment details:**
```bash
cat > keycloak-deployment-$(date +%Y%m%d).txt <<EOF
Keycloak Deployment Completed: $(date)

Keycloak Service:
  URL: http://keycloak.ca-a2a.local:8080
  Admin Username: admin
  Admin Password: (Secrets Manager: ca-a2a/keycloak-admin-password)

Configuration:
  Realm: ca-a2a
  Client ID: ca-a2a-agents
  Client Secret: (Secrets Manager: ca-a2a/keycloak-client-secret)

Users:
  - admin-user (role: admin)
  - lambda-service (role: lambda)
  - orchestrator-service (role: orchestrator)

Agent Services Updated:
  - orchestrator
  - extractor
  - validator
  - archivist

Environment Variables Added:
  A2A_USE_KEYCLOAK=true
  KEYCLOAK_URL=http://keycloak.ca-a2a.local:8080
  KEYCLOAK_REALM=ca-a2a
  KEYCLOAK_CLIENT_ID=ca-a2a-agents

Testing:
  - Authentication: ✓ Successful
  - Token Issuance: ✓ Working
  - Token Refresh: ✓ Working
  - Service Integration: ✓ Tested
EOF

cat keycloak-deployment-$(date +%Y%m%d).txt
```

---

## Post-Deployment Verification

### ✅ Final Checks

- [ ] **Keycloak service is running and healthy**
  ```bash
  aws ecs describe-services --cluster ca-a2a-cluster --services keycloak --region eu-west-3 \
      --query 'services[0].{Status:status,Running:runningCount}'
  ```

- [ ] **All agent services are running with updated task definitions**
  ```bash
  aws ecs describe-services --cluster ca-a2a-cluster \
      --services orchestrator extractor validator archivist --region eu-west-3 \
      --query 'services[*].{Name:serviceName,TaskDef:taskDefinition}' --output table
  ```

- [ ] **Secrets are stored in Secrets Manager**
  ```bash
  aws secretsmanager list-secrets --region eu-west-3 \
      --query 'SecretList[?contains(Name, `keycloak`)].Name' --output table
  ```

- [ ] **CloudWatch logs show no errors**
  ```bash
  aws logs tail /ecs/ca-a2a-keycloak --since 10m --region eu-west-3 | grep -i error || echo "No errors found"
  ```

- [ ] **Authentication test passed**
  ```bash
  ./test-keycloak-auth.sh | grep "COMPLETE"
  ```

---

## Rollback Procedure (If Needed)

### Quick Rollback

If you encounter issues, you can roll back agents to previous task definitions:

```bash
# Get previous task definition revision
PREV_REV=$(expr $(aws ecs describe-services --cluster ca-a2a-cluster --services orchestrator \
    --region eu-west-3 --query 'services[0].taskDefinition' --output text | grep -oP '\d+$') - 1)

# Rollback orchestrator (repeat for other agents)
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service orchestrator \
    --task-definition ca-a2a-orchestrator:$PREV_REV \
    --region eu-west-3

# Remove Keycloak service (optional)
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service keycloak \
    --desired-count 0 \
    --region eu-west-3
```

---

## Troubleshooting

### Issue: Keycloak service won't start

**Check:**
```bash
aws logs tail /ecs/ca-a2a-keycloak --since 30m --region eu-west-3 | grep -i error
```

**Common causes:**
- Database connection failed → Check RDS security group
- Database 'keycloak' doesn't exist → Create it manually
- Insufficient memory → Increase task definition memory

### Issue: Cannot reach Keycloak URL

**Remember:** Keycloak is only accessible from within VPC. Use:
- ECS Exec to connect to Keycloak container
- CloudShell with VPC access
- Bastion host in VPC

### Issue: Agent services failing health checks

**Check logs:**
```bash
aws logs tail /ecs/ca-a2a-orchestrator --since 10m --region eu-west-3 | grep -i error
```

**Common causes:**
- Keycloak environment variables misconfigured
- Client secret not accessible
- Keycloak service not reachable

---

## Success Criteria

✅ **Deployment is successful when:**

1. Keycloak service is running (1/1 tasks)
2. All 4 agent services are running with updated task definitions
3. Authentication test passes all checks
4. No errors in CloudWatch logs
5. Secrets are properly stored in Secrets Manager
6. Token issuance and refresh work correctly
7. Agents can validate Keycloak JWTs

---

## Next Steps After Deployment

### Optional Enhancements

1. **External Access (Production)**
   - Add ALB for external Keycloak access
   - Configure HTTPS with ACM certificate
   - Restrict access to specific IP ranges

2. **User Management**
   - Access Keycloak admin console (via port forward or ALB)
   - Create additional users
   - Configure password policies
   - Enable MFA (TOTP)

3. **Monitoring**
   - Set up CloudWatch alarms for Keycloak health
   - Configure log retention policies
   - Enable CloudTrail auditing

4. **Integration**
   - Update Lambda functions to use Keycloak
   - Integrate with frontend applications
   - Configure SSO for admin interfaces

---

## Documentation References

- **Comprehensive Guide:** `KEYCLOAK_INTEGRATION_GUIDE.md`
- **Quick Start:** `KEYCLOAK_QUICK_START.md`
- **Implementation Summary:** `KEYCLOAK_IMPLEMENTATION_SUMMARY.md`
- **Test Guide:** `test-keycloak-auth.sh`
- **Client Examples:** `keycloak_client_example.py`

---

## Deployment Complete! 🎉

**Total Time:** ~45 minutes
**Result:** Centralized OAuth2/OIDC authentication with Keycloak

Your CA-A2A system now has enterprise-grade authentication with:
- Centralized user management
- JWT token security
- Role-based access control
- MFA support (configurable)
- Comprehensive audit logging
- Backward compatibility with legacy auth

**Questions or issues?** Refer to `KEYCLOAK_INTEGRATION_GUIDE.md` or check CloudWatch logs.

