# CA-A2A CloudShell Deployment - Quick Reference

**Version:** 5.1.0  
**Date:** January 25, 2026

---

## 🚀 Quick Start (3 Commands)

```bash
# 1. Pull latest changes
git pull

# 2. Run deployment
chmod +x cloudshell-complete-deploy.sh && ./cloudshell-complete-deploy.sh

# 3. Verify security
chmod +x verify-security-features.sh && ./verify-security-features.sh
```

**Deployment Time:** 15-20 minutes  
**Cost:** ~$310/month

---

## ✅ What Was Fixed

**Issue:** `$4: unbound variable` error on line 137

**Solution Applied:**
- Changed `set -euo pipefail` to `set -eo pipefail`
- Added default values to functions: `${1:-unknown}` and `${2:-Waiting}`
- Better handling of optional parameters

**Status:** ✅ Fixed and pushed to git

---

## 📋 Script Output Sections

1. **Configuration** - Shows AWS account, region, project name
2. **Prerequisites** - Checks AWS CLI, credentials, Docker
3. **Deployment Summary** - Lists all resources to be created
4. **Phase 1-9** - Creates infrastructure step-by-step
5. **Configuration Export** - Saves deployment details
6. **Summary** - Shows ALB DNS, RDS endpoints, S3 bucket, API key

---

## 🔑 Important: Save These Values

After deployment completes, **save these immediately**:

```bash
# Client API Key (shown once)
export A2A_CLIENT_API_KEY="<displayed-key>"

# Configuration file location
source /tmp/ca-a2a-deployment-config.env

# Key endpoints
echo "ALB DNS: $ALB_DNS"
echo "RDS Endpoint: $RDS_ENDPOINT"
echo "S3 Bucket: $S3_BUCKET"
```

---

## 🧪 Quick Testing

### Test 1: Health Check (No Auth)
```bash
curl http://${ALB_DNS}/health
# Expected: {"status":"healthy","agent":"orchestrator"}
```

### Test 2: With API Key
```bash
curl -X POST http://${ALB_DNS}/message \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${A2A_CLIENT_API_KEY}" \
  -d '{"jsonrpc":"2.0","method":"list_pending_documents","params":{},"id":1}'
```

### Test 3: Security Verification
```bash
./verify-security-features.sh
# Expected: 45/45 tests passed (100%)
```

---

## 📊 Deployment Progress Tracking

| Phase | Component | Duration | Status |
|-------|-----------|----------|--------|
| 1 | VPC & Networking | 3-5 min | ⏳ |
| 2 | Security Groups | 1 min | ⏳ |
| 3 | Secrets & Keys | 1 min | ⏳ |
| 4 | RDS & S3 | 8-10 min | ⏳ |
| 5 | VPC Endpoints | 2 min | ⏳ |
| 6 | IAM Roles | 1 min | ⏳ |
| 7 | ECS & CloudWatch | 1 min | ⏳ |
| 8 | Load Balancer | 1 min | ⏳ |
| 9 | Service Discovery | 1 min | ⏳ |

**Total:** ~15-20 minutes

---

## 🔒 Security Features Checklist

After deployment, verify these are implemented:

- [ ] Layer 1: Network Isolation ✓
  - Private VPC, no public IPs on agents
  - Security groups with egress hardening
  - NAT Gateway for outbound-only access

- [ ] Layer 2-3: Keycloak OAuth2 + JWT RS256 ✓
  - Keycloak service running
  - RSA-2048 keys in Secrets Manager
  - JWKS endpoint available

- [ ] Layer 4: RBAC Authorization ✓
  - Security groups enforce agent access
  - IAM roles follow least privilege

- [ ] Layer 5: MCP Server Gateway ✓
  - MCP Server has S3/RDS access
  - Agents have NO direct S3/RDS access
  - Centralized resource pattern enforced

- [ ] Layer 6: Encryption ✓
  - S3 bucket encrypted (AES-256)
  - RDS encrypted at rest
  - TLS for AWS services

- [ ] Layer 7: Input Validation ✓
  - JSON Schema validation implemented
  - Pydantic models for type safety

- [ ] Layer 8: Token Revocation ✓
  - revoked_tokens table created
  - Hybrid storage pattern ready

- [ ] Layer 9: Audit Logging ✓
  - CloudWatch log groups created
  - audit_log table created
  - 7-day retention configured

---

## 🆘 Common Issues & Fixes

### Issue: Script stops at "unbound variable"
**Status:** ✅ FIXED (pull latest changes)
```bash
git pull
```

### Issue: AWS credentials expired
```bash
aws sso login --profile <your-profile>
# OR
aws configure
```

### Issue: Docker not available
**Solution:** Use CodeBuild or local machine for image builds
```bash
# The script will deploy infrastructure only
# Build images separately on a machine with Docker
```

### Issue: RDS takes too long
**Normal:** RDS Aurora takes 8-10 minutes to create
```bash
# Monitor progress
aws rds describe-db-clusters \
  --db-cluster-identifier ca-a2a-documents-db \
  --query 'DBClusters[0].Status'
```

---

## 📁 Files Created by Script

### In `/tmp/`
- `ca-a2a-deployment-config.env` - All resource IDs and endpoints
- `ca-a2a-jwt-private.pem` - JWT private key (temporary)
- `ca-a2a-jwt-public.pem` - JWT public key (temporary)
- `init_documents_db.sql` - Database schema

### In S3
- `s3://ca-a2a-documents-{account}/config/deployment-config-{date}.env`
- `s3://ca-a2a-documents-{account}/migrations/init_documents_db.sql`

### In AWS Secrets Manager
- `ca-a2a/db-password`
- `ca-a2a/keycloak-db-password`
- `ca-a2a/keycloak-admin-password`
- `ca-a2a/keycloak-client-secret`
- `ca-a2a/a2a-jwt-private-key-pem`
- `ca-a2a/a2a-jwt-public-key-pem`
- `ca-a2a/a2a-client-api-keys-json`

---

## 🎯 Next Steps After Infrastructure Deployment

1. **Build Docker Images** (See: CLOUDSHELL_COMPLETE_DEPLOYMENT_GUIDE.md Phase 3)
   ```bash
   # On local machine with Docker
   ./build-and-push-images.sh
   ```

2. **Register Task Definitions** (Phase 4)
   ```bash
   cd task-definitions
   for service in orchestrator extractor validator archivist keycloak mcp-server; do
     aws ecs register-task-definition --cli-input-json file://${service}-task.json
   done
   ```

3. **Create ECS Services** (Phase 5)
   ```bash
   # Start with MCP Server (dependency)
   # Then Keycloak
   # Then agents (orchestrator, extractor, validator, archivist)
   ```

4. **Initialize Database** (Phase 6)
   ```bash
   # Use ECS Exec to connect to MCP Server container
   # Apply SQL schema from S3
   ```

5. **Configure Keycloak** (Phase 7)
   ```bash
   ./configure-keycloak.sh
   ```

6. **Test End-to-End** (Phase 8)
   ```bash
   curl http://${ALB_DNS}/health
   ./verify-security-features.sh
   ```

---

## 💡 Tips

- **Monitor Progress:** Check CloudWatch Logs during deployment
- **Save Configuration:** Always source the config file before running commands
- **Backup:** Configuration is automatically backed up to S3
- **Cost Tracking:** Use tags to monitor spending by project
- **Cleanup:** Keep the `cleanup-aws.sh` script for safe teardown

---

## 📞 Support

**Author:** Jaafar Benabderrazak  
**Documentation:**
- `CLOUDSHELL_COMPLETE_DEPLOYMENT_GUIDE.md` - Full guide
- `DEPLOYMENT_PACKAGE_SUMMARY.md` - Complete overview
- `a2a_security_architecture.md` - Security reference

**Git Status:** All changes committed and pushed ✓

---

**Ready to deploy! 🚀**

