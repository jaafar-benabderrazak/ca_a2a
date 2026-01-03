# 🚀 CloudShell Deployment Guide - Enhanced Security

**Quick Start Guide for Deploying Enhanced Security Features in AWS CloudShell**

---

## ⚠️ IMPORTANT: Run in AWS CloudShell, NOT Local Terminal!

The error you encountered happened because you were running these commands in **local PowerShell** on Windows. All deployment commands **must** be run in **AWS CloudShell**.

---

## 🎯 Step-by-Step CloudShell Deployment

### **Step 1: Open AWS CloudShell**

1. Log into AWS Console: https://console.aws.amazon.com/
2. Click the **CloudShell icon** in the top-right navigation bar (looks like `>_`)
3. Wait for CloudShell to initialize (~30 seconds)

### **Step 2: Resolve Local Git Conflict (In CloudShell)**

```bash
# Navigate to project directory
cd ~/ca_a2a || git clone https://github.com/jaafar-benabderrazak/ca_a2a.git ~/ca_a2a
cd ~/ca_a2a

# Stash any local changes
git stash

# Pull latest code
git pull origin main

# Verify deployment script exists
ls -lh deploy-enhanced-security.sh
# Should show: -rw-r--r-- 1 cloudshell-user cloudshell-user 16K ...
```

**Expected Output:**
```
Saved working directory and index state WIP on main: ff24693 ...
From https://github.com/jaafar-benabderrazak/ca_a2a
   aef0e81..d0111e3  main       -> origin/main
Updating ff24693..d0111e3
Fast-forward
 SECURITY_TESTING_DOCUMENTATION.md              | 846 +++++++++
 a2a_security_enhanced.py                       | 740 ++++++++
 a2a_security_integrated.py                     | 275 +++
 test_security_enhanced.py                      | 490 ++++++
 env.security.enhanced.example                  | 240 +++
 deploy-enhanced-security.sh                    | 490 ++++++
 ...
```

---

### **Step 3: Make Script Executable**

```bash
chmod +x deploy-enhanced-security.sh
```

---

### **Step 4: Run Deployment**

```bash
./deploy-enhanced-security.sh
```

**This will take approximately 5-7 minutes and will:**

1. ✅ Install Python dependencies (jsonschema, pyOpenSSL)
2. ✅ Generate HMAC secrets (64-character random)
3. ✅ Generate JWT RSA key pair (2048-bit)
4. ✅ Generate mTLS certificates (CA + agent certs)
5. ✅ Run 25 local security tests
6. ✅ Initialize database schema (revoked_tokens table)
7. ✅ Update all ECS task definitions (orchestrator, extractor, validator, archivist)
8. ✅ Deploy new configurations to AWS ECS
9. ✅ Wait 60 seconds for services to stabilize
10. ✅ Run end-to-end security tests
11. ✅ Perform security audit
12. ✅ Display comprehensive summary

---

### **Step 5: Monitor Deployment Progress**

The script will display real-time progress:

```
============================================
ENHANCED SECURITY DEPLOYMENT & TESTING
============================================

Step 1: Installing enhanced security dependencies...
✓ Dependencies installed

Step 2: Generating security credentials...
✓ Generated HMAC secret
✓ Generated JWT key pair
✓ Generated mTLS certificates

Step 3: Running local security tests...
============================= test session starts ==============================
test_security_enhanced.py::TestHMACRequestSigning::test_sign_and_verify_valid_request PASSED [  4%]
test_security_enhanced.py::TestHMACRequestSigning::test_reject_tampered_body PASSED [  8%]
...
===================== 23 passed, 2 skipped in 0.81s =======================
✓ PASSED: Local security tests

Step 4: Updating database schema for token revocation...
Database host: documents-db.cluster-abc123.eu-west-3.rds.amazonaws.com
✓ Database schema initialized
✓ PASSED: Database schema initialization

Step 5: Updating ECS task definitions with enhanced security...
Updating orchestrator...
✓ Updated orchestrator task definition
✓ Deployed orchestrator with new configuration
✓ PASSED: orchestrator security update

Updating extractor...
✓ Updated extractor task definition
✓ Deployed extractor with new configuration
✓ PASSED: extractor security update

[... similar for validator and archivist ...]

Waiting 60 seconds for services to stabilize...

Step 6: Testing enhanced security features end-to-end...
6.1 Testing HMAC request signing...
HMAC signature generated: 1735867200:a3f2c9d8...
✓ PASSED: HMAC signature generation

6.2 Testing JSON Schema validation...
✓ Schema validation working correctly
✓ PASSED: JSON Schema validation

6.3 Testing token revocation...
✓ Token revocation working correctly
✓ PASSED: Token revocation

6.4 Testing end-to-end pipeline with enhanced security...
✓ Uploaded test document: invoices/2026/01/security_test_1735867245.pdf
Waiting 45 seconds for pipeline processing...

Checking security features in logs...
✓ PASSED: End-to-end pipeline with enhanced security
  - HMAC mentions in logs: 12
  - Schema validation mentions: 8

Step 7: Security audit...
Auditing orchestrator...
Security environment variables:
  A2A_ENABLE_HMAC_SIGNING: true
  A2A_HMAC_SECRET_KEY: [REDACTED]
  A2A_ENABLE_SCHEMA_VALIDATION: true
  A2A_ENABLE_TOKEN_REVOCATION: true

[... similar for other agents ...]

============================================
TEST SUMMARY
============================================
Passed:   11
Failed:   0

Success Rate: 100%

============================================
✓ ALL TESTS PASSED - ENHANCED SECURITY OPERATIONAL
============================================
```

---

## ✅ Expected Final Result

```
============================================
✓ ALL TESTS PASSED - ENHANCED SECURITY OPERATIONAL
============================================
```

---

## 🔍 Verifying Deployment

After successful deployment, verify all features are working:

### **Check Service Health**

```bash
# Check all ECS services
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist \
  --region eu-west-3 \
  --query 'services[*].[serviceName,runningCount,desiredCount]' \
  --output table

# Expected output:
# ----------------------------------------
# |         DescribeServices             |
# +-------------+-----------+------------+
# | orchestrator|     1     |     1      |
# | extractor   |     1     |     1      |
# | validator   |     1     |     1      |
# | archivist   |     1     |     1      |
# +-------------+-----------+------------+
```

### **Test with Real Invoice**

```bash
# Upload a test invoice
aws s3 cp facture_acme_dec2025.pdf \
  s3://ca-a2a-documents-555043101106/invoices/2026/01/test_$(date +%s).pdf \
  --region eu-west-3

# Wait 45 seconds
sleep 45

# Check orchestrator logs for security features
aws logs tail /ecs/ca-a2a-orchestrator --since 2m --region eu-west-3 | \
  grep -E "HMAC|Schema|validation|completed"
```

### **Check Database for Archived Document**

```bash
# Get database credentials
DB_HOST=$(aws rds describe-db-clusters \
  --region eu-west-3 \
  --db-cluster-identifier documents-db \
  --query 'DBClusters[0].Endpoint' \
  --output text)

echo "Database host: $DB_HOST"

# Use RDS Query Editor in AWS Console:
# 1. Go to: https://console.aws.amazon.com/rds/
# 2. Click "Query Editor" in left menu
# 3. Select cluster: documents-db
# 4. Authentication: Password
# 5. Database username: postgres
# 6. Password: benabderrazak
# 7. Database name: documents_db
# 8. Run query:
#    SELECT document_id, original_filename, status, created_at 
#    FROM documents 
#    ORDER BY created_at DESC 
#    LIMIT 5;
```

---

## 🛠️ Troubleshooting Common Issues

### **Issue 1: "chmod: cannot access"**

**Cause:** Running in local PowerShell instead of CloudShell

**Solution:** Follow Step 1 to open AWS CloudShell

---

### **Issue 2: "git: Your local changes would be overwritten"**

**Cause:** Local modifications in CloudShell

**Solution:**
```bash
cd ~/ca_a2a
git stash  # Save local changes
git pull   # Pull latest
```

---

### **Issue 3: "pip install: command not found"**

**Cause:** Python not in PATH (rare in CloudShell)

**Solution:**
```bash
python3 -m pip install jsonschema pyOpenSSL
```

---

### **Issue 4: "AWS CLI: Unable to locate credentials"**

**Cause:** CloudShell session expired or not initialized

**Solution:**
1. Close CloudShell
2. Reopen CloudShell (it auto-configures credentials)
3. Retry deployment

---

### **Issue 5: "Services not stabilizing"**

**Cause:** Services taking longer than expected to start

**Solution:**
```bash
# Check service status
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist \
  --region eu-west-3 \
  --query 'services[*].[serviceName,status,deployments[0].rolloutState]' \
  --output table

# Wait additional time
sleep 60

# Check logs for errors
aws logs tail /ecs/ca-a2a-orchestrator --since 5m --region eu-west-3 | tail -30
```

---

## 📊 What Was Deployed

### **Security Features Activated:**

| Feature | Environment Variable | Value |
|---------|---------------------|-------|
| **HMAC Signing** | `A2A_ENABLE_HMAC_SIGNING` | `true` |
| **HMAC Secret** | `A2A_HMAC_SECRET_KEY` | `[64-char random]` |
| **JSON Schema** | `A2A_ENABLE_SCHEMA_VALIDATION` | `true` |
| **Token Revocation** | `A2A_ENABLE_TOKEN_REVOCATION` | `true` |
| **mTLS** | `A2A_ENABLE_MTLS` | `false` (optional) |

### **Database Changes:**

New table `revoked_tokens`:
```sql
CREATE TABLE revoked_tokens (
    jti VARCHAR(255) PRIMARY KEY,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_by VARCHAR(100) NOT NULL,
    reason TEXT,
    expires_at TIMESTAMP NOT NULL
);
```

### **Updated Services:**

- ✅ **Orchestrator** (ca-a2a-orchestrator) - New revision deployed
- ✅ **Extractor** (ca-a2a-extractor) - New revision deployed
- ✅ **Validator** (ca-a2a-validator) - New revision deployed
- ✅ **Archivist** (ca-a2a-archivist) - New revision deployed

---

## 🎯 Next Steps

After successful deployment:

1. ✅ **Test with Production Data** - Upload real invoices and verify processing
2. ✅ **Monitor Performance** - Check CloudWatch metrics for latency impact
3. ✅ **Review Security Audit** - Examine the security audit output
4. ✅ **Update Documentation** - Document any environment-specific configurations
5. ✅ **Train Team** - Share security features with team members
6. ✅ **Enable mTLS (Optional)** - For highest security environments

---

## 📚 Related Documentation

- **SECURITY_TESTING_DOCUMENTATION.md** - Detailed test explanations
- **ENHANCED_SECURITY_IMPLEMENTATION_REPORT.md** - Implementation summary
- **a2a_security_enhanced.py** - Core security code
- **test_security_enhanced.py** - Test suite
- **env.security.enhanced.example** - Configuration template

---

## ✅ Success Criteria

Your deployment is successful when:

- ✅ All local tests pass (23/23)
- ✅ All 4 ECS services updated and running
- ✅ Database schema initialized
- ✅ End-to-end test completes successfully
- ✅ Security audit shows all features enabled
- ✅ Final summary shows: **"ALL TESTS PASSED - ENHANCED SECURITY OPERATIONAL"**

---

**Document Version:** 1.0  
**Last Updated:** January 3, 2026  
**Region:** eu-west-3  
**Environment:** Production AWS ECS

---

**Need Help?**

Check the logs:
```bash
# Orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator --since 10m --region eu-west-3

# Extractor logs
aws logs tail /ecs/ca-a2a-extractor --since 10m --region eu-west-3

# Validator logs
aws logs tail /ecs/ca-a2a-validator --since 10m --region eu-west-3

# Archivist logs
aws logs tail /ecs/ca-a2a-archivist --since 10m --region eu-west-3
```

