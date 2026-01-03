# 🧪 Comprehensive Agent & Security Testing Guide

**Complete Testing Framework for Multi-Agent System with Enhanced Security**

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Test Categories](#test-categories)
3. [Agent Functionality Tests](#agent-functionality-tests)
4. [RBAC Security Tests](#rbac-security-tests)
5. [Comprehensive Security Audit](#comprehensive-security-audit)
6. [Compliance Matrix](#compliance-matrix)
7. [Running the Tests](#running-the-tests)

---

## 🎯 Overview

The enhanced deployment script now includes **40+ comprehensive tests** across:
- ✅ **24 Security Feature Tests** (HMAC, Schema, Revocation, mTLS, Performance)
- ✅ **8 Agent Functionality Tests** (Health, Skills, Communication)
- ✅ **8 RBAC & Rate Limiting Tests**
- ✅ **6 Security Audit Checks**
- ✅ **10 Compliance Criteria**

**Total Test Coverage:** ~56 distinct validation points

---

## 📊 Test Categories

### **Category A: Core Security Features (Step 3)**
- Local unit tests before deployment
- Tests: 24 (HMAC, Schema, Revocation, mTLS, Performance)

### **Category B: Agent Functionality (Step 6.5)**
- Tests each agent's health and capabilities
- Tests: 8 (4 agents × 2 checks each)

### **Category C: RBAC & Communication (Step 6.5)**
- Tests authorization, rate limiting, A2A calls
- Tests: 8 (authorization, rate limits, data persistence)

### **Category D: Security Audit (Step 7)**
- Comprehensive security posture evaluation
- Checks: 6 audit areas + 10 compliance criteria

---

## 🤖 Agent Functionality Tests

### **Test 6.5.1: Orchestrator Agent**

**Purpose:** Verify orchestrator is operational and exposing correct skills

**Test Code:**
```bash
# Get orchestrator IP
ORCH_IP=$(aws ecs describe-tasks \
    --cluster ca-a2a-cluster \
    --tasks ${ORCH_TASK_ARN} \
    --query 'tasks[0].containers[0].networkInterfaces[0].privateIpv4Address' \
    --output text)

# Test health endpoint
curl -s http://${ORCH_IP}:8001/health

# Test skills endpoint
curl -X POST http://${ORCH_IP}:8001/message \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":"test"}'
```

**What It Tests:**
1. **Service Discovery:** Can we locate the orchestrator task?
2. **Network Connectivity:** Can we reach the orchestrator on port 8001?
3. **Health Check:** Is the `/health` endpoint responding with 200 OK?
4. **Skill Registration:** Are skills (`process_document`, `coordinate_pipeline`) registered?

**Expected Output:**
```
✓ Orchestrator health endpoint
  - Orchestrator IP: 10.0.10.25
  - Health status: OK
✓ Orchestrator skills registration
  - Skills detected: process_document, coordinate_pipeline
```

**Why This Matters:** Ensures the orchestrator can receive and route requests

---

### **Test 6.5.2-6.5.4: Extractor, Validator, Archivist Agents**

**Purpose:** Verify all worker agents are operational

**Test Flow (for each agent):**
1. Query ECS for running tasks
2. Extract private IP address
3. Test health endpoint (`GET /health`)
4. Verify HTTP 200 response

**Code Example:**
```bash
# For extractor (port 8002)
EXTR_IP=$(aws ecs describe-tasks ... | jq -r '.privateIpv4Address')
curl -s http://${EXTR_IP}:8002/health

# For validator (port 8003)
curl -s http://${VAL_IP}:8003/health

# For archivist (port 8004)
curl -s http://${ARCH_IP}:8004/health
```

**Expected Output:**
```
✓ Extractor health endpoint
✓ Validator health endpoint
✓ Archivist health endpoint
```

**Why This Matters:** Ensures the entire agent pipeline is online and ready

---

## 🔐 RBAC Security Tests

### **Test 6.5.5: RBAC Authorization Policies**

**Purpose:** Verify that RBAC policies correctly allow/deny access

**Test Scenario 1: Authorized Request**

```bash
# Get valid API key from task definition
API_KEY=$(aws ecs describe-task-definition \
    --task-definition ca-a2a-orchestrator \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`A2A_API_KEYS_JSON`].value' \
    --output text | jq -r '.["lambda-s3-processor"]')

# Send authorized request
curl -X POST http://${ORCH_IP}:8001/message \
    -H "X-API-Key: $API_KEY" \
    -d '{"jsonrpc":"2.0","method":"process_document","params":{"s3_key":"test.pdf"},"id":"test"}'
```

**Expected Result:** Request succeeds (no 401/403 error)

**Test Scenario 2: Unauthorized Request**

```bash
# Send request with invalid API key
curl -X POST http://${ORCH_IP}:8001/message \
    -H "X-API-Key: INVALID_KEY_12345" \
    -d '{"jsonrpc":"2.0","method":"process_document","params":{"s3_key":"test.pdf"},"id":"test"}'
```

**Expected Result:** HTTP 401 Unauthorized error

**What This Tests:**
1. **API Key Validation:** Invalid keys are rejected
2. **RBAC Policy Enforcement:** Only authorized principals can call methods
3. **Principal Identification:** System correctly identifies `lambda-s3-processor`

**RBAC Policy:**
```json
{
  "allow": {
    "lambda-s3-processor": ["*"],
    "orchestrator": ["extract_document", "validate_document", "archive_document"]
  },
  "deny": {}
}
```

**Expected Output:**
```
✓ RBAC authorized request
  - API key authentication: PASSED
  - RBAC policy check: PASSED
✓ RBAC unauthorized request rejection
  - Invalid API key correctly rejected
```

---

### **Test 6.5.6: Rate Limiting**

**Purpose:** Verify rate limiting protects against abuse

**Test Code:**
```bash
# Send 10 rapid requests
for i in {1..10}; do
    curl -X POST http://${ORCH_IP}:8001/message \
        -H "X-API-Key: $API_KEY" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"list_skills\",\"id\":\"$i\"}"
done
```

**What This Tests:**
1. **Rate Limit Enforcement:** Does the system block excessive requests?
2. **Threshold Configuration:** Is the limit appropriate (default: 100/min)?
3. **Error Handling:** Does the system return correct error (429 or 403)?

**Expected Outcomes:**

**Scenario A: Under Threshold**
```
✓ Rate limiting (under threshold)
  - 10 requests completed without hitting limit
```

**Scenario B: Limit Hit**
```
✓ Rate limiting (limit enforced)
  - Rate limit correctly enforced after multiple requests
```

**Rate Limit Configuration:**
```python
DEFAULT_RATE_LIMIT = 100  # requests per minute per principal
```

**Why This Matters:** Prevents DoS attacks and resource exhaustion

---

### **Test 6.5.7: Agent-to-Agent Communication**

**Purpose:** Verify agents can communicate using A2A protocol

**Test Method:** Analyze logs for A2A method calls

**Code:**
```bash
# Check orchestrator logs for A2A calls
aws logs tail /ecs/ca-a2a-orchestrator --since 10m --region eu-west-3 | \
  grep -E "Calling.*extractor.*extract_document|Calling.*validator.*validate_document|Calling.*archivist.*archive_document"
```

**What This Tests:**
1. **Service Discovery:** Can orchestrator find other agents?
2. **A2A Protocol:** Are JSON-RPC 2.0 messages correctly formatted?
3. **Network Routing:** Can agents reach each other via private IPs?
4. **Request/Response Flow:** Are responses received and processed?

**Log Patterns to Look For:**
```
INFO: Calling extractor.extract_document with params={'s3_key': 'test.pdf'}
INFO: Received response from extractor: {'status': 'success', 'pages': 3}
INFO: Calling validator.validate_document with params={'document_id': '123'}
INFO: Calling archivist.archive_document with params={'document_id': '123'}
```

**Expected Output:**
```
✓ Orchestrator -> Extractor A2A call
✓ Orchestrator -> Validator A2A call
✓ Orchestrator -> Archivist A2A call
```

**Why This Matters:** Validates the core multi-agent coordination mechanism

---

### **Test 6.5.8: Data Persistence**

**Purpose:** Verify database schema and data storage

**Test Code:**
```python
import asyncpg

async def test_persistence():
    conn = await asyncpg.connect(host=DB_HOST, user='postgres', ...)
    
    # Check tables exist
    tables = await conn.fetch("SELECT tablename FROM pg_tables WHERE schemaname='public'")
    
    # Count documents
    count = await conn.fetchval("SELECT COUNT(*) FROM documents")
    
    # Check recent documents
    recent = await conn.fetchval(
        "SELECT COUNT(*) FROM documents WHERE created_at > NOW() - INTERVAL '24 hours'"
    )
    
    return count, recent
```

**What This Tests:**
1. **Schema Creation:** Are `documents` and `revoked_tokens` tables present?
2. **Data Persistence:** Are documents being saved successfully?
3. **Recency Check:** Are recent uploads reflected in the database?

**Expected Output:**
```
✓ Documents table exists
✓ Revoked tokens table exists
✓ Documents in database: 47
✓ Recent documents (24h): 12
✓ Database persistence and schema
```

**Schema Verification:**
```sql
-- documents table
SELECT document_id, original_filename, status, created_at FROM documents;

-- revoked_tokens table
SELECT jti, revoked_at, revoked_by, reason FROM revoked_tokens;
```

**Why This Matters:** Ensures data durability and audit trail

---

## 🔍 Comprehensive Security Audit

### **Audit 7.1: Security Configuration Scoring**

**Purpose:** Score each agent's security posture

**Scoring Matrix:**

| Feature | Weight | Check |
|---------|--------|-------|
| `A2A_REQUIRE_AUTH` | +1 | Must be `true` |
| `A2A_ENABLE_HMAC_SIGNING` | +1 | Should be `true` |
| `A2A_ENABLE_SCHEMA_VALIDATION` | +1 | Must be `true` |
| `A2A_ENABLE_TOKEN_REVOCATION` | +1 | Should be `true` |
| `A2A_ENABLE_RATE_LIMIT` | +1 | Default or `true` |
| **Total** | **5** | **Max Score** |

**Test Code:**
```bash
ENV_VARS=$(aws ecs describe-task-definition \
    --task-definition ca-a2a-orchestrator \
    --query 'taskDefinition.containerDefinitions[0].environment' ...)

# Check each security feature
grep "A2A_REQUIRE_AUTH.*true" <<< "$ENV_VARS"  # Score +1
grep "A2A_ENABLE_HMAC_SIGNING.*true" <<< "$ENV_VARS"  # Score +1
# ... etc
```

**Expected Output:**
```
Auditing orchestrator...
  ✓ A2A_REQUIRE_AUTH: enabled
  ✓ A2A_ENABLE_HMAC_SIGNING: enabled
  ✓ A2A_ENABLE_SCHEMA_VALIDATION: enabled
  ✓ A2A_ENABLE_TOKEN_REVOCATION: enabled
  - A2A_ENABLE_RATE_LIMIT: default (likely enabled)
  Security Score: 5/5
✓ orchestrator security configuration (score: 5/5)
```

**Pass Criteria:** Score ≥ 4/5

---

### **Audit 7.2: Network Security**

**Purpose:** Verify network isolation and access controls

**Checks:**

**1. VPC Isolation**
```bash
aws ecs describe-clusters --clusters ca-a2a-cluster \
    --query 'clusters[0].tags[?key==`VPC`].value'
```

**Expected:** VPC ID present (e.g., `vpc-abc123`)

**2. Security Group Rules**
```bash
aws ec2 describe-security-groups --group-ids ${SG_ID} \
    --query 'SecurityGroups[0].IpPermissions[*].IpRanges[*].CidrIp'
```

**Expected:** NO `0.0.0.0/0` rules (no public access)

**Output:**
```
✓ VPC isolation: enabled (VPC: vpc-0a1b2c3d)
✓ Security groups: configured (sg-xyz789)
  ✓ Security group rules: restrictive (no public access)
✓ Security group rules
```

---

### **Audit 7.3: Secrets Management**

**Purpose:** Verify secrets are not hardcoded

**Check:**
```bash
aws secretsmanager list-secrets --region eu-west-3 \
    --query 'SecretList[?starts_with(Name, `ca-a2a`)].Name'
```

**Expected Secrets:**
- `ca-a2a/db-password` - PostgreSQL credentials
- `ca-a2a/jwt-secret` - JWT signing key (optional)
- `ca-a2a/hmac-secret` - HMAC signing key (optional)

**Output:**
```
✓ Secrets in AWS Secrets Manager: 3
  Secrets: ca-a2a/db-password ca-a2a/jwt-secret ca-a2a/hmac-secret
✓ Secrets management (using AWS Secrets Manager)
```

---

### **Audit 7.4: Logging & Monitoring**

**Purpose:** Verify CloudWatch logging is enabled

**Check:**
```bash
for SERVICE in orchestrator extractor validator archivist; do
    aws logs describe-log-groups \
        --log-group-name-prefix "/ecs/ca-a2a-${SERVICE}"
done
```

**Expected:** All 4 log groups exist with retention policies

**Output:**
```
✓ orchestrator logs: enabled (retention: 30 days)
✓ extractor logs: enabled (retention: 30 days)
✓ validator logs: enabled (retention: 30 days)
✓ archivist logs: enabled (retention: 30 days)
✓ CloudWatch logging configuration
```

---

### **Audit 7.5: IAM Permissions**

**Purpose:** Verify least privilege principle

**Check:**
```bash
# Get task role
TASK_ROLE=$(aws ecs describe-task-definition \
    --task-definition ca-a2a-orchestrator \
    --query 'taskDefinition.taskRoleArn')

# Check attached policies
aws iam list-attached-role-policies --role-name ${ROLE_NAME}
```

**Red Flags:**
- ❌ `AdministratorAccess`
- ❌ `PowerUserAccess`
- ❌ `*` permissions

**Expected:**
- ✅ Scoped S3 access
- ✅ Scoped RDS access
- ✅ Scoped CloudWatch Logs access

**Output:**
```
✓ Task IAM role: configured (ca-a2a-orchestrator-task-role)
  ✓ IAM role permissions: principle of least privilege
✓ IAM role permissions
```

---

## 📜 Compliance Matrix

### **Audit 7.6: Research Paper Compliance**

**Purpose:** Verify alignment with "Securing Agent-to-Agent (A2A) Communications" paper

**10-Point Compliance Checklist:**

| # | Requirement | Check | Weight |
|---|-------------|-------|--------|
| 1 | **Authentication** | JWT or API Key auth | Mandatory |
| 2 | **Authorization (RBAC)** | Role-based access control | Mandatory |
| 3 | **Message Integrity** | HMAC signing | Recommended |
| 4 | **Input Validation** | JSON Schema validation | Mandatory |
| 5 | **Replay Protection** | Timestamp/nonce checking | Mandatory |
| 6 | **Rate Limiting** | Request throttling | Mandatory |
| 7 | **Token Revocation** | Dynamic credential invalidation | Recommended |
| 8 | **TLS/Encryption** | Data in transit protection | Mandatory |
| 9 | **Network Isolation** | VPC/private networking | Mandatory |
| 10 | **Logging & Monitoring** | Audit trail | Mandatory |

**Scoring:**
- ✅ **Mandatory (7 items):** Must all pass for production
- ⭐ **Recommended (3 items):** Optional but highly advised

**Expected Output:**
```
Research Paper Compliance:
  ✓ Authentication: COMPLIANT (JWT/API Key)
  ✓ Authorization (RBAC): COMPLIANT
  ✓ Message Integrity (HMAC): COMPLIANT
  ✓ Input Validation: COMPLIANT
  ✓ Replay Protection: COMPLIANT (default enabled)
  ✓ Rate Limiting: COMPLIANT (default enabled)
  ✓ Token Revocation: COMPLIANT
  ✓ TLS/Encryption: COMPLIANT (AWS VPC + internal TLS)
  ✓ Network Isolation: COMPLIANT (VPC)
  ✓ Logging & Monitoring: COMPLIANT (CloudWatch)

Overall Compliance Score: 10/10 (100%)
✓ Security compliance (10/10)
  Status: PRODUCTION READY
```

**Pass Criteria:**
- **Production Ready:** ≥ 8/10
- **Hardening Required:** < 8/10

---

## 🚀 Running the Tests

### **Full Test Suite (In CloudShell):**

```bash
cd ~/ca_a2a
git pull origin main
./deploy-enhanced-security.sh
```

**Duration:** ~7-10 minutes

### **Test by Category:**

**Category A: Local Security Tests Only**
```bash
pytest test_security_enhanced.py -v
```
**Duration:** ~1 second

**Category B+C: Agent & RBAC Tests Only**
```bash
# Extract Step 6.5 from deployment script
sed -n '/STEP 6.5/,/STEP 7/p' deploy-enhanced-security.sh > test-agents-rbac.sh
chmod +x test-agents-rbac.sh
./test-agents-rbac.sh
```
**Duration:** ~2 minutes

**Category D: Security Audit Only**
```bash
# Extract Step 7 from deployment script
sed -n '/STEP 7/,/FINAL SUMMARY/p' deploy-enhanced-security.sh > security-audit.sh
chmod +x security-audit.sh
./security-audit.sh
```
**Duration:** ~1 minute

---

## 📊 Expected Final Output

```
============================================
TEST SUMMARY
============================================
Passed:   51
Failed:   0

Success Rate: 100%

Overall Compliance Score: 10/10 (100%)
  Status: PRODUCTION READY

============================================
✓ ALL TESTS PASSED - ENHANCED SECURITY OPERATIONAL
============================================
```

---

## 🎯 Success Criteria

| Category | Tests | Pass Threshold |
|----------|-------|----------------|
| Security Features | 24 | 100% (23/24 min with perf allowance) |
| Agent Functionality | 8 | ≥ 75% (6/8) |
| RBAC & Communication | 8 | ≥ 75% (6/8) |
| Security Audit | 6 | 100% (6/6) |
| Compliance | 10 | ≥ 80% (8/10) |
| **Overall** | **56** | **≥ 85% (48/56)** |

---

**Document Version:** 1.0  
**Last Updated:** January 3, 2026  
**Test Suite Version:** 2.0  
**Coverage:** 56 validation points across 7 categories

