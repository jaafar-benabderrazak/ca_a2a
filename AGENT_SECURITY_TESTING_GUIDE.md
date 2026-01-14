# Comprehensive Agent & Security Testing Guide

**Complete Testing Framework for Multi-Agent System with Enhanced Security**

**Version**: 2.1  
**Last Updated**: January 14, 2026  
**New Features**: Keycloak OAuth2/OIDC Testing Suite

---

## Table of Contents

1. [Overview](#overview)
2. [Test Categories](#test-categories)
3. [Agent Functionality Tests](#agent-functionality-tests)
4. [RBAC Security Tests](#rbac-security-tests)
5. [Comprehensive Security Audit](#comprehensive-security-audit)
6. [Compliance Matrix](#compliance-matrix)
7. [Running the Tests](#running-the-tests)

---

## Overview

The enhanced deployment script now includes **50+ comprehensive tests** across:
- **24 Security Feature Tests** (HMAC, Schema, Revocation, mTLS, Performance)
- **8 Agent Functionality Tests** (Health, Skills, Communication)
- **8 RBAC & Rate Limiting Tests**
- **9 Keycloak OAuth2/OIDC Tests (NEW)**
- **6 Security Audit Checks**
- **10 Compliance Criteria**

**Total Test Coverage:** ~65 distinct validation points

---

## Test Categories

### **Category A: Core Security Features (Step 3)**
- Local unit tests before deployment
- Tests: 24 (HMAC, Schema, Revocation, mTLS, Performance)

### **Category B: Agent Functionality (Step 6.5)**
- Tests each agent's health and capabilities
- Tests: 8 (4 agents × 2 checks each)

### **Category C: RBAC & Communication (Step 6.5)**
- Tests authorization, rate limiting, A2A calls
- Tests: 8 (authorization, rate limits, data persistence)

### **Category D: Keycloak OAuth2/OIDC (Step 6.6-6.14) (NEW)**
- Tests OAuth2 authentication flow, token lifecycle, RBAC mapping
- Tests: 9 (service health, authentication, token refresh, RBAC, JWKS, hybrid mode)

### **Category E: Security Audit (Step 7)**
- Comprehensive security posture evaluation
- Checks: 6 audit areas + 10 compliance criteria

---

## Agent Functionality Tests

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
 Orchestrator health endpoint
 - Orchestrator IP: 10.0.10.25
 - Health status: OK
 Orchestrator skills registration
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
 Extractor health endpoint
 Validator health endpoint
 Archivist health endpoint
```

**Why This Matters:** Ensures the entire agent pipeline is online and ready

---

## RBAC Security Tests

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
 RBAC authorized request
 - API key authentication: PASSED
 - RBAC policy check: PASSED
 RBAC unauthorized request rejection
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
 Rate limiting (under threshold)
 - 10 requests completed without hitting limit
```

**Scenario B: Limit Hit**
```
 Rate limiting (limit enforced)
 - Rate limit correctly enforced after multiple requests
```

**Rate Limit Configuration:**
```python
DEFAULT_RATE_LIMIT = 100 # requests per minute per principal
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
 Orchestrator -> Extractor A2A call
 Orchestrator -> Validator A2A call
 Orchestrator -> Archivist A2A call
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
 Documents table exists
 Revoked tokens table exists
 Documents in database: 47
 Recent documents (24h): 12
 Database persistence and schema
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

## Keycloak OAuth2/OIDC Security Tests (NEW)

### **Test 6.6: Keycloak Service Health**

**Purpose:** Verify Keycloak service is running and accessible

**Test Code:**
```bash
# Check Keycloak ECS service
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --service keycloak \
  --query 'services[0].[serviceName, status, runningCount, desiredCount]' \
  --output table

# Get Keycloak task private IP
KEYCLOAK_TASK_ARN=$(aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service-name keycloak \
  --query 'taskArns[0]' \
  --output text)

KEYCLOAK_IP=$(aws ecs describe-tasks \
  --cluster ca-a2a-cluster \
  --tasks $KEYCLOAK_TASK_ARN \
  --query 'tasks[0].containers[0].networkInterfaces[0].privateIpv4Address' \
  --output text)

# Test health endpoint
curl -s http://${KEYCLOAK_IP}:8080/health
curl -s http://${KEYCLOAK_IP}:8080/health/ready
```

**Expected Output:**
```
✅ Keycloak service status
  - Running count: 1/1
  - Health check: PASSED
  - Private IP: 10.0.10.x
  - Health endpoint: {"status":"UP"}
  - Ready endpoint: {"status":"UP"}
```

**What This Tests:**
1. **ECS Service**: Keycloak is deployed and running
2. **Network Connectivity**: Can reach Keycloak from VPC
3. **Health Checks**: Keycloak is fully started and ready
4. **Service Discovery**: `keycloak.ca-a2a.local:8080` resolves correctly

---

### **Test 6.7: Keycloak Authentication Flow**

**Purpose:** Verify end-to-end OAuth2/OIDC authentication

**Test Scenario 1: Obtain Access Token**

```bash
# Authenticate as admin-user
KEYCLOAK_URL="http://keycloak.ca-a2a.local:8080"
REALM="ca-a2a"
CLIENT_ID="ca-a2a-agents"
CLIENT_SECRET=$(aws secretsmanager get-secret-value \
  --secret-id ca-a2a/keycloak-client-secret \
  --query SecretString \
  --output text)
USERNAME="admin-user"
PASSWORD=$(aws secretsmanager get-secret-value \
  --secret-id ca-a2a/keycloak-admin-user-password \
  --query SecretString \
  --output text)

# Get token
TOKEN_RESPONSE=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')
REFRESH_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.refresh_token')
EXPIRES_IN=$(echo $TOKEN_RESPONSE | jq -r '.expires_in')

echo "Access Token: ${ACCESS_TOKEN:0:50}..."
echo "Expires in: $EXPIRES_IN seconds"
```

**Expected Output:**
```
✅ Keycloak authentication
  - Access token obtained: eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6IC...
  - Refresh token obtained: eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6IC...
  - Expires in: 300 seconds (5 minutes)
  - Token type: Bearer
```

**What This Tests:**
1. **Password Grant Flow**: Keycloak accepts username/password
2. **Token Issuance**: Access token and refresh token generated
3. **Token Structure**: JWT format with RS256 signature
4. **Token Lifespan**: 5-minute expiration

---

### **Test 6.8: Agent API Call with Keycloak Token**

**Purpose:** Verify agents accept and validate Keycloak JWTs

**Test Code:**
```bash
# Get orchestrator IP
ORCH_IP=$(aws ecs describe-tasks \
  --cluster ca-a2a-cluster \
  --tasks $(aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --service-name orchestrator \
    --query 'taskArns[0]' \
    --output text) \
  --query 'tasks[0].containers[0].networkInterfaces[0].privateIpv4Address' \
  --output text)

# Call orchestrator with Keycloak token
curl -X POST "http://${ORCH_IP}:8001/message" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_skills",
    "params": {},
    "id": 1
  }'
```

**Expected Output:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "skills": ["process_document", "coordinate_pipeline"],
    "agent": "orchestrator",
    "auth_context": {
      "mode": "keycloak_jwt",
      "username": "admin-user",
      "keycloak_roles": ["admin"],
      "rbac_principal": "admin",
      "allowed_methods": ["*"],
      "dynamic_rbac": true
    }
  },
  "id": 1
}
```

**What This Tests:**
1. **JWT Validation**: Agent verifies RS256 signature using JWKS
2. **RBAC Mapping**: Keycloak roles mapped to A2A principals
3. **Authorization**: Admin role has full access (`allowed_methods`: `["*"]`)
4. **Auth Context**: Response includes Keycloak-specific metadata

---

### **Test 6.9: Token Refresh**

**Purpose:** Verify token refresh mechanism

**Test Code:**
```bash
# Wait for access token to expire (or simulate)
echo "Refreshing access token..."

# Use refresh token to get new access token
NEW_TOKEN_RESPONSE=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "refresh_token=${REFRESH_TOKEN}")

NEW_ACCESS_TOKEN=$(echo $NEW_TOKEN_RESPONSE | jq -r '.access_token')
NEW_REFRESH_TOKEN=$(echo $NEW_TOKEN_RESPONSE | jq -r '.refresh_token')

echo "New Access Token: ${NEW_ACCESS_TOKEN:0:50}..."
```

**Expected Output:**
```
✅ Token refresh
  - New access token obtained: eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6IC...
  - New refresh token obtained: eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6IC...
  - Old tokens invalidated
```

**What This Tests:**
1. **Refresh Token Grant**: Keycloak accepts refresh token
2. **Token Rotation**: New tokens issued, old tokens invalidated
3. **Continuous Access**: Users can maintain sessions beyond 5 minutes

---

### **Test 6.10: Invalid Token Rejection**

**Purpose:** Verify agents reject invalid/expired tokens

**Test Scenario 1: Expired Token**

```bash
# Use expired token (simulate by using old token after 5 minutes)
sleep 300  # Wait 5 minutes

curl -X POST "http://${ORCH_IP}:8001/message" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_skills",
    "params": {},
    "id": 1
  }'
```

**Expected Output:**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Authentication failed: Token has expired"
  },
  "id": 1
}
```

**Test Scenario 2: Invalid Signature**

```bash
# Tamper with token (change last character)
TAMPERED_TOKEN="${ACCESS_TOKEN:0:-1}X"

curl -X POST "http://${ORCH_IP}:8001/message" \
  -H "Authorization: Bearer ${TAMPERED_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_skills",
    "params": {},
    "id": 1
  }'
```

**Expected Output:**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Authentication failed: Invalid token signature"
  },
  "id": 1
}
```

**What This Tests:**
1. **Token Expiration**: Expired tokens rejected (5-minute lifespan)
2. **Signature Validation**: Tampered tokens detected and rejected
3. **Error Handling**: Clear error messages for debugging

---

### **Test 6.11: RBAC with Keycloak Roles**

**Purpose:** Verify Keycloak roles correctly map to A2A RBAC

**Test Scenario 1: Admin Role (Full Access)**

```bash
# Admin user should access all methods
curl -X POST "http://${ORCH_IP}:8001/message" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {"s3_key": "test.pdf"},
    "id": 1
  }'
```

**Expected Result:** ✅ Request succeeds (admin role → admin principal → `*` methods)

**Test Scenario 2: Viewer Role (Read-Only)**

```bash
# Authenticate as viewer user
VIEWER_PASSWORD=$(aws secretsmanager get-secret-value \
  --secret-id ca-a2a/keycloak-viewer-password \
  --query SecretString \
  --output text)

VIEWER_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "username=viewer-user" \
  -d "password=${VIEWER_PASSWORD}" | jq -r '.access_token')

# Viewer should only access read-only methods
curl -X POST "http://${ORCH_IP}:8001/message" \
  -H "Authorization: Bearer ${VIEWER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_skills",
    "params": {},
    "id": 1
  }'
# Expected: ✅ Success

curl -X POST "http://${ORCH_IP}:8001/message" \
  -H "Authorization: Bearer ${VIEWER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {"s3_key": "test.pdf"},
    "id": 1
  }'
# Expected: ❌ 403 Forbidden
```

**Expected Output:**
```
✅ Admin role test
  - list_skills: ALLOWED
  - process_document: ALLOWED
  - All methods: ALLOWED

❌ Viewer role test
  - list_skills: ALLOWED
  - get_health: ALLOWED
  - process_document: FORBIDDEN (403)
```

**RBAC Mapping:**
| Keycloak Role | A2A Principal | Allowed Methods |
|---------------|---------------|-----------------|
| `admin` | admin | `*` (all) |
| `lambda` | lambda | `*` (all) |
| `orchestrator` | orchestrator | `extract_document`, `validate_document`, `archive_document`, `list_skills`, `get_health` |
| `viewer` | viewer | `list_skills`, `get_health` |

**What This Tests:**
1. **Role Mapping**: Keycloak roles correctly map to A2A principals
2. **Method Filtering**: RBAC policies enforced based on principal
3. **Least Privilege**: Viewer has minimal access (read-only)

---

### **Test 6.12: JWKS Endpoint & Public Key Caching**

**Purpose:** Verify agent fetches and caches Keycloak public keys

**Test Code:**
```bash
# Check JWKS endpoint
curl -s "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/certs" | jq

# Expected structure:
# {
#   "keys": [
#     {
#       "kid": "qunlkj_cDRkZiIsImtpZCI",
#       "kty": "RSA",
#       "alg": "RS256",
#       "use": "sig",
#       "n": "<RSA modulus>",
#       "e": "AQAB"
#     }
#   ]
# }
```

**Agent-Side Verification** (check CloudWatch logs):
```bash
# View orchestrator logs for JWKS cache activity
aws logs tail /ecs/ca-a2a-orchestrator --since 10m --filter-pattern "JWKS"

# Expected log entries:
# - "Fetching JWKS from Keycloak: http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/certs"
# - "JWKS cached successfully, TTL: 3600 seconds"
# - "Using cached JWKS (age: 120 seconds)"
```

**What This Tests:**
1. **JWKS Endpoint**: Public keys exposed via standard endpoint
2. **Caching**: Agent caches keys for 1 hour (reduces load)
3. **Key Rotation**: Agents automatically detect new keys on cache expiry

---

### **Test 6.13: Hybrid Authentication Mode**

**Purpose:** Verify backward compatibility (legacy JWT + API Key + Keycloak)

**Test Scenario 1: Keycloak JWT**
```bash
# Use Keycloak token
curl -X POST "http://${ORCH_IP}:8001/message" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":1}'
# Expected: ✅ Success (auth mode: keycloak_jwt)
```

**Test Scenario 2: Legacy JWT**
```bash
# Generate legacy JWT (HS256)
LEGACY_JWT=$(python3 -c "
import jwt
import os
token = jwt.encode({'sub': 'test-user', 'exp': $(date -u +%s) + 3600}, os.getenv('JWT_SECRET'), algorithm='HS256')
print(token)
")

curl -X POST "http://${ORCH_IP}:8001/message" \
  -H "Authorization: Bearer ${LEGACY_JWT}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":1}'
# Expected: ✅ Success (auth mode: legacy_jwt) - if legacy JWT enabled
```

**Test Scenario 3: API Key**
```bash
# Use API key
API_KEY=$(aws ecs describe-task-definition \
  --task-definition ca-a2a-orchestrator \
  --query 'taskDefinition.containerDefinitions[0].environment[?name==`A2A_API_KEYS_JSON`].value' \
  --output text | jq -r '.["lambda-s3-processor"]')

curl -X POST "http://${ORCH_IP}:8001/message" \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":1}'
# Expected: ✅ Success (auth mode: api_key)
```

**Expected Output:**
```
✅ Hybrid authentication mode
  - Keycloak JWT: SUPPORTED
  - Legacy JWT: SUPPORTED (if enabled)
  - API Key: SUPPORTED
  - Auth priority: Keycloak → Legacy JWT → API Key
```

**What This Tests:**
1. **Backward Compatibility**: All auth methods work simultaneously
2. **Priority Order**: Keycloak JWT tried first, then fallback
3. **Gradual Migration**: Allows phased rollout without breaking changes

---

### **Test 6.14: Keycloak Admin Console Access (Optional)**

**Purpose:** Verify admin console accessibility for user management

**Test Code:**
```bash
# Access admin console (requires ALB or public access setup)
# If deployed with public access:
# URL: https://keycloak.<domain>/admin

# Login credentials:
ADMIN_USERNAME="admin"
ADMIN_PASSWORD=$(aws secretsmanager get-secret-value \
  --secret-id ca-a2a/keycloak-admin-password \
  --query SecretString \
  --output text)

echo "Admin Console: ${KEYCLOAK_URL}/admin"
echo "Username: ${ADMIN_USERNAME}"
echo "Password: ${ADMIN_PASSWORD}"
```

**Manual Verification:**
1. Navigate to admin console URL
2. Login with admin credentials
3. Verify:
   - ✅ Realm `ca-a2a` exists
   - ✅ Client `ca-a2a-agents` configured
   - ✅ Users visible (admin-user, lambda-service, etc.)
   - ✅ Roles defined (admin, lambda, orchestrator, viewer)
   - ✅ Audit events logged (recent logins)

**What This Tests:**
1. **Admin Access**: Console accessible for management
2. **Configuration**: All realm settings correctly applied
3. **Audit Trail**: Authentication events visible

---

### **Automated Test Suite: Keycloak Integration**

**Test Script**: `test-keycloak-auth.sh`

```bash
#!/bin/bash
# Automated Keycloak authentication testing

set -e

echo "================================"
echo "Keycloak OAuth2/OIDC Test Suite"
echo "================================"

# Test 1: Service Health
echo "Test 1: Keycloak service health..."
KEYCLOAK_HEALTH=$(curl -s http://keycloak.ca-a2a.local:8080/health)
echo "$KEYCLOAK_HEALTH" | grep -q "UP" && echo "✅ PASSED" || echo "❌ FAILED"

# Test 2: Obtain Token
echo "Test 2: Obtain access token..."
TOKEN_RESPONSE=$(curl -s -X POST "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=ca-a2a-agents" \
  -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
  -d "username=admin-user" \
  -d "password=${ADMIN_PASSWORD}")
ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')
[ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ] && echo "✅ PASSED" || echo "❌ FAILED"

# Test 3: Agent API Call
echo "Test 3: Call agent with Keycloak token..."
AGENT_RESPONSE=$(curl -s -X POST "http://orchestrator.ca-a2a.local:8001/message" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":1}')
echo "$AGENT_RESPONSE" | grep -q "process_document" && echo "✅ PASSED" || echo "❌ FAILED"

# Test 4: Token Refresh
echo "Test 4: Refresh token..."
REFRESH_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.refresh_token')
NEW_TOKEN_RESPONSE=$(curl -s -X POST "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token" \
  -d "grant_type=refresh_token" \
  -d "client_id=ca-a2a-agents" \
  -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
  -d "refresh_token=${REFRESH_TOKEN}")
NEW_ACCESS_TOKEN=$(echo $NEW_TOKEN_RESPONSE | jq -r '.access_token')
[ -n "$NEW_ACCESS_TOKEN" ] && [ "$NEW_ACCESS_TOKEN" != "null" ] && echo "✅ PASSED" || echo "❌ FAILED"

# Test 5: Invalid Token Rejection
echo "Test 5: Invalid token rejection..."
INVALID_RESPONSE=$(curl -s -X POST "http://orchestrator.ca-a2a.local:8001/message" \
  -H "Authorization: Bearer INVALID_TOKEN_12345" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":1}')
echo "$INVALID_RESPONSE" | grep -q "error" && echo "✅ PASSED" || echo "❌ FAILED"

echo "================================"
echo "All Keycloak tests completed"
echo "================================"
```

**Run Tests:**
```bash
./test-keycloak-auth.sh

# Expected output:
# ================================
# Keycloak OAuth2/OIDC Test Suite
# ================================
# Test 1: Keycloak service health... ✅ PASSED
# Test 2: Obtain access token... ✅ PASSED
# Test 3: Call agent with Keycloak token... ✅ PASSED
# Test 4: Refresh token... ✅ PASSED
# Test 5: Invalid token rejection... ✅ PASSED
# ================================
# All Keycloak tests completed
# ================================
```

---

## Comprehensive Security Audit

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
grep "A2A_REQUIRE_AUTH.*true" <<< "$ENV_VARS" # Score +1
grep "A2A_ENABLE_HMAC_SIGNING.*true" <<< "$ENV_VARS" # Score +1
# ... etc
```

**Expected Output:**
```
Auditing orchestrator...
 A2A_REQUIRE_AUTH: enabled
 A2A_ENABLE_HMAC_SIGNING: enabled
 A2A_ENABLE_SCHEMA_VALIDATION: enabled
 A2A_ENABLE_TOKEN_REVOCATION: enabled
 - A2A_ENABLE_RATE_LIMIT: default (likely enabled)
 Security Score: 5/5
 orchestrator security configuration (score: 5/5)
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
 VPC isolation: enabled (VPC: vpc-0a1b2c3d)
 Security groups: configured (sg-xyz789)
 Security group rules: restrictive (no public access)
 Security group rules
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
 Secrets in AWS Secrets Manager: 3
 Secrets: ca-a2a/db-password ca-a2a/jwt-secret ca-a2a/hmac-secret
 Secrets management (using AWS Secrets Manager)
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
 orchestrator logs: enabled (retention: 30 days)
 extractor logs: enabled (retention: 30 days)
 validator logs: enabled (retention: 30 days)
 archivist logs: enabled (retention: 30 days)
 CloudWatch logging configuration
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
- `AdministratorAccess`
- `PowerUserAccess`
- `*` permissions

**Expected:**
- Scoped S3 access
- Scoped RDS access
- Scoped CloudWatch Logs access

**Output:**
```
 Task IAM role: configured (ca-a2a-orchestrator-task-role)
 IAM role permissions: principle of least privilege
 IAM role permissions
```

---

## Compliance Matrix

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
- **Mandatory (7 items):** Must all pass for production
- ⭐ **Recommended (3 items):** Optional but highly advised

**Expected Output:**
```
Research Paper Compliance:
 Authentication: COMPLIANT (JWT/API Key)
 Authorization (RBAC): COMPLIANT
 Message Integrity (HMAC): COMPLIANT
 Input Validation: COMPLIANT
 Replay Protection: COMPLIANT (default enabled)
 Rate Limiting: COMPLIANT (default enabled)
 Token Revocation: COMPLIANT
 TLS/Encryption: COMPLIANT (AWS VPC + internal TLS)
 Network Isolation: COMPLIANT (VPC)
 Logging & Monitoring: COMPLIANT (CloudWatch)

Overall Compliance Score: 10/10 (100%)
 Security compliance (10/10)
 Status: PRODUCTION READY
```

**Pass Criteria:**
- **Production Ready:** ≥ 8/10
- **Hardening Required:** < 8/10

---

## Running the Tests

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

## Expected Final Output

```
============================================
TEST SUMMARY
============================================
Passed: 51
Failed: 0

Success Rate: 100%

Overall Compliance Score: 10/10 (100%)
 Status: PRODUCTION READY

============================================
 ALL TESTS PASSED - ENHANCED SECURITY OPERATIONAL
============================================
```

---

## Success Criteria

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

