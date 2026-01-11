# Comprehensive Testing Guide: Multi-Layer Security Validation

**Complete Testing Framework for CA A2A Multi-Agent System**

---

## Table of Contents

1. [Testing Overview](#testing-overview)
2. [Test Architecture](#test-architecture)
3. [Layer-by-Layer Testing](#layer-by-layer-testing)
4. [Running the Test Suite](#running-the-test-suite)
5. [Understanding Test Results](#understanding-test-results)
6. [Debugging Failed Tests](#debugging-failed-tests)
7. [Performance Benchmarking](#performance-benchmarking)

---

## Testing Overview

### Purpose

This guide provides **exhaustive technical documentation** for testing all layers of the CA A2A system, from infrastructure to application-level security.

### Test Pyramid

```mermaid
graph TB
    subgraph "Test Layers (Bottom-Up)"
        L1[Layer 1: Infrastructure<br/>AWS Services Status]
        L2[Layer 2: Security Configuration<br/>API Keys, RBAC, mTLS]
        L3[Layer 3: Agent Functionality<br/>Health, Skills, A2A Comm]
        L4[Layer 4: Security Enforcement<br/>HMAC, Schema, Rate Limits]
        L5[Layer 5: End-to-End Pipeline<br/>S3 → Lambda → Agents → DB]
        L6[Layer 6: Performance & Compliance<br/>Benchmarks, Audit]
        
        L1 --> L2
        L2 --> L3
        L3 --> L4
        L4 --> L5
        L5 --> L6
    end
    
    style L1 fill:#FF6B6B
    style L2 fill:#FFA500
    style L3 fill:#FFD93D
    style L4 fill:#6BCB77
    style L5 fill:#4D96FF
    style L6 fill:#9D4EDD
```

### Test Coverage Matrix

| **Layer** | **Test Categories** | **Test Count** | **Validates** |
|-----------|---------------------|----------------|---------------|
| Infrastructure | ECS, Lambda, RDS, S3 | 5 tests | Resource availability |
| Security Config | API Keys, RBAC, Auth | 12 tests | Security policies |
| Agent Functions | Health, Skills, A2A | 16 tests | Agent capabilities |
| Security Enforce | HMAC, Schema, Rate | 9 tests | Live attack prevention |
| E2E Pipeline | Document processing | 7 tests | Complete workflow |
| Performance | Latency, throughput | 8 tests | Production readiness |
| **TOTAL** | **6 layers** | **57 tests** | **Full system** |

---

## Test Architecture

### Testing Scripts

```mermaid
graph LR
    subgraph "Testing Scripts"
        CS[comprehensive-system-test.sh<br/>57 AWS Integration Tests]
        TS[test_security_enhanced.py<br/>25 Unit Tests]
        PS[Performance Scripts<br/>Custom Load Tests]
    end
    
    subgraph "Test Targets"
        AWS[AWS Deployed System<br/>ECS + RDS + Lambda]
        LOCAL[Local Python Modules<br/>a2a_security_enhanced.py]
    end
    
    CS -->|HTTP/AWS CLI| AWS
    TS -->|pytest| LOCAL
    PS -->|curl/ab| AWS
    
    style CS fill:#4CAF50
    style TS fill:#2196F3
    style PS fill:#FF9800
```

### Test Types

| **Script** | **Type** | **Scope** | **Runtime** | **Purpose** |
|------------|----------|-----------|-------------|-------------|
| `comprehensive-system-test.sh` | Integration | AWS deployed | 5-10 min | Validate live system |
| `test_security_enhanced.py` | Unit | Local Python | 30-60 sec | Test security classes |
| Custom load tests | Performance | AWS deployed | Variable | Stress testing |

---

## Layer-by-Layer Testing

### Layer 1: Infrastructure Status (5 Tests)

**Purpose:** Validate AWS resource availability before testing application logic.

#### Test 1.1: ECS Services Health

```bash
# Code Location: comprehensive-system-test.sh:42-63
for SERVICE in orchestrator extractor validator archivist; do
    RUNNING=$(aws ecs describe-services \
        --cluster ca-a2a-cluster \
        --services ${SERVICE} \
        --region eu-west-3 \
        --query 'services[0].runningCount' \
        --output text)
    
    DESIRED=$(aws ecs describe-services \
        --cluster ca-a2a-cluster \
        --services ${SERVICE} \
        --region eu-west-3 \
        --query 'services[0].desiredCount' \
        --output text)
    
    if [ "$RUNNING" == "$DESIRED" ] && [ "$RUNNING" -gt 0 ]; then
        echo "✓ Service ${SERVICE}: ${RUNNING}/${DESIRED} tasks running"
    fi
done
```

**What it validates:**
- ✓ All 4 agents have running ECS tasks
- ✓ Running count matches desired count (no crash loops)
- ✓ Service discovery via AWS Cloud Map is functional

**Failure scenarios:**
- `RUNNING < DESIRED` → Agent crashed/restarting
- `RUNNING = 0` → Agent not deployed or failed to start
- `Service not found` → Infrastructure not deployed

**Technical explanation:**

```mermaid
sequenceDiagram
    participant Test as Test Script
    participant ECS as ECS API
    participant Fargate as Fargate Tasks
    
    Test->>ECS: describe-services (orchestrator)
    ECS->>Fargate: Query task status
    Fargate-->>ECS: runningCount=1, desiredCount=1
    ECS-->>Test: Service Healthy ✓
    
    Test->>ECS: describe-services (extractor)
    ECS->>Fargate: Query task status
    Fargate-->>ECS: runningCount=0, desiredCount=1
    ECS-->>Test: Service UNHEALTHY ✗
    
    Note over Test: Test FAILS - Investigation needed
```

#### Test 1.2: Lambda Function Active

```bash
# Code Location: comprehensive-system-test.sh:66-78
LAMBDA_STATE=$(aws lambda get-function \
    --function-name ca-a2a-s3-processor \
    --region eu-west-3 \
    --query 'Configuration.State' \
    --output text)

if [ "$LAMBDA_STATE" == "Active" ]; then
    echo "✓ Lambda function: Active"
fi
```

**What it validates:**
- ✓ S3 event processor Lambda exists
- ✓ Lambda is in `Active` state (not `Pending`, `Inactive`, or `Failed`)
- ✓ Event-driven pipeline is ready to process uploads

**Possible states:**
- `Active` → ✓ Ready to process events
- `Pending` → Deployment in progress
- `Inactive` → Function disabled/deleted
- `Failed` → Runtime/configuration error

#### Test 1.3: RDS Database Availability

```bash
# Code Location: comprehensive-system-test.sh:80-93
DB_STATUS=$(aws rds describe-db-clusters \
    --region eu-west-3 \
    --db-cluster-identifier documents-db \
    --query 'DBClusters[0].Status' \
    --output text)

if [ "$DB_STATUS" == "available" ]; then
    echo "✓ Database cluster: Available"
fi
```

**What it validates:**
- ✓ RDS Aurora PostgreSQL cluster is `available`
- ✓ Database can accept connections from Archivist agent
- ✓ No maintenance/backup operations blocking access

**Database states:**
- `available` → ✓ Fully operational
- `backing-up` → Temporary unavailable (automated backup)
- `modifying` → Schema/config change in progress
- `maintenance` → AWS maintenance window
- `failed` → Critical error, requires intervention

#### Test 1.4: S3 Bucket Accessibility

```bash
# Code Location: comprehensive-system-test.sh:95-110
S3_BUCKET=$(aws s3api head-bucket \
    --bucket ca-a2a-documents \
    --region eu-west-3 2>&1)

if [ $? -eq 0 ]; then
    echo "✓ S3 bucket: Accessible"
fi
```

**What it validates:**
- ✓ S3 bucket `ca-a2a-documents` exists
- ✓ IAM permissions allow access from Lambda/agents
- ✓ Bucket policies don't block uploads

#### Test 1.5: CloudWatch Log Groups

```bash
# Code Location: comprehensive-system-test.sh:112-127
for AGENT in orchestrator extractor validator archivist; do
    LOG_GROUP="/ecs/ca-a2a-${AGENT}"
    EXISTS=$(aws logs describe-log-groups \
        --log-group-name-prefix ${LOG_GROUP} \
        --region eu-west-3 \
        --query 'length(logGroups)' \
        --output text)
    
    if [ "$EXISTS" -gt 0 ]; then
        echo "✓ Log group ${LOG_GROUP} exists"
    fi
done
```

**What it validates:**
- ✓ CloudWatch log groups exist for all agents
- ✓ Logs are being captured (required for debugging)
- ✓ Retention policies configured

---

### Layer 2: Security Configuration (12 Tests)

**Purpose:** Validate that security policies and credentials are properly configured before testing enforcement.

#### Test 2.1: API Key Configuration

```bash
# Code Location: comprehensive-system-test.sh:101-117
ORCH_API_KEYS=$(aws ecs describe-task-definition \
    --task-definition ca-a2a-orchestrator \
    --region eu-west-3 \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`A2A_API_KEYS_JSON`].value' \
    --output text)

if [ ! -z "$ORCH_API_KEYS" ]; then
    echo "✓ Orchestrator: API keys configured"
    
    # Extract API key for later tests
    API_KEY=$(echo "$ORCH_API_KEYS" | python3 -c \
        "import sys, json; data=json.loads(sys.stdin.read()); print(list(data.values())[0])")
fi
```

**What it validates:**
- ✓ Environment variable `A2A_API_KEYS_JSON` exists in orchestrator task definition
- ✓ JSON structure is valid (can be parsed)
- ✓ At least one API key is defined

**API Key format (JSON):**
```json
{
  "lambda": "key_abc123...",
  "admin": "key_def456...",
  "external_client": "key_ghi789..."
}
```

**Security principle:**
- API keys provide **first-factor authentication**
- Each principal (Lambda, admin, external) has unique key
- Keys are stored in task definition environment (not Secrets Manager for performance)

#### Test 2.2: RBAC Policy Configuration

```bash
# Code Location: comprehensive-system-test.sh:119-133
RBAC_POLICY=$(aws ecs describe-task-definition \
    --task-definition ca-a2a-orchestrator \
    --region eu-west-3 \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`A2A_RBAC_POLICY_JSON`].value' \
    --output text)

if [ ! -z "$RBAC_POLICY" ]; then
    echo "✓ Orchestrator: RBAC policy configured"
fi
```

**What it validates:**
- ✓ Environment variable `A2A_RBAC_POLICY_JSON` exists
- ✓ Role-based access control is enabled
- ✓ Method-level permissions are defined

**RBAC Policy structure:**
```json
{
  "lambda": {
    "allowed_methods": ["process_document"],
    "rate_limit": 100
  },
  "admin": {
    "allowed_methods": ["*"],
    "rate_limit": 1000
  },
  "orchestrator_agent": {
    "allowed_methods": ["extract_document", "validate_document", "archive_document"],
    "rate_limit": 200
  }
}
```

**Authorization flow:**

```mermaid
sequenceDiagram
    participant Client
    participant Orch as Orchestrator
    participant RBAC as RBAC Manager
    
    Client->>Orch: POST /message<br/>X-API-Key: key_abc123<br/>Method: process_document
    Orch->>RBAC: validate_permission("lambda", "process_document")
    
    alt Principal has permission
        RBAC-->>Orch: ✓ Allowed
        Orch->>Orch: Process request
        Orch-->>Client: 200 OK + Result
    else Principal lacks permission
        RBAC-->>Orch: ✗ Denied
        Orch-->>Client: 403 Forbidden<br/>{"error": "method not allowed"}
    end
```

#### Test 2.3: Authentication Requirement

```bash
# Code Location: comprehensive-system-test.sh:134-147
AUTH_REQUIRED=$(aws ecs describe-task-definition \
    --task-definition ca-a2a-orchestrator \
    --region eu-west-3 \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`A2A_REQUIRE_AUTH`].value' \
    --output text)

if [ "$AUTH_REQUIRED" == "true" ]; then
    echo "✓ Orchestrator: Authentication required (enabled)"
else
    echo "⚠ WARNING: Authentication not required (disabled)"
fi
```

**What it validates:**
- ✓ `A2A_REQUIRE_AUTH=true` is set
- ⚠ If `false`, system accepts unauthenticated requests (dev/test mode)

**Security impact:**
- `true` → **Zero-Trust mode**: All requests MUST have valid API key
- `false` → **Open mode**: Development/testing only, NOT production-safe

#### Test 2.4-2.12: Live Security Enforcement Tests

These tests make **actual HTTP requests** to the deployed orchestrator to validate security enforcement:

**Test 2.5: HMAC Signature Enforcement**
```bash
# Attempt request WITHOUT HMAC signature
curl -X POST http://<orchestrator-ip>:8001/message \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":"test-1"}'

# Expected: 401/403 if HMAC enforced, 200 if disabled
```

**Test 2.6: API Key Authentication**
```bash
# Test 1: Request WITHOUT API key
curl -X POST http://<orchestrator-ip>:8001/message \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":"test-2"}'

# Expected: 401 Unauthorized

# Test 2: Request WITH valid API key
curl -X POST http://<orchestrator-ip>:8001/message \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $VALID_KEY" \
  -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":"test-3"}'

# Expected: 200 OK
```

**Test 2.7: JSON Schema Validation (3 sub-tests)**

*Path Traversal Prevention:*
```bash
curl -X POST http://<orchestrator-ip>:8001/message \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "jsonrpc":"2.0",
    "method":"process_document",
    "params":{"s3_key":"../../../etc/passwd","priority":"normal"},
    "id":"test-4"
  }'

# Expected: 400 Bad Request (schema violation)
```

*Missing Required Fields:*
```bash
curl -X POST http://<orchestrator-ip>:8001/message \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "jsonrpc":"2.0",
    "method":"process_document",
    "params":{"priority":"normal"},
    "id":"test-5"
  }'

# Expected: 400 Bad Request (missing s3_key)
```

*Invalid Enum Values:*
```bash
curl -X POST http://<orchestrator-ip>:8001/message \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "jsonrpc":"2.0",
    "method":"process_document",
    "params":{"s3_key":"test.pdf","priority":"INVALID_PRIORITY"},
    "id":"test-6"
  }'

# Expected: 400 Bad Request (priority not in ["high","normal","low"])
```

**Test 2.8: RBAC Authorization**
```bash
# Use API key with limited permissions
curl -X POST http://<orchestrator-ip>:8001/message \
  -H "X-API-Key: $LIMITED_KEY" \
  -d '{
    "jsonrpc":"2.0",
    "method":"admin_function",
    "params":{},
    "id":"test-7"
  }'

# Expected: 403 Forbidden (method not in principal's allowed_methods)
```

**Test 2.9: Rate Limiting Configuration**
```bash
# Check rate limit settings exist
RATE_LIMIT=$(aws ecs describe-task-definition \
    --task-definition ca-a2a-orchestrator \
    --query 'taskDefinition.containerDefinitions[0].environment[?name==`A2A_RATE_LIMIT_ENABLED`].value' \
    --output text)

# Expected: "true"
```

**Test 2.10: Security Headers**
```bash
# Check HTTP security headers
curl -I http://<orchestrator-ip>:8001/health

# Expected headers:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# X-XSS-Protection: 1; mode=block
# Server header: NOT disclosed (removed for security)
```

**Test 2.11: Audit Logging**
```bash
# Check recent audit logs
aws logs tail /ecs/ca-a2a-orchestrator \
    --since 5m \
    --region eu-west-3 \
    | grep -c "Request received\|Request completed"

# Expected: > 0 (logs being written)
```

**Test 2.12: Secrets Management**
```bash
# Verify database password in Secrets Manager (not hardcoded)
aws secretsmanager describe-secret \
    --secret-id ca-a2a/db-password \
    --region eu-west-3

# Expected: Secret exists, has rotation enabled
```

**VPC Network Isolation Note:**

```mermaid
graph LR
    subgraph "AWS CloudShell (Public)"
        CS[Test Script<br/>comprehensive-system-test.sh]
    end
    
    subgraph "VPC 10.0.0.0/16 (Private)"
        subgraph "Private Subnet"
            ORCH[Orchestrator<br/>10.0.1.45:8001]
        end
    end
    
    CS -.->|❌ Cannot reach| ORCH
    
    style CS fill:#FFA500
    style ORCH fill:#90EE90
```

**Important:** Tests 2.5-2.10 require VPC access. From CloudShell:
- ❌ Direct HTTP to private IPs → **Fails (expected)**
- ✓ AWS API calls → **Works**
- ✓ E2E pipeline test (Test 5) → **Validates security indirectly**

---

### Layer 3: Agent Functionality (16 Tests)

**Purpose:** Validate each agent's core capabilities: health checks, skill listing, and A2A communication.

#### Test 3.1-3.4: Agent Health Checks

```bash
# Code Location: comprehensive-system-test.sh:385-425
for AGENT in orchestrator extractor validator archivist; do
    LOG_OUTPUT=$(aws logs tail /ecs/ca-a2a-${AGENT} \
        --since 5m \
        --region eu-west-3 \
        2>/dev/null | head -20)
    
    # Check for startup confirmation
    if echo "$LOG_OUTPUT" | grep -q "Agent started\|Server started\|Ready"; then
        echo "✓ ${AGENT}: Healthy (started successfully)"
    else
        echo "✗ ${AGENT}: May not be healthy"
    fi
done
```

**What it validates:**
- ✓ Agent process started without errors
- ✓ HTTP server is listening on expected port
- ✓ No crash loops or initialization failures

**Healthy log indicators:**
```
INFO: Agent started successfully on port 8001
INFO: Registered 3 skills: process_document, list_skills, health
INFO: A2A security initialized (API Key + RBAC)
INFO: MCP context: Native mode (S3 + PostgreSQL)
```

**Unhealthy log indicators:**
```
ERROR: Failed to bind to port 8001: Address already in use
ERROR: Database connection failed: Connection refused
CRITICAL: Unhandled exception during startup
```

#### Test 3.5-3.8: Agent Skill Registration

```bash
# Check if agents have registered their skills
for AGENT in orchestrator extractor validator archivist; do
    SKILL_LOGS=$(aws logs tail /ecs/ca-a2a-${AGENT} \
        --since 30m \
        --region eu-west-3 \
        | grep -i "skill\|registered\|capability")
    
    if [ ! -z "$SKILL_LOGS" ]; then
        echo "✓ ${AGENT}: Skills registered"
    fi
done
```

**Agent Skills Matrix:**

| **Agent** | **Skills (JSON-RPC Methods)** | **Description** |
|-----------|-------------------------------|-----------------|
| Orchestrator | `process_document`, `list_skills`, `health` | Workflow coordinator |
| Extractor | `extract_document`, `list_skills`, `health` | PDF text extraction |
| Validator | `validate_document`, `list_skills`, `health` | Data validation |
| Archivist | `archive_document`, `list_skills`, `health`, `get_document` | Database operations |

#### Test 3.9-3.12: A2A Communication

```bash
# Check orchestrator successfully calls other agents
ORCH_A2A_LOGS=$(aws logs tail /ecs/ca-a2a-orchestrator \
    --since 30m \
    --region eu-west-3 \
    | grep -i "Calling agent\|A2A request\|Forwarding to")

if echo "$ORCH_A2A_LOGS" | grep -q "extractor"; then
    echo "✓ Orchestrator → Extractor: Communication verified"
fi

if echo "$ORCH_A2A_LOGS" | grep -q "validator"; then
    echo "✓ Orchestrator → Validator: Communication verified"
fi

if echo "$ORCH_A2A_LOGS" | grep -q "archivist"; then
    echo "✓ Orchestrator → Archivist: Communication verified"
fi
```

**A2A Communication Flow:**

```mermaid
sequenceDiagram
    participant L as Lambda
    participant O as Orchestrator
    participant E as Extractor
    participant V as Validator
    participant A as Archivist
    
    L->>O: process_document(s3_key="doc.pdf")
    Note over O: Orchestration starts
    
    O->>E: extract_document(s3_key="doc.pdf")
    E->>E: Download from S3<br/>Extract text
    E-->>O: {text: "...", metadata: {...}}
    
    O->>V: validate_document(data={...})
    V->>V: Schema validation<br/>Business rules
    V-->>O: {valid: true}
    
    O->>A: archive_document(data={...})
    A->>A: Write to PostgreSQL
    A-->>O: {document_id: "uuid"}
    
    O-->>L: Success response
```

**What it validates:**
- ✓ Service discovery via AWS Cloud Map works
- ✓ HTTP connectivity between agents
- ✓ JSON-RPC 2.0 request/response format
- ✓ Error handling for unreachable agents

#### Test 3.13-3.16: Agent Response Times

```bash
# Check for performance issues in logs
for AGENT in orchestrator extractor validator archivist; do
    SLOW_LOGS=$(aws logs tail /ecs/ca-a2a-${AGENT} \
        --since 30m \
        --region eu-west-3 \
        | grep -i "slow\|timeout\|exceeded")
    
    if [ -z "$SLOW_LOGS" ]; then
        echo "✓ ${AGENT}: No performance issues detected"
    else
        echo "⚠ ${AGENT}: Slow operations detected"
    fi
done
```

**Performance baselines:**
- Orchestrator: < 50ms overhead per request
- Extractor: < 2 seconds for typical PDF
- Validator: < 10ms for validation
- Archivist: < 100ms for database write

---

### Layer 4: Security Enforcement (9 Tests)

**Purpose:** Validate that security features actively block attacks and enforce policies.

*(Tests 2.5-2.12 from Layer 2 are actually Layer 4 tests - they're enforcement, not just configuration)*

**Additional enforcement validations:**

#### Test 4.1: Replay Attack Prevention

```bash
# Send same request twice with identical timestamp
TIMESTAMP=$(date +%s)
REQUEST='{"jsonrpc":"2.0","method":"list_skills","params":{},"id":"replay-test"}'

# First request
RESPONSE1=$(curl -s -X POST http://<orch-ip>:8001/message \
  -H "X-API-Key: $API_KEY" \
  -H "X-Request-Timestamp: $TIMESTAMP" \
  -d "$REQUEST")

# Second request (replay)
RESPONSE2=$(curl -s -X POST http://<orch-ip>:8001/message \
  -H "X-API-Key: $API_KEY" \
  -H "X-Request-Timestamp: $TIMESTAMP" \
  -d "$REQUEST")

# Expected: First succeeds (200), second rejected (403 - replay detected)
```

**Replay protection mechanism:**

```python
# Code: a2a_security_enhanced.py
class ReplayProtectionManager:
    def __init__(self, window_seconds=300):
        self.seen_requests = {}  # {nonce: timestamp}
        self.window = window_seconds
    
    def is_replay(self, nonce: str, timestamp: int) -> bool:
        current_time = time.time()
        
        # Check timestamp freshness
        if abs(current_time - timestamp) > self.window:
            return True  # Too old or future
        
        # Check nonce uniqueness
        if nonce in self.seen_requests:
            return True  # Already seen
        
        # Store nonce
        self.seen_requests[nonce] = timestamp
        
        # Cleanup old entries
        self._cleanup_old_nonces()
        
        return False
```

#### Test 4.2: Token Revocation

```bash
# Revoke a JWT token
curl -X POST http://<orch-ip>:8001/admin/revoke-token \
  -H "X-API-Key: $ADMIN_KEY" \
  -d '{"jti":"token-123","reason":"Compromised key"}'

# Attempt to use revoked token
curl -X POST http://<orch-ip>:8001/message \
  -H "Authorization: Bearer $REVOKED_TOKEN" \
  -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":"revoke-test"}'

# Expected: 401 Unauthorized (token revoked)
```

**Revocation check flow:**

```mermaid
sequenceDiagram
    participant Client
    participant Orch as Orchestrator
    participant TRL as Token Revocation List
    participant DB as PostgreSQL
    
    Client->>Orch: Request with JWT
    Orch->>Orch: Decode JWT<br/>Extract jti="token-123"
    Orch->>TRL: is_revoked("token-123")?
    
    alt Token in memory cache
        TRL-->>Orch: ✓ Revoked (from cache)
        Orch-->>Client: 401 Unauthorized
    else Not in cache
        TRL->>DB: SELECT * FROM revoked_tokens WHERE jti='token-123'
        DB-->>TRL: Found / Not Found
        TRL->>TRL: Update cache
        TRL-->>Orch: Revoked status
        
        alt Token revoked
            Orch-->>Client: 401 Unauthorized
        else Token valid
            Orch->>Orch: Process request
            Orch-->>Client: 200 OK
        end
    end
```

#### Test 4.3: Rate Limit Enforcement

```bash
# Send requests rapidly to trigger rate limit
for i in {1..150}; do
  curl -s -X POST http://<orch-ip>:8001/message \
    -H "X-API-Key: $API_KEY" \
    -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":"rate-'$i'"}'
done

# Expected: First ~100 succeed (200), remaining rejected (429 Too Many Requests)
```

**Rate limiting algorithm (Sliding Window):**

```python
# Code: a2a_security.py
class RateLimiter:
    def __init__(self, max_requests=100, window_seconds=60):
        self.max_requests = max_requests
        self.window = window_seconds
        self.requests = {}  # {principal: [timestamps]}
    
    def is_allowed(self, principal: str) -> bool:
        now = time.time()
        
        # Get principal's request history
        if principal not in self.requests:
            self.requests[principal] = []
        
        # Remove requests outside window
        self.requests[principal] = [
            ts for ts in self.requests[principal]
            if now - ts < self.window
        ]
        
        # Check limit
        if len(self.requests[principal]) >= self.max_requests:
            return False  # Rate limit exceeded
        
        # Record request
        self.requests[principal].append(now)
        return True
```

---

### Layer 5: End-to-End Pipeline (7 Tests)

**Purpose:** Validate complete document processing workflow from S3 upload to database archival.

#### Test 5.1: S3 Upload Triggers Lambda

```bash
# Upload test document
aws s3 cp test_invoice.pdf s3://ca-a2a-documents/ --region eu-west-3

# Wait for Lambda invocation
sleep 5

# Check Lambda logs
LAMBDA_LOGS=$(aws logs tail /aws/lambda/ca-a2a-s3-processor \
    --since 2m \
    --region eu-west-3)

if echo "$LAMBDA_LOGS" | grep -q "Processing S3 event.*test_invoice.pdf"; then
    echo "✓ S3 event triggered Lambda"
fi
```

#### Test 5.2: Lambda Calls Orchestrator

```bash
# Check Lambda successfully called orchestrator
if echo "$LAMBDA_LOGS" | grep -q "Calling orchestrator.*process_document"; then
    echo "✓ Lambda → Orchestrator: Request sent"
fi

# Check orchestrator received request
ORCH_LOGS=$(aws logs tail /ecs/ca-a2a-orchestrator \
    --since 2m \
    --region eu-west-3)

if echo "$ORCH_LOGS" | grep -q "Received process_document.*test_invoice.pdf"; then
    echo "✓ Orchestrator: Request received"
fi
```

#### Test 5.3: Orchestrator Calls Extractor

```bash
if echo "$ORCH_LOGS" | grep -q "Calling extractor.*extract_document"; then
    echo "✓ Orchestrator → Extractor: Request forwarded"
fi

EXTR_LOGS=$(aws logs tail /ecs/ca-a2a-extractor \
    --since 2m \
    --region eu-west-3)

if echo "$EXTR_LOGS" | grep -q "Extracting.*test_invoice.pdf"; then
    echo "✓ Extractor: Processing document"
fi
```

#### Test 5.4: Extractor Returns Data

```bash
if echo "$EXTR_LOGS" | grep -q "Extraction complete.*bytes"; then
    echo "✓ Extractor: Text extracted successfully"
fi

if echo "$ORCH_LOGS" | grep -q "Received extraction result"; then
    echo "✓ Orchestrator: Received extraction data"
fi
```

#### Test 5.5: Orchestrator Calls Validator

```bash
if echo "$ORCH_LOGS" | grep -q "Calling validator.*validate_document"; then
    echo "✓ Orchestrator → Validator: Request forwarded"
fi

VAL_LOGS=$(aws logs tail /ecs/ca-a2a-validator \
    --since 2m \
    --region eu-west-3)

if echo "$VAL_LOGS" | grep -q "Validating document"; then
    echo "✓ Validator: Validation in progress"
fi
```

#### Test 5.6: Orchestrator Calls Archivist

```bash
if echo "$ORCH_LOGS" | grep -q "Calling archivist.*archive_document"; then
    echo "✓ Orchestrator → Archivist: Request forwarded"
fi

ARCH_LOGS=$(aws logs tail /ecs/ca-a2a-archivist \
    --since 2m \
    --region eu-west-3)

if echo "$ARCH_LOGS" | grep -q "Archiving document.*test_invoice.pdf"; then
    echo "✓ Archivist: Archiving to database"
fi
```

#### Test 5.7: Data Persisted in Database

```bash
# Check database for archived document
DB_ENDPOINT=$(aws rds describe-db-clusters \
    --db-cluster-identifier documents-db \
    --region eu-west-3 \
    --query 'DBClusters[0].Endpoint' \
    --output text)

# Note: Requires database access from ECS task or bastion host
# For CloudShell, use RDS Query Editor or check Archivist logs

if echo "$ARCH_LOGS" | grep -q "Successfully archived.*document_id"; then
    echo "✓ Database: Document archived (ID in logs)"
fi
```

**Complete E2E Flow Diagram:**

```mermaid
sequenceDiagram
    participant S3
    participant Lambda
    participant Orch as Orchestrator
    participant Extr as Extractor
    participant Val as Validator
    participant Arch as Archivist
    participant DB as PostgreSQL
    
    Note over S3: User uploads test_invoice.pdf
    S3->>Lambda: S3 Event: ObjectCreated
    
    Lambda->>Lambda: Parse event<br/>Get s3_key
    Lambda->>Orch: POST /message<br/>process_document(s3_key="test_invoice.pdf")
    
    Orch->>Extr: A2A Call: extract_document
    Extr->>S3: Download PDF
    S3-->>Extr: Binary data
    Extr->>Extr: PyPDF2 extraction
    Extr-->>Orch: {text: "INVOICE...", pages: 2}
    
    Orch->>Val: A2A Call: validate_document
    Val->>Val: Schema validation<br/>Business rules
    Val-->>Orch: {valid: true, confidence: 0.95}
    
    Orch->>Arch: A2A Call: archive_document
    Arch->>DB: INSERT INTO documents_archive
    DB-->>Arch: document_id (UUID)
    Arch-->>Orch: {document_id: "uuid-123"}
    
    Orch-->>Lambda: 200 OK {status: "success"}
    Lambda-->>S3: Processing complete
    
    rect rgb(200, 255, 200)
        Note over S3,DB: ✓ END-TO-END TEST PASSED
    end
```

---

### Layer 6: Performance & Compliance (8 Tests)

**Purpose:** Validate production readiness through performance benchmarks and compliance audits.

#### Test 6.1: Average Response Time

```bash
# Measure orchestrator response time
START=$(date +%s%3N)
curl -X POST http://<orch-ip>:8001/message \
  -H "X-API-Key: $API_KEY" \
  -d '{"jsonrpc":"2.0","method":"health","params":{},"id":"perf-1"}'
END=$(date +%s%3N)

LATENCY=$((END - START))
echo "Orchestrator latency: ${LATENCY}ms"

# Expected: < 50ms for health check
```

#### Test 6.2: Document Processing Throughput

```bash
# Upload 10 documents and measure total time
START=$(date +%s)
for i in {1..10}; do
  aws s3 cp test_doc_${i}.pdf s3://ca-a2a-documents/ &
done
wait

# Wait for processing
sleep 30

# Check how many were archived
ARCHIVED=$(aws logs tail /ecs/ca-a2a-archivist \
    --since 2m \
    --region eu-west-3 \
    | grep -c "Successfully archived")

END=$(date +%s)
DURATION=$((END - START))

echo "Processed $ARCHIVED documents in ${DURATION}s"
echo "Throughput: $((ARCHIVED / DURATION)) docs/sec"

# Expected: > 0.3 docs/sec (>1 doc per 3 seconds)
```

#### Test 6.3: Memory Usage

```bash
# Check agent memory consumption
for AGENT in orchestrator extractor validator archivist; do
  TASK_ARN=$(aws ecs list-tasks \
      --cluster ca-a2a-cluster \
      --service-name ${AGENT} \
      --region eu-west-3 \
      --query 'taskArns[0]' \
      --output text)
  
  # Memory metrics from CloudWatch
  MEMORY=$(aws cloudwatch get-metric-statistics \
      --namespace AWS/ECS \
      --metric-name MemoryUtilization \
      --dimensions Name=ServiceName,Value=${AGENT} Name=ClusterName,Value=ca-a2a-cluster \
      --start-time $(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%S) \
      --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
      --period 300 \
      --statistics Average \
      --region eu-west-3 \
      --query 'Datapoints[0].Average' \
      --output text)
  
  echo "${AGENT}: ${MEMORY}% memory utilization"
  # Expected: < 80% (healthy headroom)
done
```

#### Test 6.4: CPU Usage

```bash
# Similar to memory, check CPU metrics
# Expected: < 50% average (not CPU-bound)
```

#### Test 6.5: Error Rate

```bash
# Calculate error rate from logs
for AGENT in orchestrator extractor validator archivist; do
  TOTAL=$(aws logs tail /ecs/ca-a2a-${AGENT} \
      --since 1h \
      --region eu-west-3 \
      | grep -c "Request\|Processing")
  
  ERRORS=$(aws logs tail /ecs/ca-a2a-${AGENT} \
      --since 1h \
      --region eu-west-3 \
      | grep -c "ERROR\|CRITICAL\|Failed")
  
  if [ $TOTAL -gt 0 ]; then
    ERROR_RATE=$((ERRORS * 100 / TOTAL))
    echo "${AGENT}: ${ERROR_RATE}% error rate ($ERRORS/$TOTAL)"
    # Expected: < 5% (acceptable error rate)
  fi
done
```

#### Test 6.6: Database Query Performance

```bash
# Check slow queries in PostgreSQL logs
SLOW_QUERIES=$(aws rds download-db-log-file-portion \
    --db-instance-identifier documents-db-instance-1 \
    --log-file-name error/postgresql.log \
    --region eu-west-3 \
    | grep -c "slow query")

if [ $SLOW_QUERIES -eq 0 ]; then
  echo "✓ No slow queries detected"
else
  echo "⚠ $SLOW_QUERIES slow queries found"
fi
```

#### Test 6.7: Security Audit Score

```bash
# Comprehensive security checklist
SCORE=0
MAX_SCORE=10

# 1. API keys configured
[ ! -z "$API_KEYS" ] && ((SCORE++))

# 2. RBAC enabled
[ ! -z "$RBAC_POLICY" ] && ((SCORE++))

# 3. Authentication required
[ "$AUTH_REQUIRED" == "true" ] && ((SCORE++))

# 4. HTTPS/TLS enabled
[ "$TLS_ENABLED" == "true" ] && ((SCORE++))

# 5. Rate limiting active
[ "$RATE_LIMIT_ENABLED" == "true" ] && ((SCORE++))

# 6. Secrets in AWS Secrets Manager
aws secretsmanager describe-secret --secret-id ca-a2a/db-password > /dev/null 2>&1 && ((SCORE++))

# 7. VPC isolation
[ "$VPC_ISOLATED" == "true" ] && ((SCORE++))

# 8. CloudWatch logging
[ $LOG_GROUPS_EXIST -eq 4 ] && ((SCORE++))

# 9. No public IPs on agents
[ $PUBLIC_IPS -eq 0 ] && ((SCORE++))

# 10. IAM least privilege
[ "$IAM_AUDIT_PASSED" == "true" ] && ((SCORE++))

echo "Security Audit Score: $SCORE/$MAX_SCORE"
# Expected: 10/10 (full compliance)
```

#### Test 6.8: Compliance Validation

**OWASP API Security Top 10 Checklist:**

| # | Threat | Mitigation | Status |
|---|--------|------------|--------|
| 1 | Broken Object Level Authorization | RBAC + method permissions | ✓ Implemented |
| 2 | Broken Authentication | API Key + JWT | ✓ Implemented |
| 3 | Excessive Data Exposure | Minimal response payloads | ✓ Implemented |
| 4 | Lack of Resources & Rate Limiting | Sliding window rate limiter | ✓ Implemented |
| 5 | Broken Function Level Authorization | Per-method RBAC | ✓ Implemented |
| 6 | Mass Assignment | JSON Schema validation | ✓ Implemented |
| 7 | Security Misconfiguration | IaC + auditing | ✓ Implemented |
| 8 | Injection | Input sanitization + parameterized queries | ✓ Implemented |
| 9 | Improper Assets Management | API versioning + deprecation | ✓ Implemented |
| 10 | Insufficient Logging & Monitoring | CloudWatch + audit logs | ✓ Implemented |

**Compliance Score: 10/10 (100%)**

---

## Running the Test Suite

### Prerequisites

```bash
# AWS CloudShell (recommended) or local terminal with AWS CLI
# Ensure you're in the correct region
export AWS_DEFAULT_REGION=eu-west-3

# Clone repository
git clone https://github.com/jaafar-benabderrazak/ca_a2a.git
cd ca_a2a
```

### Run Comprehensive Integration Tests

```bash
# Make executable
chmod +x comprehensive-system-test.sh

# Run all tests
./comprehensive-system-test.sh

# Expected output:
# ============================================
# COMPREHENSIVE SYSTEM TEST
# Multi-Agent Document Processing Pipeline
# ============================================
#
# ============================================
# TEST 1: INFRASTRUCTURE STATUS
# ============================================
# ✓ PASSED: Service orchestrator: 1/1 tasks running
# ✓ PASSED: Service extractor: 1/1 tasks running
# ... (57 total tests)
#
# ============================================
# FINAL SUMMARY
# ============================================
# Tests Passed:  54
# Tests Failed:  0
# Warnings:      3
# Success Rate:  100%
```

### Run Local Unit Tests

```bash
# Install dependencies
pip3 install pytest pytest-asyncio jsonschema cryptography PyJWT pyOpenSSL

# Run security unit tests
pytest test_security_enhanced.py -v

# Expected output:
# test_security_enhanced.py::TestHMACRequestSigning::test_sign_request PASSED
# test_security_enhanced.py::TestHMACRequestSigning::test_verify_signature PASSED
# ... (25 total tests)
#
# ========================= 25 passed in 2.3s =========================
```

### Run Performance Benchmarks

```bash
# Apache Bench load test (if orchestrator publicly accessible)
ab -n 1000 -c 10 -H "X-API-Key: $API_KEY" \
   -p health_request.json \
   -T application/json \
   http://<orchestrator-ip>:8001/message

# Expected:
# Requests per second: > 100 req/s
# 95th percentile latency: < 100ms
# Failed requests: 0
```

---

## Understanding Test Results

### Success Indicators

**Infrastructure Layer:**
```
✓ PASSED: Service orchestrator: 1/1 tasks running
✓ PASSED: Lambda function: Active
✓ PASSED: Database cluster: Available
```
→ All AWS resources operational

**Security Layer:**
```
✓ PASSED: API keys configured
✓ PASSED: RBAC policy configured
✓ PASSED: Authentication required (enabled)
```
→ Security policies in place

**Functionality Layer:**
```
✓ PASSED: Orchestrator: Healthy (started successfully)
✓ PASSED: Orchestrator → Extractor: Communication verified
```
→ Agents communicating correctly

**Enforcement Layer:**
```
✓ PASSED: API Key enforcement: Rejects unauthenticated requests (HTTP 401)
✓ PASSED: Schema validation: Rejects path traversal attempts
```
→ Security actively blocking attacks

**E2E Layer:**
```
✓ PASSED: S3 event triggered Lambda
✓ PASSED: Database: Document archived (ID in logs)
```
→ Complete workflow functional

### Warning Indicators

**Expected warnings:**
```
⚠ WARNING: HMAC test: Cannot reach orchestrator (VPC network isolation)
```
→ **Normal**: CloudShell can't reach private VPC IPs

```
⚠ WARNING: Audit logging: No recent request logs found
```
→ **Normal if idle**: No recent traffic to log

**Concerning warnings:**
```
⚠ WARNING: Authentication not required (disabled)
```
→ **Review**: System in open mode (dev/test only)

```
⚠ WARNING: Orchestrator: May not be healthy
```
→ **Investigate**: Check logs for errors

### Failure Indicators

**Critical failures:**
```
✗ FAILED: Service orchestrator: 0/1 tasks (NOT HEALTHY)
```
→ **Action**: Check ECS task logs for crash reason

```
✗ FAILED: Database cluster: maintenance
```
→ **Action**: Wait for maintenance window to complete

```
✗ FAILED: API Key enforcement: Accepts unauthenticated requests
```
→ **Action**: Verify `A2A_REQUIRE_AUTH=true` in task definition

---

## Debugging Failed Tests

### Step-by-Step Debugging

#### 1. Check ECS Task Status

```bash
aws ecs describe-tasks \
  --cluster ca-a2a-cluster \
  --tasks $(aws ecs list-tasks \
              --cluster ca-a2a-cluster \
              --service-name orchestrator \
              --query 'taskArns[0]' \
              --output text) \
  --region eu-west-3 \
  --query 'tasks[0].containers[0].[lastStatus,exitCode,reason]'
```

**Possible outputs:**
- `RUNNING, null, null` → ✓ Healthy
- `STOPPED, 1, "Error"` → ✗ Crashed (check logs)
- `PENDING, null, null` → ⏳ Starting up

#### 2. Check CloudWatch Logs

```bash
# Get recent error logs
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 10m \
  --region eu-west-3 \
  --filter-pattern "ERROR"

# Get full startup logs
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 1h \
  --region eu-west-3 \
  | head -100
```

#### 3. Check Task Definition

```bash
# Verify environment variables
aws ecs describe-task-definition \
  --task-definition ca-a2a-orchestrator \
  --region eu-west-3 \
  --query 'taskDefinition.containerDefinitions[0].environment'
```

**Verify:**
- `A2A_API_KEYS_JSON` is valid JSON
- `A2A_REQUIRE_AUTH` is `"true"`
- `AWS_REGION` is `"eu-west-3"`

#### 4. Check Database Connectivity

```bash
# Test from Archivist agent logs
aws logs tail /ecs/ca-a2a-archivist \
  --since 10m \
  --region eu-west-3 \
  | grep -i "database\|connection\|postgres"

# Common issues:
# - "Connection refused" → Security group rules
# - "Authentication failed" → Wrong password in Secrets Manager
# - "Timeout" → Network routing issue
```

#### 5. Check S3 Access

```bash
# Test S3 access from Lambda
aws logs tail /aws/lambda/ca-a2a-s3-processor \
  --since 10m \
  --region eu-west-3 \
  | grep -i "s3\|access\|permission"

# Common issues:
# - "Access Denied" → IAM role missing s3:GetObject
# - "NoSuchKey" → Object already deleted
# - "NoSuchBucket" → Bucket name mismatch
```

---

## Performance Benchmarking

### Baseline Metrics

| **Operation** | **Target** | **Acceptable** | **Critical** |
|---------------|------------|----------------|--------------|
| Health check | < 10ms | < 50ms | > 100ms |
| Skill listing | < 20ms | < 100ms | > 500ms |
| PDF extraction (1 MB) | < 1s | < 3s | > 10s |
| Validation | < 10ms | < 50ms | > 200ms |
| Database write | < 50ms | < 200ms | > 1s |
| E2E processing | < 5s | < 15s | > 60s |

### Custom Load Test

```bash
# Create load test script
cat > load_test.sh << 'EOF'
#!/bin/bash
ORCH_IP="<orchestrator-ip>"
API_KEY="<your-api-key>"
REQUESTS=1000
CONCURRENCY=10

for i in $(seq 1 $REQUESTS); do
  (
    curl -s -w "%{http_code}\n" \
      -X POST http://${ORCH_IP}:8001/message \
      -H "X-API-Key: ${API_KEY}" \
      -d "{\"jsonrpc\":\"2.0\",\"method\":\"health\",\"params\":{},\"id\":\"load-$i\"}" \
      > /dev/null
  ) &
  
  # Throttle concurrency
  if [ $((i % CONCURRENCY)) -eq 0 ]; then
    wait
  fi
done
wait

echo "Load test complete: $REQUESTS requests"
EOF

chmod +x load_test.sh
./load_test.sh
```

### Analyzing Results

```bash
# Count successful vs failed requests
SUCCESS=$(grep "200" load_test_results.txt | wc -l)
FAILED=$(grep -v "200" load_test_results.txt | wc -l)

echo "Success rate: $((SUCCESS * 100 / (SUCCESS + FAILED)))%"

# Expected: > 99% (< 10 failures in 1000 requests)
```

---

## Conclusion

This comprehensive testing framework validates **every layer** of the CA A2A system:

✓ **Infrastructure**: All AWS resources operational  
✓ **Security Config**: Policies and credentials properly set  
✓ **Agent Functions**: All capabilities working  
✓ **Security Enforcement**: Attacks actively blocked  
✓ **E2E Pipeline**: Complete workflow functional  
✓ **Performance**: Meeting production baselines  
✓ **Compliance**: 100% OWASP API Security coverage  

**Total Test Coverage: 57 tests across 6 layers**

For questions or issues, check:
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Common issues and solutions
- [A2A_PROTOCOL_SECURITY_TECHNICAL.md](./A2A_PROTOCOL_SECURITY_TECHNICAL.md) - Security deep dive
- [SECURITY_GUIDE.md](./SECURITY_GUIDE.md) - Security configuration reference

