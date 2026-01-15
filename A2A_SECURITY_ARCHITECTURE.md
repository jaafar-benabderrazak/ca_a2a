# CA-A2A Security Architecture

**Version:** 5.1  
**Last Updated:** January 15, 2026  
**Status:** Production Deployed  
**Region:** eu-west-3 (Paris)  
**Environment:** AWS ECS Fargate

---

## Executive Summary

The CA-A2A (Crédit Agricole Agent-to-Agent) system implements enterprise-grade security through a defense-in-depth architecture with 9 security layers. The system is deployed on AWS ECS Fargate in a private VPC with Keycloak OAuth2/OIDC for centralized authentication, MCP Server for resource access control, and role-based access control.

**Key Security Features:**
- ✅ OAuth2/OIDC Authentication (Keycloak RS256 JWT)
- ✅ Centralized Resource Access (MCP Server for S3/RDS)
- ✅ Role-Based Access Control (RBAC) with fine-grained permissions
- ✅ Token Revocation with hybrid storage (PostgreSQL + in-memory cache)
- ✅ Replay Protection via JWT jti claim tracking
- ✅ Rate Limiting (300 req/min per principal)
- ✅ Network Isolation (Private VPC, Security Groups)
- ✅ Encryption at Rest & In Transit
- ✅ Comprehensive Audit Logging (CloudWatch)

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Security Layers](#2-security-layers)
3. [Authentication & Authorization](#3-authentication--authorization)
4. [Resource Access Layer (MCP Server)](#4-resource-access-layer-mcp-server)
5. [Network Security](#5-network-security)
6. [Data Security](#6-data-security)
7. [Protocol Security (A2A)](#7-protocol-security-a2a)
8. [Monitoring & Audit](#8-monitoring--audit)
9. [Threat Model & Defenses](#9-threat-model--defenses)
10. [Security Operations](#10-security-operations)
11. [Implementation Reference](#11-implementation-reference)

---

## 1. System Architecture

### 1.1 Production Deployment

```mermaid
graph TB
    subgraph Internet
        User[External User]
    end
    
    subgraph AWS["AWS Cloud - eu-west-3"]
        subgraph VPC["VPC: 10.0.0.0/16"]
            subgraph Public["Public Subnets"]
                ALB[Application Load Balancer<br/>HTTPS/HTTP]
                NAT[NAT Gateway]
            end
            
            subgraph Private["Private Subnets - ECS Cluster"]
                direction TB
                Orch[Orchestrator<br/>:8001]
                Ext[Extractor<br/>:8002]
                Val[Validator<br/>:8003]
                Arch[Archivist<br/>:8004]
                KC[Keycloak<br/>:8080]
                MCP[MCP Server<br/>:8000<br/>Resource Gateway]
            end
            
            subgraph Data["Data Layer"]
                RDS[RDS Aurora PostgreSQL<br/>documents DB]
                KC_RDS[RDS PostgreSQL<br/>keycloak DB]
            end
        end
        
        subgraph Services["AWS Services"]
            SM[Secrets Manager]
            CW[CloudWatch Logs]
            S3[S3 Bucket]
            ECR[ECR Repositories]
        end
    end
    
    User -->|1. HTTPS| ALB
    ALB -->|2. HTTP| Orch
    Orch -->|A2A Protocol| Ext
    Orch -->|A2A Protocol| Val
    Orch -->|A2A Protocol| Arch
    
    Orch -.->|Auth| KC
    Ext -.->|Auth| KC
    Val -.->|Auth| KC
    Arch -.->|Auth| KC
    
    KC -->|JDBC| KC_RDS
    
    Orch -->|HTTP API| MCP
    Ext -->|HTTP API| MCP
    Val -->|HTTP API| MCP
    Arch -->|HTTP API| MCP
    
    MCP -->|asyncpg<br/>Connection Pool| RDS
    MCP -.->|aioboto3| S3
    Arch -.->|boto3| S3
    
    Private -.->|VPC Endpoints| SM
    Private -.->|VPC Endpoints| CW
    Private -.->|NAT Gateway| Internet
```

### 1.2 Component Overview

| Component | Type | Port | Purpose | Instances |
|-----------|------|------|---------|-----------|
| **Orchestrator** | ECS Fargate | 8001 | Request coordination, workflow | 2 |
| **Extractor** | ECS Fargate | 8002 | Document text extraction | 2 |
| **Validator** | ECS Fargate | 8003 | Content validation | 2 |
| **Archivist** | ECS Fargate | 8004 | Document archival, retrieval | 2 |
| **Keycloak** | ECS Fargate | 8080 | Identity Provider (OAuth2/OIDC) | 1 |
| **ALB** | AWS Service | 80/443 | Load balancing, TLS termination | Multi-AZ |
| **RDS Aurora** | Managed DB | 5432 | Document metadata, audit logs | Multi-AZ |
| **RDS Postgres** | Managed DB | 5432 | Keycloak data (users, roles) | Multi-AZ |

---

## 2. Security Layers

### 2.1 Defense-in-Depth Architecture

```mermaid
graph TB
    L1[Layer 1: Network Isolation<br/>VPC, Security Groups, NACLs]
    L2[Layer 2: Identity & Access<br/>Keycloak OAuth2/OIDC]
    L3[Layer 3: Authentication<br/>JWT RS256 Signature Verification]
    L4[Layer 4: Authorization<br/>RBAC with Keycloak Roles]
    L5[Layer 5: Resource Access Control<br/>MCP Server Gateway]
    L6[Layer 6: Message Integrity<br/>JWT Body Hash Binding]
    L7[Layer 7: Input Validation<br/>JSON Schema, Pydantic Models]
    L8[Layer 8: Replay Protection<br/>JWT jti Nonce Tracking]
    L9[Layer 9: Rate Limiting<br/>Sliding Window Per Principal]
    
    L1 --> L2 --> L3 --> L4 --> L5 --> L6 --> L7 --> L8 --> L9
    
    style L1 fill:#ff6b6b
    style L2 fill:#ffd93d
    style L3 fill:#6bcf7f
    style L4 fill:#4d96ff
    style L5 fill:#ffd700
    style L6 fill:#a66cff
    style L7 fill:#ff9a76
    style L8 fill:#62cdff
    style L9 fill:#f4b860
```

### 2.2 Layer Responsibilities

| Layer | Purpose | Technology | Threat Mitigated |
|-------|---------|------------|------------------|
| **L1: Network** | Isolation, segmentation | VPC, SG, NACL | Network attacks, DDoS |
| **L2: Identity** | Centralized authentication | Keycloak | Unauthorized access |
| **L3: Authentication** | Token verification | JWT RS256 | Impersonation, forged tokens |
| **L4: Authorization** | Permission enforcement | RBAC (Keycloak roles) | Privilege escalation |
| **L5: Resource Access** | **Centralized S3/RDS gateway** | **MCP Server** | **Direct AWS access, credential sprawl** |
| **L6: Integrity** | Message tampering detection | JWT body hash | MITM, message tampering |
| **L7: Validation** | Malformed input rejection | JSON Schema, Pydantic | Injection attacks, DoS |
| **L8: Replay** | Duplicate request detection | JWT jti + TTL cache | Replay attacks |
| **L9: Rate Limit** | Abuse prevention | Sliding window | Resource exhaustion, DoS |

---

## 3. Authentication & Authorization

### 3.1 Keycloak OAuth2/OIDC Flow

```mermaid
sequenceDiagram
    participant Client
    participant Keycloak
    participant Orchestrator
    participant Agent

    Note over Client,Agent: 1. Initial Authentication
    Client->>Keycloak: POST /realms/ca-a2a/protocol/openid-connect/token<br/>{client_id, client_secret, grant_type}
    Keycloak->>Keycloak: Verify credentials<br/>Check roles
    Keycloak-->>Client: 200 OK<br/>{access_token (JWT), refresh_token, expires_in}
    
    Note over Client,Agent: 2. API Request with JWT
    Client->>Orchestrator: POST /message<br/>Authorization: Bearer <JWT>
    Orchestrator->>Orchestrator: Extract JWT from header
    Orchestrator->>Keycloak: GET /realms/ca-a2a/protocol/openid-connect/certs
    Keycloak-->>Orchestrator: JWKS (public keys)
    Orchestrator->>Orchestrator: Verify JWT signature (RS256)<br/>Check expiration, audience, issuer
    Orchestrator->>Orchestrator: Extract Keycloak roles<br/>Map to RBAC permissions
    Orchestrator->>Orchestrator: Check if role permits method
    
    alt Authorized
        Orchestrator->>Agent: Forward request with JWT
        Agent->>Keycloak: Verify JWT (same process)
        Agent->>Orchestrator: Response
        Orchestrator-->>Client: 200 OK {result}
    else Unauthorized
        Orchestrator-->>Client: 403 Forbidden<br/>{error: "Insufficient permissions"}
    end
    
    Note over Client,Agent: 3. Token Refresh (before expiry)
    Client->>Keycloak: POST /realms/ca-a2a/protocol/openid-connect/token<br/>{grant_type: "refresh_token", refresh_token}
    Keycloak-->>Client: 200 OK<br/>{new access_token, new refresh_token}
```

### 3.2 JWT Token Structure

**Access Token (RS256 signed by Keycloak):**
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "keycloak-key-id"
  },
  "payload": {
    "exp": 1737845500,
    "iat": 1737845200,
    "jti": "abc123-token-id",
    "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
    "aud": "ca-a2a-agents",
    "sub": "user-uuid-1234",
    "typ": "Bearer",
    "azp": "ca-a2a-agents",
    "realm_access": {
      "roles": ["admin", "orchestrator", "document-processor"]
    },
    "resource_access": {
      "ca-a2a-agents": {
        "roles": ["admin"]
      }
    },
    "preferred_username": "john.doe@example.com",
    "email": "john.doe@example.com"
  },
  "signature": "..."
}
```

### 3.3 Role-Based Access Control (RBAC)

**Keycloak Realm Roles → A2A RBAC Mapping:**

| Keycloak Role | A2A Principal | Allowed Methods | Use Case |
|---------------|---------------|-----------------|----------|
| `admin` | `admin` | `*` (all methods) | Full system access |
| `lambda` | `lambda` | `upload_document`, `process_document` | External triggers (S3 events) |
| `orchestrator` | `orchestrator` | `extract_document`, `validate_document`, `archive_document` | Agent-to-agent coordination |
| `document-processor` | `document-processor` | `process_document`, `list_pending_documents`, `check_status` | Document processing workflows |
| `viewer` | `viewer` | `list_documents`, `get_document`, `check_status` | Read-only access |

**Implementation (`keycloak_auth.py`):**
```python
class KeycloakRBACMapper:
    def map_roles_to_principal(self, keycloak_roles: List[str]) -> Tuple[str, List[str]]:
        # Priority: admin > lambda > orchestrator > document-processor > viewer
        if "admin" in keycloak_roles:
            return "admin", ["*"]
        elif "lambda" in keycloak_roles:
            return "lambda", ["upload_document", "process_document"]
        elif "orchestrator" in keycloak_roles:
            return "orchestrator", ["extract_document", "validate_document", "archive_document"]
        elif "document-processor" in keycloak_roles:
            return "document-processor", ["process_document", "list_pending_documents", "check_status"]
        elif "viewer" in keycloak_roles:
            return "viewer", ["list_documents", "get_document", "check_status"]
        else:
            return "anonymous", []
```

### 3.4 Token Revocation

**Storage: Hybrid Architecture**

```mermaid
graph LR
    Admin[Admin API] -->|1. Revoke| Cache[In-Memory Cache<br/>Ultra-fast: ~1μs]
    Admin -->|2. Persist| DB[(PostgreSQL<br/>revoked_tokens)]
    
    Request[Request] -->|3. Check| Cache
    Cache -->|Cache Miss| DB
    DB -->|4. Load| Cache
    Cache -->|Hit/Miss| Response[Accept/Reject]
    
    style Cache fill:#ffd93d
    style DB fill:#4d96ff
```

**Revocation Table Schema:**
```sql
CREATE TABLE revoked_tokens (
    jti VARCHAR(255) PRIMARY KEY,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_by VARCHAR(100) NOT NULL,
    reason TEXT,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_revoked_expires ON revoked_tokens(expires_at);
CREATE INDEX idx_revoked_by ON revoked_tokens(revoked_by);
```

**Admin API Endpoints:**
- `POST /admin/revoke-token` - Revoke JWT by jti
- `GET /admin/revoked-tokens` - List revoked tokens
- `GET /admin/security-stats` - Security metrics
- `DELETE /admin/cleanup-expired-tokens` - Manual cleanup

**Performance:**
- Revoke operation: ~10ms (DB write + cache store)
- Check (cached): ~1μs
- Check (cache miss): ~10ms (DB query + cache load)
- Auto-cleanup: Every 5 minutes

---

## 4. Resource Access Layer (MCP Server)

### 4.1 Architecture Overview

The MCP (Model Context Protocol) Server acts as a **centralized gateway** for all AWS resource access (S3 and RDS PostgreSQL). Instead of agents directly accessing AWS services, they communicate with the MCP Server via HTTP API.

```mermaid
sequenceDiagram
    participant Agent as Agent<br/>(Orchestrator/Extractor/Validator/Archivist)
    participant MCP as MCP Server<br/>:8000
    participant RDS as RDS PostgreSQL
    participant S3 as S3 Bucket
    
    Note over Agent,MCP: 1. Agent needs to access S3
    Agent->>MCP: POST /call_tool<br/>{"tool": "s3_get_object", "arguments": {"key": "doc.pdf"}}
    MCP->>MCP: Circuit breaker check
    MCP->>MCP: Retry logic
    MCP->>S3: GetObject(bucket, key)
    S3-->>MCP: Object data
    MCP-->>Agent: {"content": "...", "success": true}
    
    Note over Agent,RDS: 2. Agent needs to query database
    Agent->>MCP: POST /call_tool<br/>{"tool": "postgres_query", "arguments": {"query": "SELECT..."}}
    MCP->>MCP: Get connection from pool
    MCP->>RDS: Execute query
    RDS-->>MCP: Rows
    MCP-->>Agent: {"rows": [...], "count": N, "success": true}
```

### 4.2 Security Benefits

| Benefit | Description | Impact |
|---------|-------------|--------|
| **Reduced Attack Surface** | Only MCP Server has AWS credentials, not all 4 agents | -75% IAM roles with AWS access |
| **Centralized Audit** | All S3/RDS access logged in one place | +100% visibility |
| **Connection Pooling** | Shared PostgreSQL connection pool (max 10 connections) | -88% DB connections (4×20=80 → 10) |
| **Consistent Security** | Retry logic, circuit breakers, timeouts applied uniformly | Standardized error handling |
| **Easier IAM Management** | Update permissions in single task role | -4 IAM policy updates per change |
| **Credential Isolation** | Agents never see DB passwords or AWS keys | Reduced secret sprawl |

### 4.3 Component Details

**ECS Service:**
- **Name:** `mcp-server`
- **Task Definition:** `ca-a2a-mcp-server`
- **CPU:** 256 (.25 vCPU)
- **Memory:** 512 MB
- **Port:** 8000
- **Service Discovery:** `mcp-server.ca-a2a.local:8000`

**IAM Permissions (MCP Server Task Role):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::ca-a2a-documents-555043101106",
        "arn:aws:s3:::ca-a2a-documents-555043101106/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:eu-west-3:555043101106:secret:ca-a2a/*"
    }
  ]
}
```

**Note:** Agents no longer need S3 or Secrets Manager permissions. MCP Server handles all AWS API calls.

### 4.4 Available Operations

**S3 Operations:**
```python
# List objects with prefix
POST /call_tool
{
  "tool": "s3_list_objects",
  "arguments": {
    "prefix": "uploads/",
    "limit": 100
  }
}

# Get object content
POST /call_tool
{
  "tool": "s3_get_object",
  "arguments": {
    "key": "uploads/document123.pdf"
  }
}

# Upload object
POST /call_tool
{
  "tool": "s3_put_object",
  "arguments": {
    "key": "processed/document123.pdf",
    "body": "<base64-encoded-content>",
    "content_type": "application/pdf"
  }
}
```

**PostgreSQL Operations:**
```python
# Execute SELECT query
POST /call_tool
{
  "tool": "postgres_query",
  "arguments": {
    "query": "SELECT * FROM documents WHERE status = $1",
    "params": ["pending"]
  }
}

# Execute INSERT/UPDATE/DELETE
POST /call_tool
{
  "tool": "postgres_execute",
  "arguments": {
    "query": "INSERT INTO documents (s3_key, status) VALUES ($1, $2)",
    "params": ["uploads/doc.pdf", "processing"]
  }
}

# Initialize database schema
POST /call_tool
{
  "tool": "postgres_init_schema",
  "arguments": {}
}
```

### 4.5 Health Check

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-01-15T12:34:56Z",
  "services": {
    "postgresql": "ok",
    "s3": "ok"
  }
}
```

### 4.6 Connection Pooling

**PostgreSQL Pool Configuration:**
```python
# mcp_server_http.py
await asyncpg.create_pool(
    host=POSTGRES_CONFIG['host'],
    port=POSTGRES_CONFIG['port'],
    user=POSTGRES_CONFIG['user'],
    password=POSTGRES_CONFIG['password'],  # From Secrets Manager
    database=POSTGRES_CONFIG['database'],
    min_size=2,        # Keep 2 connections warm
    max_size=10,       # Max 10 concurrent connections
    command_timeout=60, # 60-second query timeout
    ssl='require'      # Force SSL/TLS
)
```

**Benefits:**
- 4 agents × 20 connections = 80 total → **Reduced to 10 total**
- Connection reuse reduces latency
- Automatic connection health checks
- Graceful degradation on connection loss

### 4.7 Circuit Breaker & Retry Logic

**Circuit Breaker:**
```python
circuit_breaker = CircuitBreaker(
    failure_threshold=5,      # Open after 5 consecutive failures
    recovery_timeout=60,      # Try to recover after 60 seconds
    expected_exception=ClientError  # S3/RDS exceptions
)
```

**Retry Strategy:**
```python
@retry_with_backoff(
    max_retries=3,           # Retry up to 3 times
    exceptions=(ClientError, PostgresError)
)
async def call_aws_service():
    # Operation that may fail transiently
    pass
```

**States:**
1. **Closed (Normal):** All requests pass through
2. **Open (Failed):** All requests immediately fail (fail-fast)
3. **Half-Open (Testing):** Limited requests allowed to test recovery

### 4.8 Performance Characteristics

| Operation | Latency | Throughput |
|-----------|---------|------------|
| S3 GetObject (1MB) | ~175ms | 50 req/sec |
| S3 PutObject (1MB) | ~200ms | 40 req/sec |
| PostgreSQL Query (simple) | ~25ms | 400 req/sec |
| PostgreSQL Insert | ~18ms | 550 req/sec |

**Overhead vs. Direct Access:** ~20-25% (acceptable for security benefits)

### 4.9 Monitoring

**CloudWatch Metrics:**
- Request count per tool
- Success vs. error rates
- Circuit breaker state changes
- Connection pool usage
- Response time percentiles (p50, p95, p99)

**Log Queries:**
```bash
# View MCP server logs
aws logs tail /ecs/ca-a2a-mcp-server --follow --region eu-west-3

# Filter for errors
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-mcp-server \
  --filter-pattern "ERROR" \
  --region eu-west-3

# Count tool calls by type
aws logs insights start-query \
  --log-group-name /ecs/ca-a2a-mcp-server \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string 'fields @timestamp, tool | stats count() by tool'
```

### 4.10 Security Hardening

**Network Isolation:**
- MCP Server in private subnet (no public IP)
- Only accessible via service discovery DNS
- Security group allows inbound only from agent security groups

**Secrets Management:**
- PostgreSQL password retrieved from Secrets Manager at startup
- Never logged or exposed in environment variables
- Automatic rotation supported

**Least Privilege:**
- Task role has minimal required S3 permissions
- No write access to CloudWatch Logs (execution role handles logging)
- No access to other AWS services (ECR, ECS, etc.)

**Request Validation:**
- Tool name validated against whitelist
- Query parameters sanitized
- Maximum request size enforced (1MB)

---

## 5. Network Security

### 4.1 VPC Architecture

```
VPC: 10.0.0.0/16 (65,536 IPs)
├── Public Subnets (Internet-facing)
│   ├── 10.0.1.0/24 (AZ-a) - ALB, NAT Gateway
│   └── 10.0.2.0/24 (AZ-b) - ALB (Multi-AZ)
│
└── Private Subnets (Internal only)
    ├── 10.0.10.0/24 (AZ-a) - ECS Tasks
    └── 10.0.20.0/24 (AZ-b) - ECS Tasks, RDS
```

**Security Implications:**
- ✅ **Zero public IPs on agents**: All ECS tasks in private subnets
- ✅ **Outbound only via NAT**: Agents cannot receive inbound internet traffic
- ✅ **Multi-AZ redundancy**: Survives single AZ failure
- ✅ **Private DNS**: Service discovery via `agent.ca-a2a.local`

### 4.2 Security Groups (Virtual Firewalls)

```mermaid
graph TB
    subgraph Internet
        User[User]
    end
    
    subgraph ALB_SG["ALB Security Group"]
        ALB[Load Balancer]
    end
    
    subgraph Orch_SG["Orchestrator SG"]
        Orch[Orchestrator:8001]
    end
    
    subgraph Agent_SG["Agent Security Groups"]
        Ext[Extractor:8002]
        Val[Validator:8003]
        Arch[Archivist:8004]
    end
    
    subgraph KC_SG["Keycloak SG"]
        KC[Keycloak:8080]
    end
    
    subgraph RDS_SG["RDS Security Group"]
        RDS[(PostgreSQL:5432)]
    end
    
    User -->|"Inbound: 80/443<br/>from 0.0.0.0/0"| ALB
    ALB -->|"Inbound: 8001<br/>from ALB-SG"| Orch
    Orch -->|"Inbound: 8002<br/>from Orch-SG"| Ext
    Orch -->|"Inbound: 8003<br/>from Orch-SG"| Val
    Orch -->|"Inbound: 8004<br/>from Orch-SG"| Arch
    
    Orch -.->|"Inbound: 8080<br/>from Agent-SGs"| KC
    Ext -.->|"Inbound: 8080<br/>from Agent-SGs"| KC
    Val -.->|"Inbound: 8080<br/>from Agent-SGs"| KC
    Arch -.->|"Inbound: 8080<br/>from Agent-SGs"| KC
    
    Orch -.->|"Inbound: 5432<br/>from Agent-SGs"| RDS
    Ext -.->|"Inbound: 5432<br/>from Agent-SGs"| RDS
    Val -.->|"Inbound: 5432<br/>from Agent-SGs"| RDS
    Arch -.->|"Inbound: 5432<br/>from Agent-SGs"| RDS
    KC -.->|"Inbound: 5432<br/>from KC-SG"| RDS
```

**Rules Summary:**

| Security Group | Inbound Rules | Purpose |
|----------------|---------------|---------|
| **ALB-SG** | 80/tcp from 0.0.0.0/0<br/>443/tcp from 0.0.0.0/0 | Public HTTP/HTTPS access |
| **Orchestrator-SG** | 8001/tcp from ALB-SG | ALB → Orchestrator only |
| **Extractor-SG** | 8002/tcp from Orch-SG | Orchestrator → Extractor only |
| **Validator-SG** | 8003/tcp from Orch-SG | Orchestrator → Validator only |
| **Archivist-SG** | 8004/tcp from Orch-SG | Orchestrator → Archivist only |
| **Keycloak-SG** | 8080/tcp from Agent-SGs | All agents → Keycloak auth |
| **RDS-SG** | 5432/tcp from Agent-SGs + KC-SG | Database access |

**Default Deny:** All security groups have implicit deny-all rules. Only explicitly allowed traffic is permitted.

### 4.3 VPC Endpoints (AWS PrivateLink)

**Purpose:** Access AWS services without internet gateway

| Service | Endpoint Type | Purpose |
|---------|--------------|---------|
| **com.amazonaws.eu-west-3.ecr.api** | Interface | Pull container images |
| **com.amazonaws.eu-west-3.ecr.dkr** | Interface | Docker registry authentication |
| **com.amazonaws.eu-west-3.s3** | Gateway | S3 object storage |
| **com.amazonaws.eu-west-3.logs** | Interface | CloudWatch Logs |
| **com.amazonaws.eu-west-3.secretsmanager** | Interface | Secrets Manager |

**Benefits:**
- ✅ Traffic stays within AWS network (no public internet)
- ✅ Reduced NAT Gateway costs
- ✅ Enhanced security (no exposure to internet threats)

---

## 5. Data Security

### 5.1 Encryption at Rest

| Resource | Encryption | Key Management |
|----------|-----------|----------------|
| **RDS Aurora PostgreSQL** | AES-256 | AWS KMS (default key) |
| **RDS PostgreSQL (Keycloak)** | AES-256 | AWS KMS (default key) |
| **S3 Bucket** | SSE-S3 (AES-256) | AWS-managed keys |
| **EBS Volumes (ECS)** | AES-256 | AWS KMS (default key) |
| **Secrets Manager** | AES-256 | AWS KMS (dedicated key) |
| **CloudWatch Logs** | AES-256 | AWS-managed keys |

### 5.2 Encryption in Transit

```mermaid
graph LR
    User[User] -->|"1. HTTPS (TLS 1.2+)"| ALB[ALB]
    ALB -->|"2. HTTP"| Orch[Orchestrator]
    Orch -->|"3. HTTP + JWT"| Agents[Other Agents]
    Agents -->|"4. TLS 1.2"| RDS[RDS PostgreSQL]
    Agents -->|"5. HTTPS"| S3[S3 API]
    Agents -->|"6. HTTPS"| SM[Secrets Manager]
    
    style User fill:#90EE90
    style ALB fill:#FFD93D
    style Orch fill:#87CEEB
    style Agents fill:#DDA0DD
```

**Current State:**
- ✅ User → ALB: HTTPS (TLS 1.2+) - Can be enabled via ACM certificate
- ⚠️ ALB → Orchestrator: HTTP (within VPC) - Low risk due to VPC isolation
- ⚠️ Agent-to-Agent: HTTP (within VPC) - Protected by JWT signature
- ✅ Agents → RDS: TLS 1.2 (asyncpg with SSL)
- ✅ Agents → AWS Services: HTTPS (boto3 default)

**Recommendation:** Enable TLS between ALB and agents for defense-in-depth.

### 5.3 Secrets Management

**AWS Secrets Manager:**

| Secret Name | Purpose | Rotation |
|-------------|---------|----------|
| `ca-a2a/db-password` | RDS Aurora master password | Manual |
| `ca-a2a/keycloak-admin-password` | Keycloak admin console | Manual |
| `ca-a2a/keycloak-db-password` | Keycloak RDS password | Manual |
| `ca-a2a/keycloak-client-secret` | OAuth2 client secret | Manual |

**Retrieval Method:**
```python
import boto3

def get_secret(secret_name: str) -> str:
    client = boto3.client('secretsmanager', region_name='eu-west-3')
    response = client.get_secret_value(SecretId=secret_name)
    return response['SecretString']

# Used in ECS task definitions via valueFrom
{
  "name": "POSTGRES_PASSWORD",
  "valueFrom": "arn:aws:secretsmanager:eu-west-3:555043101106:secret:ca-a2a/db-password"
}
```

**No Hardcoded Secrets:** All sensitive values are retrieved at runtime from Secrets Manager.

---

## 7. Protocol Security (A2A)

### 7.1 JSON-RPC 2.0 Message Format

**Request Structure:**
```json
{
  "jsonrpc": "2.0",
  "id": "req-12345",
  "method": "process_document",
  "params": {
    "document_id": "doc-789",
    "s3_key": "uploads/invoice.pdf"
  }
}
```

**Response Structure:**
```json
{
  "jsonrpc": "2.0",
  "id": "req-12345",
  "result": {
    "status": "success",
    "document_id": "doc-789",
    "extracted_text": "..."
  },
  "_meta": {
    "correlation_id": "2026-01-15T10:30:00Z-a1b2c3d4",
    "duration_ms": 250
  }
}
```

**Error Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "req-12345",
  "error": {
    "code": -32600,
    "message": "Invalid request",
    "data": {
      "detail": "Missing required field: document_id"
    }
  }
}
```

### 7.2 HTTP Headers Schema

**Required Headers:**

| Header | Type | Required | Description | Example |
|--------|------|----------|-------------|---------|
| `Content-Type` | String | ✅ Yes | Must be `application/json` | `application/json` |
| `Authorization` | String | ✅ Yes | Bearer JWT token from Keycloak | `Bearer eyJhbGc...` |
| `X-Correlation-ID` | String | ⚠️ Optional | Request tracing ID | `2026-01-15T10:30:00Z-a1b2c3d4` |
| `User-Agent` | String | ⚠️ Optional | Client identifier | `CA-A2A-Client/1.0` |

**Security Headers (Response):**

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevent MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-XSS-Protection` | `1; mode=block` | XSS protection |
| `Strict-Transport-Security` | `max-age=31536000` | Force HTTPS |
| `Content-Security-Policy` | `default-src 'self'` | CSP policy |

**Header Validation:**
```python
# base_agent.py - Header validation
def validate_headers(headers: Dict[str, str]) -> Tuple[bool, Optional[str]]:
    """Validate required HTTP headers"""
    
    # Check Content-Type
    content_type = headers.get('Content-Type', '')
    if not content_type.startswith('application/json'):
        return False, "Content-Type must be application/json"
    
    # Check Authorization
    auth = headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return False, "Authorization header must use Bearer token"
    
    # Extract and validate JWT format
    token = auth.replace('Bearer ', '').strip()
    if not token or len(token) < 10:
        return False, "Invalid JWT token format"
    
    return True, None
```

### 7.3 JSON Schema Validation

**Schema Definition for All Methods:**

The system validates all incoming requests against predefined JSON schemas. This prevents injection attacks, malformed data, and ensures type safety.

#### 7.3.1 Process Document Schema

```json
{
  "type": "object",
  "properties": {
    "s3_key": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9/_-][a-zA-Z0-9/_.-]*$",
      "not": {"pattern": "\\.\\."},
      "minLength": 1,
      "maxLength": 1024,
      "description": "S3 object key (no path traversal)"
    },
    "priority": {
      "type": "string",
      "enum": ["low", "normal", "high"],
      "description": "Processing priority"
    },
    "correlation_id": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9-]+$",
      "maxLength": 128,
      "description": "Request correlation ID for tracing"
    }
  },
  "required": ["s3_key"],
  "additionalProperties": false
}
```

**Security Features:**
- ✅ **Path Traversal Protection:** Pattern `^[a-zA-Z0-9/_-]` prevents `../` sequences
- ✅ **Length Limits:** Max 1024 chars prevents buffer overflow
- ✅ **No Additional Properties:** `additionalProperties: false` prevents mass assignment
- ✅ **Type Safety:** Strict string type checking

#### 7.3.2 Extract Document Schema

```json
{
  "type": "object",
  "properties": {
    "s3_key": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9/_-][a-zA-Z0-9/_.-]*$",
      "not": {"pattern": "\\.\\."},
      "minLength": 1,
      "maxLength": 1024
    },
    "correlation_id": {
      "type": "string",
      "maxLength": 128
    }
  },
  "required": ["s3_key"],
  "additionalProperties": false
}
```

#### 7.3.3 Validate Document Schema

```json
{
  "type": "object",
  "properties": {
    "extracted_data": {
      "type": "object",
      "description": "Extracted document data from extractor"
    },
    "s3_key": {
      "type": "string",
      "maxLength": 1024
    },
    "correlation_id": {
      "type": "string",
      "maxLength": 128
    }
  },
  "required": ["extracted_data"],
  "additionalProperties": false
}
```

#### 7.3.4 Archive Document Schema

```json
{
  "type": "object",
  "properties": {
    "s3_key": {
      "type": "string",
      "maxLength": 1024
    },
    "extracted_data": {
      "type": "object",
      "description": "Extracted document data"
    },
    "validation_result": {
      "type": "object",
      "description": "Validation results from validator"
    },
    "correlation_id": {
      "type": "string",
      "maxLength": 128
    }
  },
  "required": ["s3_key", "extracted_data", "validation_result"],
  "additionalProperties": false
}
```

#### 7.3.5 Get Document Schema

```json
{
  "type": "object",
  "properties": {
    "document_id": {
      "type": "integer",
      "minimum": 1,
      "description": "Database document ID"
    }
  },
  "required": ["document_id"],
  "additionalProperties": false
}
```

**Implementation:**
```python
# a2a_security_enhanced.py
class JSONSchemaValidator:
    """Validates JSON-RPC method parameters against predefined schemas"""
    
    SCHEMAS = {
        "process_document": {...},  # As above
        "extract_document": {...},
        "validate_document": {...},
        "archive_document": {...},
        "get_document": {...}
    }
    
    def validate(self, method: str, params: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Validate params against schema for given method
        Returns: (is_valid, error_message)
        """
        if not self.enabled:
            return True, None
        
        schema = self.SCHEMAS.get(method)
        if not schema:
            logger.debug(f"No schema defined for method: {method}")
            return True, None  # No schema = allow (backward compatibility)
        
        try:
            self.validator.validate(instance=params, schema=schema)
            return True, None
        except self.validator.ValidationError as e:
            error_msg = f"Schema validation failed for '{method}': {e.message}"
            logger.warning(error_msg)
            return False, error_msg
```

### 7.4 Pydantic Models (Type-Safe Validation)

In addition to JSON Schema, the system uses **Pydantic models** for stronger type safety and automatic validation.

#### 7.4.1 Process Document Models

```python
from pydantic import BaseModel, Field, field_validator
from typing import Literal

class ProcessDocumentRequest(BaseModel):
    """Type-safe request for document processing"""
    s3_key: str = Field(
        ..., 
        description="S3 key of the document", 
        min_length=1,
        max_length=1024
    )
    priority: Literal["low", "normal", "high"] = Field(
        default="normal", 
        description="Processing priority"
    )
    
    @field_validator('s3_key')
    @classmethod
    def validate_s3_key(cls, v: str) -> str:
        """Custom validation: prevent path traversal"""
        if not v.strip():
            raise ValueError("s3_key cannot be empty")
        if ".." in v:
            raise ValueError("Path traversal not allowed")
        if not v[0].isalnum():
            raise ValueError("s3_key must start with alphanumeric")
        return v.strip()
    
    model_config = {"extra": "forbid"}  # Reject unknown fields

class ProcessDocumentResponse(BaseModel):
    """Type-safe response from document processing"""
    task_id: str
    s3_key: str
    status: Literal["pending", "processing", "completed", "failed"]
    message: str
```

#### 7.4.2 Extract Document Models

```python
class ExtractDocumentRequest(BaseModel):
    """Request to extract document data"""
    s3_key: str = Field(..., min_length=1, max_length=1024)

class PDFExtractedData(BaseModel):
    """Complete PDF extraction result"""
    pages: List[Dict[str, Any]]
    tables: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    total_pages: int
    text_content: str

class ExtractDocumentResponse(BaseModel):
    """Response from document extraction"""
    s3_key: str
    document_type: Literal["pdf", "csv", "unknown"]
    file_name: str
    file_size: int
    extracted_data: Dict[str, Any]  # PDFExtractedData or CSVExtractedData
    extraction_status: Literal["success", "partial", "failed"]
```

#### 7.4.3 Complete Model Inventory

| Method | Request Model | Response Model | Fields |
|--------|---------------|----------------|--------|
| `process_document` | `ProcessDocumentRequest` | `ProcessDocumentResponse` | s3_key, priority |
| `process_batch` | `ProcessBatchRequest` | `ProcessBatchResponse` | prefix, limit |
| `extract_document` | `ExtractDocumentRequest` | `ExtractDocumentResponse` | s3_key |
| `validate_document` | `ValidateDocumentRequest` | `ValidateDocumentResponse` | extracted_data |
| `archive_document` | `ArchiveDocumentRequest` | `ArchiveDocumentResponse` | s3_key, data |
| `get_task_status` | `GetTaskStatusRequest` | `GetTaskStatusResponse` | task_id |
| `list_pending_documents` | `ListPendingDocumentsRequest` | `ListPendingDocumentsResponse` | limit |

**Usage in Agent:**
```python
# base_agent.py
from pydantic import ValidationError
from pydantic_models import ProcessDocumentRequest

async def handle_process_document(self, params: dict) -> dict:
    """Handle process_document with Pydantic validation"""
    try:
        # Validate input with Pydantic
        request = ProcessDocumentRequest(**params)
        
        # Access type-safe fields
        s3_key = request.s3_key  # Guaranteed to be valid
        priority = request.priority  # Guaranteed to be "low", "normal", or "high"
        
        # Process document...
        result = await self._process(s3_key, priority)
        
        # Return validated response
        return ProcessDocumentResponse(
            task_id=result['task_id'],
            s3_key=s3_key,
            status=result['status'],
            message=result['message']
        ).model_dump()
        
    except ValidationError as e:
        # Pydantic validation failed
        raise ValueError(f"Invalid request: {e.errors()}")
```

### 7.5 Content Validation Rules

**Validation Layers:**

```mermaid
graph TD
    A[Incoming Request] --> B{1. HTTP Headers Valid?}
    B -->|No| E1[401 Unauthorized]
    B -->|Yes| C{2. JSON Parseable?}
    C -->|No| E2[-32700 Parse Error]
    C -->|Yes| D{3. JSON-RPC 2.0 Format?}
    D -->|No| E3[-32600 Invalid Request]
    D -->|Yes| F{4. JSON Schema Valid?}
    F -->|No| E4[-32602 Invalid Params]
    F -->|Yes| G{5. Pydantic Model Valid?}
    G -->|No| E5[-32602 Type Error]
    G -->|Yes| H{6. Business Rules Valid?}
    H -->|No| E6[-32000 Business Error]
    H -->|Yes| I[Execute Method]
    
    style A fill:#90EE90
    style I fill:#6bcf7f
    style E1 fill:#ff6b6b
    style E2 fill:#ff6b6b
    style E3 fill:#ff6b6b
    style E4 fill:#ff6b6b
    style E5 fill:#ff6b6b
    style E6 fill:#ff6b6b
```

**Validation Order:**
1. **HTTP Headers:** Check Authorization, Content-Type
2. **JSON Parsing:** Ensure valid JSON syntax
3. **JSON-RPC Format:** Verify jsonrpc, id, method fields
4. **JSON Schema:** Validate against predefined schema
5. **Pydantic Model:** Type checking and custom validators
6. **Business Rules:** Application-specific validation

**Security Benefits:**

| Layer | Attack Prevented | Example |
|-------|------------------|---------|
| **HTTP Headers** | Unauthorized access | Missing/invalid JWT |
| **JSON Parsing** | DoS via malformed JSON | `{"key": "value"` (unclosed) |
| **JSON-RPC Format** | Protocol confusion | Missing `jsonrpc: "2.0"` |
| **JSON Schema** | Injection attacks | `s3_key: "../../etc/passwd"` |
| **Pydantic Models** | Type confusion | `document_id: "abc"` (should be int) |
| **Business Rules** | Logic bypass | `priority: "critical"` (invalid enum) |

### 7.6 Error Code Reference

**JSON-RPC 2.0 Error Codes:**

| Code | Meaning | Trigger | Response Status |
|------|---------|---------|-----------------|
| `-32700` | Parse error | Invalid JSON syntax | 400 Bad Request |
| `-32600` | Invalid Request | Missing jsonrpc field | 400 Bad Request |
| `-32601` | Method not found | Unknown method name | 404 Not Found |
| `-32602` | Invalid params | Schema/type validation failed | 400 Bad Request |
| `-32603` | Internal error | Server-side exception | 500 Internal Error |
| `-32000` | Server error | Business logic error | 400 Bad Request |

**Security Error Codes:**

| Code | Meaning | Trigger | Response Status |
|------|---------|---------|-----------------|
| `-32010` | Unauthorized | JWT missing/invalid/expired | 401 Unauthorized |
| `-32011` | Forbidden | Insufficient permissions (RBAC) | 403 Forbidden |
| `-32012` | Rate limit exceeded | Too many requests | 429 Too Many Requests |
| `-32013` | Replay detected | Duplicate jti | 403 Forbidden |
| `-32014` | Token revoked | Blacklisted JWT | 403 Forbidden |

**Example Error Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "req-12345",
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {
      "detail": "Schema validation failed for 'process_document': 's3_key' does not match pattern '^[a-zA-Z0-9/_-][a-zA-Z0-9/_.-]*$'",
      "field": "s3_key",
      "provided_value": "../../../etc/passwd",
      "expected_pattern": "^[a-zA-Z0-9/_-][a-zA-Z0-9/_.-]*$"
    }
  },
  "_meta": {
    "correlation_id": "2026-01-15T10:30:00Z-a1b2c3d4"
  }
}
```

### 7.7 Request/Response Examples

#### Example 1: Successful Process Document

**Request:**
```bash
curl -X POST http://orchestrator.ca-a2a.local:8001/message \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "X-Correlation-ID: demo-2026-01-15-001" \
  -d '{
    "jsonrpc": "2.0",
    "id": "req-001",
    "method": "process_document",
    "params": {
      "s3_key": "uploads/invoice_2026_01_15.pdf",
      "priority": "high"
    }
  }'
```

**Response (200 OK):**
```json
{
  "jsonrpc": "2.0",
  "id": "req-001",
  "result": {
    "task_id": "task-abc123",
    "s3_key": "uploads/invoice_2026_01_15.pdf",
    "status": "processing",
    "message": "Document processing started",
    "started_at": "2026-01-15T10:30:00Z"
  },
  "_meta": {
    "correlation_id": "demo-2026-01-15-001",
    "duration_ms": 25,
    "agent": "orchestrator",
    "principal": "document-processor"
  }
}
```

#### Example 2: Validation Failure (Path Traversal)

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "req-002",
  "method": "process_document",
  "params": {
    "s3_key": "../../etc/passwd",
    "priority": "high"
  }
}
```

**Response (400 Bad Request):**
```json
{
  "jsonrpc": "2.0",
  "id": "req-002",
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {
      "detail": "Schema validation failed: 's3_key' contains path traversal sequence",
      "field": "s3_key",
      "validation": "pattern_mismatch"
    }
  },
  "_meta": {
    "correlation_id": "2026-01-15T10:30:01Z-def456"
  }
}
```

#### Example 3: Authorization Failure (Insufficient Permissions)

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "req-003",
  "method": "delete_all_documents",
  "params": {}
}
```

**Headers:**
```
Authorization: Bearer <JWT with roles: ["viewer"]>
```

**Response (403 Forbidden):**
```json
{
  "jsonrpc": "2.0",
  "id": "req-003",
  "error": {
    "code": -32011,
    "message": "Forbidden",
    "data": {
      "detail": "Principal 'viewer' not authorized to call method 'delete_all_documents'",
      "principal": "viewer",
      "method": "delete_all_documents",
      "required_role": "admin",
      "provided_roles": ["viewer"]
    }
  },
  "_meta": {
    "correlation_id": "2026-01-15T10:30:02Z-ghi789"
  }
}
```

#### Example 4: Rate Limit Exceeded

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": "req-350",
  "method": "list_documents",
  "params": {}
}
```

**Response (429 Too Many Requests):**
```json
{
  "jsonrpc": "2.0",
  "id": "req-350",
  "error": {
    "code": -32012,
    "message": "Rate limit exceeded",
    "data": {
      "detail": "Principal 'document-processor' exceeded 300 requests per minute",
      "limit": 300,
      "window_seconds": 60,
      "retry_after": 15
    }
  },
  "_meta": {
    "correlation_id": "2026-01-15T10:31:00Z-jkl012",
    "rate_limit": {
      "limit": 300,
      "remaining": 0,
      "reset_at": "2026-01-15T10:31:15Z"
    }
  }
}
```

### 7.8 Security Checks per Request

**Order of Execution:**

```mermaid
graph TD
    A[1. Parse JSON] --> B{Valid JSON?}
    B -->|No| E1[Return -32700 Parse Error]
    B -->|Yes| C[2. Extract JWT from Authorization header]
    
    C --> D{JWT Present?}
    D -->|No| E2[Return 401 Unauthorized]
    D -->|Yes| F[3. Verify JWT Signature RS256]
    
    F --> G{Valid Signature?}
    G -->|No| E3[Return 401 Invalid Token]
    G -->|Yes| H[4. Check JWT Expiration]
    
    H --> I{Not Expired?}
    I -->|No| E4[Return 401 Token Expired]
    I -->|Yes| J[5. Check Token Revocation]
    
    J --> K{Revoked?}
    K -->|Yes| E5[Return 403 Token Revoked]
    K -->|No| L[6. Extract Keycloak Roles]
    
    L --> M[7. Map Roles to RBAC Principal]
    M --> N[8. Check Method Permission]
    
    N --> O{Authorized?}
    O -->|No| E6[Return 403 Forbidden]
    O -->|Yes| P[9. Check Rate Limit]
    
    P --> Q{Within Limit?}
    Q -->|No| E7[Return 429 Rate Limit Exceeded]
    Q -->|Yes| R[10. Validate JSON Schema]
    
    R --> S{Valid Schema?}
    S -->|No| E8[Return -32602 Invalid Params]
    S -->|Yes| T[11. Check Replay jti]
    
    T --> U{Duplicate?}
    U -->|Yes| E9[Return 403 Replay Detected]
    U -->|No| V[12. Execute Method]
    
    V --> W[13. Log Audit Event]
    W --> X[14. Return Result]
    
    style A fill:#90EE90
    style V fill:#4d96ff
    style X fill:#6bcf7f
    style E1 fill:#ff6b6b
    style E2 fill:#ff6b6b
    style E3 fill:#ff6b6b
    style E4 fill:#ff6b6b
    style E5 fill:#ff6b6b
    style E6 fill:#ff6b6b
    style E7 fill:#ff6b6b
    style E8 fill:#ff6b6b
    style E9 fill:#ff6b6b
```

### 7.9 Replay Protection Implementation

**Mechanism:** Track JWT `jti` (JWT ID) claim in a TTL-based cache.

```python
class ReplayProtector:
    def __init__(self, ttl_seconds: int = 120):
        self.ttl_seconds = ttl_seconds
        self._seen: Dict[str, int] = {}  # {jti: expiration_timestamp}
    
    def check_and_store(self, nonce: str, exp: int) -> bool:
        now = int(time.time())
        self._cleanup(now)
        
        if nonce in self._seen and self._seen[nonce] >= now:
            return False  # Replay detected!
        
        # Store until JWT expiration (max: ttl_seconds)
        self._seen[nonce] = min(exp, now + self.ttl_seconds)
        return True
```

**Storage:** In-memory per agent (stateless agents benefit from load balancer stickiness)

**TTL:** 120 seconds (2 minutes) - matches typical JWT expiration

### 7.10 Rate Limiting

**Algorithm:** Sliding Window per Principal

```python
class SlidingWindowRateLimiter:
    def __init__(self, limit: int = 300, window_seconds: int = 60):
        self.limit = limit  # 300 requests
        self.window_seconds = window_seconds  # per 60 seconds (1 minute)
        self._events: Dict[str, List[int]] = {}  # {principal: [timestamps]}
    
    def allow(self, key: str) -> Tuple[bool, Dict]:
        now = int(time.time())
        window_start = now - self.window_seconds
        
        # Get events in current window
        events = [t for t in self._events.get(key, []) if t >= window_start]
        
        if len(events) < self.limit:
            events.append(now)
            self._events[key] = events
            return True, {"remaining": self.limit - len(events)}
        
        return False, {"retry_after": events[0] + self.window_seconds - now}
```

**Limits:**
- **Default:** 300 requests/minute per principal
- **Configurable:** `A2A_RATE_LIMIT_PER_MINUTE` environment variable
- **Scope:** Per agent instance (distributed rate limiting via Redis recommended for production)

---

## 8. Monitoring & Audit

### 8.1 CloudWatch Logs

**Log Groups:**

| Log Group | Purpose | Retention |
|-----------|---------|-----------|
| `/ecs/ca-a2a-orchestrator` | Orchestrator logs | 7 days |
| `/ecs/ca-a2a-extractor` | Extractor logs | 7 days |
| `/ecs/ca-a2a-validator` | Validator logs | 7 days |
| `/ecs/ca-a2a-archivist` | Archivist logs | 7 days |
| `/ecs/ca-a2a-keycloak` | Keycloak logs | 7 days |

**Structured Logging Format:**
```json
{
  "timestamp": "2026-01-15T10:30:00Z",
  "level": "INFO",
  "agent": "orchestrator",
  "event_type": "request",
  "correlation_id": "2026-01-15T10:30:00Z-a1b2c3d4",
  "method": "process_document",
  "principal": "document-processor",
  "duration_ms": 250,
  "success": true
}
```

### 8.2 Security Events Logged

| Event Type | Trigger | Log Level |
|------------|---------|-----------|
| `authentication_success` | Valid JWT verified | INFO |
| `authentication_failure` | Invalid JWT | WARN |
| `authorization_failure` | Insufficient permissions | WARN |
| `rate_limit_exceeded` | Too many requests | WARN |
| `replay_detected` | Duplicate JWT jti | WARN |
| `token_revoked` | Attempt with revoked token | WARN |
| `invalid_input` | Schema validation failed | WARN |
| `method_executed` | Successful method call | INFO |

**Query Examples:**

```bash
# View all authentication failures in last hour
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "authentication_failure" \
  --start-time $(date -d '1 hour ago' +%s)000 \
  --region eu-west-3

# Count rate limit violations by principal
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "rate_limit_exceeded" \
  --region eu-west-3 \
  | jq '.events[].message | fromjson | .principal' | sort | uniq -c
```

### 8.3 Metrics (Recommended)

**CloudWatch Custom Metrics to Implement:**

| Metric | Unit | Dimensions | Purpose |
|--------|------|------------|---------|
| `RequestLatency` | Milliseconds | Agent, Method | Performance monitoring |
| `ErrorCount` | Count | Agent, ErrorType | Error rate tracking |
| `RequestCount` | Count | Agent | Throughput monitoring |
| `AuthenticationFailures` | Count | Agent | Security monitoring |
| `RateLimitViolations` | Count | Principal | Abuse detection |
| `TokenRevocationChecks` | Count | Agent | Revocation usage |

---

## 9. Threat Model & Defenses

### 9.1 STRIDE Analysis

| Threat | Attack Vector | Defense Layer | Mitigation |
|--------|---------------|---------------|------------|
| **Spoofing** | Impersonate agent/user | L2, L3 | Keycloak authentication + JWT RS256 signature |
| **Tampering** | Modify request/response | L5 | JWT body hash binding |
| **Repudiation** | Deny actions | L7 | Audit logs with correlation IDs |
| **Information Disclosure** | Intercept traffic | L1, Data | VPC isolation + TLS |
| **Denial of Service** | Flood requests | L6, L8 | Input validation + rate limiting |
| **Elevation of Privilege** | Bypass RBAC | L4 | Keycloak roles + RBAC enforcement |

### 9.2 Attack Scenarios & Defenses

#### Scenario 1: Token Theft

**Attack:** Attacker steals JWT access token from legitimate user.

**Defenses:**
1. **Short TTL:** Tokens expire in 5 minutes (Keycloak default)
2. **Token Revocation:** Admin can revoke compromised token by jti
3. **Replay Protection:** Prevents token reuse after first use
4. **Network Isolation:** Tokens only valid within VPC (no internet exposure)

#### Scenario 2: Replay Attack

**Attack:** Attacker captures valid request and replays it multiple times.

**Defenses:**
1. **JWT jti Tracking:** Each token has unique ID tracked in cache
2. **TTL-based Expiration:** jti cache entries expire after 2 minutes
3. **Timestamp Validation:** JWT iat (issued-at) checked for freshness

#### Scenario 3: Privilege Escalation

**Attack:** User with `viewer` role attempts to call admin-only method.

**Defenses:**
1. **RBAC Enforcement:** Keycloak roles mapped to allowed methods
2. **Method-level Authorization:** Each method checks principal permissions
3. **Audit Logging:** All authorization failures logged with principal ID

#### Scenario 4: DDoS / Resource Exhaustion

**Attack:** Attacker floods system with requests to exhaust resources.

**Defenses:**
1. **Rate Limiting:** 300 req/min per principal
2. **ALB-level Protection:** AWS Shield Standard (automatic)
3. **Auto-scaling:** ECS tasks scale based on CPU/memory
4. **Payload Limits:** Max request size 1MB (`client_max_size`)

#### Scenario 5: SQL Injection

**Attack:** Attacker injects SQL in document metadata fields.

**Defenses:**
1. **Parameterized Queries:** asyncpg with prepared statements
2. **Input Validation:** JSON Schema validates all inputs
3. **Pydantic Models:** Type checking and sanitization
4. **Least Privilege:** Database users have minimal required permissions

#### Scenario 6: Man-in-the-Middle (MITM)

**Attack:** Attacker intercepts traffic between agents.

**Defenses:**
1. **VPC Isolation:** All traffic within private network
2. **JWT Signature:** RS256 signature prevents tampering
3. **TLS to AWS Services:** RDS, S3, Secrets Manager use TLS
4. **Recommendation:** Enable TLS between agents for defense-in-depth

#### Scenario 7: JWT Algorithm Confusion Attack

**Attack:** Attacker modifies JWT header to use `HS256` instead of `RS256`, then signs with the public key (treating it as symmetric).

```json
// Attacker modifies header from:
{"alg": "RS256", "typ": "JWT"} 
// To:
{"alg": "HS256", "typ": "JWT"}
// Then signs with Keycloak's public key as HMAC secret
```

**Defenses:**
1. **Algorithm Enforcement:** Keycloak JWT validator explicitly requires RS256
   ```python
   # In keycloak_auth.py
   payload = jwt.decode(
       token,
       key=public_key,
       algorithms=["RS256"],  # Only RS256 allowed, no HS256!
       ...
   )
   ```
2. **Reject None Algorithm:** JWT library configured to reject `alg: none`
3. **Keycloak JWKS:** Public keys fetched from trusted source only
4. **Algorithm Whitelist:** No fallback to symmetric algorithms

**Impact if Successful:** Complete authentication bypass (critical)

#### Scenario 8: Keycloak Compromise

**Attack:** Attacker gains access to Keycloak admin console or database.

**Attack Vectors:**
- Brute force Keycloak admin password
- SQL injection in Keycloak database
- Exploit Keycloak vulnerability (CVE)
- Compromise Keycloak RDS credentials

**Defenses:**
1. **Strong Admin Password:** 32+ character password in Secrets Manager
2. **Network Isolation:** Keycloak only accessible from agent security groups
3. **Regular Updates:** Keycloak 23.0+ with security patches
4. **Database Encryption:** RDS at rest encryption (AES-256)
5. **Audit Logging:** All Keycloak admin actions logged
6. **Backup & Recovery:** Automated RDS snapshots (daily)
7. **Multi-Factor Auth:** Enable MFA for Keycloak admin (recommended)

**Incident Response:**
```bash
# 1. Immediately rotate Keycloak admin password
aws secretsmanager update-secret \
  --secret-id ca-a2a/keycloak-admin-password \
  --secret-string "$(openssl rand -base64 32)"

# 2. Revoke all active tokens
curl -X POST http://admin-api:9000/admin/revoke-all-tokens \
  -H "Authorization: Bearer $ADMIN_JWT"

# 3. Reset Keycloak database from backup
aws rds restore-db-cluster-to-point-in-time \
  --source-db-cluster-identifier ca-a2a-keycloak-db \
  --target-db-cluster-identifier ca-a2a-keycloak-db-restored \
  --restore-to-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)

# 4. Force all users to re-authenticate
```

#### Scenario 9: Agent Impersonation

**Attack:** Attacker creates rogue agent claiming to be "orchestrator" or "extractor".

**Attack Vectors:**
- Deploy malicious container in same VPC
- DNS spoofing (if using DNS for service discovery)
- ARP poisoning within subnet

**Defenses:**
1. **Service Discovery:** AWS Cloud Map with private DNS (not public DNS)
2. **JWT Audience Check:** Each agent validates JWT `aud` claim matches its ID
   ```python
   # In a2a_security.py
   claims = jwt.decode(
       token,
       audience=self.agent_id,  # Must match receiving agent
       ...
   )
   ```
3. **Security Groups:** Whitelist only known agent security group IDs
4. **Mutual Authentication:** Both sides verify JWT (bidirectional)
5. **ECS Task Role Verification:** Check IAM task role ARN in logs
6. **Certificate Pinning (Future):** mTLS with certificate validation

**Detection:**
```bash
# Monitor for unexpected service registrations
aws servicediscovery list-services \
  --namespace-id ns-3x674lhfa4vvu72f \
  --region eu-west-3

# Check for unauthorized ECS tasks
aws ecs list-tasks --cluster ca-a2a-cluster \
  --query 'taskArns[*]' | \
  xargs -I {} aws ecs describe-tasks --tasks {} --cluster ca-a2a-cluster \
  --query 'tasks[*].{Task:taskArn,Image:containers[0].image}'
```

#### Scenario 10: Time-Based Attacks (Clock Skew Exploitation)

**Attack:** Attacker exploits clock skew to extend JWT validity or bypass expiration checks.

**Attack Methods:**
- Use JWT with future `iat` (issued-at) time
- Rely on `exp` (expiration) not being checked strictly
- Exploit `nbf` (not-before) for delayed attacks

**Defenses:**
1. **Clock Skew Tolerance:** 30-second maximum (`max_skew_seconds=30`)
   ```python
   # JWT verification with limited skew
   claims = jwt.decode(
       token,
       leeway=30,  # Only 30 seconds tolerance
       ...
   )
   ```
2. **NTP Synchronization:** ECS tasks sync with AWS NTP servers
3. **Freshness Check:** Reject tokens older than 2 minutes
   ```python
   now = int(time.time())
   iat = int(claims.get('iat', 0))
   if (now - iat) > 120:  # 2 minutes
       raise AuthError("JWT too old")
   ```
4. **Replay Protection:** jti tracking prevents reuse even if within time window
5. **Monitoring:** Alert on tokens with suspicious timestamps

**Attack Example:**
```json
// Attacker creates JWT with:
{
  "iat": 1737845000,  // Current time
  "exp": 1737945000,  // 27 hours in future (suspicious!)
  "nbf": 1737844000   // 1 hour ago
}
```

**Detection Query:**
```python
# Flag JWTs with excessive TTL
if claims['exp'] - claims['iat'] > 3600:  # More than 1 hour
    logger.warning(f"Suspicious JWT TTL: {claims['exp'] - claims['iat']} seconds")
```

#### Scenario 11: S3 Bucket Poisoning

**Attack:** Attacker uploads malicious document to S3 bucket to exploit extraction vulnerabilities.

**Attack Payloads:**
- PDF with embedded malware
- ZIP bomb (small file expands to GB)
- XXE (XML External Entity) in document metadata
- Path traversal in filename (`../../etc/passwd`)

**Defenses:**
1. **S3 Bucket Policy:** Only allow uploads from specific IAM roles
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": {"AWS": "arn:aws:iam::555043101106:role/ca-a2a-lambda-role"},
       "Action": "s3:PutObject",
       "Resource": "arn:aws:s3:::ca-a2a-documents-555043101106/uploads/*"
     }]
   }
   ```
2. **File Size Limits:** Max 10MB per document
3. **Content-Type Validation:** Only allow PDF, TXT, CSV
4. **Virus Scanning:** S3 Object Lambda with ClamAV (recommended)
5. **Sandboxed Extraction:** Extractor runs in isolated container with limited resources
6. **Filename Sanitization:** Strip path traversal characters
   ```python
   import os
   safe_filename = os.path.basename(s3_key).replace("..", "")
   ```
7. **S3 Versioning:** Track all object versions for forensics
8. **S3 Event Logging:** CloudTrail logs all S3 API calls

**Incident Response:**
```bash
# 1. Identify suspicious upload
aws s3api list-objects-v2 \
  --bucket ca-a2a-documents-555043101106 \
  --query "Contents[?Size > 10485760]"  # Files > 10MB

# 2. Quarantine suspicious object
aws s3 mv s3://ca-a2a-documents-555043101106/uploads/malicious.pdf \
         s3://ca-a2a-documents-555043101106/quarantine/

# 3. Check CloudTrail for uploader
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=malicious.pdf
```

#### Scenario 12: Database Connection Exhaustion

**Attack:** Attacker floods agents with requests to exhaust PostgreSQL connection pool.

**Attack Vector:**
- High-volume request spam (beyond rate limit)
- Slowloris-style attacks (hold connections open)
- Nested agent calls causing cascade

**Defenses:**
1. **Connection Pooling:** asyncpg with max connections limit
   ```python
   pool = await asyncpg.create_pool(
       host=rds_endpoint,
       max_size=20,        # Max 20 connections per agent
       min_size=5,         # Keep 5 warm connections
       max_inactive_connection_lifetime=300  # 5 min timeout
   )
   ```
2. **RDS Connection Limits:** Aurora max_connections = 1000
3. **Per-Agent Limits:** 8 agents × 20 connections = 160 total (well under limit)
4. **Connection Timeout:** 30-second query timeout
5. **Health Checks:** Monitor connection pool exhaustion
   ```python
   if pool.get_size() >= pool.get_max_size():
       logger.error("Connection pool exhausted!")
   ```
6. **Auto-scaling:** ECS tasks scale based on CPU/memory, not connections
7. **Circuit Breaker:** Stop accepting requests if DB unreachable

**Monitoring:**
```bash
# Check RDS connection count
aws cloudwatch get-metric-statistics \
  --namespace AWS/RDS \
  --metric-name DatabaseConnections \
  --dimensions Name=DBInstanceIdentifier,Value=ca-a2a-postgres \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average \
  --region eu-west-3
```

#### Scenario 13: Log Injection

**Attack:** Attacker injects malicious content into logs to hide tracks or execute code.

**Attack Payload:**
```json
// Malicious request with ANSI escape codes
{
  "jsonrpc": "2.0",
  "method": "process_document\u001b[2J\u001b[H",  // Clear screen
  "params": {
    "document_id": "'; DROP TABLE documents; --"  // SQL-like injection
  }
}
```

**Defenses:**
1. **Structured Logging:** JSON format prevents log parsing attacks
   ```python
   logger.info("Request", extra={
       "method": method,  # Automatically escaped by JSON encoder
       "params": params
   })
   ```
2. **Input Sanitization:** Strip control characters
   ```python
   import re
   clean_method = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', method)
   ```
3. **CloudWatch Logs:** Immutable once written (can't be modified)
4. **Log Aggregation:** Centralized logging prevents local log tampering
5. **Audit Trail:** Separate audit log table in RDS (write-only)

**Safe Logging Pattern:**
```python
# GOOD: Structured logging with JSON
logger.info("Request received", extra={
    "event_type": "request",
    "method": method,  # Automatically escaped
    "correlation_id": correlation_id
})

# BAD: String concatenation
logger.info(f"Request: {method}")  # Vulnerable to injection
```

#### Scenario 14: Secrets Leakage

**Attack:** Attacker discovers secrets through various leakage vectors.

**Leakage Vectors:**
- Environment variable exposure in error messages
- Secrets in CloudWatch Logs
- Secrets in ECR image layers
- Secrets in git history
- Secrets in S3 objects (e.g., config files)

**Defenses:**
1. **Secrets Manager:** All secrets retrieved at runtime, never hardcoded
2. **ECS valueFrom:** Task definitions reference secrets by ARN, not value
   ```json
   {
     "name": "POSTGRES_PASSWORD",
     "valueFrom": "arn:aws:secretsmanager:...:secret:ca-a2a/db-password"
   }
   ```
3. **Error Handling:** Never log secret values
   ```python
   try:
       password = get_secret("ca-a2a/db-password")
   except Exception as e:
       logger.error("Failed to retrieve secret")  # Don't log password!
   ```
4. **Git Pre-commit Hooks:** Scan for secrets before commit
   ```bash
   # .git/hooks/pre-commit
   #!/bin/bash
   git diff --cached | grep -E '(password|secret|key).*=.*[A-Za-z0-9]{20,}'
   if [ $? -eq 0 ]; then
       echo "Possible secret detected! Commit aborted."
       exit 1
   fi
   ```
5. **ECR Image Scanning:** Automated vulnerability and secret scanning
6. **Least Privilege IAM:** Task roles only have access to needed secrets
7. **Secrets Rotation:** Rotate secrets every 90 days

**Detection:**
```bash
# Scan CloudWatch Logs for leaked secrets (pattern matching)
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "[password]" \
  --region eu-west-3 | \
  grep -i "password.*="
```

#### Scenario 15: Container Escape

**Attack:** Attacker escapes container to access host or other containers.

**Attack Methods:**
- Exploit kernel vulnerability (e.g., Dirty COW)
- Mount host filesystem via misconfigured volume
- Privileged container escape
- Docker socket exposure (`/var/run/docker.sock`)

**Defenses:**
1. **Fargate Security:** No host access (serverless containers)
2. **No Privileged Mode:** Task definitions never use `privileged: true`
3. **Read-Only Root Filesystem:** Prevent file modifications
   ```json
   {
     "readonlyRootFilesystem": true,
     "containerDefinitions": [{
       "mountPoints": [{
         "sourceVolume": "tmp",
         "containerPath": "/tmp",
         "readOnly": false
       }]
     }]
   }
   ```
4. **Limited Linux Capabilities:** Drop all unnecessary capabilities
5. **AppArmor/SELinux:** Mandatory access control (ECS default)
6. **No Docker Socket:** Never mount `/var/run/docker.sock`
7. **Regular Patching:** Base images updated weekly

**AWS Fargate Advantage:**
- No SSH access to host
- No host filesystem access
- Isolated VM per task
- Automatic security patches

#### Scenario 16: Supply Chain Attack

**Attack:** Compromised dependency (PyPI package, base image) with malicious code.

**Attack Vectors:**
- Typosquatting (`reqeusts` instead of `requests`)
- Compromised maintainer account
- Backdoored Docker base image
- Malicious transitive dependency

**Defenses:**
1. **Dependency Pinning:** Lock all versions in `requirements.txt`
   ```txt
   # Pin exact versions, not ranges
   aiohttp==3.9.1  # Good
   # aiohttp>=3.9   # Bad (allows future versions)
   ```
2. **Hash Verification:** Use `pip install --require-hashes`
3. **Private PyPI Mirror:** Host vetted packages internally (recommended)
4. **Base Image Verification:** Use official images with digest pinning
   ```dockerfile
   FROM python:3.11-slim@sha256:abc123...  # Digest ensures immutability
   ```
5. **Vulnerability Scanning:** ECR scans all images for CVEs
6. **SBOM Generation:** Software Bill of Materials for audit
7. **Dependency Review:** Manual review of new dependencies

**Automated Scanning:**
```bash
# Scan requirements.txt for vulnerabilities
pip install safety
safety check -r requirements.txt

# Scan Docker image
docker scan ca-a2a/orchestrator:latest

# Check for typosquatting
pip install pip-audit
pip-audit -r requirements.txt
```

#### Scenario 17: Side-Channel Timing Attack

**Attack:** Attacker infers secrets by measuring response times.

**Attack Example:**
```python
# Vulnerable code (string comparison)
if provided_api_key == stored_api_key:  # Takes longer if first chars match
    return True

# Attacker measures timing:
# "a..." -> 0.1ms (wrong first char)
# "x..." -> 0.5ms (correct first char!) -> leak
```

**Defenses:**
1. **Constant-Time Comparison:** Use `hmac.compare_digest`
   ```python
   import hmac
   
   # GOOD: Constant-time comparison
   if hmac.compare_digest(provided_api_key, stored_api_key):
       return True
   
   # BAD: Variable-time comparison
   if provided_api_key == stored_api_key:
       return True
   ```
2. **Hashed Comparisons:** Compare hashes, not raw secrets
3. **Rate Limiting:** Slows down timing attack iterations
4. **Random Delays:** Add jitter to response times (optional)
5. **Network Latency:** AWS network adds natural timing noise

**All Security-Critical Comparisons:**
```python
# JWT signature verification (PyJWT library)
# API key hashing (hashlib + hmac.compare_digest)
# Password verification (bcrypt with constant-time compare)
```

#### Scenario 18: Cross-Agent Request Forgery (CARF)

**Attack:** Attacker tricks one agent into making unauthorized requests to another agent.

**Attack Flow:**
```
Attacker -> Orchestrator: "process_document with id=../../../etc/passwd"
Orchestrator -> Extractor: extract_document(key="../../../etc/passwd")
Extractor -> S3: GetObject("../../../etc/passwd")  # Path traversal!
```

**Defenses:**
1. **Input Validation:** Strict regex for document IDs
   ```python
   import re
   
   # Only allow alphanumeric and hyphens
   if not re.match(r'^[a-zA-Z0-9\-]+$', document_id):
       raise ValueError("Invalid document ID format")
   ```
2. **Path Sanitization:** Strip path traversal sequences
   ```python
   safe_path = os.path.normpath(s3_key).replace("..", "")
   if safe_path.startswith("/"):
       raise ValueError("Absolute paths not allowed")
   ```
3. **Whitelisted S3 Prefixes:** Only allow `uploads/`, `processed/`, `archive/`
4. **S3 Bucket Policy:** Deny access outside allowed prefixes
5. **Agent Authentication:** Each agent verifies caller's JWT
6. **RBAC Enforcement:** Orchestrator can't call admin-only methods

**Example Validation:**
```python
def validate_s3_key(s3_key: str) -> bool:
    """Validate S3 key is within allowed prefixes"""
    allowed_prefixes = ["uploads/", "processed/", "archive/"]
    
    # Normalize path
    normalized = os.path.normpath(s3_key)
    
    # Check for path traversal
    if ".." in normalized or normalized.startswith("/"):
        return False
    
    # Check allowed prefix
    return any(normalized.startswith(prefix) for prefix in allowed_prefixes)
```

---

## 10. Security Operations

### 10.1 Incident Response

**Token Compromise Procedure:**

```bash
# 1. Identify compromised token's jti
jti="abc123-compromised-token"

# 2. Revoke token via Admin API
curl -X POST http://admin-api:9000/admin/revoke-token \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{
    \"jti\": \"$jti\",
    \"reason\": \"Security incident - suspected compromise\",
    \"revoked_by\": \"security-team\"
  }"

# 3. Verify revocation
curl http://admin-api:9000/admin/revoked-tokens \
  -H "Authorization: Bearer $ADMIN_JWT" | jq '.tokens[] | select(.jti=="'$jti'")'

# 4. Investigate in CloudWatch Logs
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "$jti" \
  --start-time $(date -d '24 hours ago' +%s)000 \
  --region eu-west-3
```

### 10.2 Security Auditing

**Weekly Security Review Checklist:**

- [ ] Review CloudWatch Logs for authentication failures
- [ ] Check revoked tokens list for anomalies
- [ ] Verify no tokens with excessive TTL
- [ ] Review rate limit violations by principal
- [ ] Check for unusual traffic patterns in ALB logs
- [ ] Verify all secrets rotated within policy (90 days)
- [ ] Review IAM role permissions (least privilege)
- [ ] Check security group rules for unnecessary access

**Automated Monitoring:**

```bash
# Script: security-audit.sh
#!/bin/bash

echo "=== Security Audit Report ==="
echo "Date: $(date)"
echo ""

# Check authentication failures (last 24h)
echo "1. Authentication Failures:"
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "authentication_failure" \
  --start-time $(date -d '24 hours ago' +%s)000 \
  --region eu-west-3 \
  --query 'length(events)' \
  --output text

# Check rate limit violations
echo "2. Rate Limit Violations:"
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "rate_limit_exceeded" \
  --start-time $(date -d '24 hours ago' +%s)000 \
  --region eu-west-3 \
  --query 'length(events)' \
  --output text

# Check revoked tokens count
echo "3. Active Revoked Tokens:"
curl -s http://admin-api:9000/admin/security-stats \
  -H "Authorization: Bearer $ADMIN_JWT" \
  | jq '.active_revoked_tokens'

echo ""
echo "=== End of Report ==="
```

### 10.3 Compliance

**GDPR Considerations:**

| Requirement | Implementation |
|-------------|----------------|
| **Data Encryption** | ✅ AES-256 at rest, TLS in transit |
| **Access Control** | ✅ RBAC with Keycloak roles |
| **Audit Trail** | ✅ CloudWatch Logs with 7-day retention |
| **Right to be Forgotten** | ⚠️ Manual deletion via SQL (implement API endpoint) |
| **Data Minimization** | ✅ Only essential fields stored |
| **Pseudonymization** | ⚠️ User emails stored in Keycloak (consider hashing) |

**PCI-DSS Considerations (if processing payment data):**

| Requirement | Implementation |
|-------------|----------------|
| **Network Segmentation** | ✅ VPC with private subnets |
| **Strong Access Control** | ✅ Multi-factor via Keycloak (optional) |
| **Encryption** | ✅ At rest and in transit |
| **Logging & Monitoring** | ✅ CloudWatch Logs + audit trail |
| **Vulnerability Management** | ⚠️ Regular container image updates (automate) |

---

## 11. Implementation Reference

### 11.1 Key Files

| File | Purpose | Lines |
|------|---------|-------|
| `a2a_security.py` | Core security manager, JWT, RBAC, rate limiting | 515 |
| `keycloak_auth.py` | Keycloak JWT validation, RBAC mapper | 280 |
| `a2a_security_enhanced.py` | Token revocation, request signing, mTLS | 650 |
| `admin_api.py` | Admin API for token revocation | 350 |
| `base_agent.py` | Agent base class with security integration | 395 |
| `deploy-keycloak.sh` | Keycloak deployment script | 250 |
| `configure-keycloak.sh` | Keycloak realm/client setup | 180 |

### 11.2 Environment Variables

**Security Configuration:**

```bash
# Authentication
A2A_REQUIRE_AUTH=true
A2A_USE_KEYCLOAK=true
KEYCLOAK_URL=http://keycloak.ca-a2a.local:8080
KEYCLOAK_REALM=ca-a2a
KEYCLOAK_CLIENT_ID=ca-a2a-agents
KEYCLOAK_CACHE_TTL=3600

# RBAC
A2A_RBAC_POLICY_JSON='{"allow":{"admin":["*"],"lambda":["upload_document"]},"deny":{}}'

# Rate Limiting
A2A_ENABLE_RATE_LIMIT=true
A2A_RATE_LIMIT_PER_MINUTE=300

# Replay Protection
A2A_ENABLE_REPLAY_PROTECTION=true
A2A_REPLAY_TTL_SECONDS=120

# JWT (if using native JWT instead of Keycloak)
A2A_JWT_ISSUER=ca-a2a
A2A_JWT_ALG=RS256
A2A_JWT_PUBLIC_KEY_PEM=/path/to/public.pem
A2A_JWT_PRIVATE_KEY_PEM=/path/to/private.pem
A2A_JWT_MAX_SKEW_SECONDS=30
A2A_JWT_MAX_TOKEN_AGE_SECONDS=120

# Secrets
POSTGRES_PASSWORD=<retrieved-from-secrets-manager>
KEYCLOAK_ADMIN_PASSWORD=<retrieved-from-secrets-manager>
KEYCLOAK_CLIENT_SECRET=<retrieved-from-secrets-manager>
```

### 11.3 Deployment Commands

**Deploy Keycloak:**
```bash
cd /path/to/ca_a2a
./deploy-keycloak.sh
./configure-keycloak.sh
```

**Update Agents with Keycloak:**
```bash
./update-agents-keycloak.sh
```

**Test Authentication:**
```bash
./test-keycloak-auth.sh
```

**View Security Metrics:**
```bash
# Admin API (deploy separately or run locally)
python admin_api.py

# Get security stats
curl http://localhost:9000/admin/security-stats \
  -H "Authorization: Bearer $ADMIN_JWT"
```

---

## Appendix A: Security Checklist

### Pre-Production Deployment

- [ ] **Network Security**
  - [ ] VPC with private subnets configured
  - [ ] Security groups follow least-privilege
  - [ ] NAT Gateway for outbound access only
  - [ ] VPC endpoints for AWS services
  - [ ] No public IPs on agent tasks

- [ ] **Authentication & Authorization**
  - [ ] Keycloak deployed and configured
  - [ ] Realms and clients created
  - [ ] Roles defined and mapped to RBAC
  - [ ] Client secrets stored in Secrets Manager
  - [ ] JWT signature verification enabled

- [ ] **Data Security**
  - [ ] RDS encryption at rest enabled
  - [ ] S3 bucket encryption enabled
  - [ ] Secrets Manager for all credentials
  - [ ] TLS for RDS connections configured
  - [ ] Backups enabled with retention policy

- [ ] **Application Security**
  - [ ] Rate limiting enabled (300/min)
  - [ ] Replay protection enabled (120s TTL)
  - [ ] Input validation with JSON Schema
  - [ ] Token revocation system deployed
  - [ ] Audit logging to CloudWatch

- [ ] **Monitoring & Alerting**
  - [ ] CloudWatch Logs retention set (7 days)
  - [ ] CloudWatch alarms for errors
  - [ ] Security audit log monitoring
  - [ ] Metrics for authentication failures
  - [ ] Dashboard for security events

- [ ] **Compliance**
  - [ ] Data retention policy documented
  - [ ] Incident response plan defined
  - [ ] Security review schedule established
  - [ ] Vulnerability scanning enabled
  - [ ] Penetration testing completed

### Post-Deployment Verification

```bash
# 1. Verify all agents are running
aws ecs list-tasks --cluster ca-a2a-cluster --region eu-west-3

# 2. Test authentication
./test-keycloak-auth.sh

# 3. Check CloudWatch Logs
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3

# 4. Verify security groups
aws ec2 describe-security-groups \
  --filters "Name=vpc-id,Values=vpc-086392a3eed899f72" \
  --region eu-west-3

# 5. Test rate limiting
for i in {1..350}; do 
  curl -X POST http://alb-url/message \
    -H "Authorization: Bearer $JWT" \
    -d '{"jsonrpc":"2.0","method":"list_documents","params":{},"id":'$i'}'
done
# Should see 429 after 300 requests
```

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **A2A** | Agent-to-Agent: Communication protocol for autonomous agents |
| **ALB** | Application Load Balancer: AWS load balancing service |
| **ECS** | Elastic Container Service: AWS container orchestration |
| **Fargate** | Serverless compute engine for containers |
| **JWKS** | JSON Web Key Set: Public keys for JWT verification |
| **JWT** | JSON Web Token: Compact, URL-safe token format |
| **jti** | JWT ID: Unique identifier claim in JWT |
| **OAuth2** | Open standard for access delegation |
| **OIDC** | OpenID Connect: Identity layer on top of OAuth2 |
| **RBAC** | Role-Based Access Control: Access control based on roles |
| **RS256** | RSA Signature with SHA-256: JWT signing algorithm |
| **VPC** | Virtual Private Cloud: Isolated network in AWS |

---

## Document Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 5.1 | 2026-01-15 | Jaafar Benabderrazak | Added comprehensive JSON schema documentation, HTTP headers schema, Pydantic models, content validation rules, error code reference, and request/response examples |
| 5.0 | 2026-01-15 | Jaafar Benabderrazak | Added MCP Server (Layer 5), updated architecture diagrams, increased layers from 8 to 9 |
| 4.0 | 2026-01-15 | Jaafar Benabderrazak | Complete rewrite based on production architecture |
| 3.0 | 2026-01-14 | - | Added Keycloak OAuth2, token revocation |
| 2.0 | 2026-01-12 | - | Added mTLS, token binding |
| 1.0 | 2025-12-18 | - | Initial security documentation |

---

**End of Document**

