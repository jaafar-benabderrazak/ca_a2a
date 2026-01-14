# A2A Protocol Security: Technical Deep Dive

**Comprehensive Technical Documentation on Agent-to-Agent Communication Protocol and Security Implementation**

**Version**: 3.0  
**Last Updated**: January 14, 2026  
**Breaking Changes**: Keycloak OAuth2/OIDC Only (Legacy API Keys & JWT Removed)

---

## Table of Contents

1. [A2A Protocol Overview](#a2a-protocol-overview)
2. [Protocol Stack Architecture](#protocol-stack-architecture)
3. [Message Structure & Format](#message-structure--format)
4. [Security Layers Deep Dive](#security-layers-deep-dive)
5. [Authentication Mechanisms](#authentication-mechanisms)
6. [Authorization & RBAC](#authorization--rbac)
7. [Message Integrity (HMAC)](#message-integrity-hmac)
8. [Input Validation (JSON Schema)](#input-validation-json-schema)
9. [Replay Protection](#replay-protection)
10. [Rate Limiting](#rate-limiting)
11. [Token Revocation](#token-revocation)
12. [Complete Request Flow](#complete-request-flow)
13. [Attack Scenarios & Defenses](#attack-scenarios--defenses)
14. [Code Implementation Details](#code-implementation-details)

---

## A2A Protocol Overview

### **What is A2A Protocol?**

**A2A (Agent-to-Agent) Protocol** is a standardized communication protocol for autonomous agents to exchange messages and coordinate actions in a distributed system.

**Our Implementation:**
- **Base Protocol:** JSON-RPC 2.0 (RFC 4627)
- **Transport:** HTTP/1.1 over TCP
- **Encoding:** UTF-8 JSON
- **Security:** 8-layer defense-in-depth architecture

### **Why JSON-RPC 2.0?**

```mermaid
graph LR
 subgraph "JSON-RPC 2.0 Benefits"
 A[Standardized] --> B[Well-defined spec]
 A --> C[Language agnostic]
 A --> D[Tool support]
 
 E[Method-based] --> F[Natural for RPC]
 E --> G[Clear semantics]
 
 H[Lightweight] --> I[Simple JSON]
 H --> J[Human readable]
 H --> K[Easy debugging]
 
 L[Error Handling] --> M[Standard error codes]
 L --> N[Structured errors]
 end
 
 style A fill:#90EE90
 style E fill:#87CEEB
 style H fill:#FFD700
 style L fill:#FFA07A
```

**Comparison with alternatives:**
<img width="1340" height="587" alt="Capture d’écran 2026-01-11 222928" src="https://github.com/user-attachments/assets/f175345c-646c-40a7-ba88-e316b9cacc71" />

| Protocol | Pros | Cons | Our Choice |
|----------|------|------|------------|
| **JSON-RPC 2.0** | Simple, standardized, debuggable | Text overhead | **Selected** |
| gRPC | Fast, binary, streaming | Complex, needs .proto files | Not needed |
| REST | Universal, cacheable | Verbose, CRUD-focused | Not RPC pattern |
| GraphQL | Flexible queries | Overkill for RPC | Too complex |
| WebSocket | Bidirectional, persistent | Complex state management | Not needed |

---

## Protocol Stack Architecture

### **Full Stack Visualization**

```mermaid
graph TB
 subgraph "Application Layer (L7)"
 A2A[A2A Protocol<br/>JSON-RPC 2.0]
 Security[Security Layer<br/>Auth + HMAC + Schema]
 end
 
 subgraph "Presentation Layer (L6)"
 JSON[JSON Encoding<br/>UTF-8]
 end
 
 subgraph "Session Layer (L5)"
 HTTP[HTTP/1.1<br/>Request/Response]
 end
 
 subgraph "Transport Layer (L4)"
 TCP[TCP<br/>Port 8001-8004]
 end
 
 subgraph "Network Layer (L3)"
 IP[IP<br/>Private VPC<br/>10.0.0.0/16]
 end
 
 subgraph "Data Link Layer (L2)"
 Ethernet[Ethernet<br/>AWS ENI]
 end
 
 A2A --> Security
 Security --> JSON
 JSON --> HTTP
 HTTP --> TCP
 TCP --> IP
 IP --> Ethernet
 
 style A2A fill:#90EE90
 style Security fill:#FF6B6B
 style HTTP fill:#87CEEB
 style TCP fill:#FFD700
 style IP fill:#DDA0DD
```

### **Production Infrastructure: AWS VPC Architecture**

This screenshot shows the actual deployed network architecture:

- **VPC CIDR:** `10.0.0.0/16` - Private network space isolating all agent communication
- **Public Subnets:** `10.0.1.0/24` (AZ-a), `10.0.2.0/24` (AZ-b) - Host NAT Gateway for outbound internet access
- **Private Subnets:** `10.0.10.0/24` (AZ-a), `10.0.20.0/24` (AZ-b) - Host ECS Fargate tasks with NO public IPs
- **Internet Gateway:** Enables outbound connectivity via NAT (agents never directly exposed)
- **Route Tables:** Separate routing for public (0.0.0.0/0 → IGW) and private (0.0.0.0/0 → NAT) subnets

**Security Implications:**
- ✅ All agent-to-agent communication occurs within private subnets (Layer 3 isolation)
- ✅ No direct internet access from agents (outbound only through NAT)
- ✅ Multi-AZ deployment ensures high availability (fault tolerance across availability zones)
- ✅ Security groups act as virtual firewalls at the instance level (default deny all)

### **Protocol Encapsulation**
<img width="808" height="491" alt="image" src="https://github.com/user-attachments/assets/0399c2d4-7c73-4365-8d3c-47d75ebe13e3" />

```
┌─────────────────────────────────────────────────────────────┐
│ A2A Message (JSON-RPC 2.0) │
│ {"jsonrpc":"2.0","method":"extract_document","id":"123"} │
├─────────────────────────────────────────────────────────────┤
│ Security Headers │
│ X-API-Key: abc123... │
│ X-Signature: 1735867245:def456... │
│ X-Correlation-ID: pipe-789 │
├─────────────────────────────────────────────────────────────┤
│ HTTP Headers │
│ POST /message HTTP/1.1 │
│ Host: extractor.ca-a2a.local:8002 │
│ Content-Type: application/json │
│ Content-Length: 89 │
├─────────────────────────────────────────────────────────────┤
│ TCP Header (Source: 8001, Dest: 8002) │
├─────────────────────────────────────────────────────────────┤
│ IP Header (Src: 10.0.10.25, Dst: 10.0.20.158) │
├─────────────────────────────────────────────────────────────┤
│ Ethernet Frame │
└─────────────────────────────────────────────────────────────┘
```

---

## Message Structure & Format

### **JSON-RPC 2.0 Message Anatomy**

```mermaid
classDiagram
 class A2AMessage {
 +string jsonrpc = "2.0"
 +string id
 +string method
 +dict params
 +any result
 +dict error
 +dict _meta
 
 +create_request()
 +create_response()
 +create_error()
 +to_dict()
 +validate()
 }
 
 class Request {
 +string method 
 +dict params 
 +string id 
 -result 
 -error 
 }
 
 class Response {
 -method 
 -params 
 +any result 
 +string id 
 }
 
 class Error {
 -method 
 -params 
 -result 
 +dict error 
 +string id 
 }
 
 A2AMessage <|-- Request
 A2AMessage <|-- Response
 A2AMessage <|-- Error
```

### **Request Message Format**

**Code Definition** (`a2a_protocol.py:24-30`):
```python
@dataclass
class A2AMessage:
 """JSON-RPC 2.0 compliant message structure"""
 jsonrpc: str = "2.0"
 id: Optional[str] = None # Request ID (for matching responses)
 method: Optional[str] = None # RPC method name
 params: Optional[Dict[str, Any]] = None # Method parameters
 result: Optional[Any] = None # Response result (only in responses)
 error: Optional[Dict[str, Any]] = None # Error details (only in errors)
```

**Example Request:**
```json
{
 "jsonrpc": "2.0",
 "method": "extract_document",
 "params": {
 "s3_key": "invoices/2026/01/test.pdf",
 "correlation_id": "pipe-1735867245-abc123"
 },
 "id": "req-456def"
}
```

**Field Constraints:**
- `jsonrpc`: Must be exactly `"2.0"`
- `method`: Required for requests, snake_case convention
- `params`: Optional dict, validated against JSON schema
- `id`: Required for requests, should be unique per request
- `result`: Not present in requests
- `error`: Not present in requests

### **Response Message Format**

**Success Response:**
```json
{
 "jsonrpc": "2.0",
 "result": {
 "format": "pdf",
 "total_pages": 3,
 "text_content": "Invoice #INV-2026-001...",
 "pages": [
 {"page_number": 1, "text": "...", "char_count": 250}
 ],
 "metadata": {
 "title": "ACME Corporation Invoice",
 "author": "Finance Department"
 }
 },
 "id": "req-456def",
 "_meta": {
 "correlation_id": "pipe-1735867245-abc123",
 "processing_time_ms": 245,
 "agent_id": "extractor",
 "timestamp": 1735867245
 }
}
```

**Error Response:**
```json
{
 "jsonrpc": "2.0",
 "error": {
 "code": -32602,
 "message": "Invalid params: s3_key is required",
 "data": {
 "field": "s3_key",
 "constraint": "required"
 }
 },
 "id": "req-456def",
 "_meta": {
 "correlation_id": "pipe-1735867245-abc123",
 "timestamp": 1735867245
 }
}
```

**Standard Error Codes:**
| Code | Meaning | When Used |
|------|---------|-----------|
| -32700 | Parse error | Invalid JSON |
| -32600 | Invalid Request | Missing required fields |
| -32601 | Method not found | Unknown RPC method |
| -32602 | Invalid params | Parameter validation failed |
| -32603 | Internal error | Server-side exception |
| -32000 | Server error | Application-specific errors |
| -32010 | Unauthorized | Authentication failed |
| -32011 | Forbidden | Authorization failed |

---

## ️ Security Layers Deep Dive

### **Defense-in-Depth Architecture**
<img width="1377" height="367" alt="Capture d’écran 2026-01-11 222956" src="https://github.com/user-attachments/assets/673e6017-03f2-46d4-9d14-218f7baf2453" />

```mermaid
graph TB
 Request[Incoming Request] --> L1
 
 L1[Layer 1: Network Security<br/>VPC + Security Groups] --> L1_Check{IP Allowed?}
 L1_Check -->|No| Reject1[ Connection Refused<br/>TCP RST]
 L1_Check -->|Yes| L2
 
 L2[Layer 2: Transport Security<br/>TLS Encryption] --> L2_Check{TLS Valid?}
 L2_Check -->|No| Reject2[ SSL Handshake Failed]
 L2_Check -->|Yes| L3
 
 L3[Layer 3: Message Integrity<br/>HMAC Signature] --> L3_Check{Signature Valid?}
 L3_Check -->|No| Reject3[ 401 Tampered Request]
 L3_Check -->|Yes| L4
 
 L4[Layer 4: Authentication<br/>API Key / JWT] --> L4_Check{Auth Valid?}
 L4_Check -->|No| Reject4[ 401 Unauthorized]
 L4_Check -->|Yes| L5
 
 L5[Layer 5: Authorization<br/>RBAC Policy] --> L5_Check{Principal Allowed?}
 L5_Check -->|No| Reject5[ 403 Forbidden]
 L5_Check -->|Yes| L6
 
 L6[Layer 6: Input Validation<br/>JSON Schema] --> L6_Check{Params Valid?}
 L6_Check -->|No| Reject6[ 400 Invalid Params]
 L6_Check -->|Yes| L7
 
 L7[Layer 7: Rate Limiting<br/>Token Bucket] --> L7_Check{Under Limit?}
 L7_Check -->|No| Reject7[ 429 Rate Exceeded]
 L7_Check -->|Yes| L8
 
 L8[Layer 8: Replay Protection<br/>Nonce + Timestamp] --> L8_Check{Fresh Request?}
 L8_Check -->|No| Reject8[ 401 Replay Detected]
 L8_Check -->|Yes| Handler
 
 Handler[ Execute Method<br/>Process Request] --> Response
 Response[Return Result] --> Audit[Layer 9: Audit Log<br/>CloudWatch]
 
 style Request fill:#87CEEB
 style Handler fill:#32CD32
 style Response fill:#90EE90
 style Audit fill:#FFD700
 
 style L1 fill:#FFE4E1
 style L2 fill:#F0E68C
 style L3 fill:#E0FFFF
 style L4 fill:#FFB6C1
 style L5 fill:#DDA0DD
 style L6 fill:#98FB98
 style L7 fill:#FFDAB9
 style L8 fill:#B0E0E6
 
 style Reject1 fill:#FF6B6B
 style Reject2 fill:#FF6B6B
 style Reject3 fill:#FF6B6B
 style Reject4 fill:#FF6B6B
 style Reject5 fill:#FF6B6B
 style Reject6 fill:#FF6B6B
 style Reject7 fill:#FF6B6B
 style Reject8 fill:#FF6B6B
```

### **Security Layer Details**
<img width="1196" height="493" alt="image" src="https://github.com/user-attachments/assets/e1fe5aee-1ffa-45f9-947a-c34074c031bb" />

| Layer | Technology | Protection Against | 
|-------|------------|-------------------|
| **1. Network** | AWS VPC + SG | Unauthorized IPs, DDoS |
| **2. Transport** | TLS 1.3 | Eavesdropping, MITM | 
| **3. Integrity** | HMAC-SHA256 (Optional) | Message tampering | 
| **4. Authentication** | Keycloak JWT (RS256) | Impersonation |
| **5. Authorization** | Dynamic RBAC | Privilege escalation |
| **6. Validation** | JSON Schema | Injection, XSS, path traversal | 
| **7. Rate Limiting** | Token bucket | DoS, abuse | 
| **8. Replay Protection** | Timestamp + nonce | Replay attacks | 

###  **Production Deployment: ECS Fargate Cluster**

This production screenshot demonstrates:

- **Cluster:** `ca-a2a-cluster` with 4 active services
- **Service Health:** All services showing `ACTIVE` status with 1/1 tasks running (100% healthy)
- **Services Deployed:**
  - `orchestrator` - Workflow coordinator (Port 8001)
  - `extractor` - PDF text extraction (Port 8002)
  - `validator` - Data validation (Port 8003)
  - `archivist` - Database persistence (Port 8004)

**Platform Configuration:**
- **Launch Type:** FARGATE (serverless container execution)
- **Network Mode:** awsvpc (each task gets its own ENI with private IP)
- **Service Discovery:** AWS Cloud Map for internal DNS resolution (*.ca-a2a.local)
- **Load Balancing:** Service Connect for inter-agent communication

**Security Enforcement at Runtime:**
Each running task enforces all 8 security layers shown in the defense-in-depth diagram above. Every incoming request is validated through the complete security chain before reaching the application logic.

---

### **Task Definition Configuration**

Production task configuration details:

- **CPU:** 512 units (0.5 vCPU) per service - Optimized for JSON processing workload
- **Memory:** 1024 MB per service - Sufficient for Python runtime + libraries
- **Network Mode:** awsvpc - Provides ENI with private IP from VPC subnet
- **Execution Role:** `ca-a2a-ecs-execution-role` - Permissions for ECR pull, CloudWatch, Secrets Manager
- **Task Role:** `ca-a2a-ecs-task-role` - Permissions for S3 access, CloudWatch logs

**Security Features in Task Definition:**
- ✅ Secrets via AWS Secrets Manager (no hardcoded credentials)
- ✅ Read-only root filesystem (when applicable)
- ✅ Non-root user execution
- ✅ Limited IAM permissions (least privilege principle)
- ✅ Container-level logging to CloudWatch

---

### **Security Groups: Network-Level Enforcement**

This screenshot shows the actual security group rules implementing Layer 1 (Network Security):

**Inbound Rules Example (Orchestrator):**
- Port 8001 from Lambda security group (for process_document calls)
- Port 8001 from within VPC (for internal health checks)
- **Default:** DENY all other inbound traffic

**Outbound Rules Example (Orchestrator):**
- Port 8002 to Extractor security group only
- Port 8003 to Validator security group only
- Port 8004 to Archivist security group only
- Port 443 to VPC CIDR (for AWS API calls: S3, CloudWatch, Secrets Manager)
- Port 53 to VPC CIDR (DNS resolution via Route 53 Resolver)
- **Default:** DENY all other outbound traffic

**Principle Applied:** Microsegmentation
- Each agent has a dedicated security group
- Communication limited to specific ports and source/destination security groups
- No broad CIDR ranges (0.0.0.0/0) except for NAT-routed internet access
- Prevents lateral movement in case of compromise

---

## Authentication Mechanisms

### **Overview: Keycloak OAuth2/OIDC Only**

**IMPORTANT - Breaking Change (v3.0):**

As of version 3.0, the A2A protocol **only supports Keycloak OAuth2/OIDC authentication**. Legacy authentication methods have been removed:

❌ **REMOVED:** API Key authentication  
❌ **REMOVED:** Legacy JWT (HS256) authentication  
✅ **REQUIRED:** Keycloak JWT (RS256) authentication

**Migration Path:**
- See [`MIGRATION_GUIDE_KEYCLOAK_ONLY.md`](./MIGRATION_GUIDE_KEYCLOAK_ONLY.md) for upgrade instructions
- See [`AUTHENTICATION_ARCHITECTURE_UPDATE.md`](./AUTHENTICATION_ARCHITECTURE_UPDATE.md) for technical details

---

### **Production Infrastructure**

**RDS PostgreSQL Cluster:**

The RDS cluster provides persistent storage for:
- **Keycloak Identity Database** - User accounts, roles, sessions, audit logs
- **Document Archive** - Processed documents with metadata
- **Audit Records** - Long-term security audit trail

**Configuration:**
- **Engine:** Aurora PostgreSQL 15 (AWS-managed)
- **Instance Class:** db.t3.medium (2 vCPU, 4 GB RAM)
- **Endpoint:** `documents-db.cluster-czkdu9wcburt.eu-west-3.rds.amazonaws.com:5432`
- **Databases:** 
  - `keycloak` - Keycloak identity and access management
  - `documents_db` - Document processing and archival
- **Multi-AZ:** Yes (automatic failover to standby instance)
- **Encryption:** At-rest encryption enabled (AWS KMS)
- **Backup:** Automated daily backups with 7-day retention
- **Security:** Accessible only from Keycloak and Archivist security groups (port 5432)

**Keycloak Database Schema:**
```sql
-- Keycloak creates 60+ tables for identity management
-- Key tables include:
-- - user_entity: User accounts and credentials
-- - realm: Realm configurations
-- - client: OAuth2 clients (ca-a2a-agents)
-- - user_role_mapping: User-to-role assignments
-- - user_session: Active user sessions
-- - event_entity: Audit events (login, logout, token issuance)
```

**Performance:**
- Token verification: ~2ms (JWKS public key cached for 1 hour)
- User authentication: ~50ms (password verification + token issuance)
- Role lookup: <1ms (included in JWT claims, no database query)

---

### **Authentication Flow (Keycloak OAuth2/OIDC)**
<img width="1374" height="598" alt="Capture d’écran 2026-01-11 223046" src="https://github.com/user-attachments/assets/f38999f7-895f-459f-8021-00d7d3483211" />

```mermaid
sequenceDiagram
    participant Client
    participant Keycloak
    participant Agent as Agent<br/>(BaseAgent)
    participant Security as A2ASecurityManager
    participant JWKS as JWKS Endpoint<br/>(Keycloak)
    participant Handler as Method Handler
    
    Note over Client: 1. Obtain Access Token
    Client->>Keycloak: POST /realms/ca-a2a/protocol/openid-connect/token<br/>(client_id, client_secret, username, password)
    Keycloak->>Keycloak: Authenticate user credentials
    Keycloak->>Client: Access Token (JWT RS256) + Refresh Token
    
    Note over Client: 2. Call Agent API
    Client->>Agent: POST /message<br/>Authorization: Bearer <access_token>
    
    Note over Agent: 3. Extract Token
    Agent->>Security: authenticate_and_authorize(headers)
    Security->>Security: Extract Bearer token from Authorization header
    
    Note over Security: 4. Verify Keycloak JWT
    Security->>JWKS: GET /realms/ca-a2a/protocol/openid-connect/certs<br/>(Fetch RSA public key, cached 1h)
    JWKS-->>Security: Public key (RSA)
    Security->>Security: Verify JWT signature (RS256)
    Security->>Security: Check token expiration (exp claim)
    Security->>Security: Validate issuer (iss claim)
    Security->>Security: Validate audience (aud claim)
    Security->>Security: Extract username (preferred_username)
    Security->>Security: Extract Keycloak roles (realm_access.roles)
    Security->>Security: Map roles to A2A principal<br/>(admin → admin, orchestrator → orchestrator)
    
    alt Token Valid
        Security-->>Agent: principal="admin", allowed_methods=["*"]
        
        Note over Agent: 5. Execute Method
        Agent->>Handler: Execute method with principal context
        Handler-->>Agent: Result
        Agent-->>Client: 200 OK + Result
    else Token Invalid/Expired
        Security-->>Client: 401 Unauthorized (Invalid/Expired Token)
    else Insufficient Permissions
        Security-->>Client: 403 Forbidden (Method Not Allowed)
    end
```

### **Keycloak JWT Validation Code**

**Configuration** (`a2a_security.py:50-85`):
```python
class A2ASecurityManager:
    def __init__(self, agent_id: str):
        self.agent_id = _normalize_agent_id(agent_id)
        self.require_auth = os.getenv("A2A_REQUIRE_AUTH", "true").lower() == "true"
        self.enable_rate_limit = os.getenv("A2A_ENABLE_RATE_LIMIT", "true").lower() == "true"
        self.enable_replay_protection = os.getenv("A2A_ENABLE_REPLAY_PROTECTION", "true").lower() == "true"

        # Keycloak OAuth2/OIDC integration (REQUIRED)
        if not KEYCLOAK_AVAILABLE:
            raise RuntimeError("Keycloak authentication enabled but keycloak_auth module not available")
        
        keycloak_url = os.getenv("KEYCLOAK_URL")
        keycloak_realm = os.getenv("KEYCLOAK_REALM", "ca-a2a")
        keycloak_client_id = os.getenv("KEYCLOAK_CLIENT_ID", "ca-a2a-agents")
        
        if not keycloak_url:
            raise ValueError("KEYCLOAK_URL environment variable required")
        
        self.keycloak_validator = KeycloakJWTValidator(
            keycloak_url=keycloak_url,
            realm=keycloak_realm,
            client_id=keycloak_client_id,
            cache_ttl=int(os.getenv("KEYCLOAK_CACHE_TTL", "3600"))
        )
        
        self.keycloak_rbac_mapper = KeycloakRBACMapper()
        logger.info(f"Keycloak authentication enabled for realm: {keycloak_realm}")

        self.rbac_policy = _parse_json_env("A2A_RBAC_POLICY_JSON", default={"allow": {}, "deny": {}})

        self.rate_limiter = SlidingWindowRateLimiter(
            limit=int(os.getenv("A2A_RATE_LIMIT_PER_MINUTE", "300")),
            window_seconds=60,
        )
        self.replay = ReplayProtector(ttl_seconds=int(os.getenv("A2A_REPLAY_TTL_SECONDS", "120")))
```

**Verification** (`a2a_security.py:120-175`):
```python
def _authenticate(self, *, headers: Dict[str, str], method: str, message_dict: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Authenticate request using Keycloak JWT
    
    Security Features:
    1. RS256 signature verification (asymmetric cryptography)
    2. Token expiration validation
    3. Issuer verification (prevents token substitution)
    4. Audience verification (ensures token is for this client)
    5. Role extraction from realm_access.roles
    """
    auth_header = headers.get("Authorization", "") or ""

    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        # Only Keycloak JWT validation is supported
        return self._verify_keycloak_jwt(token=token, method=method, message_dict=message_dict)
    
    raise AuthError("Missing Authorization header (expected Bearer Keycloak JWT)")

def _verify_keycloak_jwt(self, *, token: str, method: str, message_dict: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Verify JWT token issued by Keycloak
    
    Returns:
        Tuple of (principal, auth_context)
    """
    # Verify token signature and extract claims
    username, keycloak_roles, claims = self.keycloak_validator.verify_token(token)
    
    # Map Keycloak roles to A2A principal and allowed methods
    principal, allowed_methods = self.keycloak_rbac_mapper.map_roles_to_principal(keycloak_roles)
    
    # Build auth context
    auth_context = {
        "mode": "keycloak_jwt",
        "username": username,
        "keycloak_roles": keycloak_roles,
        "rbac_principal": principal,
        "allowed_methods": allowed_methods,
        "dynamic_rbac": True,
        "token_claims": claims,
        "authenticated_at": time.time()
    }
    
    logger.info(f"Keycloak JWT authentication successful: username={username}, principal={principal}")
    
    return principal, auth_context
```

**Security Considerations:**

1. **Asymmetric Cryptography (RS256):**
   ```python
   # Keycloak signs with PRIVATE key (secret)
   signature = RSA_sign(private_key, token_payload)
   
   # Agents verify with PUBLIC key (distributed via JWKS)
   is_valid = RSA_verify(public_key, token_payload, signature)
   
   # Benefits:
   # - No shared secrets between Keycloak and agents
   # - Public key can be freely distributed
   # - Private key compromise doesn't affect all agents
   ```

2. **JWKS Public Key Caching:**
   ```python
   # Public key cached for 1 hour (reduces Keycloak load)
   jwks_cache = {
       "keys": [...],
       "timestamp": 1736900100,
       "ttl": 3600
   }
   
   # Cache hit: No network call to Keycloak
   # Cache miss: Fetch from /realms/ca-a2a/protocol/openid-connect/certs
   ```

3. **Token Expiration:**
   ```python
   # Short-lived access tokens (5 minutes)
   exp_claim = claims["exp"] # 1736900100
   now = int(time.time()) # 1736899900
   
   if now >= exp_claim:
       raise ValueError("Token has expired")
   
   # Benefits:
   # - Limited exposure window if token is stolen
   # - Automatic expiration without revocation list
   ```

4. **Issuer & Audience Validation:**
   ```python
   # Issuer must match Keycloak realm
   expected_issuer = "http://keycloak.ca-a2a.local:8080/realms/ca-a2a"
   if claims["iss"] != expected_issuer:
       raise ValueError("Invalid issuer")
   
   # Audience must match client ID
   expected_audience = "ca-a2a-agents"
   if claims["aud"] != expected_audience:
       raise ValueError("Invalid audience")
   
   # Prevents token substitution attacks
   ```

5. **Dynamic Role Extraction:**
   ```python
   # Roles extracted from JWT claims (no database lookup)
   keycloak_roles = claims.get("realm_access", {}).get("roles", [])
   # Example: ["admin", "default-roles-ca-a2a"]
   
   # Mapped to A2A principal
   principal, allowed_methods = mapper.map_roles_to_principal(keycloak_roles)
   # Example: ("admin", ["*"])
   
   # Benefits:
   # - Real-time role updates (just reissue token)
   # - No agent redeployment needed
   # - Centralized role management in Keycloak
   ```

---

## OAuth2/OIDC Authentication with Keycloak (NEW)

### **Overview**

The system now supports **enterprise-grade OAuth2/OIDC authentication** via Keycloak, complementing the existing API Key and JWT authentication methods.

**Key Benefits:**
- ✅ **Centralized Identity Management** - Single source of truth for users
- ✅ **Industry Standards** - OAuth 2.0 (RFC 6749) + OpenID Connect 1.0
- ✅ **Dynamic Token Issuance** - No manual key distribution
- ✅ **Token Lifecycle Management** - Automatic expiration, refresh, revocation
- ✅ **Asymmetric Cryptography** - RS256 (RSA + SHA-256) instead of HS256
- ✅ **Dynamic RBAC** - Real-time role updates without agent redeployment
- ✅ **Audit Trail** - Comprehensive authentication event logging
- ✅ **MFA Support** - Ready for multi-factor authentication

### **Keycloak Service Architecture**

**Deployment:**
```
ECS Fargate Cluster (ca-a2a-cluster)
├─ Keycloak Service
│  ├─ Task Definition: ca-a2a-keycloak
│  ├─ Image: 555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/keycloak:23.0
│  ├─ Port: 8080 (HTTP, internal only)
│  ├─ CPU: 1024 (1 vCPU)
│  ├─ Memory: 2048 MB (2 GB)
│  ├─ Service Discovery: keycloak.ca-a2a.local:8080
│  ├─ Health Check: /health/ready (90s start period)
│  └─ Database: PostgreSQL keycloak schema in RDS
```

**Network Security:**
- Private subnet deployment (no public IP)
- Security group: `ca-a2a-keycloak-sg`
  - Inbound: Port 8080 from agent security groups only
  - Outbound: Port 5432 (RDS), Port 443 (CloudWatch)
- Service Discovery via AWS Cloud Map (private DNS)

**Database:**
```sql
-- In RDS PostgreSQL cluster
CREATE DATABASE keycloak;
-- Keycloak creates 60+ tables for:
-- - User accounts and credentials
-- - Realms, clients, roles
-- - Sessions and tokens
-- - Audit events
```

### **OAuth2/OIDC Authentication Flow**

```mermaid
sequenceDiagram
    participant Client
    participant Keycloak
    participant Agent as Agent<br/>(BaseAgent)
    participant Security as A2ASecurityManager
    participant JWKS as JWKS Endpoint<br/>(Keycloak)
    participant Handler as Method Handler
    
    Note over Client: 1. Obtain Access Token
    Client->>Keycloak: POST /realms/ca-a2a/protocol/openid-connect/token<br/>(username, password, client_id, client_secret)
    Keycloak->>Keycloak: Validate credentials
    Keycloak->>Client: Access Token (JWT) + Refresh Token
    
    Note over Client: 2. Call Agent API
    Client->>Agent: POST /message<br/>Authorization: Bearer <access_token>
    
    Note over Agent: 3. Authenticate & Authorize
    Agent->>Security: authenticate_and_authorize(headers)
    Security->>Security: Extract Bearer token
    Security->>Security: Check if Keycloak enabled (A2A_USE_KEYCLOAK=true)
    
    alt Keycloak JWT
        Security->>JWKS: GET /realms/ca-a2a/protocol/openid-connect/certs<br/>(Fetch RSA public key, cached 1h)
        JWKS-->>Security: Public key (RSA)
        Security->>Security: Verify JWT signature (RS256)
        Security->>Security: Check token expiration (exp claim)
        Security->>Security: Extract username (preferred_username)
        Security->>Security: Extract Keycloak roles (realm_access.roles)
        Security->>Security: Map roles to A2A principal<br/>(admin → admin, orchestrator → orchestrator)
        Security-->>Agent: principal="admin", allowed_methods=["*"]
    else Legacy JWT/API Key
        Security->>Security: Fall back to legacy authentication
        Security-->>Agent: principal from legacy auth
    end
    
    Note over Agent: 4. Execute Method
    Agent->>Handler: Execute method
    Handler-->>Agent: Result
    Agent-->>Client: 200 OK + Result
```

### **Keycloak Realm Configuration**

**Realm**: `ca-a2a`

**Client Configuration**:
```json
{
  "clientId": "ca-a2a-agents",
  "clientAuthenticatorType": "client-secret",
  "protocol": "openid-connect",
  "publicClient": false,
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "serviceAccountsEnabled": true,
  "attributes": {
    "access.token.lifespan": "300",       // 5 minutes
    "refresh.token.lifespan": "2592000",  // 30 days
    "use.refresh.tokens": "true"
  }
}
```

**Token Settings**:
| Setting | Value | Rationale |
|---------|-------|-----------|
| Access Token Lifespan | 5 minutes | Short-lived reduces exposure risk |
| Refresh Token Lifespan | 30 days | Long-lived balances security & UX |
| Session Idle Timeout | 30 minutes | Auto-logout inactive users |
| Session Max Lifespan | 10 hours | Force periodic re-authentication |
| Token Signature Algorithm | RS256 | Asymmetric (public/private key pair) |

**Users**:
```
1. admin-user
   - Type: Human user
   - Role: admin
   - Permissions: Full access to all methods
   - MFA: Optional (TOTP ready)

2. lambda-service
   - Type: Service account
   - Role: lambda
   - Permissions: Full access (Lambda function authentication)
   - MFA: N/A (service accounts)

3. orchestrator-service
   - Type: Service account
   - Role: orchestrator
   - Permissions: extract_document, validate_document, archive_document, list_skills, get_health
   - MFA: N/A
```

**Roles → A2A Principal Mapping**:
| Keycloak Role | A2A Principal | Allowed Methods |
|---------------|---------------|-----------------|
| `admin` | admin | `*` (all methods) |
| `lambda` | lambda | `*` (all methods) |
| `orchestrator` | orchestrator | `extract_document`, `validate_document`, `archive_document`, `list_skills`, `get_health` |
| `document-processor` | document-processor | `process_document`, `extract_document`, `validate_document`, `archive_document` |
| `viewer` | viewer | `list_skills`, `get_health` (read-only) |

### **Implementation: KeycloakJWTValidator**

**File**: `keycloak_auth.py` (lines 1-210)

**Key Components**:
```python
class KeycloakJWTValidator:
    """
    Validates JWT tokens issued by Keycloak using JWKS (JSON Web Key Set)
    
    Features:
    - RS256 signature verification using RSA public key
    - Public key caching (1-hour TTL) to reduce JWKS endpoint load
    - Token expiration validation
    - Issuer verification (iss claim must match Keycloak URL)
    - Audience verification (aud claim must match client_id)
    - Role extraction from realm_access.roles
    """
    
    def __init__(self, keycloak_url: str, realm: str, client_id: str, cache_ttl: int = 3600):
        self.keycloak_url = keycloak_url.rstrip('/')
        self.realm = realm
        self.client_id = client_id
        self.cache_ttl = cache_ttl
        
        # JWKS endpoint for public key retrieval
        self.jwks_uri = f"{self.keycloak_url}/realms/{realm}/protocol/openid-connect/certs"
        
        # In-memory cache for public keys
        self._jwks_cache = None
        self._cache_timestamp = None
    
    def verify_token(self, token: str) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Verify JWT token and extract claims
        
        Returns:
            Tuple of (username, roles, full_claims)
        
        Raises:
            ValueError: If token is invalid, expired, or signature verification fails
        """
        # 1. Fetch public keys from JWKS endpoint (cached)
        jwks = self._get_jwks()
        
        # 2. Decode JWT header to get key ID (kid)
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get('kid')
        
        # 3. Find matching public key
        rsa_key = self._find_rsa_key(jwks, kid)
        
        # 4. Verify signature and decode claims
        try:
            claims = jwt.decode(
                token,
                rsa_key,
                algorithms=['RS256'],
                audience=self.client_id,
                issuer=f"{self.keycloak_url}/realms/{self.realm}"
            )
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {e}")
        
        # 5. Extract username and roles
        username = claims.get('preferred_username') or claims.get('sub')
        roles = claims.get('realm_access', {}).get('roles', [])
        
        return username, roles, claims
```

**Security Features**:
1. **Asymmetric Cryptography (RS256)**:
   - Keycloak signs tokens with **private key** (kept secret)
   - Agents verify tokens with **public key** (distributed via JWKS)
   - No shared secrets → easier key distribution, better security

2. **Public Key Caching**:
   - JWKS endpoint called once per hour
   - Reduces load on Keycloak
   - Cached in memory (no disk I/O)

3. **Token Expiration**:
   - `exp` claim checked on every request
   - Expired tokens rejected immediately
   - Short lifespan (5 min) limits exposure

4. **Issuer & Audience Validation**:
   - `iss` claim must match `http://keycloak.ca-a2a.local:8080/realms/ca-a2a`
   - `aud` claim must match `ca-a2a-agents`
   - Prevents token substitution attacks

### **Implementation: KeycloakRBACMapper**

**File**: `keycloak_auth.py` (lines 211-305)

**Role Mapping Logic**:
```python
class KeycloakRBACMapper:
    """
    Maps Keycloak roles to A2A RBAC principals
    
    Default Mappings:
    - admin role → admin principal → all methods
    - lambda role → lambda principal → all methods
    - orchestrator role → orchestrator principal → specific methods
    - document-processor role → document-processor principal → document methods
    - viewer role → viewer principal → read-only methods
    """
    
    def __init__(self, custom_mappings: Dict[str, Tuple[str, List[str]]] = None):
        # Default role → (principal, allowed_methods) mappings
        self.role_mappings = {
            "admin": ("admin", ["*"]),
            "lambda": ("lambda", ["*"]),
            "orchestrator": ("orchestrator", [
                "extract_document",
                "validate_document",
                "archive_document",
                "list_skills",
                "get_health"
            ]),
            "document-processor": ("document-processor", [
                "process_document",
                "extract_document",
                "validate_document",
                "archive_document"
            ]),
            "viewer": ("viewer", [
                "list_skills",
                "get_health"
            ])
        }
        
        # Merge custom mappings if provided
        if custom_mappings:
            self.role_mappings.update(custom_mappings)
    
    def map_roles_to_principal(self, keycloak_roles: List[str]) -> Tuple[str, List[str]]:
        """
        Map Keycloak roles to A2A principal and allowed methods
        
        Priority order (most privileged first):
        1. admin - Full access
        2. lambda - Full access (service account)
        3. orchestrator - Pipeline orchestration
        4. document-processor - Document operations
        5. viewer - Read-only access
        
        Returns:
            Tuple of (principal, allowed_methods)
        """
        # Check roles in priority order
        priority_order = ["admin", "lambda", "orchestrator", "document-processor", "viewer"]
        
        for role in priority_order:
            if role in keycloak_roles:
                return self.role_mappings[role]
        
        # No recognized roles → default to viewer (least privilege)
        return self.role_mappings["viewer"]
```

**Integration: A2ASecurityManager**

**File**: `a2a_security.py` (lines 45-92, 120-175)

**Initialization**:
```python
class A2ASecurityManager:
    def __init__(self, agent_id: str):
        # ... existing code ...
        
        # Keycloak OAuth2/OIDC integration (REQUIRED)
        if not KEYCLOAK_AVAILABLE:
            raise RuntimeError("Keycloak authentication enabled but keycloak_auth module not available")
        
        keycloak_url = os.getenv("KEYCLOAK_URL")
        keycloak_realm = os.getenv("KEYCLOAK_REALM", "ca-a2a")
        keycloak_client_id = os.getenv("KEYCLOAK_CLIENT_ID", "ca-a2a-agents")
        
        if not keycloak_url:
            raise ValueError("KEYCLOAK_URL environment variable required")
        
        self.keycloak_validator = KeycloakJWTValidator(
            keycloak_url=keycloak_url,
            realm=keycloak_realm,
            client_id=keycloak_client_id,
            cache_ttl=int(os.getenv("KEYCLOAK_CACHE_TTL", "3600"))
        )
        
        self.keycloak_rbac_mapper = KeycloakRBACMapper()
        logger.info(f"Keycloak authentication enabled for realm: {keycloak_realm}")
```

**Keycloak-Only Authentication**:
```python
async def authenticate_and_authorize(self, headers: Dict[str, str], method: str, message_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Authenticate and authorize request (Keycloak JWT only)
    
    Returns:
        Auth context with principal, allowed_methods, dynamic_rbac
    
    Raises:
        AuthError: If no valid Bearer token found
        ValueError: If token verification fails
        PermissionError: If method not allowed for principal
    """
    # Extract Authorization header
    auth_header = headers.get("authorization", headers.get("Authorization", ""))
    
    if not auth_header.startswith("Bearer "):
        raise AuthError("Missing Authorization header (expected Bearer Keycloak JWT)")
    
    token = auth_header[7:]  # Remove "Bearer " prefix
    
    # Verify Keycloak JWT (only authentication method)
    return await self._verify_keycloak_jwt(token=token, method=method, message_dict=message_dict)
```

**Keycloak JWT Verification**:
```python
async def _verify_keycloak_jwt(self, *, token: str, method: str, message_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify JWT token issued by Keycloak
    
    Returns:
        Auth context with Keycloak-specific metadata
    
    Raises:
        ValueError: If token is invalid, expired, or signature verification fails
        PermissionError: If method not allowed for principal's roles
    """
    # Verify token signature and extract claims
    username, keycloak_roles, claims = self.keycloak_validator.verify_token(token)
    
    # Map Keycloak roles to A2A principal
    principal, allowed_methods = self.keycloak_rbac_mapper.map_roles_to_principal(keycloak_roles)
    
    # Check method authorization
    if "*" not in allowed_methods and method not in allowed_methods:
        raise PermissionError(f"Principal '{principal}' not authorized for method '{method}'")
    
    # Build auth context
    auth_context = {
        "mode": "keycloak_jwt",
        "username": username,
        "keycloak_roles": keycloak_roles,
        "rbac_principal": principal,
        "allowed_methods": allowed_methods,
        "dynamic_rbac": True,  # Roles can be updated in Keycloak without redeployment
        "methods_override": allowed_methods,
        "token_claims": claims
    }
    
    return auth_context
```

### **API Usage Examples**

**1. Obtain Access Token (Password Grant)**:
```bash
curl -X POST "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=ca-a2a-agents" \
  -d "client_secret=<client_secret>" \
  -d "username=admin-user" \
  -d "password=<user_password>"

# Response:
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJxdW5...",
  "expires_in": 300,
  "refresh_expires_in": 2592000,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3...",
  "token_type": "Bearer",
  "not-before-policy": 0,
  "session_state": "8f3e4d2c-1b7a-4c9d-8e2f-5a6b7c8d9e0f",
  "scope": "profile email"
}
```

**2. Call Agent with Keycloak Token**:
```bash
curl -X POST "http://orchestrator.ca-a2a.local:8001/message" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJxdW5..." \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_skills",
    "params": {},
    "id": 1
  }'

# Response:
{
  "jsonrpc": "2.0",
  "result": {
    "skills": ["process_document", "coordinate_pipeline"],
    "agent": "orchestrator",
    "auth_context": {
      "mode": "keycloak_jwt",
      "username": "admin-user",
      "rbac_principal": "admin",
      "dynamic_rbac": true
    }
  },
  "id": 1
}
```

**3. Refresh Access Token**:
```bash
curl -X POST "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "client_id=ca-a2a-agents" \
  -d "client_secret=<client_secret>" \
  -d "refresh_token=<refresh_token>"

# Returns new access_token and refresh_token
```

### **Token Structure (Decoded JWT)**

**Keycloak Access Token**:
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "qunlkj_cDRkZiIsImtpZCI"  // Key ID for JWKS lookup
  },
  "payload": {
    "exp": 1736900100,  // Expiration (5 min from iat)
    "iat": 1736899800,  // Issued at
    "jti": "8f3e4d2c-1b7a-4c9d-8e2f-5a6b7c8d9e0f",  // Unique token ID
    "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",  // Issuer
    "aud": "ca-a2a-agents",  // Audience (client ID)
    "sub": "f1234567-89ab-cdef-0123-456789abcdef",  // Subject (user ID)
    "typ": "Bearer",
    "azp": "ca-a2a-agents",  // Authorized party
    "session_state": "8f3e4d2c-1b7a-4c9d-8e2f-5a6b7c8d9e0f",
    "acr": "1",
    "realm_access": {
      "roles": ["admin", "default-roles-ca-a2a"]  // User roles
    },
    "scope": "profile email",
    "email_verified": true,
    "preferred_username": "admin-user",  // Username extracted by validator
    "email": "admin@example.com"
  },
  "signature": "..."  // RS256 signature verified using public key from JWKS
}
```

### **Security Evolution: Keycloak vs Legacy Authentication**

| Aspect | Legacy API Keys | Legacy JWT (HS256) | Keycloak JWT (RS256) ✅ |
|--------|----------------|-------------------|----------------------|
| **Algorithm** | N/A (plaintext match) | HS256 (HMAC + SHA-256) | RS256 (RSA + SHA-256) |
| **Key Type** | Shared secret | Symmetric (shared secret) | Asymmetric (public/private key pair) |
| **Key Distribution** | Manual (env vars) | Secret must be shared with all agents | Public key distributed via JWKS endpoint |
| **Key Rotation** | Manual env update + redeploy | Requires agent redeployment | Automatic via JWKS cache refresh |
| **Token Issuance** | Manual generation | Manual generation (Python script) | Automatic via Keycloak API |
| **User Management** | Manual (no database) | Manual (no central database) | Centralized (Keycloak admin console) |
| **Role Management** | Static mapping in code | Static RBAC JSON file | Dynamic (Keycloak roles) |
| **Token Revocation** | Not supported | Database-backed revocation list | Built-in Keycloak revocation |
| **Audit Logging** | Application logs only | Application logs only | Keycloak audit events + app logs |
| **MFA Support** | Not supported | Not supported | Built-in TOTP, SMS, email |
| **SSO Integration** | Not supported | Not supported | SAML, OAuth2, OIDC providers |
| **Token Lifespan** | N/A (never expires) | Manual expiration | Short-lived (5 min) + refresh tokens |
| **Security Rating** | ⚠️ Low | ⚠️ Medium | ✅ High (Enterprise-grade) |

### **Monitoring & Observability**

**CloudWatch Logs** (`/ecs/ca-a2a-keycloak`):
```
2026-01-14 12:30:45 INFO  [org.keycloak.services] (ServerService Thread Pool -- 45) KC-SERVICES0001: Keycloak 23.0 started in 12345ms
2026-01-14 12:30:45 INFO  [io.quarkus] (main) Listening on: http://0.0.0.0:8080
2026-01-14 12:31:10 INFO  [org.keycloak.events] (executor-thread-1) type=LOGIN, realmId=ca-a2a, clientId=ca-a2a-agents, userId=f1234567-89ab-cdef-0123-456789abcdef, username=admin-user, ipAddress=10.0.10.25, auth_method=password, auth_session_id=8f3e4d2c-1b7a-4c9d-8e2f-5a6b7c8d9e0f
```

**Agent Logs** (Keycloak JWT verification):
```python
logger.info(f"Keycloak JWT verification successful: username={username}, roles={keycloak_roles}, principal={principal}")
# Output: Keycloak JWT verification successful: username=admin-user, roles=['admin'], principal=admin
```

### **Testing**

**Unit Tests** (`test_keycloak_integration.py`):
```bash
pytest test_keycloak_integration.py -v

# Tests:
# ✅ test_keycloak_jwt_validator_initialization
# ✅ test_keycloak_jwt_validator_verify_token (mocked)
# ✅ test_keycloak_rbac_mapper_default_roles
# ✅ test_keycloak_rbac_mapper_admin_role
# ✅ test_keycloak_rbac_mapper_orchestrator_role
# ✅ test_keycloak_rbac_mapper_viewer_role
# ✅ test_keycloak_auth_client_initialization
# ✅ test_security_manager_keycloak_integration
# ✅ test_keycloak_integration_end_to_end (requires running Keycloak)
```

**Integration Tests** (`test-keycloak-auth.sh`):
```bash
./test-keycloak-auth.sh

# Tests:
# ✅ Authenticate user and obtain token
# ✅ Verify JWKS endpoint
# ✅ Call orchestrator with Keycloak JWT
# ✅ Refresh token
# ✅ Invalid token rejection
```

### **Documentation References**

- [`KEYCLOAK_INTEGRATION_GUIDE.md`](./KEYCLOAK_INTEGRATION_GUIDE.md) - Comprehensive guide (624 lines)
- [`KEYCLOAK_QUICK_START.md`](./KEYCLOAK_QUICK_START.md) - 15-minute quick start (248 lines)
- [`KEYCLOAK_IMPLEMENTATION_SUMMARY.md`](./KEYCLOAK_IMPLEMENTATION_SUMMARY.md) - Implementation summary (421 lines)
- [`keycloak_auth.py`](./keycloak_auth.py) - Source code with docstrings (450 lines)
- [`keycloak_client_example.py`](./keycloak_client_example.py) - Client usage examples (331 lines)

---

## Authorization & RBAC

### **RBAC Policy Structure**

```mermaid
graph TB
 subgraph "RBAC Policy"
 Policy[RBAC Policy JSON]
 Allow[Allow Rules]
 Deny[Deny Rules]
 end
 
 Policy --> Allow
 Policy --> Deny
 
 subgraph "Allow Rules"
 A1["lambda-s3-processor: [*]"]
 A2["orchestrator: [extract_document, validate_document, archive_document]"]
 A3["admin: [*]"]
 end
 
 subgraph "Deny Rules"
 D1["guest: [archive_document]"]
 D2["read-only: [process_document]"]
 end
 
 Allow --> A1
 Allow --> A2
 Allow --> A3
 
 Deny --> D1
 Deny --> D2
 
 style Policy fill:#FFD700
 style Allow fill:#90EE90
 style Deny fill:#FF6B6B
```

**Policy JSON Example:**
<img width="659" height="561" alt="Capture d’écran 2026-01-11 223112" src="https://github.com/user-attachments/assets/528e12eb-9c36-4443-b868-c12aa546cf89" />

```json
{
 "allow": {
 "lambda-s3-processor": ["*"],
 "orchestrator": [
 "extract_document",
 "validate_document",
 "archive_document"
 ],
 "admin": ["*"],
 "viewer": [
 "list_skills",
 "get_health"
 ]
 },
 "deny": {
 "guest": ["archive_document"],
 "read-only": [
 "process_document",
 "archive_document"
 ]
 }
}
```

### **Authorization Decision Flow**
<img width="690" height="549" alt="Capture d’écran 2026-01-11 223124" src="https://github.com/user-attachments/assets/c45e0abb-0783-47c8-bdf1-22dd3ae0744c" />

```mermaid
flowchart TD
 Start[Authorization Check] --> Auth{Authenticated?}
 Auth -->|No| Reject1[ 401 Unauthorized]
 Auth -->|Yes| ExtractPrincipal[Extract Principal<br/>e.g., lambda-s3-processor]
 
 ExtractPrincipal --> ExtractMethod[Extract Method<br/>e.g., process_document]
 
 ExtractMethod --> CheckDeny{Principal in<br/>Deny List?}
 
 CheckDeny -->|Yes| CheckDenyMethod{Method in<br/>Denied Methods?}
 CheckDenyMethod -->|Yes| Reject2[ 403 Forbidden<br/>Explicitly Denied]
 CheckDenyMethod -->|No| CheckAllow
 
 CheckDeny -->|No| CheckAllow{Principal in<br/>Allow List?}
 
 CheckAllow -->|No| Reject3[ 403 Forbidden<br/>Not Authorized]
 
 CheckAllow -->|Yes| CheckWildcard{Has Wildcard '*'<br/>Permission?}
 
 CheckWildcard -->|Yes| Allow[ Authorized<br/>Wildcard Access]
 CheckWildcard -->|No| CheckSpecific{Method in<br/>Allowed Methods?}
 
 CheckSpecific -->|Yes| Allow2[ Authorized<br/>Specific Method]
 CheckSpecific -->|No| Reject4[ 403 Forbidden<br/>Method Not Allowed]
 
 Allow --> Execute[Execute Method]
 Allow2 --> Execute
 
 style Start fill:#87CEEB
 style Auth fill:#FFD700
 style CheckDeny fill:#FFA07A
 style CheckAllow fill:#90EE90
 style Allow fill:#32CD32
 style Allow2 fill:#32CD32
 style Execute fill:#32CD32
 style Reject1 fill:#FF6B6B
 style Reject2 fill:#FF6B6B
 style Reject3 fill:#FF6B6B
 style Reject4 fill:#FF6B6B
```

### **Authorization Code Implementation**

**RBAC Check** (`a2a_security.py:358-386`):
```python
def _is_allowed(self, principal: str, method: str) -> bool:
 """
 Check if principal is allowed to call method
 
 Decision Logic:
 1. Check deny list first (explicit deny overrides allow)
 2. Check allow list
 3. Support wildcard "*" for all methods
 4. Default deny (secure by default)
 """
 # Step 1: Check deny list (highest priority)
 if principal in self.rbac_policy["deny"]:
 denied_methods = self.rbac_policy["deny"][principal]
 
 # Wildcard deny = deny all methods
 if "*" in denied_methods:
 self.logger.warning(f"RBAC: {principal} denied from all methods (wildcard)")
 return False
 
 # Specific method deny
 if method in denied_methods:
 self.logger.warning(f"RBAC: {principal} explicitly denied from calling {method}")
 return False
 
 # Step 2: Check allow list
 if principal in self.rbac_policy["allow"]:
 allowed_methods = self.rbac_policy["allow"][principal]
 
 # Wildcard allow = allow all methods
 if "*" in allowed_methods:
 self.logger.info(f"RBAC: {principal} has wildcard access to all methods")
 return True
 
 # Specific method allow
 if method in allowed_methods:
 self.logger.info(f"RBAC: {principal} allowed to call {method}")
 return True
 
 # Step 3: Default deny (not in allow list)
 self.logger.warning(f"RBAC: {principal} not authorized to call {method}")
 return False
```

**Configuration** (Environment Variable):
```bash
# Set via ECS task definition
A2A_RBAC_POLICY_JSON='{
 "allow": {
 "lambda-s3-processor": ["*"],
 "orchestrator": ["extract_document", "validate_document", "archive_document"]
 },
 "deny": {}
}'
```

---

## ️ Message Integrity (HMAC)

### **HMAC Signing & Verification Flow**
<img width="1386" height="578" alt="Capture d’écran 2026-01-11 223027" src="https://github.com/user-attachments/assets/dc82f3c4-0070-47e2-9a11-87b86571d6ba" />

```mermaid
sequenceDiagram
 participant Client as Client Agent
 participant Server as Server Agent
 
 Note over Client: Prepare Request
 Client->>Client: 1. body = '{"method":"extract_document"}'
 Client->>Client: 2. timestamp = current_unix_time()
 Client->>Client: 3. body_hash = SHA256(body)
 Client->>Client: 4. signing_string = "POST\n/message\n{timestamp}\n{body_hash}"
 
 Note over Client: Generate HMAC Signature
 Client->>Client: 5. signature = HMAC-SHA256(secret_key, signing_string)
 Client->>Client: 6. header = "{timestamp}:{signature}"
 
 Client->>Server: POST /message<br/>X-Signature: {timestamp}:{signature}<br/>Body: {body}
 
 Note over Server: Verify Signature
 Server->>Server: 7. Extract timestamp & signature from header
 Server->>Server: 8. Check timestamp freshness (< 5 min)
 
 alt Timestamp Too Old/Future
 Server-->>Client: 401 Signature Expired/Future
 end
 
 Server->>Server: 9. body_hash = SHA256(received_body)
 Server->>Server: 10. signing_string = "POST\n/message\n{timestamp}\n{body_hash}"
 Server->>Server: 11. expected_sig = HMAC-SHA256(secret_key, signing_string)
 Server->>Server: 12. Compare signatures (constant-time)
 
 alt Signatures Match
 Server-->>Client: Request Processed
 else Signatures Don't Match
 Server-->>Client: 401 Invalid Signature (Tampered)
 end
```

### **HMAC Implementation Details**

**Signing String Construction:**
```
Signing String Format:
{HTTP_METHOD}\n{PATH}\n{TIMESTAMP}\n{BODY_SHA256}

Example:
POST
/message
1735867245
abc123def456...789
```

**Code Implementation** (`a2a_security_enhanced.py:45-89`):
```python
class RequestSigner:
 def __init__(self, secret_key: str, max_age_seconds: int = 300):
 self.secret_key = secret_key.encode('utf-8')
 self.max_age_seconds = max_age_seconds # Default: 5 minutes
 
 def sign_request(self, method: str, path: str, body: bytes) -> str:
 """
 Sign request with HMAC-SHA256
 
 Returns: "{timestamp}:{signature}"
 Example: "1735867245:a3f2c9d8e1b4f5a6b7c8d9e0f1a2b3c4..."
 """
 # Get current Unix timestamp
 timestamp = str(int(time.time()))
 
 # Hash the request body
 body_hash = hashlib.sha256(body).hexdigest()
 
 # Construct signing string
 signing_string = f"{method.upper()}\n{path}\n{timestamp}\n{body_hash}"
 
 # Generate HMAC signature
 signature = hmac.new(
 self.secret_key,
 signing_string.encode('utf-8'),
 hashlib.sha256
 ).hexdigest()
 
 return f"{timestamp}:{signature}"
 
 def verify_signature(
 self,
 signature_header: str,
 method: str,
 path: str,
 body: bytes
 ) -> Tuple[bool, Optional[str]]:
 """
 Verify HMAC signature
 
 Security Checks:
 1. Signature format validation
 2. Timestamp freshness (replay protection)
 3. Signature verification (integrity)
 """
 # Parse signature header
 if not signature_header or ":" not in signature_header:
 return False, "Invalid signature format"
 
 try:
 timestamp_str, received_signature = signature_header.split(':', 1)
 timestamp = int(timestamp_str)
 except ValueError:
 return False, "Invalid timestamp in signature"
 
 # Check timestamp freshness (replay protection)
 now = int(time.time())
 age = abs(now - timestamp)
 
 if age > self.max_age_seconds:
 return False, f"Signature too old/future (age: {age}s, max: {self.max_age_seconds}s)"
 
 # Reconstruct signing string
 body_hash = hashlib.sha256(body).hexdigest()
 signing_string = f"{method.upper()}\n{path}\n{timestamp_str}\n{body_hash}"
 
 # Compute expected signature
 expected_signature = hmac.new(
 self.secret_key,
 signing_string.encode('utf-8'),
 hashlib.sha256
 ).hexdigest()
 
 # Constant-time comparison (prevents timing attacks)
 if not hmac.compare_digest(received_signature, expected_signature):
 return False, "Invalid signature (tampered)"
 
 return True, None
```

### **Security Properties**

**1. Message Integrity:**
```python
# Original request
body = b'{"method":"test","params":{"s3_key":"valid.pdf"}}'
signature = sign(body) # abc123...

# Attacker modifies body
tampered = b'{"method":"test","params":{"s3_key":"../../etc/passwd"}}'

# Verification fails
verify(signature, tampered) # False - body hash mismatch
```

**2. Replay Protection:**
```python
# Request at 10:00 AM
timestamp = 1735867200
signature = sign(timestamp, body) # Valid

# Attacker replays at 10:10 AM (10 minutes later)
current_time = 1735867800
age = current_time - timestamp # 600 seconds

if age > max_age_seconds (300): # Rejected
 return "Signature expired"
```

**3. Authentication:**
```python
# Only agents with secret_key can generate valid signatures
secret_key = "shared_secret_64_chars_minimum"

# Attacker without secret_key cannot forge signatures
attacker_signature = hmac(attacker_guess, body) # Wrong key
```

---

## Input Validation (JSON Schema)

### **Schema Validation Flow**
<img width="682" height="536" alt="Capture d’écran 2026-01-11 223138" src="https://github.com/user-attachments/assets/0c5aeac2-7910-40d1-ba04-947c467db381" />

```mermaid
flowchart TD
 Start[Receive Request] --> Extract[Extract params]
 Extract --> SchemaLookup{Schema Exists<br/>for Method?}
 
 SchemaLookup -->|No| Warn[️ Log Warning<br/>Skip Validation]
 Warn --> Process[Process Request]
 
 SchemaLookup -->|Yes| TypeCheck[Type Check<br/>string, number, object, array]
 
 TypeCheck -->|Fail| Error1[ 400 Type Error<br/>e.g., Expected string, got number]
 TypeCheck -->|Pass| PatternCheck[Pattern Check<br/>Regex validation]
 
 PatternCheck -->|Fail| Error2[ 400 Pattern Error<br/>e.g., Path traversal detected]
 PatternCheck -->|Pass| RequiredCheck[Required Fields<br/>Must be present]
 
 RequiredCheck -->|Fail| Error3[ 400 Missing Field<br/>e.g., s3_key is required]
 RequiredCheck -->|Pass| EnumCheck[Enum Check<br/>Allowed values]
 
 EnumCheck -->|Fail| Error4[ 400 Invalid Value<br/>e.g., priority must be low/normal/high]
 EnumCheck -->|Pass| AdditionalCheck[Additional Properties<br/>Check for unexpected fields]
 
 AdditionalCheck -->|Found| Error5[ 400 Unexpected Field<br/>e.g., extra_field not allowed]
 AdditionalCheck -->|None| RangeCheck[Range Check<br/>Min/max length, value]
 
 RangeCheck -->|Fail| Error6[ 400 Range Error<br/>e.g., string too long]
 RangeCheck -->|Pass| Success[ Validation Passed]
 
 Success --> Process
 Process --> Response[Return Result]
 
 style Start fill:#87CEEB
 style Success fill:#32CD32
 style Process fill:#90EE90
 style Response fill:#90EE90
 style Warn fill:#FFD700
 style Error1 fill:#FF6B6B
 style Error2 fill:#FF6B6B
 style Error3 fill:#FF6B6B
 style Error4 fill:#FF6B6B
 style Error5 fill:#FF6B6B
 style Error6 fill:#FF6B6B
```

### **Schema Definition Example**

**Schema for `process_document` method:**
```json
{
 "type": "object",
 "properties": {
 "s3_key": {
 "type": "string",
 "pattern": "^(?!.*\\.\\./)[a-zA-Z0-9/._-]+$",
 "minLength": 1,
 "maxLength": 1024,
 "description": "S3 object key without path traversal"
 },
 "priority": {
 "type": "string",
 "enum": ["low", "normal", "high"],
 "description": "Processing priority level"
 },
 "correlation_id": {
 "type": "string",
 "pattern": "^[a-zA-Z0-9-]+$",
 "minLength": 1,
 "maxLength": 128,
 "description": "Optional request tracing ID"
 }
 },
 "required": ["s3_key"],
 "additionalProperties": false
}
```

### **Attack Prevention Examples**
<img width="1227" height="519" alt="image" src="https://github.com/user-attachments/assets/838d21d1-741f-42bd-860d-4318dd03e609" />

**1. Path Traversal Prevention:**
```python
# ATTACK: Path traversal
params = {"s3_key": "../../../etc/passwd"}

# Schema pattern: ^(?!.*\\.\\./)[a-zA-Z0-9/._-]+$
# - Negative lookahead: (?!.*\\.\\.) - Rejects any string containing ".."
# - Character whitelist: [a-zA-Z0-9/._-] - Only safe characters

validate(params) # Pattern mismatch - BLOCKED
```

**2. SQL Injection Prevention:**
```python
# ATTACK: SQL injection attempt
params = {"s3_key": "'; DROP TABLE documents--"}

# Schema constraints:
# - Pattern: Only alphanumeric + /._-
# - Type: Must be string (not raw SQL)

validate(params) # Pattern mismatch - BLOCKED
```

**3. Buffer Overflow Prevention:**
```python
# ATTACK: Extremely long string
params = {"s3_key": "A" * 100000} # 100KB string

# Schema constraint: "maxLength": 1024

validate(params) # Too long - BLOCKED
```

**4. Type Confusion Prevention:**
```python
# ATTACK: Type confusion
params = {"s3_key": ["malicious", "array"]}

# Schema constraint: "type": "string"

validate(params) # Type error - BLOCKED
```

**5. Unexpected Field Prevention:**
```python
# ATTACK: Inject malicious field
params = {
 "s3_key": "test.pdf",
 "__proto__": {"isAdmin": true} # Prototype pollution attempt
}

# Schema constraint: "additionalProperties": false

validate(params) # Unexpected field - BLOCKED
```

### **Validation Code Implementation**

**Code** (`a2a_security_enhanced.py:140-172`):
```python
class JSONSchemaValidator:
 def __init__(self):
 self.schemas = self._load_schemas()
 
 def validate(self, method: str, params: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
 """
 Validate params against JSON schema
 
 Returns: (is_valid, error_message)
 """
 schema = self.schemas.get(method)
 
 if not schema:
 logger.warning(f"No JSON schema found for method: {method}")
 return True, None # Skip validation if no schema
 
 try:
 # Use jsonschema library for validation
 jsonschema.validate(instance=params, schema=schema)
 return True, None
 
 except jsonschema.ValidationError as e:
 error_msg = f"JSON Schema validation failed for method '{method}': {e.message}"
 logger.error(error_msg)
 return False, error_msg
 
 except Exception as e:
 error_msg = f"Unexpected error during validation: {str(e)}"
 logger.error(error_msg)
 return False, error_msg
```

---

## Replay Protection

### **Replay Attack Scenario**
<img width="690" height="549" alt="Capture d’écran 2026-01-11 223124" src="https://github.com/user-attachments/assets/c45e0abb-0783-47c8-bdf1-22dd3ae0744c" />

```mermaid
sequenceDiagram
 participant Attacker
 participant Victim as Legitimate Agent
 participant Server
 
 Note over Victim,Server: Normal Request
 Victim->>Server: POST /message<br/>X-API-Key: valid_key<br/>Body: {transfer $1000}
 Server-->>Victim: Success
 
 Note over Attacker: Attacker intercepts valid request
 Attacker->>Attacker: Capture entire request<br/>(headers + body)
 
 Note over Attacker,Server: Replay Attack (1 minute later)
 Attacker->>Server: POST /message<br/>X-API-Key: valid_key<br/>Body: {transfer $1000}<br/>(Exact same request)
 
 alt Without Replay Protection
 Server-->>Attacker: Success<br/> $1000 transferred again!
 else With Replay Protection
 Server->>Server: Check request timestamp
 Server->>Server: Request > 5 min old 
 Server-->>Attacker: 401 Replay Detected
 end
```

### **Replay Protection Mechanisms**

**1. Timestamp-Based (HMAC Signature):**
```python
# Signature includes timestamp
signature = f"{timestamp}:{hmac_sig}"
# Example: "1735867245:abc123..."

# Server checks age
now = int(time.time())
age = now - timestamp

if age > 300: # 5 minutes
 return "Signature expired - possible replay attack"
```

**2. Nonce-Based (Optional):**
```python
# Client generates unique nonce
nonce = str(uuid.uuid4()) # "a1b2c3d4-e5f6-..."

# Server tracks used nonces
used_nonces = set() # Or Redis cache

if nonce in used_nonces:
 return "Nonce already used - replay attack detected"

used_nonces.add(nonce)
```

**3. Combined Approach:**
```python
# Signature includes both timestamp and nonce
signing_string = f"{method}\n{path}\n{timestamp}\n{nonce}\n{body_hash}"

# Double protection:
# - Timestamp prevents long-term replay
# - Nonce prevents short-term replay
```

### **Configuration**

```python
# Environment variable (seconds)
A2A_SIGNATURE_MAX_AGE_SECONDS=300 # 5 minutes

# Trade-offs:
# - Too short (< 60s): Legitimate requests fail due to clock skew
# - Too long (> 600s): Wider replay window
# - Recommended: 300s (5 minutes)
```

---

## ⏱️ Rate Limiting

### **Token Bucket Algorithm**
<img width="648" height="388" alt="Capture d’écran 2026-01-11 223213" src="https://github.com/user-attachments/assets/a03e0ba2-4543-414f-9fac-0217a2ec01d3" />

```mermaid
graph TB
 subgraph "Token Bucket"
 Bucket[Token Bucket<br/>Capacity: 100 tokens]
 Refill[Refill Rate<br/>+100 tokens/minute]
 end
 
 Request1[Request 1] -->|Consume 1 token| Bucket
 Request2[Request 2] -->|Consume 1 token| Bucket
 Request3[Request 3] -->|Consume 1 token| Bucket
 RequestN[Request 101] -->|No tokens!| Reject[ 429 Rate Limit Exceeded]
 
 Refill -->|Every minute| Bucket
 
 style Bucket fill:#90EE90
 style Refill fill:#87CEEB
 style Reject fill:#FF6B6B
```

### **Rate Limiting Logic**

```python
class RateLimiter:
 def __init__(self, limit: int = 100, window: int = 60):
 """
 Token bucket rate limiter
 
 Args:
 limit: Max requests per window
 window: Time window in seconds
 """
 self.limit = limit
 self.window = window
 self.buckets: Dict[str, Dict] = {} # {principal: {tokens, last_refill}}
 
 def allow(self, principal: str) -> Tuple[bool, Dict[str, Any]]:
 """
 Check if request is allowed
 
 Returns: (allowed, metadata)
 """
 now = time.time()
 
 # Initialize bucket for new principal
 if principal not in self.buckets:
 self.buckets[principal] = {
 "tokens": self.limit,
 "last_refill": now
 }
 
 bucket = self.buckets[principal]
 
 # Refill tokens based on time elapsed
 elapsed = now - bucket["last_refill"]
 refill_amount = (elapsed / self.window) * self.limit
 
 bucket["tokens"] = min(self.limit, bucket["tokens"] + refill_amount)
 bucket["last_refill"] = now
 
 # Check if tokens available
 if bucket["tokens"] >= 1:
 bucket["tokens"] -= 1
 return True, {
 "limit": self.limit,
 "remaining": int(bucket["tokens"]),
 "reset": int(now + self.window)
 }
 else:
 return False, {
 "limit": self.limit,
 "remaining": 0,
 "reset": int(now + self.window)
 }
```

### **Rate Limit Response**

**Headers (informational):**
```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1735867300
```

**Error Response (limit exceeded):**
```json
{
 "jsonrpc": "2.0",
 "error": {
 "code": -32011,
 "message": "Forbidden: Rate limit exceeded (limit=100/min)",
 "data": {
 "limit": 100,
 "remaining": 0,
 "reset": 1735867300
 }
 },
 "id": "req-123",
 "_meta": {
 "rate_limit": {
 "limit": 100,
 "remaining": 0,
 "reset": 1735867300
 }
 }
}
```

---

## Token Revocation

### **Revocation Architecture**
<img width="561" height="89" alt="image" src="https://github.com/user-attachments/assets/7f44f9ef-2203-4569-b353-ef9128c26b2a" />

```mermaid
graph TB
 subgraph "Token Lifecycle"
 Issue[Token Issued<br/>jti=abc-123]
 Use1[Token Used<br/> Valid]
 Breach[Security Breach!<br/>Laptop Stolen]
 Revoke[Admin Revokes Token<br/>jti=abc-123]
 Use2[Token Used Again<br/> Revoked]
 end
 
 subgraph "Revocation Database"
 DB[(PostgreSQL<br/>revoked_tokens)]
 Cache[In-Memory Cache]
 end
 
 Issue --> Use1
 Use1 --> Breach
 Breach --> Revoke
 Revoke --> DB
 DB --> Cache
 Use2 --> Cache
 Cache -->|Check| Blocked[ Access Denied]
 
 style Issue fill:#90EE90
 style Use1 fill:#90EE90
 style Breach fill:#FFD700
 style Revoke fill:#FFA07A
 style Use2 fill:#FF6B6B
 style Blocked fill:#FF6B6B
 style DB fill:#87CEEB
```

### **Revocation Database Schema**

```sql
CREATE TABLE revoked_tokens (
 jti VARCHAR(255) PRIMARY KEY, -- JWT ID (unique token identifier)
 revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 revoked_by VARCHAR(100) NOT NULL, -- Who revoked it (admin username)
 reason TEXT, -- Why revoked (e.g., "Security breach")
 expires_at TIMESTAMP NOT NULL -- When token would have expired
);

CREATE INDEX idx_revoked_expires ON revoked_tokens(expires_at);
CREATE INDEX idx_revoked_by ON revoked_tokens(revoked_by);
```

### **Revocation Code Implementation**

**Revoke Token** (`a2a_security_enhanced.py:200-225`):
```python
class TokenRevocationList:
 def __init__(self, db_pool: Optional[asyncpg.Pool] = None):
 self.db_pool = db_pool
 self._revoked_cache: Dict[str, int] = {} # {jti: expires_at_timestamp}
 
 async def revoke_token(
 self,
 jti: str,
 expires_at: datetime,
 reason: str = "manual",
 revoked_by: str = "system"
 ) -> bool:
 """
 Revoke a token
 
 Stores in both database (persistent) and cache (fast lookup)
 """
 if self.db_pool:
 async with self.db_pool.acquire() as conn:
 await conn.execute(
 """
 INSERT INTO revoked_tokens (jti, expires_at, reason, revoked_by)
 VALUES ($1, $2, $3, $4)
 ON CONFLICT (jti) DO UPDATE SET
 expires_at = GREATEST(EXCLUDED.expires_at, revoked_tokens.expires_at),
 reason = EXCLUDED.reason,
 revoked_by = EXCLUDED.revoked_by,
 revoked_at = CURRENT_TIMESTAMP;
 """,
 jti, expires_at, reason, revoked_by
 )
 
 # Add to in-memory cache for fast lookup
 self._revoked_cache[jti] = int(expires_at.timestamp())
 
 logger.info(f"Token {jti} revoked by {revoked_by}: {reason}")
 return True
 
 async def is_revoked(self, jti: str) -> bool:
 """
 Check if token is revoked
 
 Checks cache first, then database
 """
 now_ts = int(time.time())
 
 # Check in-memory cache (fast)
 if jti in self._revoked_cache:
 if self._revoked_cache[jti] > now_ts:
 return True # Still revoked
 else:
 del self._revoked_cache[jti] # Expired, clean up
 
 # Check database (persistent)
 if self.db_pool:
 async with self.db_pool.acquire() as conn:
 record = await conn.fetchrow(
 "SELECT expires_at FROM revoked_tokens WHERE jti = $1 AND expires_at > NOW()",
 jti
 )
 if record:
 self._revoked_cache[jti] = int(record['expires_at'].timestamp())
 return True
 
 return False
```

**Integration with Authentication:**
```python
# In authenticate_and_authorize()
if self.enable_token_revocation and "jwt_jti" in auth_ctx:
 if await self.token_revocation_list.is_revoked(auth_ctx["jwt_jti"]):
 raise ForbiddenError("Token has been revoked")
```

---

## Complete Request Flow

### **Production Evidence: S3 Event-Driven Pipeline**

**Bucket Configuration:**
- **Name:** `ca-a2a-documents-555043101106`
- **Versioning:** Enabled (tracks all versions of uploaded documents)
- **Encryption:** SSE-S3 (server-side encryption at rest)
- **Public Access:** Blocked (all four public access block settings enabled)
- **Event Notifications:** Configured to trigger Lambda on `s3:ObjectCreated:*` events

**Event-Driven Workflow:**
1. User/system uploads PDF to S3 bucket
2. S3 generates `ObjectCreated` event
3. Event notification triggers Lambda function (`ca-a2a-s3-processor`)
4. Lambda retrieves API key from Secrets Manager
5. Lambda calls Orchestrator with `process_document(s3_key=...)`
6. Processing pipeline executes (Extract → Validate → Archive)

**Security Features:**
- ✅ Bucket policy restricts access to specific IAM roles only
- ✅ No public read/write permissions
- ✅ Object lock (optional) for compliance requirements
- ✅ CloudTrail logging for all S3 API calls

---

### **Lambda Function: S3 Event Processor**

**Function Configuration:**
- **Name:** `ca-a2a-s3-processor`
- **Runtime:** Python 3.11
- **Trigger:** S3 event notification (`ObjectCreated`)
- **Timeout:** 30 seconds (sufficient for orchestrator API call)
- **Memory:** 256 MB
- **Environment Variables:**
  - `ORCHESTRATOR_URL` - Internal endpoint (via VPC if needed)
  - `API_KEY_SECRET` - Reference to Secrets Manager secret
  - `AWS_REGION` - eu-west-3

**Lambda Function Code (Keycloak Authentication):**
```python
import boto3
import json
import requests

secrets_client = boto3.client('secretsmanager')
keycloak_client = None

def get_keycloak_token():
    """Obtain access token from Keycloak for Lambda service account"""
    global keycloak_client
    
    # Retrieve Keycloak client credentials from Secrets Manager
    secret = secrets_client.get_secret_value(SecretId='ca-a2a/keycloak-lambda-client')
    credentials = json.loads(secret['SecretString'])
    
    # Authenticate with Keycloak (client credentials grant)
    response = requests.post(
        f"{credentials['keycloak_url']}/realms/ca-a2a/protocol/openid-connect/token",
        data={
            'grant_type': 'client_credentials',
            'client_id': credentials['client_id'],
            'client_secret': credentials['client_secret']
        }
    )
    
    return response.json()['access_token']

def lambda_handler(event, context):
    # Parse S3 event
    s3_key = event['Records'][0]['s3']['object']['key']
    bucket = event['Records'][0]['s3']['bucket']['name']
    
    # Obtain Keycloak access token
    access_token = get_keycloak_token()
    
    # Call Orchestrator with Keycloak JWT authentication
    response = requests.post(
        'http://orchestrator.ca-a2a.local:8001/message',
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}',
            'X-Correlation-ID': f"lambda-{context.request_id}"
        },
        json={
            'jsonrpc': '2.0',
            'method': 'process_document',
            'params': {'s3_key': s3_key, 'priority': 'normal'},
            'id': context.request_id
        }
    )
    
    return {'statusCode': 200, 'body': json.dumps(response.json())}
```

**Security Features:**
- ✅ Client credentials retrieved from Secrets Manager (not hardcoded)
- ✅ Short-lived access tokens (5 minutes, auto-refresh)
- ✅ Service account authentication (lambda role in Keycloak)
- ✅ IAM role with least-privilege permissions (S3 read, Secrets Manager read, CloudWatch write)
- ✅ VPC execution (optional) to reach private orchestrator endpoint
- ✅ Correlation ID for request tracing across services
- ✅ No long-lived API keys (improved security)

---

### **CloudWatch Logs: Real-Time Security Monitoring**

**Log Groups:**
- `/ecs/ca-a2a-orchestrator` - Workflow coordination logs
- `/ecs/ca-a2a-extractor` - PDF extraction logs
- `/ecs/ca-a2a-validator` - Validation logs
- `/ecs/ca-a2a-archivist` - Database archival logs
- `/aws/lambda/ca-a2a-s3-processor` - Lambda function logs

**Log Retention:** 30 days (configurable via CloudWatch settings)

**Sample Log Entry (Structured JSON):**
```json
{
  "timestamp": "2026-01-11T22:29:45.123Z",
  "level": "INFO",
  "agent": "orchestrator",
  "correlation_id": "pipe-abc123",
  "message": "Request received",
  "principal": "lambda",
  "method": "process_document",
  "request_id": "req-xyz789",
  "source_ip": "10.0.10.45"
}
```

**Security Audit Trail:**
Each log entry captures:
- ✅ **Authentication:** Which principal made the request (API key → principal mapping)
- ✅ **Authorization:** RBAC policy decision (allowed/denied)
- ✅ **Integrity:** HMAC signature verification result
- ✅ **Validation:** JSON schema validation outcome
- ✅ **Rate Limiting:** Request count and rate limit status
- ✅ **Replay Protection:** Timestamp age and nonce tracking
- ✅ **Performance:** Request duration and response size
- ✅ **Errors:** Any security violations with detailed reasons

---

### **API Key Authentication in Action**

This screenshot shows actual API key authentication in the production system:

**Log Sequence:**
1. **Request Received:** Log entry shows incoming request with `Authorization: Bearer` header
2. **Token Verification:** Keycloak JWT signature verified using JWKS public key
3. **Principal Extraction:** Username `lambda-service` mapped to principal `lambda` from realm roles
4. **RBAC Policy Check:** Principal `lambda` has wildcard access (`*`) to all methods
5. **Rate Limit Check:** Principal has 45/300 requests in current window (under limit)
6. **Request Forwarded:** After all checks pass, request forwarded to Extractor

**Key Observations:**
- ✅ JWT is logged as truncated claims (not full token for security)
- ✅ Correlation ID `pipe-abc123` links all related log entries
- ✅ Each security layer logs its decision (pass/fail)
- ✅ Timing information shows authentication overhead: ~2ms (JWKS cached)
- ✅ Dynamic role resolution from Keycloak (no static configuration)

---

### **HMAC Signature Verification in Action**

**Verification Process (logged):**
1. **Extract Signature:** Parse `X-Signature: 1736631585:a3f2...` header
2. **Timestamp Validation:** Check timestamp `1736631585` (age: 2.3 seconds < 300s threshold)
3. **Recompute Signature:**
   ```
   signing_string = "POST\n/message\n1736631585\n{...request_body...}"
   expected_signature = HMAC-SHA256(secret_key, signing_string)
   ```
4. **Constant-Time Comparison:** `hmac.compare_digest(provided, expected)` → `True`
5. **Result:** Signature valid, request integrity verified

**Attack Prevention:**
- ❌ Modified request body → Signature mismatch → 401 Tampered Request
- ❌ Replayed old request → Timestamp too old → 401 Replay Detected
- ❌ Missing signature → No signature header → 401 Signature Required

---

### **JSON Schema Validation in Action**

**Validation Process:**
1. **Extract Parameters:** `params = {"s3_key": "../../etc/passwd", "priority": "normal"}`
2. **Schema Lookup:** Load schema for method `process_document`
3. **Regex Pattern Check:**
   ```python
   pattern = r"^[a-zA-Z0-9_\-./]+$"  # Allowed characters
   if not re.match(pattern, s3_key):
       raise ValidationError("s3_key contains invalid characters")
   ```
4. **Path Traversal Detection:** `"../"` not in allowed pattern
5. **Rejection:** 400 Bad Request with error message

**Blocked Attacks (from production logs):**
- ❌ `s3_key: "../../../etc/passwd"` → Path traversal attempt
- ❌ `s3_key: "file.pdf; rm -rf /"` → Command injection attempt
- ❌ `priority: "URGENT"` → Invalid enum value (must be "high", "normal", or "low")
- ❌ Missing required field `s3_key` → Schema validation failure

**Protection Effectiveness:**
- 100% of malicious input attempts blocked at validation layer
- No malicious requests reached business logic or database
- Average validation time: 1.2ms per request

---

### **End-to-End Request Timeline**

<img width="1313" height="415" alt="Capture d’écran 2026-01-11 223238" src="https://github.com/user-attachments/assets/199bb585-39e0-4c2e-ab1f-8434976afeb4" />

**Figure 12: Complete Document Processing Flow with Timestamps**

**Measured Latency Breakdown:**
- **T+0ms:** S3 ObjectCreated event generated
- **T+100ms:** Lambda triggered and starts execution
- **T+200ms:** Lambda calls Orchestrator with API key
- **T+205ms:** Orchestrator completes 8-layer security validation
- **T+250ms:** Orchestrator calls Extractor
- **T+1,450ms:** Extractor completes PDF text extraction (PyPDF2)
- **T+1,500ms:** Orchestrator calls Validator
- **T+1,510ms:** Validator completes schema and business rule validation
- **T+1,550ms:** Orchestrator calls Archivist
- **T+1,650ms:** Archivist writes to PostgreSQL database
- **T+1,700ms:** Archivist returns success with document_id
- **T+1,750ms:** Orchestrator returns final result to Lambda
- **T+1,850ms:** Lambda completes execution

**Total End-to-End Time:** ~1.85 seconds (from S3 upload to database archival)

**Performance Analysis:**
- Security overhead: 5ms (8 layers) = 0.27% of total time
- Network latency (A2A calls): ~150ms (3 calls × 50ms)
- PDF extraction: 1,200ms (65% of total time - I/O bound)
- Database write: 100ms (5% of total time)
- Lambda cold start: ~100ms (amortized across requests)

---

### **End-to-End Request Processing**

```mermaid
sequenceDiagram
 participant Client as Client Agent
 participant Network as Network Layer<br/>(AWS VPC)
 participant Server as Server Agent
 participant Security as Security Manager
 participant Handler as Method Handler
 participant DB as Database
 participant Logs as CloudWatch Logs
 
 Note over Client: Prepare Request
 Client->>Client: 1. Create JSON-RPC message
 Client->>Client: 2. Sign with HMAC
 Client->>Client: 3. Add correlation ID
 
 Client->>Network: POST /message<br/>X-API-Key, X-Signature, X-Correlation-ID
 
 Note over Network: Layer 1: Network Security
 Network->>Network: Check source IP vs Security Group
 alt IP Not Allowed
 Network-->>Client: TCP RST (Connection Refused)
 end
 
 Network->>Server: Forward Request
 
 Note over Server: Layer 2: TLS (if enabled)
 Server->>Server: TLS handshake validation
 
 Note over Server: Layer 3: HMAC Integrity
 Server->>Security: Verify HMAC signature
 Security->>Security: Check timestamp freshness
 Security->>Security: Recompute signature
 alt Signature Invalid
 Security-->>Client: 401 Tampered Request
 end
 
 Note over Server: Layer 4: Authentication
 Security->>Security: Extract API key / JWT
 Security->>Security: Lookup principal
 alt Auth Failed
 Security-->>Client: 401 Unauthorized
 end
 
 Note over Server: Layer 5: Authorization
 Security->>Security: Check RBAC policy
 alt Not Authorized
 Security-->>Client: 403 Forbidden
 end
 
 Note over Server: Layer 6: Input Validation
 Security->>Security: Validate params against schema
 alt Invalid Params
 Security-->>Client: 400 Invalid Params
 end
 
 Note over Server: Layer 7: Rate Limiting
 Security->>Security: Check token bucket
 alt Rate Exceeded
 Security-->>Client: 429 Rate Limit Exceeded
 end
 
 Note over Server: Layer 8: Replay Protection
 Security->>Security: Check nonce/timestamp
 alt Replay Detected
 Security-->>Client: 401 Replay Attack
 end
 
 Note over Server: All Security Checks Passed
 Security-->>Server: Authorized (principal, context)
 
 Server->>Handler: Execute method(params)
 Handler->>DB: Query/Update data
 DB-->>Handler: Result
 Handler-->>Server: Return result
 
 Note over Server: Layer 9: Audit Logging
 Server->>Logs: Log request + response
 
 Server-->>Client: 200 OK + Result<br/>X-Correlation-ID, X-RateLimit-*
```

**Total Request Processing Time:**
- Network: ~1ms
- TLS: ~2-5ms (handshake, first request only)
- HMAC: ~0.3ms
- Authentication: ~0.1ms
- Authorization: ~0.1ms
- Schema Validation: ~1.5ms
- Rate Limiting: ~0.1ms
- Method Execution: Variable (180ms for PDF extraction)
- **Total Overhead:** ~4-7ms (~1% of pipeline)

---

## ️ Attack Scenarios & Defenses

### **Attack Matrix**

| Attack Type | Attack Vector | Defense Layer | Mitigation |
|-------------|---------------|---------------|------------|
| **DDoS** | Flood with requests | Rate Limiting | Token bucket (300 req/min) |
| **Man-in-the-Middle** | Intercept traffic | TLS + JWT signature | Encrypted transport + RS256 |
| **Replay Attack** | Reuse captured request | Token expiration | 5-minute token lifespan |
| **Message Tampering** | Modify request body | JWT integrity | RS256 signature verification |
| **SQL Injection** | `'; DROP TABLE--` | JSON Schema | Pattern validation |
| **Path Traversal** | `../../etc/passwd` | JSON Schema | Negative lookahead regex |
| **Buffer Overflow** | 10MB string | JSON Schema | maxLength: 1024 |
| **XSS** | `<script>alert()</script>` | JSON Schema | Pattern validation |
| **Privilege Escalation** | Call unauthorized method | Dynamic RBAC | Keycloak role-based enforcement |
| **Token Theft** | Stolen JWT used | Token expiration | Short-lived tokens (5 min) |
| **Timing Attack** | Measure comparison time | Constant-time JWT verify | PyJWT library constant-time ops |
| **Brute Force** | Guess credentials | Keycloak + Rate Limiting | Account lockout + rate limits |

### **Attack Scenario 1: SQL Injection Attempt**

**Attack:**
```python
# Attacker tries SQL injection
malicious_request = {
 "jsonrpc": "2.0",
 "method": "archive_document",
 "params": {
 "document_id": "123'; DROP TABLE documents;--"
 },
 "id": "attack-1"
}
```

**Defense (Layer 6):**
```python
# JSON Schema for document_id
{
 "document_id": {
 "type": "string",
 "pattern": "^[a-zA-Z0-9-]+$", # Only alphanumeric and hyphens
 "maxLength": 64
 }
}

# Validation rejects malicious input
validate(params) # Pattern mismatch
# Error: "document_id does not match pattern"
```

### **Attack Scenario 2: Path Traversal**
<img width="1149" height="231" alt="image" src="https://github.com/user-attachments/assets/64f9fb54-6927-465c-a9c8-4014dd3d82c9" />

**Attack:**
```python
# Attacker tries to access sensitive files
malicious_request = {
 "jsonrpc": "2.0",
 "method": "process_document",
 "params": {
 "s3_key": "../../../../../../../etc/passwd"
 },
 "id": "attack-2"
}
```

**Defense (Layer 6):**
```python
# JSON Schema with negative lookahead
{
 "s3_key": {
 "pattern": "^(?!.*\\.\\./)[a-zA-Z0-9/._-]+$"
 # ^^^^^^^^^^^ Rejects any string containing "../"
 }
}

# Validation blocks path traversal
validate(params) # Pattern mismatch
# Error: "s3_key contains path traversal"
```

### **Attack Scenario 3: Token Theft and Replay**

**Attack:**
```python
# Attacker intercepts valid Keycloak JWT at 10:00 AM
stolen_token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJxdW5..."

# Attacker tries to use stolen token immediately
attack_request = {
    "headers": {"Authorization": f"Bearer {stolen_token}"},
    "body": '{"method":"archive_document","params":{"document_id":"sensitive-123"}}'
}

# Attacker tries to replay at 10:10 AM (10 minutes later)
replay_attack(attack_request)
```

**Defense (Layer 4):**
```python
# Token contains expiration claim
claims = decode_jwt(stolen_token)
exp = claims["exp"] # 1735867500 (10:05 AM)
iat = claims["iat"] # 1735867200 (10:00 AM)

# At 10:03 AM (3 minutes later)
current_time = 1735867380
if current_time < exp:
    # Token still valid (attacker can use for remaining 2 minutes)
    # Mitigation: Short token lifespan (5 min) limits exposure window
    pass

# At 10:10 AM (10 minutes later)
current_time = 1735867800
if current_time >= exp: # True
    return "401 Token expired"
    # Token automatically invalid after 5 minutes
```

**Additional Protections:**
1. **Refresh Token Rotation:** Each refresh issues new refresh token
2. **Token Binding (optional):** Bind token to client IP or device fingerprint
3. **Audit Logging:** All token usage logged to CloudWatch
4. **Keycloak Session Revocation:** Admin can revoke all user sessions

---

## Code Implementation Details

### **Base Agent HTTP Handler**
<img width="1274" height="627" alt="Capture d’écran 2026-01-11 223303" src="https://github.com/user-attachments/assets/f4445bc9-9590-47ef-b2bc-f129e789af1b" />

**Full Request Processing** (`base_agent.py:111-207`):
```python
async def handle_http_message(self, request: web.Request) -> web.Response:
 """
 Handle incoming A2A messages via HTTP
 
 Implements complete security stack
 """
 start_time = time.time()
 correlation_id = request.headers.get('X-Correlation-ID', generate_correlation_id())
 
 try:
 # Parse request body
 raw = await request.read()
 data = json.loads(raw.decode("utf-8"))
 message = A2AMessage(**data)
 
 # ═══════════════════════════════════════════════════════════
 # SECURITY STACK: Layers 3-8
 # ═══════════════════════════════════════════════════════════
 principal = "unknown"
 auth_ctx: Dict[str, Any] = {}
 
 try:
 # Authenticate + Authorize + Validate
 principal, auth_ctx = await self.security.authenticate_and_authorize(
 headers={k: v for k, v in request.headers.items()},
 message_method=message.method,
 message_dict=data,
 request_body=raw, # For HMAC verification
 client_cert_pem=request.transport.get_extra_info('peercert') # For mTLS
 )
 
 except AuthError as e:
 self.logger.warning(f"Unauthorized request: {str(e)}")
 error_response = A2AMessage.create_error(message.id, -32010, "Unauthorized")
 error_dict = error_response.to_dict()
 error_dict.setdefault("_meta", {})["correlation_id"] = correlation_id
 return web.json_response(error_dict, status=401)
 
 except ForbiddenError as e:
 self.logger.warning(f"Forbidden request: {str(e)}")
 error_response = A2AMessage.create_error(message.id, -32011, "Forbidden")
 error_dict = error_response.to_dict()
 meta = error_dict.setdefault("_meta", {})
 meta["correlation_id"] = correlation_id
 if auth_ctx.get("rate_limit"):
 meta["rate_limit"] = auth_ctx["rate_limit"]
 return web.json_response(error_dict, status=403)
 
 # ═══════════════════════════════════════════════════════════
 # METHOD EXECUTION
 # ═══════════════════════════════════════════════════════════
 self.structured_logger.log_request(
 method=message.method,
 params=message.params,
 principal=principal,
 correlation_id=correlation_id
 )
 
 # Call skill handler
 result = await self._dispatch_method(message.method, message.params)
 
 # Build response
 response_message = A2AMessage.create_response(message.id, result)
 response_dict = response_message.to_dict()
 
 # Add metadata
 processing_time = (time.time() - start_time) * 1000
 response_dict["_meta"] = {
 "correlation_id": correlation_id,
 "processing_time_ms": round(processing_time, 2),
 "agent_id": self.name,
 "timestamp": int(time.time())
 }
 
 # Add rate limit info
 if auth_ctx.get("rate_limit"):
 response_dict["_meta"]["rate_limit"] = auth_ctx["rate_limit"]
 
 # ═══════════════════════════════════════════════════════════
 # AUDIT LOGGING (Layer 9)
 # ═══════════════════════════════════════════════════════════
 self.structured_logger.log_response(
 method=message.method,
 result=result,
 principal=principal,
 correlation_id=correlation_id,
 processing_time_ms=processing_time
 )
 
 return web.json_response(response_dict)
 
 except Exception as e:
 self.logger.error(f"Error handling message: {str(e)}", exc_info=True)
 error_response = A2AMessage.create_error(
 message.id if 'message' in locals() else None,
 -32603,
 f"Internal error: {str(e)}"
 )
 error_dict = error_response.to_dict()
 error_dict.setdefault("_meta", {})["correlation_id"] = correlation_id
 return web.json_response(error_dict, status=500)
```

---

## Summary

### **Key Takeaways**

1. **Protocol Choice:** JSON-RPC 2.0 over HTTP provides the best balance of simplicity and functionality for A2A communication

2. **Security Layers:** 8 layers of defense-in-depth protect against a wide range of attacks

3. **Performance:** Total security overhead is ~4-7ms (~1% of pipeline), acceptable for production

4. **Standards Compliance:** Implements security principles from peer-reviewed research paper

5. **Operational Excellence:** CloudWatch logging, correlation IDs, and structured logs enable observability

### **Security Metrics**

| Metric | Value |
|--------|-------|
| **Security Layers** | 8 (network → audit) |
| **Authentication Methods** | 1 (Keycloak JWT RS256 only) |
| **Authorization Model** | Dynamic RBAC (Keycloak roles) |
| **Message Integrity** | HMAC-SHA256 (optional) |
| **Input Validation** | JSON Schema v7 |
| **Rate Limiting** | Token bucket (300 req/min) |
| **Replay Window** | 2 minutes |
| **Token Algorithm** | RS256 (asymmetric) |
| **Token Lifespan** | 5 minutes (access) + 30 days (refresh) |
| **Total Overhead** | ~2-5ms (~0.3%) |
| **Test Coverage** | 56+ tests (100% pass rate) |
| **Compliance Score** | 10/10 (enterprise OAuth2/OIDC standards) |

---

**Document Version:** 3.0  
**Last Updated:** January 14, 2026  
**Authors:** Security Team  
**Status:** Production Ready - Keycloak OAuth2/OIDC Only

**Breaking Changes in v3.0:**
- ❌ Removed API Key authentication
- ❌ Removed Legacy JWT (HS256) authentication
- ✅ Keycloak JWT (RS256) is now the only authentication method
- See [`MIGRATION_GUIDE_KEYCLOAK_ONLY.md`](./MIGRATION_GUIDE_KEYCLOAK_ONLY.md) for upgrade instructions

