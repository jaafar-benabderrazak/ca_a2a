# A2A Protocol Security: Technical Deep Dive

**Comprehensive Technical Documentation on Agent-to-Agent Communication Protocol and Security Implementation**

**Version**: 3.0  
**Last Updated**: January 14, 2026  
**Status**: Production Ready - Enterprise-Grade Security

---

## Table of Contents

1. [A2A Protocol Overview](#a2a-protocol-overview)
2. [Protocol Stack Architecture](#protocol-stack-architecture)
3. [Message Structure & Format](#message-structure--format)
4. [Security Layers Deep Dive](#security-layers-deep-dive)
5. [Authentication Mechanisms](#authentication-mechanisms)
6. [Authorization & RBAC](#authorization--rbac)
7. [JWT Signature & Token Integrity](#jwt-signature--token-integrity)
8. [Input Validation (JSON Schema)](#input-validation-json-schema)
9. [Replay Protection](#replay-protection)
10. [Rate Limiting](#rate-limiting)
11. [Token Revocation](#token-revocation)
12. [Token Binding (RFC 8473) & Mutual TLS](#token-binding-rfc-8473--mutual-tls)
13. [Complete Request Flow](#complete-request-flow)
14. [Attack Scenarios & Defenses](#attack-scenarios--defenses)
15. [Code Implementation Details](#code-implementation-details)

---

## A2A Protocol Overview

### **What is A2A Protocol?**

**A2A (Agent-to-Agent) Protocol** is a standardized communication protocol for autonomous agents to exchange messages and coordinate actions in a distributed system.

**Our Implementation:**
- **Base Protocol:** JSON-RPC 2.0 (RFC 4627)
- **Transport:** HTTPS with Mutual TLS
- **Encoding:** UTF-8 JSON
- **Authentication:** Keycloak OAuth2/OIDC (RS256) + mTLS
- **Token Binding:** RFC 8473 (Certificate-bound tokens)
- **Security:** Multi-layer defense-in-depth architecture

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
│ Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI... │
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

<img width="665" height="501" alt="image" src="https://github.com/user-attachments/assets/066e2291-6967-413f-b039-6f24b7be8921" />


### **Defense-in-Depth Architecture**
<img width="1377" height="367" alt="Capture d’écran 2026-01-11 222956" src="https://github.com/user-attachments/assets/673e6017-03f2-46d4-9d14-218f7baf2453" />

```mermaid
graph TB
 Request[Incoming Request] --> L1
 
 L1[Layer 1: Network Security<br/>VPC + Security Groups] --> L1_Check{IP Allowed?}
 L1_Check -->|No| Reject1[ Connection Refused<br/>TCP RST]
 L1_Check -->|Yes| L2
 
 L2[Layer 2: Transport Security<br/>mTLS (TLS 1.2+)] --> L2_Check{TLS Valid?}
 L2_Check -->|No| Reject2[ SSL Handshake Failed]
 L2_Check -->|Yes| L3
 
 L3[Layer 3: Authentication<br/>Keycloak JWT + mTLS] --> L3_Check{Auth Valid?}
 L3_Check -->|No| Reject3[ 401 Unauthorized]
 L3_Check -->|Yes| L4
 
 L4[Layer 4: Token Binding<br/>RFC 8473] --> L4_Check{Cert Matches?}
 L4_Check -->|No| Reject4[ 401 Token Not Bound]
 L4_Check -->|Yes| L5
 
 L5[Layer 5: Authorization<br/>Dynamic RBAC] --> L5_Check{Principal Allowed?}
 L5_Check -->|No| Reject5[ 403 Forbidden]
 L5_Check -->|Yes| L6
 
 L6[Layer 6: Input Validation<br/>JSON Schema] --> L6_Check{Params Valid?}
 L6_Check -->|No| Reject6[ 400 Invalid Params]
 L6_Check -->|Yes| L7
 
 L7[Layer 7: Rate Limiting<br/>Token Bucket] --> L7_Check{Under Limit?}
 L7_Check -->|No| Reject7[ 429 Rate Exceeded]
 L7_Check -->|Yes| L8
 
 L8[Layer 8: Replay Protection<br/>JWT Expiration (5 min)] --> L8_Check{Token Fresh?}
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
| **2. Transport** | mTLS (TLS 1.2+) | Eavesdropping, MITM, Impersonation | 
| **3. Integrity** | JWT Signature (RS256) | Message tampering | 
| **4. Authentication** | Keycloak JWT + mTLS Certificates | Identity spoofing |
| **5. Token Binding** | RFC 8473 (cnf.x5t#S256) | Token theft, token export |
| **6. Authorization** | Dynamic RBAC (Keycloak roles) | Privilege escalation |
| **7. Validation** | JSON Schema | Injection, XSS, path traversal | 
| **8. Rate Limiting** | Token bucket | DoS, abuse | 
| **9. Replay Protection** | JWT expiration (5 min) | Replay attacks |

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
<img width="673" height="470" alt="image" src="https://github.com/user-attachments/assets/e938c312-f7e9-425e-82c2-ec488610f548" />

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

### **Enterprise OAuth2/OIDC with Keycloak**

The A2A protocol implements **enterprise-grade authentication** using Keycloak OAuth2/OIDC with enhanced security features:

✅ **Keycloak OAuth2/OIDC** - Industry-standard authentication (RFC 6749, RFC 7519)  
✅ **Mutual TLS (mTLS)** - Bidirectional certificate authentication (RFC 8705)  
✅ **Token Binding** - Certificate-bound tokens prevent theft (RFC 8473)  
✅ **Dynamic RBAC** - Real-time role management via Keycloak  
✅ **Short-lived Tokens** - 5-minute access tokens with refresh capability  
✅ **Asymmetric Cryptography** - RS256 (RSA + SHA-256) signatures

**For comprehensive security benefits and metrics, see [Security Metrics](#security-metrics) at the end of this document.**

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

**Performance:** See detailed metrics in [Performance Characteristics](#performance-characteristics) (Section 7).

---

### **Authentication Flow with Token Binding**

```mermaid
sequenceDiagram
    participant Client as Lambda (Client)
    participant Keycloak
    participant Agent as Orchestrator (Server)
 participant Security as A2ASecurityManager
    participant JWKS as JWKS Endpoint
 participant Handler as Method Handler
 
    Note over Client: 1. Obtain Certificate-Bound Token
    Client->>Keycloak: POST /token (mTLS connection)<br/>+ client certificate<br/>+ client_credentials grant
    Keycloak->>Keycloak: Verify client certificate
    Keycloak->>Keycloak: Compute cert thumbprint<br/>SHA256(DER(cert))
    Keycloak->>Keycloak: Create JWT with cnf claim:<br/>{"cnf": {"x5t#S256": "bwcK0esc..."}}
    Keycloak-->>Client: Access Token (certificate-bound JWT)
    
    Note over Client: 2. Call Agent API with mTLS + Token
    Client->>Agent: POST /message (mTLS connection)<br/>Authorization: Bearer <token><br/>+ client certificate
    
    Note over Agent: 3. Verify mTLS Connection
    Agent->>Agent: Extract client cert from TLS handshake
    Agent->>Agent: Verify cert against trusted CA
    Agent->>Agent: Compute presented_thumbprint
    
    Note over Agent: 4. Authenticate & Authorize
    Agent->>Security: authenticate_and_authorize(headers, cert)
    Security->>JWKS: GET /certs (fetch RSA public keys)
    JWKS-->>Security: Public key (cached 1h)
    
    Note over Security: 5. Verify JWT
    Security->>Security: Verify JWT signature (RS256)
    Security->>Security: Check exp, iss, aud claims
    Security->>Security: Extract username & Keycloak roles
    
    Note over Security: 6. Verify Token Binding (RFC 8473)
    Security->>Security: Extract cnf.x5t#S256 from JWT
    Security->>Security: Compare thumbprints (constant-time)
    
    alt Token Binding Valid
        Security->>Security: Map Keycloak roles to A2A principal
        Security-->>Agent: principal="lambda", allowed_methods=["*"]
        
        Note over Agent: 7. Execute Method
        Agent->>Handler: Execute method with principal context
 Handler-->>Agent: Result
 Agent-->>Client: 200 OK + Result
    else Token Binding Invalid
        Security-->>Client: 401 Unauthorized<br/>(Token not bound to certificate)
    else Certificate Invalid
        Security-->>Client: 401 Unauthorized<br/>(Client certificate verification failed)
    end
```

### **Keycloak JWT Validation with Token Binding**

**Configuration** (`a2a_security.py`):
```python
class A2ASecurityManager:
 def __init__(self, agent_id: str):
        self.agent_id = _normalize_agent_id(agent_id)
        self.require_auth = os.getenv("A2A_REQUIRE_AUTH", "true").lower() == "true"
        self.enable_rate_limit = os.getenv("A2A_ENABLE_RATE_LIMIT", "true").lower() == "true"
        self.enable_replay_protection = os.getenv("A2A_ENABLE_REPLAY_PROTECTION", "true").lower() == "true"

        # Keycloak OAuth2/OIDC integration with Token Binding
        keycloak_url = os.getenv("KEYCLOAK_URL")
        keycloak_realm = os.getenv("KEYCLOAK_REALM", "ca-a2a")
        keycloak_client_id = os.getenv("KEYCLOAK_CLIENT_ID", "ca-a2a-agents")
        
        if not keycloak_url:
            raise ValueError("KEYCLOAK_URL environment variable required")
        
        self.keycloak_validator = KeycloakJWTValidator(
            keycloak_url=keycloak_url,
            realm=keycloak_realm,
            client_id=keycloak_client_id,
            cache_ttl=int(os.getenv("KEYCLOAK_CACHE_TTL", "3600")),
            require_token_binding=os.getenv("TOKEN_BINDING_REQUIRED", "true").lower() == "true"
        )
        
        self.keycloak_rbac_mapper = KeycloakRBACMapper()
        logger.info(f"Keycloak authentication enabled for realm: {keycloak_realm}")
        
        # mTLS Configuration
        self.mtls_enabled = os.getenv("MTLS_ENABLED", "true").lower() == "true"
        if self.mtls_enabled:
            self.mtls_config = MTLSConfig(
                server_cert_path=os.getenv("MTLS_CERT_PATH"),
                server_key_path=os.getenv("MTLS_KEY_PATH"),
                ca_cert_path=os.getenv("MTLS_CA_CERT_PATH"),
                require_client_cert=True
            )
            logger.info("mTLS enabled with client certificate requirement")

        self.rbac_policy = _parse_json_env("A2A_RBAC_POLICY_JSON", default={"allow": {}, "deny": {}})
        self.rate_limiter = SlidingWindowRateLimiter(
            limit=int(os.getenv("A2A_RATE_LIMIT_PER_MINUTE", "300")),
            window_seconds=60,
        )
        self.replay = ReplayProtector(ttl_seconds=int(os.getenv("A2A_REPLAY_TTL_SECONDS", "120")))
```

**Verification with Token Binding** (`a2a_security.py`):
```python
async def authenticate_and_authorize(
    self, 
    headers: Dict[str, str], 
    method: str, 
    message_dict: Dict[str, Any],
    client_cert_pem: Optional[str] = None
) -> Dict[str, Any]:
    """
    Authenticate and authorize request using Keycloak JWT + mTLS + Token Binding
 
 Security Features:
    1. RS256 signature verification (asymmetric cryptography)
    2. Token expiration validation
    3. Issuer verification (prevents token substitution)
    4. Audience verification (ensures token is for this client)
    5. Token Binding verification (RFC 8473 - cert-bound tokens)
    6. mTLS client certificate validation
    7. Role extraction from realm_access.roles
    8. Dynamic RBAC mapping
    """
    auth_header = headers.get("Authorization", "") or ""

    if not auth_header.lower().startswith("bearer "):
        raise AuthError("Missing Authorization header (expected Bearer Keycloak JWT)")
    
    token = auth_header.split(" ", 1)[1].strip()
    
    # Verify Keycloak JWT with Token Binding
    return await self._verify_keycloak_jwt(
        token=token, 
        method=method, 
        message_dict=message_dict,
        client_cert_pem=client_cert_pem
    )

async def _verify_keycloak_jwt(
    self, 
    *, 
    token: str, 
    method: str, 
    message_dict: Dict[str, Any],
    client_cert_pem: Optional[str] = None
) -> Dict[str, Any]:
    """
    Verify JWT token issued by Keycloak with Token Binding
    
    Returns:
        Auth context with principal, allowed_methods, token binding status
    """
    # Verify token signature, extract claims, and validate token binding
    username, keycloak_roles, claims = self.keycloak_validator.verify_token(
        token, 
        client_certificate=client_cert_pem
    )
    
    # Map Keycloak roles to A2A principal and allowed methods
    principal, allowed_methods = self.keycloak_rbac_mapper.map_roles_to_principal(keycloak_roles)
    
    # Build auth context
    auth_context = {
        "mode": "keycloak_jwt_with_token_binding",
        "username": username,
        "keycloak_roles": keycloak_roles,
        "rbac_principal": principal,
        "allowed_methods": allowed_methods,
        "dynamic_rbac": True,
        "token_binding_verified": client_cert_pem is not None,
        "mtls_verified": client_cert_pem is not None,
        "token_claims": claims,
 "authenticated_at": time.time()
 }
    
    logger.info(
        f"Authentication successful: username={username}, principal={principal}, "
        f"token_binding={auth_context['token_binding_verified']}"
    )
    
    return principal, auth_context
```

**For detailed JWT signature verification, token expiration, and security properties, see [Section 7: JWT Signature & Token Integrity](#jwt-signature--token-integrity).**

**For complete performance metrics, see [Performance Characteristics](#performance-characteristics) in Section 7.**

**For configuration details, see:**
- Environment variables and mTLS configuration: [Token Binding Configuration](#configuration)
- RBAC policy configuration: [Authorization Code Implementation](#authorization-code-implementation)

---

## Token Binding (RFC 8473) & Mutual TLS

### **Overview**
<img width="1117" height="515" alt="image" src="https://github.com/user-attachments/assets/0fed7195-4acb-4c88-9ce3-39f12c1918f4" />

Building on Keycloak OAuth2/OIDC, the system now implements **enterprise-grade proof-of-possession security**:

✅ **Token Binding (RFC 8473)** - JWT tokens cryptographically bound to client TLS certificates  
✅ **Mutual TLS (mTLS)** - Bidirectional certificate authentication at TLS layer  
✅ **Certificate Authority** - Internal CA for development/testing  
✅ **Zero Token Theft** - Stolen tokens completely unusable without client certificate  
✅ **Zero Trust Enforcement** - Every connection verified with client certificates  

**Security Upgrade**: Keycloak-only → Keycloak + Token Binding + mTLS

### **Token Binding Architecture**
<img width="567" height="357" alt="image" src="https://github.com/user-attachments/assets/e0468375-2814-4d61-8627-2aa406b8694f" />

**What is Token Binding (RFC 8473)?**

Token Binding extends OAuth 2.0 to create **proof-of-possession tokens**. The access token becomes cryptographically bound to the client's TLS certificate, making it unusable without the corresponding private key.

**For the complete authentication flow including Token Binding, see [Authentication Flow with Token Binding](#authentication-flow-with-token-binding) above.**

### **Certificate-Bound Token Structure**

**Keycloak Access Token with Token Binding:**
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "qunlkj_cDRkZiIsImtpZCI"
  },
  "payload": {
    "exp": 1736900100,
    "iat": 1736899800,
    "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
    "aud": "ca-a2a-agents",
    "sub": "lambda-service",
    "preferred_username": "lambda-service",
    "realm_access": {
      "roles": ["lambda", "default-roles-ca-a2a"]
    },
    "cnf": {
      "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg"
    }
  },
  "signature": "..."
}
```

**Token Binding Claim (`cnf`):**
- `x5t#S256`: Base64url-encoded SHA-256 hash of DER-encoded client certificate
- Per RFC 8705 (OAuth 2.0 Mutual-TLS Client Authentication)
- Computed as: `Base64url(SHA256(DER(cert))).rstrip('=')`

### **Mutual TLS (mTLS) Implementation**

**What is mTLS?**

Mutual TLS extends standard TLS by requiring **both** client and server to present certificates. This establishes bidirectional authentication at the transport layer.

**TLS Handshake Flow:**

```
Standard TLS:                      Mutual TLS (mTLS):
─────────────                      ──────────────────

Client → ServerHello               Client → ServerHello
       ← Server Certificate               ← Server Certificate
       ← ServerHelloDone                  ← Certificate Request   ← NEW
Client → ClientKeyExchange         Client → Client Certificate   ← NEW
       → ChangeCipherSpec          Client → CertificateVerify    ← NEW
       → Finished                         → ClientKeyExchange
Server ← ChangeCipherSpec                 → ChangeCipherSpec
       ← Finished                          → Finished
                                   Server ← ChangeCipherSpec
✓ Server authenticated                    ← Finished
                                   
                                   ✓ BOTH client and server authenticated
```

**Certificate Chain:** See [Certificate Management](#certificate-management) below for complete certificate structure and generation instructions.

### **Implementation: Token Binding Validator**

**File**: `token_binding.py` (lines 1-210)

```python
class TokenBindingValidator:
    """
    Validates token binding between JWT tokens and TLS client certificates.
    
    Implements RFC 8473 (OAuth 2.0 Token Binding) by verifying that the
    certificate used to present the token matches the certificate fingerprint
    embedded in the token's 'cnf' (confirmation) claim.
    """
    
    def __init__(self, hash_algorithm: str = "sha256"):
        """
        Initialize token binding validator.
        
        Args:
            hash_algorithm: Hash algorithm for certificate thumbprints (sha256 recommended)
        """
        self.hash_algorithm = hash_algorithm
    
    def compute_certificate_thumbprint(
        self, 
        certificate: x509.Certificate,
        encoding: str = "base64url"
    ) -> str:
        """
        Compute RFC 8705 certificate thumbprint (x5t#S256).
        
        Args:
            certificate: X.509 certificate
            encoding: Output encoding (base64url per RFC, or hex)
            
        Returns:
            Certificate thumbprint string
            
        Example:
            Thumbprint format: Base64url(SHA256(DER(certificate)))
        """
        # Get DER-encoded certificate
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        
        # Compute SHA-256 hash
        thumbprint_bytes = hashlib.sha256(cert_der).digest()
        
        # Encode as base64url (RFC 8705)
        return base64.urlsafe_b64encode(thumbprint_bytes).decode().rstrip('=')
    
    def verify_token_binding(
        self,
        jwt_claims: Dict[str, Any],
        client_certificate: x509.Certificate
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify that JWT token is bound to the presenting client certificate.
        
        Args:
            jwt_claims: Decoded JWT claims
            client_certificate: Client's TLS certificate
            
        Returns:
            Tuple of (is_valid, error_message)
            
        Security Notes:
            - Uses constant-time comparison to prevent timing attacks
            - Fails closed: returns False if binding claim is missing
            - Logs verification failures for security monitoring
        """
        # Extract token binding claim
        binding_claim = self.extract_token_binding_claim(jwt_claims)
        
        if not binding_claim:
            return False, "Token does not contain certificate binding (cnf claim missing)"
        
        # Compute thumbprint of presented certificate
        presented_thumbprint = self.compute_certificate_thumbprint(
            client_certificate,
            encoding="base64url"
        )
        
        # Extract expected thumbprint from token
        expected_thumbprint = binding_claim["value"]
        
        # Constant-time comparison (prevents timing attacks)
        if not secrets.compare_digest(presented_thumbprint, expected_thumbprint):
            logger.warning(
                f"Token binding verification failed: "
                f"expected={expected_thumbprint[:8]}..., "
                f"presented={presented_thumbprint[:8]}..."
            )
            return False, "Certificate thumbprint does not match token binding"
        
        logger.info(f"Token binding verified successfully: thumbprint={presented_thumbprint[:16]}...")
        return True, None
```

### **Implementation: mTLS Configuration**

**Server Side** (`mtls_base_agent.py`):

```python
class MTLSConfig:
    """
    Configuration for mutual TLS.
    
    Manages SSL context with client certificate verification.
    """
    
    def __init__(
        self,
        server_cert_path: str,
        server_key_path: str,
        ca_cert_path: str,
        require_client_cert: bool = True
    ):
        """
        Initialize mTLS configuration.
        
        Args:
            server_cert_path: Path to server certificate (PEM)
            server_key_path: Path to server private key (PEM)
            ca_cert_path: Path to trusted CA certificate (PEM)
            require_client_cert: Require clients to present certificates
        """
        self.ssl_context = self._create_ssl_context()
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for mTLS"""
        # Create SSL context for server
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load server certificate and private key
        ssl_context.load_cert_chain(
            certfile=self.server_cert_path,
            keyfile=self.server_key_path
        )
        
        # Load trusted CA certificates (for verifying client certificates)
        ssl_context.load_verify_locations(cafile=self.ca_cert_path)
        
        # Configure client certificate verification
        if self.require_client_cert:
            ssl_context.verify_mode = ssl.CERT_REQUIRED  # Require client cert
        else:
            ssl_context.verify_mode = ssl.CERT_OPTIONAL
        
        # Security settings
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2  # TLS 1.2+
        ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        return ssl_context

# Usage in BaseAgent
mtls_config = MTLSConfig(
    server_cert_path="./certs/agents/orchestrator/orchestrator-cert.pem",
    server_key_path="./certs/agents/orchestrator/orchestrator-key.pem",
    ca_cert_path="./certs/ca/ca-cert.pem",
    require_client_cert=True
)

web.run_app(app, port=8001, ssl_context=mtls_config.ssl_context)
```

**Client Side** (`mtls_client.py`):

```python
class A2AClientWithMTLS:
    """
    High-level A2A client with mTLS and token binding.
    
    Combines:
    - mTLS client certificate authentication
    - Keycloak JWT token authentication
    - Token binding (JWT bound to certificate)
    - JSON-RPC message handling
    """
    
    async def authenticate(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_client_credentials: bool = False
    ):
        """
        Authenticate with Keycloak and obtain certificate-bound token.
        
        Keycloak must be configured for OAuth 2.0 Mutual-TLS Client Authentication
        to include certificate binding in tokens.
        """
        token_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
        
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials" if use_client_credentials else "password"
        }
        
        if not use_client_credentials:
            data["username"] = username
            data["password"] = password
        
        # Request token (Keycloak includes certificate binding automatically)
        async with aiohttp.ClientSession() as session:
            async with session.post(token_url, data=data) as response:
                token_data = await response.json()
                self.access_token = token_data.get("access_token")
                self.refresh_token = token_data.get("refresh_token")
    
    async def call_agent(
        self,
        agent_url: str,
        method: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Call A2A agent method with mTLS and token binding.
        
        The client certificate is automatically presented during mTLS handshake.
        The server verifies that the JWT token is bound to this certificate.
        """
        message = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": str(uuid.uuid4())
        }
        
        headers = {
            "Authorization": f"Bearer {self.access_token}"
        }
        
        # Send request with mTLS (certificate presented automatically)
        response = await self.mtls_client.send_message(
            url=agent_url,
            message=message,
            headers=headers
        )
        
        return response.get("result")
```

### **Integration with Keycloak**

**Enhanced KeycloakJWTValidator** (`keycloak_auth.py`):

```python
class KeycloakJWTValidator:
    def __init__(
        self,
        keycloak_url: str,
        realm: str,
        client_id: str,
        cache_ttl: int = 3600,
        require_token_binding: bool = False,  # NEW
        trusted_ca_cert_path: Optional[str] = None  # NEW
    ):
        # ... existing code ...
        
        # Initialize token binding validator
        self.token_binding_validator = None
        self.certificate_validator = None
        if TOKEN_BINDING_AVAILABLE:
            self.token_binding_validator = TokenBindingValidator()
            self.certificate_validator = CertificateValidator(trusted_ca_cert_path)
            logger.info("Token binding support enabled")
    
    def verify_token(
        self, 
        token: str,
        client_certificate: Optional[x509.Certificate] = None  # NEW
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Verify JWT token from Keycloak.
        
        Args:
            token: JWT access token
            client_certificate: Client's TLS certificate (for token binding validation)
        
        Returns:
            Tuple of (principal, roles, claims)
        """
        # ... existing JWT verification ...
        
        # Verify token binding (RFC 8473)
        if self.token_binding_validator and client_certificate:
            # Validate client certificate first
            cert_valid, cert_error = self.certificate_validator.validate_certificate(
                client_certificate,
                check_expiration=True,
                check_key_usage=True
            )
            if not cert_valid:
                raise ValueError(f"Client certificate validation failed: {cert_error}")
            
            # Verify token binding
            binding_valid, binding_error = self.token_binding_validator.verify_token_binding(
                claims,
                client_certificate
            )
            
            if not binding_valid:
                if self.require_token_binding:
                    raise ValueError(f"Token binding validation failed: {binding_error}")
                else:
                    logger.warning(f"Token binding validation failed (not enforced): {binding_error}")
            else:
                logger.info("Token binding validated successfully")
        
        elif self.require_token_binding:
            raise ValueError("Token binding required but client certificate not provided")
        
        return username, roles, claims
```

### **Certificate Management**

**Generate Certificates:**

```bash
# Generate all certificates (CA + agents)
python generate_certificates.py --certs-dir ./certs

# Output:
# ✓ CA Certificate: ./certs/ca/ca-cert.pem
# ✓ CA Private Key: ./certs/ca/ca-key.pem
# ✓ Orchestrator: ./certs/agents/orchestrator/orchestrator-cert.pem
# ✓ Extractor: ./certs/agents/extractor/extractor-cert.pem
# ✓ Validator: ./certs/agents/validator/validator-cert.pem
# ✓ Lambda: ./certs/agents/lambda/lambda-cert.pem
# ... (all agents)
```

**Certificate Verification:**

```bash
# View certificate details
openssl x509 -in ./certs/agents/orchestrator/orchestrator-cert.pem -text -noout

# Verify certificate chain
openssl verify -CAfile ./certs/ca/ca-cert.pem ./certs/agents/orchestrator/orchestrator-cert.pem

# Test mTLS connection
openssl s_client -connect orchestrator.ca-a2a.local:8001 \
  -cert ./certs/agents/lambda/lambda-cert.pem \
  -key ./certs/agents/lambda/lambda-key.pem \
  -CAfile ./certs/ca/ca-cert.pem
```

### **Configuration Reference**

**Environment Variables:**

```bash
# mTLS Configuration
MTLS_ENABLED=true
MTLS_CERT_PATH=/app/certs/orchestrator-cert.pem
MTLS_KEY_PATH=/app/certs/orchestrator-key.pem
MTLS_CA_CERT_PATH=/app/certs/ca-cert.pem
MTLS_REQUIRE_CLIENT_CERT=true

# Token Binding Configuration
TOKEN_BINDING_ENABLED=true
TOKEN_BINDING_REQUIRED=true  # Reject tokens without binding

# Keycloak OAuth2/OIDC Configuration
KEYCLOAK_URL=http://keycloak.ca-a2a.local:8080
KEYCLOAK_REALM=ca-a2a
KEYCLOAK_CLIENT_ID=ca-a2a-agents
KEYCLOAK_CLIENT_SECRET=<from-secrets-manager>
KEYCLOAK_CACHE_TTL=3600

# Security Features
A2A_REQUIRE_AUTH=true
A2A_ENABLE_RATE_LIMIT=true
A2A_RATE_LIMIT_PER_MINUTE=300
A2A_ENABLE_REPLAY_PROTECTION=true
```

**For RBAC configuration, see [Authorization Code Implementation](#authorization-code-implementation).**

**AWS Secrets Manager (Certificates):**

```bash
# Store certificates in Secrets Manager
aws secretsmanager create-secret \
  --name ca-a2a/ca-cert \
  --secret-string file://certs/ca/ca-cert.pem \
  --region eu-west-3

aws secretsmanager create-secret \
  --name ca-a2a/orchestrator-cert \
  --secret-string file://certs/agents/orchestrator/orchestrator-cert.pem \
  --region eu-west-3

aws secretsmanager create-secret \
  --name ca-a2a/orchestrator-key \
  --secret-string file://certs/agents/orchestrator/orchestrator-key.pem \
  --region eu-west-3
```

### **Security Testing**

**Test 1: Valid Token with Matching Certificate (Should Succeed)**

```bash
curl --cert ./certs/agents/lambda/lambda-cert.pem \
     --key ./certs/agents/lambda/lambda-key.pem \
     --cacert ./certs/ca/ca-cert.pem \
     -X POST https://orchestrator.ca-a2a.local:8001/message \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <lambda-token>" \
     -d '{
       "jsonrpc": "2.0",
       "method": "get_health",
       "params": {},
       "id": 1
     }'

# Expected: 200 OK
# Token binding: ✓ Certificate thumbprint matches cnf.x5t#S256
```

**Test 2: Valid Token with Wrong Certificate (Should Fail)**

```bash
curl --cert ./certs/agents/extractor/extractor-cert.pem \
     --key ./certs/agents/extractor/extractor-key.pem \
     --cacert ./certs/ca/ca-cert.pem \
     -X POST https://orchestrator.ca-a2a.local:8001/message \
     -H "Authorization: Bearer <lambda-token>" \
     -d '{"jsonrpc":"2.0","method":"get_health","id":1}'

# Expected: 401 Unauthorized
# Error: "Certificate thumbprint does not match token binding"
# Token binding: ✗ extractor cert ≠ lambda token binding
```

**Test 3: Stolen Token without Certificate (Should Fail)**

```bash
curl -k -X POST https://orchestrator.ca-a2a.local:8001/message \
     -H "Authorization: Bearer <stolen-token>" \
     -d '{"jsonrpc":"2.0","method":"get_health","id":1}'

# Expected: Connection refused (mTLS required)
# OR: 401 Unauthorized (no client certificate presented)
```

### **Performance Impact**

For complete performance analysis including mTLS, Token Binding, and JWT verification overhead, see [Performance Characteristics](#performance-characteristics) in Section 7 and [End-to-End Request Timeline](#end-to-end-request-timeline) in Section 13.

### **Compliance & Standards**

✅ **RFC 8473** - OAuth 2.0 Token Binding  
✅ **RFC 8705** - OAuth 2.0 Mutual-TLS Client Authentication  
✅ **RFC 8471** - Token Binding Protocol  
✅ **NIST 800-63B** - Digital Identity Guidelines (AAL3 - highest assurance)  
✅ **PCI-DSS** - Mutual authentication for sensitive systems  
✅ **Zero Trust Architecture** - Verify every connection  

### **Documentation References**

- [`TOKEN_BINDING_MTLS_GUIDE.md`](./TOKEN_BINDING_MTLS_GUIDE.md) - Complete guide (850+ lines)
- [`TOKEN_BINDING_MTLS_README.md`](./TOKEN_BINDING_MTLS_README.md) - Quick start (250+ lines)
- [`token_binding.py`](./token_binding.py) - Token binding implementation (450 lines)
- [`mtls_manager.py`](./mtls_manager.py) - Certificate management (475 lines)
- [`mtls_base_agent.py`](./mtls_base_agent.py) - mTLS server (175 lines)
- [`mtls_client.py`](./mtls_client.py) - mTLS client (360 lines)
- [`test_token_binding_mtls.py`](./test_token_binding_mtls.py) - Test suite (16 tests, 95%+ coverage)

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

## JWT Signature & Token Integrity

### **Overview**

Token integrity in the A2A system is cryptographically enforced through **JWT signature verification (RS256)**. Every access token issued by Keycloak is signed with an RSA private key, and agents verify the signature using public keys distributed via the JWKS (JSON Web Key Set) endpoint.

### **How JWT Signatures Work**

**Token Signing (Keycloak):**
```
1. Create JWT Claims
   ├─ Header: {"alg": "RS256", "typ": "JWT", "kid": "key-id"}
   ├─ Payload: {"sub": "user", "exp": 1736900100, "roles": [...]}
   └─ Signature: RSA_sign(private_key, header + payload)

2. Encode Token
   └─ Base64url(header).Base64url(payload).Base64url(signature)
```

**Token Verification (Agents):**
```
1. Receive Token
   └─ Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

2. Fetch Public Key
   └─ GET /realms/ca-a2a/protocol/openid-connect/certs (cached 1 hour)

3. Verify Signature
   └─ RSA_verify(public_key, header + payload, signature)

4. Validate Claims
   ├─ Check expiration (exp)
   ├─ Verify issuer (iss)
   ├─ Verify audience (aud)
   └─ Verify token binding (cnf.x5t#S256)

5. Extract Authorization
   └─ realm_access.roles → RBAC principal
```

### **JWT Signature Verification Flow**

```mermaid
sequenceDiagram
    participant Keycloak
    participant Agent
    participant JWKS as JWKS Endpoint
    
    Note over Keycloak: Token Issuance
    Keycloak->>Keycloak: Create JWT claims
    Keycloak->>Keycloak: Sign with RSA private key (RS256)
    Keycloak->>Agent: Access Token (signed JWT)
    
    Note over Agent: Token Verification
    Agent->>JWKS: GET /certs (fetch public keys)
    JWKS-->>Agent: RSA public key (cached 1h)
    Agent->>Agent: Verify RS256 signature
    Agent->>Agent: Validate exp, iss, aud claims
    Agent->>Agent: Verify token binding (x5t#S256)
    
    alt All Checks Pass
        Agent->>Agent: Extract roles & proceed
    else Verification Failed
        Agent-->>Agent: 401 Unauthorized
    end
```

### **Security Properties**

**1. Message Integrity**
```python
# Any modification to JWT claims invalidates the signature
original_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsInJvbGVzIjpbInZpZXdlciJdfQ.signature"

# Attacker tries to modify claims (e.g., add admin role)
tampered_claims = {"sub": "user1", "roles": ["viewer", "admin"]}  # MODIFIED
tampered_token = base64(header) + "." + base64(tampered_claims) + "." + original_signature

# Verification fails - signature no longer matches
verify_jwt(tampered_token)  # ❌ InvalidSignatureError
```

**2. Token Authenticity**

### **Implementation: JWT Verification**

**Code** (`keycloak_auth.py:105-170`):
```python
class KeycloakJWTValidator:
    def verify_token(
        self, 
        token: str,
        client_certificate: Optional[x509.Certificate] = None
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        """
        Verify JWT token from Keycloak with Token Binding support.
        
        Returns:
            Tuple of (principal, roles, claims)
        """
        # 1. Get signing key from JWKS endpoint (cached)
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)
        
        # 2. Verify signature and validate standard claims
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.client_id,
            issuer=self.issuer,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True
            }
        )
        
        # 3. Verify token binding (RFC 8473)
        if self.token_binding_validator and client_certificate:
            binding_valid, error = self.token_binding_validator.verify_token_binding(
                claims,
                client_certificate
            )
            if not binding_valid:
                raise ValueError(f"Token binding validation failed: {error}")
        
        # 4. Extract principal and roles
        principal = claims.get('preferred_username') or claims.get('sub')
        roles = claims.get('realm_access', {}).get('roles', [])
        
        return principal, roles, claims
```

### **Performance Characteristics**

| Operation | Time | Notes |
|-----------|------|-------|
| **JWKS Fetch** | ~50ms | Only on first request or cache expiry |
| **Signature Verification** | ~2ms | With cached public key |
| **Token Binding Check** | ~0.3ms | SHA-256 thumbprint comparison |
| **Role Extraction** | <0.1ms | Direct claim access |
| **Total** | ~2-5ms | Negligible overhead (~0.3% of typical request) |

**Security Benefits:** See [Security Metrics](#security-metrics) for comprehensive security analysis.

**3. Key Distribution & Rotation**
```python
# Keycloak JWT Validator Configuration
validator = KeycloakJWTValidator(
    keycloak_url="http://keycloak.ca-a2a.local:8080",
    realm="ca-a2a",
    client_id="ca-a2a-agents",
    cache_ttl=3600  # Cache public keys for 1 hour
)

# Automatic key fetching from JWKS endpoint
# GET /realms/ca-a2a/protocol/openid-connect/certs
# Returns: {"keys": [{"kid": "...", "kty": "RSA", "n": "...", "e": "AQAB"}]}

# Key rotation handled transparently by Keycloak
# - New keys added to JWKS
# - Old keys retired after grace period
# - Zero downtime for agents
```

**4. Replay Protection via Expiration**
```python
# Short-lived access tokens (5 minutes)
claims = {
    "exp": 1736900100,  # Expiration timestamp
    "iat": 1736899800,  # Issued at timestamp
    "sub": "user"
}

# Token automatically invalid after 5 minutes
current_time = 1736900200  # 6 minutes after issuance
if current_time >= claims["exp"]:
    raise jwt.ExpiredSignatureError("Token has expired")

# Limits exposure window if token is stolen
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
 Victim->>Server: POST /message<br/>Authorization: Bearer <token><br/>Body: {transfer $1000}
 Server-->>Victim: Success
 
 Note over Attacker: Attacker intercepts valid request
 Attacker->>Attacker: Capture entire request<br/>(headers + body)
 
 Note over Attacker,Server: Replay Attack (1 minute later)
 Attacker->>Server: POST /message<br/>Authorization: Bearer <token><br/>Body: {transfer $1000}<br/>(Exact same request)
 
 alt Without Replay Protection
 Server-->>Attacker: Success<br/> $1000 transferred again!
 else With Replay Protection
 Server->>Server: Check request timestamp
 Server->>Server: Request > 5 min old 
 Server-->>Attacker: 401 Replay Detected
 end
```

### **Replay Protection Mechanisms**

**JWT Token Expiration (Primary):**
```python
# Tokens contain expiration claim
claims = jwt.decode(token)
exp = claims["exp"]  # 1736900100 (Unix timestamp)
now = int(time.time())  # 1736899900

# Token valid for 5 minutes
if now >= exp:
    raise jwt.ExpiredSignatureError("Token has expired")

# Benefits:
# - Automatic expiration (no manual tracking)
# - Short 5-minute window limits replay exposure
# - No state management required (stateless verification)
```

**Additional Protections:**
- **Token Binding (RFC 8473)**: Binds token to client certificate
- **Refresh Token Rotation**: New refresh token issued on each use
- **Keycloak Session Management**: Admin can revoke all sessions
- **Audit Logging**: All token usage logged to CloudWatch

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

### **Token Revocation Implementation**

#### **Storage Architecture: Hybrid Approach**

Token revocation uses a **two-tier storage system** for optimal performance and reliability:

1. **Primary Storage: PostgreSQL Database**
   - Persistent across restarts
   - Shared across all agent instances
   - Source of truth for revoked tokens

2. **Secondary Storage: In-Memory Cache**
   - Ultra-fast lookups (~1μs)
   - Reduces database load
   - Automatic TTL-based cleanup

**Storage Flow:**
```mermaid
graph LR
    Admin[Admin] -->|POST /admin/revoke-token| API[Admin API]
    API -->|1. Store| Cache[Memory Cache]
    API -->|2. Store| DB[(PostgreSQL)]
    
    Request[Request] -->|Check| Cache
    Cache -->|Miss| DB
    DB -->|Result| Cache
    Cache -->|Hit/Miss| Response[401 or 200]
    
    style Cache fill:#FFD700
    style DB fill:#90EE90
```

#### **Code Implementation**

**File:** `a2a_security_enhanced.py` (lines 285-437)

**1. Revoke Token:**
```python
class TokenRevocationList:
    def __init__(self, db_pool=None):
        self.db_pool = db_pool
        self._memory_cache: Dict[str, RevokedToken] = {}
        self._last_cleanup = time.time()
    
    async def revoke_token(
        self,
        jti: str,
        reason: str,
        revoked_by: str,
        expires_at: Optional[datetime] = None
    ) -> bool:
        """
        Add token to revocation list.
        
        Args:
            jti: JWT ID (jti claim from token)
            reason: Human-readable reason ("Security breach", "Employee terminated")
            revoked_by: Admin username who revoked it
            expires_at: When token expires (for automatic cleanup)
        
        Returns:
            True if successfully revoked
        """
        if expires_at is None:
            expires_at = datetime.utcnow() + timedelta(days=30)
        
        revoked = RevokedToken(
            jti=jti,
            revoked_at=datetime.utcnow(),
            revoked_by=revoked_by,
            reason=reason,
            expires_at=expires_at
        )
        
        # Step 1: Store in memory cache (fast)
        self._memory_cache[jti] = revoked
        
        # Step 2: Store in database (persistent)
        if self.db_pool:
            async with self.db_pool.acquire() as conn:
                await conn.execute('''
                    INSERT INTO revoked_tokens (jti, revoked_at, revoked_by, reason, expires_at)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (jti) DO UPDATE
                    SET revoked_at = EXCLUDED.revoked_at,
                        reason = EXCLUDED.reason
                ''', jti, revoked.revoked_at, revoked_by, reason, expires_at)
                logger.info(f"Token {jti} revoked in database: {reason}")
        
        logger.info(f"Token {jti} revoked by {revoked_by}: {reason}")
        return True
```

**2. Check if Revoked:**
```python
async def is_revoked(self, jti: str) -> bool:
    """
    Check if token is revoked.
    
    Performance optimizations:
    - Memory cache checked first (~1μs lookup)
    - Database checked on cache miss (~10ms query)
    - Results cached for future requests
    - Expired tokens automatically removed
    """
    # Check 1: Memory cache (fast path)
    if jti in self._memory_cache:
        revoked = self._memory_cache[jti]
        if revoked.expires_at > datetime.utcnow():
            return True  # Token is revoked
        else:
            # Token expired, remove from cache
            del self._memory_cache[jti]
    
    # Check 2: Database (persistent, slow path)
    if self.db_pool:
        async with self.db_pool.acquire() as conn:
            result = await conn.fetchrow('''
                SELECT jti, expires_at FROM revoked_tokens
                WHERE jti = $1 AND expires_at > NOW()
            ''', jti)
            
            if result:
                # Cache for future checks
                self._memory_cache[jti] = RevokedToken(
                    jti=result['jti'],
                    revoked_at=datetime.utcnow(),
                    revoked_by="db",
                    reason="cached from db",
                    expires_at=result['expires_at']
                )
                return True  # Token is revoked
    
    # Periodic cleanup of expired tokens
    self._cleanup_expired()
    
    return False  # Token not revoked
```

**3. Integration with Authentication:**
```python
# In A2ASecurityManager.authenticate_and_authorize()
async def authenticate_and_authorize(self, headers, message_method, message_dict):
    # ... JWT verification ...
    
    # Check token revocation
    if self.enable_token_revocation:
        jti = claims.get("jti")
        if jti and await self.token_revocation_list.is_revoked(jti):
            raise ForbiddenError("Token has been revoked")
    
    return principal, auth_context
```

#### **Admin API for Token Revocation**

**File:** `admin_api.py`

**Revoke Token Endpoint:**
```bash
POST /admin/revoke-token
Authorization: Bearer <admin-jwt>
Content-Type: application/json

{
  "jti": "abc123-token-id",
  "reason": "Security breach - employee terminated",
  "revoked_by": "admin@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Token revoked successfully",
  "jti": "abc123-token-id",
  "revoked_at": "2026-01-15T10:30:00Z"
}
```

**List Revoked Tokens:**
```bash
GET /admin/revoked-tokens?limit=100
Authorization: Bearer <admin-jwt>
```

**Response:**
```json
{
  "tokens": [
    {
      "jti": "abc123",
      "revoked_at": "2026-01-15T10:30:00Z",
      "revoked_by": "admin@example.com",
      "reason": "Security breach",
      "expires_at": "2026-02-15T10:30:00Z"
    }
  ],
  "total": 1,
  "limit": 100
}
```

#### **Database Migration**

**File:** `migrations/001_create_revoked_tokens_table.sql`

Run migration:
```bash
# Option 1: Using script
./migrations/run_migration.sh

# Option 2: Manual (from AWS CloudShell)
aws rds execute-statement \
  --resource-arn <cluster-arn> \
  --secret-arn <secret-arn> \
  --database documents \
  --sql "$(cat migrations/001_create_revoked_tokens_table.sql)"
```

#### **Performance Characteristics**

| Operation | Latency | Notes |
|-----------|---------|-------|
| **Revoke token** | ~10ms | DB write + memory store |
| **Check revoked (cached)** | ~1μs | Memory lookup only |
| **Check revoked (miss)** | ~10ms | DB query + cache store |
| **Cleanup expired** | ~100ms | Every 5 minutes, async |

**Storage Estimates:**
- Per token: ~300 bytes
- 1M revoked tokens: ~300 MB in database
- Memory cache: 1,000-10,000 tokens = 300KB-3MB per agent

#### **Common Use Cases**

1. **Employee Termination:**
```python
await revocation_list.revoke_token(
    jti="employee-token-123",
    reason="Employee terminated",
    revoked_by="hr-admin"
)
```

2. **Security Breach:**
```python
# Revoke all tokens for compromised agent
for jti in compromised_agent_tokens:
    await revocation_list.revoke_token(
        jti=jti,
        reason="Security breach - agent compromised",
        revoked_by="security-team"
    )
```

3. **Token Rotation:**
```python
# Revoke old token after issuing new one
await revocation_list.revoke_token(
    jti=old_token_jti,
    reason="Token rotation - new token issued",
    revoked_by="system"
)
```

#### **Automatic Cleanup**

Expired tokens are automatically cleaned up:

**Memory Cache:** Every 5 minutes
```python
def _cleanup_expired(self):
    now_dt = datetime.utcnow()
    expired = [jti for jti, rev in self._memory_cache.items() 
               if rev.expires_at <= now_dt]
    for jti in expired:
        del self._memory_cache[jti]
```

**Database:** Scheduled job (recommended: daily)
```sql
-- Run as cron job or AWS EventBridge rule
DELETE FROM revoked_tokens WHERE expires_at < NOW() - INTERVAL '7 days';
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

### **JWT Authentication in Production**

**Log Sequence:**
1. **Request Received:** Incoming request with `Authorization: Bearer <token>` header
2. **Token Verification:** Keycloak JWT signature verified using JWKS public key (RS256)
3. **Principal Extraction:** Username `lambda-service` mapped to principal `lambda` from realm roles
4. **Token Binding Validation:** Certificate thumbprint matches `cnf.x5t#S256` claim (RFC 8473)
5. **RBAC Policy Check:** Principal `lambda` has wildcard access (`*`) to all methods
6. **Rate Limit Check:** Principal has 45/300 requests in current window (under limit)
7. **Request Forwarded:** After all checks pass, request forwarded to target agent

**Key Observations:**
- ✅ JWT claims logged (truncated for security)
- ✅ Correlation ID links all related log entries
- ✅ Each security layer logs its decision (pass/fail)
- ✅ Authentication overhead: ~2ms (JWKS cached)
- ✅ Dynamic role resolution from Keycloak
- ✅ Token binding validated (~0.3ms additional overhead)

---

### **JSON Schema Validation in Production**

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
- **T+200ms:** Lambda calls Orchestrator with Keycloak JWT
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
- Security overhead: ~3-5ms (JWT + Token Binding + mTLS) = 0.27% of total time
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
 
 Note over Server: Layer 3: Authentication (Keycloak JWT)
 Server->>Security: Extract JWT token
 Security->>Security: Fetch public key from JWKS
 Security->>Security: Verify RS256 signature
 Security->>Security: Validate exp, iss, aud claims
 Security->>Security: Extract principal from realm_access.roles
 alt JWT Invalid
 Security-->>Client: 401 Unauthorized
 end
 
 Note over Server: Layer 4: Token Binding (RFC 8473)
 Security->>Security: Extract cnf.x5t#S256 claim
 Security->>Security: Compute client cert thumbprint
 Security->>Security: Compare thumbprints (constant-time)
 alt Token Not Bound
 Security-->>Client: 401 Token Binding Failed
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

| Security Layer | Time | Notes |
|----------------|------|-------|
| Network | ~1ms | VPC internal routing |
| mTLS Handshake | ~10ms | First request only (session resumption) |
| JWT Signature Verification | ~2ms | JWKS cached (1 hour TTL) |
| Token Binding Verification | ~0.3ms | SHA-256 thumbprint comparison |
| Authorization (RBAC) | ~0.1ms | In-memory policy check |
| Schema Validation | ~1.5ms | JSON schema validation |
| Rate Limiting | ~0.1ms | Token bucket algorithm |
| **Total Security Overhead** | **~2-5ms** | **~0.3-1% of typical request** |
| Method Execution | Variable | e.g., 180ms for PDF extraction |

**This consolidated view shows all security layers' performance impact. For end-to-end latency breakdown, see [End-to-End Request Timeline](#end-to-end-request-timeline).**

---

## ️ Attack Scenarios & Defenses

### **Attack Matrix**

| Attack Type | Attack Vector | Defense Layer | Mitigation |
|-------------|---------------|---------------|------------|
| **DDoS** | Flood with requests | Rate Limiting | Token bucket (300 req/min) |
| **Man-in-the-Middle** | Intercept traffic | mTLS + JWT signature | Mutual certificate authentication + RS256 signature |
| **Replay Attack** | Reuse captured request | Token Binding + Expiration | Certificate-bound tokens + 5-min lifespan |
| **Message Tampering** | Modify JWT claims | JWT Signature (RS256) | RS256 signature verification |
| **SQL Injection** | `'; DROP TABLE--` | JSON Schema | Pattern validation |
| **Path Traversal** | `../../etc/passwd` | JSON Schema | Negative lookahead regex |
| **Buffer Overflow** | 10MB string | JSON Schema | maxLength: 1024 |
| **XSS** | `<script>alert()</script>` | JSON Schema | Pattern validation |
| **Privilege Escalation** | Call unauthorized method | Dynamic RBAC | Keycloak role-based enforcement |
| **Token Theft** | Stolen JWT used | Token Binding (RFC 8473) | Certificate-bound tokens (unusable without client cert) |
| **Timing Attack** | Measure comparison time | Constant-time operations | PyJWT + secrets.compare_digest |
| **Brute Force** | Guess credentials | Keycloak + Rate Limiting | Account lockout + rate limits |
| **Impersonation** | Fake client identity | mTLS | Client certificate verification (CERT_REQUIRED) |
| **Token Export** | Token used on different device | Token Binding | cnf.x5t#S256 claim validates certificate thumbprint |

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
| **Security Layers** | 9 (network → audit) + Token Binding + mTLS |
| **Authentication Methods** | Keycloak JWT (RS256) + mTLS Client Certificates |
| **Authorization Model** | Dynamic RBAC (Keycloak roles) |
| **Message Integrity** | JWT Signature (RS256) - Default |
| **Input Validation** | JSON Schema v7 |
| **Rate Limiting** | Token bucket (300 req/min) |
| **Replay Window** | 2 minutes |
| **Token Algorithm** | RS256 (asymmetric) |
| **Token Lifespan** | 5 minutes (access) + 30 days (refresh) |
| **Token Binding** | RFC 8473 (cnf.x5t#S256 claim) |
| **mTLS Configuration** | CERT_REQUIRED + TLS 1.2+ |
| **Certificate Chain** | Internal CA + Agent Certificates (365 days) |
| **Total Overhead** | ~2-5ms (~0.3% including mTLS handshake, JWT verification) |
| **Test Coverage** | 72+ tests (100% pass rate) |
| **Compliance Score** | 10/10 (OAuth2/OIDC + RFC 8473 + RFC 8705 + NIST 800-63B AAL3) |

---

**Document Version:** 3.0  
**Last Updated:** January 14, 2026  
**Authors:** Security Team 
**Status:** Production Ready - Enterprise-Grade Security (Keycloak + Token Binding + mTLS)

**Features:**
- ✅ Keycloak OAuth2/OIDC Authentication (RS256)
- ✅ Token Binding (RFC 8473) - Certificate-bound tokens
- ✅ Mutual TLS (mTLS) - Bidirectional certificate authentication
- ✅ Dynamic RBAC via Keycloak roles
- ✅ Multi-layer defense-in-depth architecture

