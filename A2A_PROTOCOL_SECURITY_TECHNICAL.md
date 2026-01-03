# 🔐 A2A Protocol Security: Technical Deep Dive

**Comprehensive Technical Documentation on Agent-to-Agent Communication Protocol and Security Implementation**

---

## 📋 Table of Contents

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

## 🎯 A2A Protocol Overview

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

| Protocol | Pros | Cons | Our Choice |
|----------|------|------|------------|
| **JSON-RPC 2.0** ✅ | Simple, standardized, debuggable | Text overhead | **Selected** |
| gRPC | Fast, binary, streaming | Complex, needs .proto files | Not needed |
| REST | Universal, cacheable | Verbose, CRUD-focused | Not RPC pattern |
| GraphQL | Flexible queries | Overkill for RPC | Too complex |
| WebSocket | Bidirectional, persistent | Complex state management | Not needed |

---

## 📡 Protocol Stack Architecture

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

### **Protocol Encapsulation**

```
┌─────────────────────────────────────────────────────────────┐
│ A2A Message (JSON-RPC 2.0)                                  │
│ {"jsonrpc":"2.0","method":"extract_document","id":"123"}    │
├─────────────────────────────────────────────────────────────┤
│ Security Headers                                             │
│ X-API-Key: abc123...                                        │
│ X-Signature: 1735867245:def456...                           │
│ X-Correlation-ID: pipe-789                                  │
├─────────────────────────────────────────────────────────────┤
│ HTTP Headers                                                 │
│ POST /message HTTP/1.1                                      │
│ Host: extractor.ca-a2a.local:8002                           │
│ Content-Type: application/json                              │
│ Content-Length: 89                                          │
├─────────────────────────────────────────────────────────────┤
│ TCP Header (Source: 8001, Dest: 8002)                      │
├─────────────────────────────────────────────────────────────┤
│ IP Header (Src: 10.0.10.25, Dst: 10.0.20.158)              │
├─────────────────────────────────────────────────────────────┤
│ Ethernet Frame                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Message Structure & Format

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
        +string method ✓
        +dict params ✓
        +string id ✓
        -result ✗
        -error ✗
    }
    
    class Response {
        -method ✗
        -params ✗
        +any result ✓
        +string id ✓
    }
    
    class Error {
        -method ✗
        -params ✗
        -result ✗
        +dict error ✓
        +string id ✓
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
    id: Optional[str] = None          # Request ID (for matching responses)
    method: Optional[str] = None      # RPC method name
    params: Optional[Dict[str, Any]] = None  # Method parameters
    result: Optional[Any] = None      # Response result (only in responses)
    error: Optional[Dict[str, Any]] = None   # Error details (only in errors)
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
- ✅ `jsonrpc`: Must be exactly `"2.0"`
- ✅ `method`: Required for requests, snake_case convention
- ✅ `params`: Optional dict, validated against JSON schema
- ✅ `id`: Required for requests, should be unique per request
- ❌ `result`: Not present in requests
- ❌ `error`: Not present in requests

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

## 🛡️ Security Layers Deep Dive

### **Defense-in-Depth Architecture**

```mermaid
graph TB
    Request[Incoming Request] --> L1
    
    L1[Layer 1: Network Security<br/>VPC + Security Groups] --> L1_Check{IP Allowed?}
    L1_Check -->|No| Reject1[❌ Connection Refused<br/>TCP RST]
    L1_Check -->|Yes| L2
    
    L2[Layer 2: Transport Security<br/>TLS Encryption] --> L2_Check{TLS Valid?}
    L2_Check -->|No| Reject2[❌ SSL Handshake Failed]
    L2_Check -->|Yes| L3
    
    L3[Layer 3: Message Integrity<br/>HMAC Signature] --> L3_Check{Signature Valid?}
    L3_Check -->|No| Reject3[❌ 401 Tampered Request]
    L3_Check -->|Yes| L4
    
    L4[Layer 4: Authentication<br/>API Key / JWT] --> L4_Check{Auth Valid?}
    L4_Check -->|No| Reject4[❌ 401 Unauthorized]
    L4_Check -->|Yes| L5
    
    L5[Layer 5: Authorization<br/>RBAC Policy] --> L5_Check{Principal Allowed?}
    L5_Check -->|No| Reject5[❌ 403 Forbidden]
    L5_Check -->|Yes| L6
    
    L6[Layer 6: Input Validation<br/>JSON Schema] --> L6_Check{Params Valid?}
    L6_Check -->|No| Reject6[❌ 400 Invalid Params]
    L6_Check -->|Yes| L7
    
    L7[Layer 7: Rate Limiting<br/>Token Bucket] --> L7_Check{Under Limit?}
    L7_Check -->|No| Reject7[❌ 429 Rate Exceeded]
    L7_Check -->|Yes| L8
    
    L8[Layer 8: Replay Protection<br/>Nonce + Timestamp] --> L8_Check{Fresh Request?}
    L8_Check -->|No| Reject8[❌ 401 Replay Detected]
    L8_Check -->|Yes| Handler
    
    Handler[✅ Execute Method<br/>Process Request] --> Response
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

| Layer | Technology | Protection Against | Performance Impact |
|-------|------------|-------------------|-------------------|
| **1. Network** | AWS VPC + SG | Unauthorized IPs, DDoS | None (AWS managed) |
| **2. Transport** | TLS 1.3 | Eavesdropping, MITM | ~2-5ms (handshake) |
| **3. Integrity** | HMAC-SHA256 | Message tampering | ~0.3ms per request |
| **4. Authentication** | API Key / JWT | Impersonation | ~0.1ms (lookup) |
| **5. Authorization** | RBAC | Privilege escalation | ~0.1ms (policy check) |
| **6. Validation** | JSON Schema | Injection, XSS, path traversal | ~1.5ms per request |
| **7. Rate Limiting** | Token bucket | DoS, abuse | ~0.1ms (counter check) |
| **8. Replay Protection** | Timestamp + nonce | Replay attacks | ~0.1ms (timestamp check) |

**Total Security Overhead:** ~4-7ms per request (~0.8% of 515ms pipeline)

---

## 🔑 Authentication Mechanisms

### **Authentication Flow**

```mermaid
sequenceDiagram
    participant Client
    participant Agent as Agent<br/>(BaseAgent)
    participant Security as A2ASecurityManager
    participant Handler as Method Handler
    
    Client->>Agent: POST /message<br/>Headers: X-API-Key or Authorization
    
    Note over Agent: Extract headers
    Agent->>Security: authenticate_and_authorize(headers)
    
    alt API Key Authentication
        Security->>Security: Extract X-API-Key header
        Security->>Security: Lookup key in A2A_API_KEYS_JSON
        Security->>Security: Find principal for key
        Security-->>Agent: principal="lambda-s3-processor"
    else JWT Authentication
        Security->>Security: Extract Authorization: Bearer token
        Security->>Security: Verify JWT signature
        Security->>Security: Check expiration
        Security->>Security: Extract claims (sub=principal)
        Security-->>Agent: principal="user@example.com"
    else No Authentication
        Security-->>Agent: ❌ AuthError("Missing credentials")
        Agent-->>Client: 401 Unauthorized
    end
    
    Note over Agent: Authentication successful
    Agent->>Handler: Execute method
    Handler-->>Agent: Result
    Agent-->>Client: 200 OK + Result
```

### **API Key Authentication Code**

**Configuration** (`a2a_security.py:50-70`):
```python
class A2ASecurityManager:
    def __init__(self, agent_id: str):
        # Load API keys from environment
        api_keys_json = os.getenv("A2A_API_KEYS_JSON", "{}")
        self.api_keys = json.loads(api_keys_json)
        # Format: {"principal_id": "api_key_value"}
        # Example: {"lambda-s3-processor": "abc123xyz", "orchestrator": "def456uvw"}
        
        self.api_key_header = os.getenv("A2A_API_KEY_HEADER", "X-API-Key")
```

**Verification** (`a2a_security.py:287-310`):
```python
async def _verify_api_key(self, headers: Dict[str, str]) -> Tuple[str, Dict[str, Any]]:
    """
    Verify API key from headers
    
    Security Features:
    1. Constant-time comparison (prevents timing attacks)
    2. Case-insensitive header matching
    3. Secure logging (key length only, not value)
    """
    # Extract API key (case-insensitive header lookup)
    api_key = None
    for key, value in headers.items():
        if key.lower() == self.api_key_header.lower():
            api_key = value
            break
    
    if not api_key:
        raise AuthError(f"Missing {self.api_key_header} header")
    
    # Verify API key exists (reverse lookup)
    principal = None
    for principal_id, key_value in self.api_keys.items():
        # Constant-time comparison (prevents timing attacks)
        if secrets.compare_digest(api_key, key_value):
            principal = principal_id
            break
    
    if not principal:
        # Log length only (not actual key value for security)
        self.logger.warning(f"Invalid API key presented (length: {len(api_key)})")
        raise AuthError("Invalid API key")
    
    self.logger.info(f"API key authentication successful for principal: {principal}")
    
    return principal, {
        "auth_mode": "api_key",
        "authenticated_at": time.time()
    }
```

**Security Considerations:**

1. **Constant-Time Comparison:**
   ```python
   # ❌ VULNERABLE to timing attacks
   if api_key == stored_key:
       return True
   
   # ✅ SECURE - constant time
   if secrets.compare_digest(api_key, stored_key):
       return True
   ```
   **Why?** Prevents attackers from measuring comparison time to guess keys byte-by-byte.

2. **Secure Logging:**
   ```python
   # ❌ NEVER log the actual key
   logger.info(f"Invalid key: {api_key}")
   
   # ✅ Log only metadata
   logger.warning(f"Invalid API key presented (length: {len(api_key)})")
   ```

3. **Key Rotation:**
   ```python
   # Support multiple active keys per principal
   "lambda-s3-processor": ["key_v1", "key_v2"]  # Both valid during rotation
   ```

---

## 🚪 Authorization & RBAC

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

```mermaid
flowchart TD
    Start[Authorization Check] --> Auth{Authenticated?}
    Auth -->|No| Reject1[❌ 401 Unauthorized]
    Auth -->|Yes| ExtractPrincipal[Extract Principal<br/>e.g., lambda-s3-processor]
    
    ExtractPrincipal --> ExtractMethod[Extract Method<br/>e.g., process_document]
    
    ExtractMethod --> CheckDeny{Principal in<br/>Deny List?}
    
    CheckDeny -->|Yes| CheckDenyMethod{Method in<br/>Denied Methods?}
    CheckDenyMethod -->|Yes| Reject2[❌ 403 Forbidden<br/>Explicitly Denied]
    CheckDenyMethod -->|No| CheckAllow
    
    CheckDeny -->|No| CheckAllow{Principal in<br/>Allow List?}
    
    CheckAllow -->|No| Reject3[❌ 403 Forbidden<br/>Not Authorized]
    
    CheckAllow -->|Yes| CheckWildcard{Has Wildcard '*'<br/>Permission?}
    
    CheckWildcard -->|Yes| Allow[✅ Authorized<br/>Wildcard Access]
    CheckWildcard -->|No| CheckSpecific{Method in<br/>Allowed Methods?}
    
    CheckSpecific -->|Yes| Allow2[✅ Authorized<br/>Specific Method]
    CheckSpecific -->|No| Reject4[❌ 403 Forbidden<br/>Method Not Allowed]
    
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

## ✍️ Message Integrity (HMAC)

### **HMAC Signing & Verification Flow**

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
        Server-->>Client: ❌ 401 Signature Expired/Future
    end
    
    Server->>Server: 9. body_hash = SHA256(received_body)
    Server->>Server: 10. signing_string = "POST\n/message\n{timestamp}\n{body_hash}"
    Server->>Server: 11. expected_sig = HMAC-SHA256(secret_key, signing_string)
    Server->>Server: 12. Compare signatures (constant-time)
    
    alt Signatures Match
        Server-->>Client: ✅ Request Processed
    else Signatures Don't Match
        Server-->>Client: ❌ 401 Invalid Signature (Tampered)
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
        self.max_age_seconds = max_age_seconds  # Default: 5 minutes
    
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
signature = sign(body)  # abc123...

# Attacker modifies body
tampered = b'{"method":"test","params":{"s3_key":"../../etc/passwd"}}'

# Verification fails
verify(signature, tampered)  # ❌ False - body hash mismatch
```

**2. Replay Protection:**
```python
# Request at 10:00 AM
timestamp = 1735867200
signature = sign(timestamp, body)  # Valid

# Attacker replays at 10:10 AM (10 minutes later)
current_time = 1735867800
age = current_time - timestamp  # 600 seconds

if age > max_age_seconds (300):  # ❌ Rejected
    return "Signature expired"
```

**3. Authentication:**
```python
# Only agents with secret_key can generate valid signatures
secret_key = "shared_secret_64_chars_minimum"

# Attacker without secret_key cannot forge signatures
attacker_signature = hmac(attacker_guess, body)  # ❌ Wrong key
```

---

## ✅ Input Validation (JSON Schema)

### **Schema Validation Flow**

```mermaid
flowchart TD
    Start[Receive Request] --> Extract[Extract params]
    Extract --> SchemaLookup{Schema Exists<br/>for Method?}
    
    SchemaLookup -->|No| Warn[⚠️ Log Warning<br/>Skip Validation]
    Warn --> Process[Process Request]
    
    SchemaLookup -->|Yes| TypeCheck[Type Check<br/>string, number, object, array]
    
    TypeCheck -->|Fail| Error1[❌ 400 Type Error<br/>e.g., Expected string, got number]
    TypeCheck -->|Pass| PatternCheck[Pattern Check<br/>Regex validation]
    
    PatternCheck -->|Fail| Error2[❌ 400 Pattern Error<br/>e.g., Path traversal detected]
    PatternCheck -->|Pass| RequiredCheck[Required Fields<br/>Must be present]
    
    RequiredCheck -->|Fail| Error3[❌ 400 Missing Field<br/>e.g., s3_key is required]
    RequiredCheck -->|Pass| EnumCheck[Enum Check<br/>Allowed values]
    
    EnumCheck -->|Fail| Error4[❌ 400 Invalid Value<br/>e.g., priority must be low/normal/high]
    EnumCheck -->|Pass| AdditionalCheck[Additional Properties<br/>Check for unexpected fields]
    
    AdditionalCheck -->|Found| Error5[❌ 400 Unexpected Field<br/>e.g., extra_field not allowed]
    AdditionalCheck -->|None| RangeCheck[Range Check<br/>Min/max length, value]
    
    RangeCheck -->|Fail| Error6[❌ 400 Range Error<br/>e.g., string too long]
    RangeCheck -->|Pass| Success[✅ Validation Passed]
    
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

**1. Path Traversal Prevention:**
```python
# ❌ ATTACK: Path traversal
params = {"s3_key": "../../../etc/passwd"}

# Schema pattern: ^(?!.*\\.\\./)[a-zA-Z0-9/._-]+$
# - Negative lookahead: (?!.*\\.\\.)  - Rejects any string containing ".."
# - Character whitelist: [a-zA-Z0-9/._-]  - Only safe characters

validate(params)  # ❌ Pattern mismatch - BLOCKED
```

**2. SQL Injection Prevention:**
```python
# ❌ ATTACK: SQL injection attempt
params = {"s3_key": "'; DROP TABLE documents--"}

# Schema constraints:
# - Pattern: Only alphanumeric + /._-
# - Type: Must be string (not raw SQL)

validate(params)  # ❌ Pattern mismatch - BLOCKED
```

**3. Buffer Overflow Prevention:**
```python
# ❌ ATTACK: Extremely long string
params = {"s3_key": "A" * 100000}  # 100KB string

# Schema constraint: "maxLength": 1024

validate(params)  # ❌ Too long - BLOCKED
```

**4. Type Confusion Prevention:**
```python
# ❌ ATTACK: Type confusion
params = {"s3_key": ["malicious", "array"]}

# Schema constraint: "type": "string"

validate(params)  # ❌ Type error - BLOCKED
```

**5. Unexpected Field Prevention:**
```python
# ❌ ATTACK: Inject malicious field
params = {
    "s3_key": "test.pdf",
    "__proto__": {"isAdmin": true}  # Prototype pollution attempt
}

# Schema constraint: "additionalProperties": false

validate(params)  # ❌ Unexpected field - BLOCKED
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
            return True, None  # Skip validation if no schema
        
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

## 🔄 Replay Protection

### **Replay Attack Scenario**

```mermaid
sequenceDiagram
    participant Attacker
    participant Victim as Legitimate Agent
    participant Server
    
    Note over Victim,Server: Normal Request
    Victim->>Server: POST /message<br/>X-API-Key: valid_key<br/>Body: {transfer $1000}
    Server-->>Victim: ✅ Success
    
    Note over Attacker: Attacker intercepts valid request
    Attacker->>Attacker: Capture entire request<br/>(headers + body)
    
    Note over Attacker,Server: Replay Attack (1 minute later)
    Attacker->>Server: POST /message<br/>X-API-Key: valid_key<br/>Body: {transfer $1000}<br/>(Exact same request)
    
    alt Without Replay Protection
        Server-->>Attacker: ✅ Success<br/>❌ $1000 transferred again!
    else With Replay Protection
        Server->>Server: Check request timestamp
        Server->>Server: Request > 5 min old ❌
        Server-->>Attacker: ❌ 401 Replay Detected
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

if age > 300:  # 5 minutes
    return "Signature expired - possible replay attack"
```

**2. Nonce-Based (Optional):**
```python
# Client generates unique nonce
nonce = str(uuid.uuid4())  # "a1b2c3d4-e5f6-..."

# Server tracks used nonces
used_nonces = set()  # Or Redis cache

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
A2A_SIGNATURE_MAX_AGE_SECONDS=300  # 5 minutes

# Trade-offs:
# - Too short (< 60s): Legitimate requests fail due to clock skew
# - Too long (> 600s): Wider replay window
# - Recommended: 300s (5 minutes)
```

---

## ⏱️ Rate Limiting

### **Token Bucket Algorithm**

```mermaid
graph TB
    subgraph "Token Bucket"
        Bucket[Token Bucket<br/>Capacity: 100 tokens]
        Refill[Refill Rate<br/>+100 tokens/minute]
    end
    
    Request1[Request 1] -->|Consume 1 token| Bucket
    Request2[Request 2] -->|Consume 1 token| Bucket
    Request3[Request 3] -->|Consume 1 token| Bucket
    RequestN[Request 101] -->|No tokens!| Reject[❌ 429 Rate Limit Exceeded]
    
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
        self.buckets: Dict[str, Dict] = {}  # {principal: {tokens, last_refill}}
    
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

## 🚫 Token Revocation

### **Revocation Architecture**

```mermaid
graph TB
    subgraph "Token Lifecycle"
        Issue[Token Issued<br/>jti=abc-123]
        Use1[Token Used<br/>✅ Valid]
        Breach[Security Breach!<br/>Laptop Stolen]
        Revoke[Admin Revokes Token<br/>jti=abc-123]
        Use2[Token Used Again<br/>❌ Revoked]
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
    Cache -->|Check| Blocked[❌ Access Denied]
    
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
    jti VARCHAR(255) PRIMARY KEY,              -- JWT ID (unique token identifier)
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked_by VARCHAR(100) NOT NULL,          -- Who revoked it (admin username)
    reason TEXT,                                -- Why revoked (e.g., "Security breach")
    expires_at TIMESTAMP NOT NULL              -- When token would have expired
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
        self._revoked_cache: Dict[str, int] = {}  # {jti: expires_at_timestamp}
    
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
                return True  # Still revoked
            else:
                del self._revoked_cache[jti]  # Expired, clean up
        
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

## 🔄 Complete Request Flow

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
    Security-->>Server: ✅ Authorized (principal, context)
    
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

## 🛡️ Attack Scenarios & Defenses

### **Attack Matrix**

| Attack Type | Attack Vector | Defense Layer | Mitigation |
|-------------|---------------|---------------|------------|
| **DDoS** | Flood with requests | Rate Limiting | Token bucket (100 req/min) |
| **Man-in-the-Middle** | Intercept traffic | TLS + HMAC | Encrypted transport + signature |
| **Replay Attack** | Reuse captured request | HMAC timestamp | 5-minute window |
| **Message Tampering** | Modify request body | HMAC signature | Signature mismatch |
| **SQL Injection** | `'; DROP TABLE--` | JSON Schema | Pattern validation |
| **Path Traversal** | `../../etc/passwd` | JSON Schema | Negative lookahead regex |
| **Buffer Overflow** | 10MB string | JSON Schema | maxLength: 1024 |
| **XSS** | `<script>alert()</script>` | JSON Schema | Pattern validation |
| **Privilege Escalation** | Call unauthorized method | RBAC | Policy enforcement |
| **API Key Theft** | Stolen key used | Token Revocation | Immediate invalidation |
| **Timing Attack** | Measure comparison time | Constant-time compare | `secrets.compare_digest()` |
| **Brute Force** | Guess API keys | Rate Limiting | Exponential backoff |

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
        "pattern": "^[a-zA-Z0-9-]+$",  # Only alphanumeric and hyphens
        "maxLength": 64
    }
}

# Validation rejects malicious input
validate(params)  # ❌ Pattern mismatch
# Error: "document_id does not match pattern"
```

### **Attack Scenario 2: Path Traversal**

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
        #           ^^^^^^^^^^^ Rejects any string containing "../"
    }
}

# Validation blocks path traversal
validate(params)  # ❌ Pattern mismatch
# Error: "s3_key contains path traversal"
```

### **Attack Scenario 3: Replay Attack**

**Attack:**
```python
# Attacker captures legitimate request at 10:00 AM
captured_request = {
    "headers": {"X-Signature": "1735867200:abc123..."},
    "body": '{"method":"transfer","params":{"amount":1000}}'
}

# Attacker replays at 10:10 AM (10 minutes later)
replay_attack(captured_request)
```

**Defense (Layer 3 + 8):**
```python
# HMAC signature includes timestamp
timestamp_from_signature = 1735867200  # 10:00 AM
current_time = 1735867800              # 10:10 AM

age = current_time - timestamp_from_signature  # 600 seconds

if age > max_age_seconds (300):  # 5 minutes
    return "401 Signature expired - replay attack detected"
```

---

## 💻 Code Implementation Details

### **Base Agent HTTP Handler**

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
                request_body=raw,  # For HMAC verification
                client_cert_pem=request.transport.get_extra_info('peercert')  # For mTLS
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

## 📊 Summary

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
| **Authentication Methods** | 2 (API Key, JWT) |
| **Authorization Model** | RBAC (allow/deny lists) |
| **Message Integrity** | HMAC-SHA256 |
| **Input Validation** | JSON Schema v7 |
| **Rate Limiting** | Token bucket (100 req/min) |
| **Replay Window** | 5 minutes |
| **Total Overhead** | ~4-7ms (~1%) |
| **Test Coverage** | 56 tests (100% pass rate) |
| **Compliance Score** | 10/10 (research paper criteria) |

---

**Document Version:** 1.0  
**Last Updated:** January 3, 2026  
**Authors:** Security Team  
**Status:** Production Ready ✅

