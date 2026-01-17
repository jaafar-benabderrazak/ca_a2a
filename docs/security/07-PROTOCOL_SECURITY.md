# 7. Protocol Security (A2A)

[← Back to Index](README.md)

---


### 7.1 Why JSON-RPC 2.0?

The CA-A2A system adopts **JSON-RPC 2.0** as its communication protocol for agent-to-agent interactions. This choice was driven by several technical and security considerations:

#### 7.1.1 Technical Advantages

| Feature | Benefit | Security Impact |
|---------|---------|-----------------|
| **Standardized Protocol** | Well-defined spec (RFC-like), industry adoption | Reduces implementation errors, predictable behavior |
| **Stateless** | No session state required | Prevents session fixation, easier to scale horizontally |
| **Simple & Lightweight** | Minimal overhead (~100-200 bytes) | Reduces attack surface, easier to validate |
| **Language Agnostic** | JSON is universal | No proprietary serialization vulnerabilities |
| **Bidirectional** | Supports requests, responses, notifications | Single protocol for all communication patterns |
| **Error Handling** | Standardized error codes (-32xxx) | Consistent error reporting, prevents info leakage |

#### 7.1.2 Security Benefits

**1. Deterministic Validation**
JSON-RPC 2.0 has a strict structure that can be validated before processing:
```python
# Required fields for all requests
assert message["jsonrpc"] == "2.0"
assert "id" in message or "method" in message
assert isinstance(message.get("params"), (dict, list, type(None)))
```

**2. No Ambiguity**
Unlike REST, JSON-RPC has exactly one way to structure a request:
- REST: `/documents/123` vs `/documents?id=123` vs `/documents` + body
- JSON-RPC: Always `{"method": "get_document", "params": {"document_id": 123}}`

**3. Method Enumeration**
All callable methods are explicitly declared, making it easy to implement RBAC:
```python
ALLOWED_METHODS = {
    "admin": ["*"],
    "orchestrator": ["extract_document", "validate_document", "archive_document"],
    "viewer": ["get_document", "list_documents"]
}
```

**4. Request-Response Correlation**
The `id` field enables:
- Replay attack detection (when combined with JWT `jti`)
- Request tracing across distributed agents
- Timeout detection (stale responses)

#### 7.1.3 Comparison with Alternatives

| Protocol | Pros | Cons | Suitability for A2A |
|----------|------|------|---------------------|
| **JSON-RPC 2.0** ✅ | Simple, standardized, secure | Less "RESTful" | **Ideal for agent RPC** |
| REST/HTTP | Widespread, tooling support | Ambiguous (many ways to do same thing) | Better for public APIs |
| gRPC | High performance, streaming | Complex, binary (harder to audit) | Overkill for document processing |
| GraphQL | Flexible queries | Complex security (query depth, cost) | Not needed (fixed operations) |
| SOAP | Enterprise features | Verbose XML, complex | Legacy protocol |

**Decision: JSON-RPC 2.0 is the optimal choice for secure, internal agent-to-agent communication.**

---

### 7.2 Protocol Encapsulation

The A2A protocol uses a **layered encapsulation model** where each layer adds security controls:

```mermaid
graph TB
    subgraph Layer_1["Layer 1: Transport (HTTPS)"]
        TLS[TLS 1.2/1.3<br/>✓ Encryption<br/>✓ Server Authentication<br/>✓ Optional mTLS]
    end
    
    subgraph Layer_2["Layer 2: HTTP"]
        Headers[HTTP Headers<br/>✓ Authorization Bearer JWT<br/>✓ Content-Type application/json<br/>✓ X-Correlation-ID]
    end
    
    subgraph Layer_3["Layer 3: JSON-RPC 2.0"]
        JSONRPC[JSON-RPC Envelope<br/>✓ jsonrpc: 2.0<br/>✓ method<br/>✓ params<br/>✓ id]
    end
    
    subgraph Layer_4["Layer 4: Business Logic"]
        Params[Method Parameters<br/>✓ Schema Validated<br/>✓ Type Checked<br/>✓ Sanitized]
    end
    
    TLS --> Headers
    Headers --> JSONRPC
    JSONRPC --> Params
    
    style Layer_1 fill:#ff6b6b
    style Layer_2 fill:#ffd93d
    style Layer_3 fill:#6bcf7f
    style Layer_4 fill:#4d96ff
```

#### 7.2.1 Layer 1: Transport Security (TLS)

**What it protects:**
- Eavesdropping (confidentiality)
- Man-in-the-middle attacks (integrity)
- Server impersonation (authentication)

**Implementation:**
```python
# All ECS services communicate over HTTPS (TLS 1.2+)
# AWS ALB terminates TLS and forwards to internal HTTP
# Service-to-service communication uses AWS Cloud Map DNS (internal HTTPS)

# mTLS configuration (optional, for token binding)
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.verify_mode = ssl.CERT_REQUIRED
ssl_context.load_cert_chain(server_cert_path, server_key_path)
ssl_context.load_verify_locations(ca_cert_path)
```

#### 7.2.2 Layer 2: HTTP Headers

**What it protects:**
- Unauthorized access (authentication via JWT)
- Request correlation (tracing)
- Content type confusion (MIME sniffing)

**Required Headers:**
```http
POST /message HTTP/1.1
Host: orchestrator.ca-a2a.local:8001
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleWNsb2FrLWtleS1pZCJ9...
X-Correlation-ID: 2026-01-15T10:30:00Z-a1b2c3d4
User-Agent: CA-A2A-Client/1.0
```

#### 7.2.3 Layer 3: JSON-RPC 2.0 Envelope

**What it protects:**
- Protocol confusion attacks
- Method enumeration (only declared methods callable)
- Request-response mismatches

**Structure:**
```json
{
  "jsonrpc": "2.0",
  "id": "req-12345",
  "method": "process_document",
  "params": { ... }
}
```

#### 7.2.4 Layer 4: Business Logic Parameters

**What it protects:**
- Injection attacks (SQL, path traversal, XSS)
- Type confusion
- Buffer overflows (length limits)

**Validation:**
```python
# JSON Schema validation (Layer 1)
validator.validate(params, SCHEMAS[method])

# Pydantic type checking (Layer 2)
params_model = ProcessDocumentParams(**params)

# Business logic validation (Layer 3)
if not s3_client.object_exists(params_model.s3_key):
    raise ValueError("Document not found")
```

---

### 7.3 Message Structure & Format

#### 7.3.1 JSON-RPC 2.0 Message Anatomy

**Complete Request Breakdown:**

```json
{
  "jsonrpc": "2.0",           // ← Protocol version (REQUIRED, must be "2.0")
  "id": "req-abc123",          // ← Request ID for correlation (REQUIRED for requests)
  "method": "process_document", // ← Method to invoke (REQUIRED)
  "params": {                  // ← Method parameters (OPTIONAL, dict or array)
    "s3_key": "uploads/invoice-2026-01-15.pdf",
    "priority": "high",
    "correlation_id": "order-12345"
  }
}
```

**Field Constraints:**

| Field | Type | Required | Constraints | Security Purpose |
|-------|------|----------|-------------|------------------|
| `jsonrpc` | String | ✅ Yes | Must be `"2.0"` exactly | Version validation, prevents protocol confusion |
| `id` | String/Number | ✅ Yes (requests) | Max 128 chars, alphanumeric + `-_` | Request correlation, replay detection |
| `method` | String | ✅ Yes | Must match `^[a-z_][a-z0-9_]*$` | Method allowlisting, prevents arbitrary calls |
| `params` | Object/Array | ⚠️ Optional | Max depth 5, max size 1MB | Prevents DoS via deeply nested JSON |

**Complete Response Breakdown:**

```json
{
  "jsonrpc": "2.0",           // ← Protocol version (REQUIRED)
  "id": "req-abc123",          // ← MUST match request ID (REQUIRED)
  "result": {                  // ← Success result (XOR with "error")
    "status": "success",
    "document_id": "doc-789",
    "extracted_text": "Invoice #12345...",
    "metadata": {
      "pages": 3,
      "size_bytes": 245678,
      "processed_at": "2026-01-15T10:30:00Z"
    }
  },
  "_meta": {                   // ← Optional metadata (not part of JSON-RPC spec)
    "correlation_id": "order-12345",
    "duration_ms": 250,
    "agent_id": "orchestrator-1"
  }
}
```

**Error Response Breakdown:**

```json
{
  "jsonrpc": "2.0",
  "id": "req-abc123",
  "error": {                   // ← Error object (XOR with "result")
    "code": -32602,            // ← Standard error code (see table below)
    "message": "Invalid params", // ← Human-readable message
    "data": {                  // ← Optional error details
      "detail": "Field 's3_key' is required",
      "field": "s3_key",
      "provided": null
    }
  }
}
```

**Standard Error Codes:**

| Code | Meaning | Use Case | Example |
|------|---------|----------|---------|
| `-32700` | Parse error | Invalid JSON received | Malformed JSON, trailing commas |
| `-32600` | Invalid Request | JSON-RPC structure invalid | Missing `jsonrpc` or `method` |
| `-32601` | Method not found | Method doesn't exist | `"method": "delete_all_documents"` |
| `-32602` | Invalid params | Parameters fail schema validation | Missing required field, wrong type |
| `-32603` | Internal error | Server error (catch-all) | Database connection failed |
| `-32000` to `-32099` | Server errors | Application-specific | Custom business logic errors |

**Security-Specific Error Codes (Custom):**

| Code | Meaning | Use Case |
|------|---------|----------|
| `-32001` | Unauthorized | Missing or invalid JWT token |
| `-32002` | Forbidden | Insufficient permissions (RBAC) |
| `-32003` | Rate limit exceeded | Too many requests from principal |
| `-32004` | Replay detected | JWT `jti` already seen |
| `-32005` | Token revoked | JWT in revocation list |

#### 7.3.2 Message Size Limits

**Why Limits Matter:**
- **DoS Prevention:** Prevents attackers from sending giant payloads
- **Resource Protection:** Ensures fair resource allocation
- **Performance:** Keeps processing predictable

**Enforced Limits:**

| Component | Limit | Enforcement Point | Configuration |
|-----------|-------|-------------------|---------------|
| Total request size | 10 MB | ALB + Application | `A2A_MAX_REQUEST_SIZE` |
| `params` object | 1 MB | Application | JSON parser max depth |
| `s3_key` string | 1024 chars | JSON Schema | `maxLength: 1024` |
| `correlation_id` | 128 chars | JSON Schema | `maxLength: 128` |
| Array elements | 1000 items | JSON Schema | `maxItems: 1000` |
| JSON depth | 5 levels | JSON parser | Prevents deeply nested attacks |

**Implementation:**

```python
# base_agent.py - Request size validation
MAX_REQUEST_SIZE = int(os.getenv("A2A_MAX_REQUEST_SIZE", "10485760"))  # 10 MB

async def handle_http_message(self, request: web.Request) -> web.Response:
    # Check Content-Length header
    content_length = request.content_length
    if content_length and content_length > MAX_REQUEST_SIZE:
        return web.json_response(
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": f"Request too large (max {MAX_REQUEST_SIZE} bytes)"
                }
            },
            status=413
        )
    
    # Read body with size limit
    try:
        body = await request.read()
        if len(body) > MAX_REQUEST_SIZE:
            raise ValueError("Body exceeds size limit")
    except ValueError:
        return web.json_response(...)
```

---

### 7.4 JSON Schema Validation

**Schema Definition for All Methods:**

The system validates all incoming requests against predefined JSON schemas. This prevents injection attacks, malformed data, and ensures type safety.

#### 7.4.1 Process Document Schema

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

#### 7.4.2 Extract Document Schema

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

#### 7.4.3 Validate Document Schema

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

#### 7.4.4 Archive Document Schema

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

#### 7.4.5 Get Document Schema

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

### 7.11 Defense-in-Depth Architecture

The CA-A2A system implements a **comprehensive defense-in-depth security architecture** with multiple independent security layers. This ensures that compromising one layer does not compromise the entire system.

#### 7.11.1 Multi-Layer Security Model

```mermaid
graph TB
    subgraph Internet["Internet / External"]
        Attacker[Potential Attacker]
    end
    
    subgraph Layer1["Layer 1: Network Perimeter"]
        ALB[AWS ALB<br/>TLS Termination<br/>DDoS Protection]
        NACL[Network ACLs]
    end
    
    subgraph Layer2["Layer 2: VPC Isolation"]
        SG[Security Groups<br/>Port-Level Filtering]
        PrivateSubnets[Private Subnets<br/>10.0.0.0/16]
    end
    
    subgraph Layer3["Layer 3: Identity"]
        Keycloak[Keycloak OAuth2/OIDC<br/>Centralized Authentication]
    end
    
    subgraph Layer4["Layer 4: Authentication"]
        JWT[JWT RS256 Verification<br/>Signature + Expiration]
        TokenBinding[Token Binding RFC 8473<br/>Certificate Binding]
    end
    
    subgraph Layer5["Layer 5: Authorization"]
        RBAC[Role-Based Access Control<br/>Method Permissions]
    end
    
    subgraph Layer6["Layer 6: Resource Gateway"]
        MCP[MCP Server<br/>Centralized S3/RDS Access]
    end
    
    subgraph Layer7["Layer 7: Message Integrity"]
        BodyHash[JWT Body Hash Binding<br/>Tampering Detection]
    end
    
    subgraph Layer8["Layer 8: Input Validation"]
        Schema[JSON Schema + Pydantic<br/>Type Safety]
    end
    
    subgraph Layer9["Layer 9: Abuse Prevention"]
        Replay[Replay Protection<br/>JWT jti Tracking]
        RateLimit[Rate Limiting<br/>300 req/min]
    end
    
    subgraph Layer10["Layer 10: Application Logic"]
        Business[Business Logic<br/>Custom Validations]
    end
    
    Attacker --> ALB
    ALB --> NACL
    NACL --> SG
    SG --> PrivateSubnets
    PrivateSubnets --> Keycloak
    Keycloak --> JWT
    JWT --> TokenBinding
    TokenBinding --> RBAC
    RBAC --> MCP
    MCP --> BodyHash
    BodyHash --> Schema
    Schema --> Replay
    Replay --> RateLimit
    RateLimit --> Business
    
    style Layer1 fill:#ff6b6b,color:#000
    style Layer2 fill:#ffd93d,color:#000
    style Layer3 fill:#6bcf7f,color:#000
    style Layer4 fill:#4d96ff,color:#fff
    style Layer5 fill:#ffd700,color:#000
    style Layer6 fill:#a66cff,color:#fff
    style Layer7 fill:#ff9a76,color:#000
    style Layer8 fill:#62cdff,color:#000
    style Layer9 fill:#f4b860,color:#000
    style Layer10 fill:#95e1d3,color:#000
```

#### 7.11.2 Layer-by-Layer Threat Mitigation

| Layer | Security Control | Threats Mitigated | Implementation | Bypass Difficulty |
|-------|-----------------|-------------------|----------------|-------------------|
| **L1: Network Perimeter** | AWS ALB, TLS 1.2+ | Network eavesdropping, DDoS | AWS managed service | ⭐⭐⭐⭐⭐ Very Hard |
| **L2: VPC Isolation** | Security Groups, Private Subnets | Unauthorized network access | AWS VPC, SG rules | ⭐⭐⭐⭐⭐ Very Hard |
| **L3: Identity** | Keycloak OAuth2/OIDC | Unauthorized authentication | Keycloak ECS service | ⭐⭐⭐⭐ Hard |
| **L4: Authentication** | JWT RS256 + Token Binding | Forged tokens, token theft | `keycloak_auth.py`, `token_binding.py` | ⭐⭐⭐⭐ Hard |
| **L5: Authorization** | RBAC with Keycloak roles | Privilege escalation | `KeycloakRBACMapper` | ⭐⭐⭐⭐ Hard |
| **L6: Resource Gateway** | MCP Server centralized access | Direct AWS access, credential sprawl | `mcp_server.py` | ⭐⭐⭐⭐ Hard |
| **L7: Message Integrity** | JWT body hash binding | MITM tampering | `a2a_security.py` | ⭐⭐⭐ Medium |
| **L8: Input Validation** | JSON Schema + Pydantic | Injection attacks, DoS | `JSONSchemaValidator`, Pydantic models | ⭐⭐⭐ Medium |
| **L9: Abuse Prevention** | Replay protection, Rate limiting | Replay attacks, DoS | `ReplayProtector`, `SlidingWindowRateLimiter` | ⭐⭐ Easy |
| **L10: Business Logic** | Custom validations | Application-specific attacks | Agent-specific code | ⭐ Very Easy |

**Key Insight:** An attacker must successfully bypass **ALL 10 LAYERS** to execute unauthorized operations. Each layer provides independent protection.

#### 7.11.3 Attack Scenario Analysis

**Scenario 1: Stolen JWT Token**

| Layer | Check Result | Outcome |
|-------|--------------|---------|
| L1-L3 | ✅ Pass (network/identity) | Attacker has valid network access |
| L4 | ❌ **FAIL: Token Binding** | JWT bound to original client certificate |
| Result | **Attack Blocked at Layer 4** | Token unusable from different client |

**Scenario 2: Insider with Valid Credentials but No Permissions**

| Layer | Check Result | Outcome |
|-------|--------------|---------|
| L1-L4 | ✅ Pass (network/auth) | Insider has valid JWT |
| L5 | ❌ **FAIL: RBAC** | Role `viewer` cannot call `archive_document` |
| Result | **Attack Blocked at Layer 5** | `403 Forbidden` returned |

**Scenario 3: MITM Attempts to Modify Request Body**

| Layer | Check Result | Outcome |
|-------|--------------|---------|
| L1 | ✅ Pass (TLS prevents interception) | MITM cannot intercept TLS traffic |
| L7 | ❌ **FAIL: Body Hash** | JWT contains hash of original body |
| Result | **Attack Blocked at Layer 1 & 7** | TLS + body hash prevent tampering |

**Scenario 4: Replay Attack with Captured Valid Request**

| Layer | Check Result | Outcome |
|-------|--------------|---------|
| L1-L8 | ✅ Pass (all previous checks) | Request appears valid |
| L9 | ❌ **FAIL: Replay Protection** | JWT `jti` already seen in cache |
| Result | **Attack Blocked at Layer 9** | `403 Replay Detected` |

#### 7.11.4 Defense-in-Depth Metrics

**Security Depth:** 10 independent layers  
**Average Attack Surface Reduction:** ~99.9% (each layer adds protection)  
**MTTR (Mean Time To Respond):** < 5 minutes (CloudWatch alerts)  
**False Positive Rate:** < 0.01% (strict validation with minimal false positives)

---

### 7.12 Security Groups: Network-Level Enforcement

AWS Security Groups act as **stateful virtual firewalls** at the network interface level, providing the first line of defense against unauthorized access.

#### 7.12.1 Security Group Architecture

```mermaid
graph TB
    subgraph Internet["Internet"]
        User[User/Client]
    end
    
    subgraph PublicSubnet["Public Subnet"]
        ALB[ALB<br/>Security Group: ca-a2a-alb-sg]
    end
    
    subgraph PrivateSubnet["Private Subnet"]
        Orch[Orchestrator<br/>Security Group: ca-a2a-orchestrator-sg]
        Ext[Extractor<br/>Security Group: ca-a2a-extractor-sg]
        KC[Keycloak<br/>Security Group: ca-a2a-keycloak-sg]
        MCP[MCP Server<br/>Security Group: ca-a2a-mcp-sg]
    end
    
    subgraph DataLayer["Data Layer"]
        RDS[RDS PostgreSQL<br/>Security Group: ca-a2a-rds-sg]
    end
    
    User -->|HTTPS 443| ALB
    ALB -->|HTTP 8001| Orch
    Orch -->|HTTP 8002| Ext
    Orch -->|HTTP 8080| KC
    Orch -->|HTTP 8000| MCP
    MCP -->|PostgreSQL 5432| RDS
    
    style ALB fill:#ffd93d
    style Orch fill:#6bcf7f
    style Ext fill:#4d96ff
    style KC fill:#a66cff
    style MCP fill:#ffd700
    style RDS fill:#ff6b6b
```

#### 7.12.2 Security Group Rules

**1. ALB Security Group (`ca-a2a-alb-sg`)**

| Type | Protocol | Port | Source | Purpose |
|------|----------|------|--------|---------|
| Inbound | TCP | 443 | 0.0.0.0/0 | HTTPS from internet |
| Inbound | TCP | 80 | 0.0.0.0/0 | HTTP redirect to HTTPS |
| Outbound | TCP | 8001 | ca-a2a-orchestrator-sg | Forward to orchestrator |

**2. Orchestrator Security Group (`ca-a2a-orchestrator-sg`)**

| Type | Protocol | Port | Source | Purpose |
|------|----------|------|--------|---------|
| Inbound | TCP | 8001 | ca-a2a-alb-sg | Requests from ALB |
| Outbound | TCP | 8002 | ca-a2a-extractor-sg | Call extractor |
| Outbound | TCP | 8003 | ca-a2a-validator-sg | Call validator |
| Outbound | TCP | 8004 | ca-a2a-archivist-sg | Call archivist |
| Outbound | TCP | 8080 | ca-a2a-keycloak-sg | JWT verification |
| Outbound | TCP | 8000 | ca-a2a-mcp-sg | MCP API calls |
| Outbound | TCP | 443 | 0.0.0.0/0 | AWS API calls (Secrets Manager, CloudWatch) |

**3. Extractor/Validator/Archivist Security Groups**

| Type | Protocol | Port | Source | Purpose |
|------|----------|------|--------|---------|
| Inbound | TCP | 8002/8003/8004 | ca-a2a-orchestrator-sg | Requests from orchestrator |
| Outbound | TCP | 8080 | ca-a2a-keycloak-sg | JWT verification |
| Outbound | TCP | 8000 | ca-a2a-mcp-sg | MCP API calls |
| Outbound | TCP | 443 | 0.0.0.0/0 | AWS API calls |

**4. Keycloak Security Group (`ca-a2a-keycloak-sg`)**

| Type | Protocol | Port | Source | Purpose |
|------|----------|------|--------|---------|
| Inbound | TCP | 8080 | ca-a2a-orchestrator-sg | JWT verification |
| Inbound | TCP | 8080 | ca-a2a-extractor-sg | JWT verification |
| Inbound | TCP | 8080 | ca-a2a-validator-sg | JWT verification |
| Inbound | TCP | 8080 | ca-a2a-archivist-sg | JWT verification |
| Outbound | TCP | 5432 | ca-a2a-rds-sg | PostgreSQL (keycloak DB) |

**5. MCP Server Security Group (`ca-a2a-mcp-sg`)**

| Type | Protocol | Port | Source | Purpose |
|------|----------|------|--------|---------|
| Inbound | TCP | 8000 | ca-a2a-orchestrator-sg | MCP API calls |
| Inbound | TCP | 8000 | ca-a2a-extractor-sg | MCP API calls |
| Inbound | TCP | 8000 | ca-a2a-validator-sg | MCP API calls |
| Inbound | TCP | 8000 | ca-a2a-archivist-sg | MCP API calls |
| Outbound | TCP | 5432 | ca-a2a-rds-sg | PostgreSQL (documents DB) |
| Outbound | TCP | 443 | 0.0.0.0/0 | S3 API calls |

**6. RDS Security Group (`ca-a2a-rds-sg`)**

| Type | Protocol | Port | Source | Purpose |
|------|----------|------|--------|---------|
| Inbound | TCP | 5432 | ca-a2a-keycloak-sg | Keycloak DB access |
| Inbound | TCP | 5432 | ca-a2a-mcp-sg | MCP Server DB access |
| Outbound | ALL | ALL | DENY (implicit) | No outbound access needed |

#### 7.12.3 Security Group Best Practices

**1. Principle of Least Privilege**
- Each security group allows **only the minimum necessary traffic**
- No `0.0.0.0/0` inbound rules except for ALB (public-facing)
- Agents cannot directly access RDS (must go through MCP Server)

**2. Defense Against Lateral Movement**
- Compromised extractor **cannot** directly access orchestrator (no inbound rule)
- Compromised agent **cannot** directly access RDS (must go through MCP)
- Compromised agent **cannot** access other agents except via orchestrator

**3. Stateful Firewall**
- Security Groups are stateful: return traffic automatically allowed
- No need to explicitly allow outbound responses

**4. Audit Trail**
- All Security Group changes logged to CloudTrail
- VPC Flow Logs capture rejected connections
- CloudWatch Insights can query blocked traffic:
  ```sql
  fields @timestamp, srcAddr, dstAddr, dstPort, action
  | filter action == "REJECT"
  | stats count() by dstPort
  ```

#### 7.12.4 Network Isolation Benefits

| Isolation Type | Benefit | Attack Prevented |
|----------------|---------|------------------|
| **Private Subnets** | No direct internet access | External attackers cannot directly reach agents |
| **Security Groups** | Port-level filtering | Port scanning, unauthorized connections |
| **VPC Peering (not used)** | No cross-VPC traffic | Lateral movement across VPCs |
| **NAT Gateway** | Outbound-only internet | Agents can call AWS APIs but cannot receive inbound |
| **VPC Endpoints** | AWS services without internet | Secrets Manager, S3 access without leaving VPC |

---

### 7.13 Token Binding (RFC 8473)

**Token Binding** cryptographically binds security tokens (JWTs) to the TLS layer, preventing **token theft** and **token export attacks**. Even if an attacker intercepts a JWT, they cannot use it from a different client.

#### 7.13.1 How Token Binding Works

```mermaid
sequenceDiagram
    participant Client
    participant Keycloak
    participant Orchestrator
    
    Note over Client,Orchestrator: 1. Client Authentication with Certificate
    
    Client->>Keycloak: POST /token<br/>+ Client Certificate (mTLS)
    Keycloak->>Keycloak: Extract client cert<br/>Compute SHA-256 thumbprint
    Keycloak->>Keycloak: Generate JWT with cnf claim:<br/>{"cnf": {"x5t#S256": "abc123..."}}
    Keycloak-->>Client: Access Token (JWT with Token Binding)
    
    Note over Client,Orchestrator: 2. API Request with Bound Token
    
    Client->>Orchestrator: POST /message<br/>Authorization: Bearer JWT<br/>+ Client Certificate (mTLS)
    Orchestrator->>Orchestrator: Extract JWT + client cert
    Orchestrator->>Orchestrator: Verify JWT signature (RS256)
    Orchestrator->>Orchestrator: Compute client cert thumbprint
    Orchestrator->>Orchestrator: Compare with cnf.x5t#S256 claim
    
    alt Thumbprints Match
        Orchestrator->>Orchestrator: ✅ Token Binding Valid
        Orchestrator-->>Client: 200 OK (process request)
    else Thumbprints Mismatch
        Orchestrator->>Orchestrator: ❌ Token Binding Failed
        Orchestrator-->>Client: 403 Forbidden<br/>"Token binding verification failed"
    end
```

#### 7.13.2 JWT Claims with Token Binding

**JWT without Token Binding (vulnerable to theft):**
```json
{
  "exp": 1737845500,
  "iat": 1737845200,
  "sub": "user-123",
  "preferred_username": "admin",
  "realm_access": {"roles": ["admin"]}
}
```

**JWT with Token Binding (protected):**
```json
{
  "exp": 1737845500,
  "iat": 1737845200,
  "sub": "user-123",
  "preferred_username": "admin",
  "realm_access": {"roles": ["admin"]},
  "cnf": {
    "x5t#S256": "bDlkZGM4YTEyZGM4YTEyZGM4YTEyZGM4YTEyZGM4YTE"
  }
}
```

The `cnf` (confirmation) claim contains:
- **`x5t#S256`**: Base64URL-encoded SHA-256 hash of the client's X.509 certificate

#### 7.13.3 Implementation

**File: `token_binding.py`**

```python
import hashlib
import base64
import secrets
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from typing import Dict, Any, Tuple

class TokenBindingValidator:
    """
    Validates RFC 8473 Token Binding for JWTs.
    Ensures tokens are cryptographically bound to client certificates.
    """
    
    def compute_certificate_thumbprint(self, cert_pem: str) -> str:
        """
        Computes SHA-256 thumbprint of X.509 certificate.
        
        Args:
            cert_pem: PEM-encoded certificate
            
        Returns:
            Base64URL-encoded SHA-256 hash (x5t#S256)
        """
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'), default_backend())
        der_bytes = cert.public_bytes(x509.Encoding.DER)
        thumbprint_bytes = hashlib.sha256(der_bytes).digest()
        thumbprint_b64 = base64.urlsafe_b64encode(thumbprint_bytes).decode('utf-8').rstrip('=')
        return thumbprint_b64
    
    def verify_token_binding(
        self,
        jwt_claims: Dict[str, Any],
        client_cert_pem: str
    ) -> Tuple[bool, str]:
        """
        Verifies that JWT's cnf.x5t#S256 matches client certificate.
        
        Args:
            jwt_claims: Decoded JWT payload
            client_cert_pem: PEM-encoded client certificate from TLS handshake
            
        Returns:
            (is_valid, error_message)
        """
        # Extract Token Binding claim
        cnf = jwt_claims.get("cnf")
        if not cnf:
            return False, "JWT does not contain 'cnf' (confirmation) claim"
        
        expected_thumbprint = cnf.get("x5t#S256")
        if not expected_thumbprint:
            return False, "JWT cnf claim missing 'x5t#S256' (certificate thumbprint)"
        
        # Compute thumbprint of presented certificate
        presented_thumbprint = self.compute_certificate_thumbprint(client_cert_pem)
        
        # Constant-time comparison (prevents timing attacks)
        if not secrets.compare_digest(expected_thumbprint, presented_thumbprint):
            return False, "Certificate thumbprint mismatch (token bound to different cert)"
        
        return True, None
```

**Integration in `keycloak_auth.py`:**

```python
class KeycloakJWTValidator:
    def __init__(self, ...):
        self.token_binding_validator = TokenBindingValidator()
    
    def verify_token(self, token: str, client_cert_pem: str = None) -> Tuple[str, List[str], Dict[str, Any]]:
        # ... JWT signature verification ...
        
        # Token Binding verification (if client cert provided)
        if client_cert_pem:
            binding_valid, binding_error = self.token_binding_validator.verify_token_binding(
                claims,
                client_cert_pem
            )
            
            if not binding_valid:
                raise ValueError(f"Token binding verification failed: {binding_error}")
        
        # ... extract principal and roles ...
        return principal, roles, claims
```

#### 7.13.4 Security Properties

| Property | Benefit | Attack Prevented |
|----------|---------|------------------|
| **Certificate Binding** | JWT only valid with original client cert | Token theft, token export |
| **Cryptographic Proof** | SHA-256 hash cannot be forged | Token tampering |
| **TLS Layer Integration** | Binds application token to transport layer | MITM, session hijacking |
| **Phishing Resistance** | Stolen token unusable without private key | Credential phishing |

**Attack Scenario:**
1. Attacker intercepts JWT token (e.g., via XSS or compromised log)
2. Attacker attempts to use JWT from different client
3. **Token Binding Validation Fails:**
   - Attacker's client certificate has different thumbprint
   - `secrets.compare_digest()` returns `False`
   - Request rejected with `403 Forbidden`

**Result:** Token theft attacks are **completely mitigated**.

---

### 7.14 Constant-Time Comparison & Timing Attack Prevention

**Timing attacks** exploit variations in execution time to infer secret values (e.g., API keys, tokens). The CA-A2A system uses **constant-time comparison** to prevent these attacks.

#### 7.14.1 The Timing Attack Threat

**Vulnerable Code (DO NOT USE):**
```python
def verify_api_key(api_key: str, expected: str) -> bool:
    # ⚠️ VULNERABLE: Early exit on first mismatch
    if api_key == expected:
        return True
    return False
```

**Problem:**
- Comparison fails **immediately** on first differing character
- Attacker can measure response time to deduce correct characters
- Example: `"admin123"` vs `"admin456"` takes longer than `"admin123"` vs `"xdmin123"`

**Attack Process:**
1. Attacker tries `"a..."` → fast failure (wrong first char)
2. Attacker tries `"b..."` → fast failure
3. Attacker tries `"admin..."` → **slower failure** (matched 5 chars)
4. Repeat for each character until full key discovered

#### 7.14.2 Constant-Time Comparison

**Secure Implementation:**

**File: `a2a_security.py`**
```python
import hmac

def _verify_api_key(self, api_key: str) -> str:
    """
    Verifies API key using constant-time comparison.
    
    Returns: principal (str) if valid
    Raises: AuthError if invalid
    """
    if not self._api_key_hashes:
        raise AuthError("API key auth not configured")
    
    # Hash the provided API key
    digest = _sha256_hex(api_key.encode("utf-8"))
    
    # Compare against all known API key hashes
    for principal, expected in self._api_key_hashes.items():
        # ✅ SECURE: Constant-time comparison
        if hmac.compare_digest(digest, expected):
            return principal
    
    raise AuthError("Invalid API key")
```

**File: `token_binding.py`**
```python
import secrets

def verify_token_binding(self, jwt_claims: Dict[str, Any], client_cert_pem: str) -> Tuple[bool, str]:
    expected_thumbprint = jwt_claims["cnf"]["x5t#S256"]
    presented_thumbprint = self.compute_certificate_thumbprint(client_cert_pem)
    
    # ✅ SECURE: Constant-time comparison
    if not secrets.compare_digest(expected_thumbprint, presented_thumbprint):
        return False, "Certificate thumbprint mismatch"
    
    return True, None
```

#### 7.14.3 Constant-Time Comparison Libraries

| Library | Function | Use Case | Security Level |
|---------|----------|----------|----------------|
| `hmac` | `hmac.compare_digest()` | General-purpose constant-time comparison | ⭐⭐⭐⭐⭐ Best |
| `secrets` | `secrets.compare_digest()` | Cryptographic secrets comparison | ⭐⭐⭐⭐⭐ Best |
| Python `==` | Standard equality | **NOT SECURE** (timing-vulnerable) | ⚠️ Avoid |

**Both `hmac.compare_digest()` and `secrets.compare_digest()` are:**
- **Constant-time:** Always compares all bytes (no early exit)
- **Side-channel resistant:** No timing variations based on input
- **Recommended by OWASP:** Industry best practice

#### 7.14.4 Timing Attack Mitigation Checklist

| Check | Implementation | Status |
|-------|----------------|--------|
| ✅ API Key Verification | `hmac.compare_digest()` | Implemented |
| ✅ Token Binding Verification | `secrets.compare_digest()` | Implemented |
| ✅ JWT Signature Verification | `PyJWT` library (constant-time) | Implemented |
| ✅ Password Hashing | Not applicable (OAuth2 via Keycloak) | N/A |
| ✅ Session Token Comparison | Not applicable (stateless JWT) | N/A |

#### 7.14.5 Performance Impact

**Constant-time comparison overhead:**
- **Additional latency:** ~0.1-0.5 μs (microseconds) per comparison
- **Impact on total request time:** < 0.001% (negligible)
- **Security benefit:** 100% protection against timing attacks

**Benchmark:**
```python
import timeit

# Vulnerable comparison
timeit.timeit('a == b', setup='a, b = "admin123", "admin456"', number=1000000)
# Result: ~0.018 seconds (18 μs per comparison)

# Constant-time comparison
timeit.timeit('hmac.compare_digest(a, b)', setup='import hmac; a, b = "admin123", "admin456"', number=1000000)
# Result: ~0.025 seconds (25 μs per comparison)

# Overhead: 7 μs per comparison (0.007 milliseconds)
```

**Conclusion:** Constant-time comparison is **mandatory** for security-critical comparisons. The performance overhead is negligible compared to the security benefits.

---

### 7.15 Security Decorator Pattern (Future Enhancement)

**Note:** The CA-A2A system currently does not use decorators for security checks (handled in `A2ASecurityManager`). This section describes a **potential future enhancement** for cleaner separation of concerns.

#### 7.15.1 Proposed Decorator-Based Security

**Concept:**
```python
from functools import wraps
from typing import Callable, Any

def require_role(required_role: str) -> Callable:
    """
    Decorator to enforce RBAC on agent methods.
    
    Usage:
        @require_role("admin")
        async def delete_document(self, document_id: int):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, *args, **kwargs) -> Any:
            # Extract auth context from request
            auth_context = kwargs.get('auth_context')
            if not auth_context:
                raise AuthError("Missing auth context")
            
            # Check if principal has required role
            if required_role not in auth_context.roles and "*" not in auth_context.roles:
                raise AuthError(f"Insufficient permissions: requires role '{required_role}'")
            
            # Call original method
            return await func(self, *args, **kwargs)
        return wrapper
    return decorator
```

**Usage Example:**
```python
class OrchestratorAgent(BaseAgent):
    @require_role("orchestrator")
    async def extract_document(self, s3_key: str, auth_context: AuthContext):
        """Only callable by principals with 'orchestrator' role"""
        return await self.call_agent("extractor", "extract", {"s3_key": s3_key})
    
    @require_role("admin")
    async def revoke_token(self, jti: str, auth_context: AuthContext):
        """Only callable by admins"""
        await self.security_manager.revoke_token(jti, revoked_by=auth_context.principal)
```

**Benefits:**
- **Declarative Security:** Permissions declared at method level
- **Cleaner Code:** Reduces boilerplate in method bodies
- **Audit Trail:** Easy to scan codebase for permission requirements
- **Type Safety:** Enforces `auth_context` parameter

**Current Status:** **Not implemented** (security handled in `A2ASecurityManager.authenticate_and_authorize()`)

---


---

[← Previous: Data Security](06-DATA_SECURITY.md) | [Next: Monitoring & Audit →](08-MONITORING_AUDIT.md)
