# CA-A2A Protocol Security

**Version:** 6.0  
**Last Updated:** January 17, 2026

---

## JSON-RPC 2.0 Protocol

### Why JSON-RPC 2.0?

✅ **Standardized:** Well-defined spec, predictable behavior  
✅ **Simple:** Minimal overhead (~100-200 bytes)  
✅ **Secure:** Deterministic validation, no ambiguity  
✅ **Language Agnostic:** JSON is universal  
✅ **Error Handling:** Standardized error codes

---

## Message Structure

### Request Format

```json
{
  "jsonrpc": "2.0",
  "id": "req-abc123",
  "method": "process_document",
  "params": {
    "s3_key": "uploads/invoice.pdf",
    "priority": "high"
  }
}
```

### Response Format

```json
{
  "jsonrpc": "2.0",
  "id": "req-abc123",
  "result": {
    "status": "success",
    "document_id": "doc-789"
  }
}
```

### Error Format

```json
{
  "jsonrpc": "2.0",
  "id": "req-abc123",
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {"detail": "Field 's3_key' is required"}
  }
}
```

---

## Security Controls

### 1. JSON Schema Validation

**Purpose:** Reject malformed input

**Example Schema:**
```json
{
  "type": "object",
  "properties": {
    "s3_key": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9/_-][a-zA-Z0-9/_.-]*$",
      "maxLength": 1024
    }
  },
  "required": ["s3_key"],
  "additionalProperties": false
}
```

**Security Features:**
- Path traversal protection (`../` blocked)
- Length limits (prevent DoS)
- Type safety (string vs number)
- No additional properties (prevent mass assignment)

### 2. Message Integrity (Body Hash Binding)

**Purpose:** Detect tampering

**Implementation:**
```python
# Compute SHA-256 hash of request body
body_hash = hashlib.sha256(json.dumps(params).encode()).hexdigest()

# Add to JWT claims
jwt_claims = {
    "body_hash": body_hash,
    ...
}

# Verify on agent side
expected_hash = jwt_claims["body_hash"]
actual_hash = hashlib.sha256(request.body).hexdigest()
if not secrets.compare_digest(expected_hash, actual_hash):
    raise ValueError("Body tampering detected")
```

### 3. Replay Protection

**Purpose:** Prevent request duplication

**Implementation:**
```python
# Check JWT jti (unique token ID)
jti = jwt_claims["jti"]
if await replay_protector.is_seen(jti):
    raise ValueError("Replay attack detected")

# Mark as seen (TTL: 120 seconds)
await replay_protector.mark_seen(jti, ttl=120)
```

### 4. Rate Limiting

**Purpose:** Prevent abuse

**Configuration:**
- **Limit:** 300 requests per minute per principal
- **Algorithm:** Sliding window
- **Response:** `429 Too Many Requests`

---

## Constant-Time Comparison

**Purpose:** Prevent timing attacks

**Implementation:**
```python
import hmac
import secrets

# API Key verification
if hmac.compare_digest(provided_digest, expected_digest):
    return True

# Token binding verification
if secrets.compare_digest(token_thumbprint, cert_thumbprint):
    return True
```

**Why?** Standard `==` comparison fails fast on first mismatch, leaking information via timing.

---

## Error Codes

| Code | Meaning | Use Case |
|------|---------|----------|
| `-32700` | Parse error | Invalid JSON |
| `-32600` | Invalid Request | Missing required fields |
| `-32601` | Method not found | Unknown method |
| `-32602` | Invalid params | Schema validation failed |
| `-32603` | Internal error | Server error |
| `-32001` | Unauthorized | Invalid JWT |
| `-32002` | Forbidden | Insufficient permissions |
| `-32003` | Rate limit exceeded | Too many requests |
| `-32004` | Replay detected | Duplicate jti |
| `-32005` | Token revoked | Revoked token used |

---

**Related:** [Security Layers](SECURITY_LAYERS_DEFENSE_IN_DEPTH.md), [Authentication](AUTHENTICATION_AUTHORIZATION.md)
