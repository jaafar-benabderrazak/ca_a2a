# 2. Security Layers (Defense-in-Depth)

[← Back to Index](README.md)

---


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

### 2.3 Complete Request Security Flow

**Single Request Journey Through All 9 Layers:**

```mermaid
sequenceDiagram
    participant User as User/Client
    participant ALB as ALB
    participant Orch as Orchestrator
    participant KC as Keycloak
    participant MCP as MCP Server
    participant RDS as RDS PostgreSQL
    participant S3 as S3 Bucket

    Note over User,S3: Complete Security Journey

    User->>ALB: 1. HTTPS Request + JWT
    
    rect rgb(255, 107, 107)
    Note over ALB: L1: Network Isolation<br/>✓ VPC Security Groups<br/>✓ TLS Termination
    end
    
    ALB->>Orch: 2. Forward to Orchestrator
    
    rect rgb(255, 217, 61)
    Note over Orch: L2: Identity Check<br/>✓ JWT Present in Header?<br/>✓ Valid Format?
    end
    
    Orch->>KC: 3. Fetch JWKS Public Keys
    KC-->>Orch: Public Keys (cached 1h)
    
    rect rgb(107, 207, 127)
    Note over Orch: L3: Authentication<br/>✓ Verify JWT RS256 Signature<br/>✓ Check Expiration (exp)<br/>✓ Validate Issuer/Audience
    end
    
    rect rgb(77, 150, 255)
    Note over Orch: L4: Authorization<br/>✓ Extract Keycloak Roles<br/>✓ Map to RBAC Principal<br/>✓ Check Method Permission
    end
    
    Orch->>MCP: 4. Call MCP Server API
    
    rect rgb(255, 215, 0)
    Note over MCP: L5: Resource Access Control<br/>✓ Centralized Gateway<br/>✓ Circuit Breaker Check<br/>✓ Connection Pool Management
    end
    
    MCP->>RDS: 5. Query Database
    RDS-->>MCP: Query Results
    
    MCP->>S3: 6. Access S3 Objects
    S3-->>MCP: Object Data
    
    MCP-->>Orch: 7. Return Results
    
    rect rgb(166, 108, 255)
    Note over Orch: L6: Message Integrity<br/>✓ Verify JWT Body Hash<br/>✓ Detect Tampering
    end
    
    rect rgb(255, 154, 118)
    Note over Orch: L7: Input Validation<br/>✓ JSON Schema Check<br/>✓ Pydantic Type Safety<br/>✓ Path Traversal Protection
    end
    
    rect rgb(98, 205, 255)
    Note over Orch: L8: Replay Protection<br/>✓ Check JWT jti in Cache<br/>✓ Mark as Used (TTL 120s)<br/>✓ Reject Duplicates
    end
    
    rect rgb(244, 184, 96)
    Note over Orch: L9: Rate Limiting<br/>✓ Check Request Count<br/>✓ 300 req/min per Principal<br/>✓ Sliding Window Algorithm
    end
    
    Note over Orch: ✅ All Checks Passed<br/>Execute Business Logic
    
    Orch-->>ALB: 8. JSON-RPC Response
    ALB-->>User: 9. HTTPS Response
    
    Note over User,S3: Request Complete: 9 Layers Validated
```

**Layer-by-Layer Security Checkpoints:**

| Layer | Checkpoint | Pass Criteria | Failure Response |
|-------|-----------|---------------|------------------|
| **L1** | Network Entry | Request from allowed IP/VPC | Connection refused |
| **L2** | Identity Presence | JWT in `Authorization: Bearer` header | 401 Unauthorized |
| **L3** | Authentication | Valid JWT signature, not expired | 401 Invalid Token |
| **L4** | Authorization | Principal has permission for method | 403 Forbidden |
| **L5** | Resource Access | MCP Server circuit breaker closed | 503 Service Unavailable |
| **L6** | Message Integrity | JWT body hash matches request | 403 Tampering Detected |
| **L7** | Input Validation | Schema valid, no injection attempts | 400 Invalid Params (-32602) |
| **L8** | Replay Protection | JWT jti not seen before | 403 Replay Detected |
| **L9** | Rate Limiting | Under 300 requests/minute | 429 Rate Limit Exceeded |
| **✅** | **Business Logic** | Application-specific validation | 200 OK or error |

**Security Guarantees:**

- 🛡️ **Defense-in-Depth**: Each layer provides independent protection
- 🔒 **Fail-Secure**: All checks must pass; any failure rejects request
- 📊 **Observable**: Each layer logs decisions to CloudWatch
- ⚡ **Performance**: Total security overhead ~53ms (21% of total request)
- 🔄 **No Single Point of Failure**: Compromising one layer doesn't bypass others

---


---

[← Previous: System Architecture](01-SYSTEM_ARCHITECTURE.md) | [Next: Authentication & Authorization →](03-AUTHENTICATION_AUTHORIZATION.md)
