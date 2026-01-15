# Présentation : Architecture de Sécurité CA-A2A

**Titre :** Architecture de Sécurité du Système Multi-Agents CA-A2A  
**Audience :** Experts Techniques (Architectes, Ingénieurs Sécurité, DevSecOps)  
**Durée :** 60 minutes + 15 minutes Q&A  
**Présentateur :** [Votre Nom]  
**Date :** 15 Janvier 2026  
**Version Document :** 5.1  
**Basé sur :** A2A_SECURITY_ARCHITECTURE.md v5.1

---

## 📋 Table des Matières

**Structure Alignée avec A2A_SECURITY_ARCHITECTURE.md**

1. [Introduction](#1-introduction) (5 min)
2. [Section 1: System Architecture](#2-system-architecture) (8 min)
3. [Section 2: Security Layers](#3-security-layers) (8 min)
4. [Section 3: Authentication & Authorization](#4-authentication--authorization) (8 min)
5. [Section 4: Resource Access Layer (MCP Server)](#5-resource-access-layer-mcp-server) (6 min)
6. [Section 5: Network Security](#6-network-security) (5 min)
7. [Section 6: Data Security](#7-data-security) (3 min)
8. [Section 7: Protocol Security (A2A)](#8-protocol-security-a2a) (8 min)
9. [Section 8: Monitoring & Audit](#9-monitoring--audit) (4 min)
10. [Section 9: Threat Model & Defenses](#10-threat-model--defenses) (3 min)
11. [Conclusion](#11-conclusion) (2 min)

**Durée Totale : 75 minutes (60 min présentation + 15 min Q&A)**

---

## 1. Introduction (5 minutes)

### 1.1 Ouverture

**[SLIDE 1 - Titre]**

> "Bonjour à tous. Aujourd'hui, je vais vous présenter l'architecture de sécurité du système CA-A2A version 5.1, un système multi-agents déployé sur AWS ECS Fargate qui implémente 9 couches de sécurité indépendantes."

**Points Clés :**
- Production : AWS ECS Fargate, région eu-west-3 (Paris)
- Architecture : 5 agents + Keycloak + MCP Server
- Conformité : ISO 27001, SOC 2
- Approche : Defense-in-Depth avec Zero-Trust

### 1.2 Structure de la Présentation

**[SLIDE 2 - Structure]**

> "Cette présentation suit exactement la structure du document A2A_SECURITY_ARCHITECTURE.md. Chaque section correspond à une section du document technique."

**11 Sections :**

| Section | Contenu | Temps |
|---------|---------|-------|
| **1** | System Architecture | 8 min |
| **2** | Security Layers (9 couches) | 8 min |
| **3** | Authentication & Authorization | 8 min |
| **4** | Resource Access Layer (MCP) | 6 min |
| **5** | Network Security | 5 min |
| **6** | Data Security | 3 min |
| **7** | Protocol Security (A2A) | 8 min |
| **8** | Monitoring & Audit | 4 min |
| **9** | Threat Model & Defenses | 3 min |
| **10** | Security Operations | 3 min |
| **11** | Conclusion | 2 min |

**Transition :** "Commençons par la Section 1 : System Architecture..."

---

## 2. System Architecture (8 minutes) → **Section 1 du document**

### 2.1 Production Deployment (Doc Section 1.1)

**[SLIDE 3 - Architecture Diagram]**

> "Voici l'architecture complète de production. Elle correspond exactement au diagramme de la Section 1.1 du document."

```
🌐 Internet
   ↓ HTTPS (TLS 1.2+)
📊 ALB (Application Load Balancer)
   ↓ HTTP (VPC Privé)
🎯 Orchestrator :8001
   ↓ A2A Protocol (JWT)
┌─────────────────────┐
│ Extractor    :8002  │
│ Validator    :8003  │ ← Agents Métier
│ Archivist    :8004  │
└─────────────────────┘
        ↓ HTTP API
   🔐 MCP Server :8000 ← Gateway de Ressources
        ↓
   ┌────────────┐
   │ RDS Aurora │ ← Données
   │ S3 Bucket  │
   │ Keycloak   │ ← IAM
   └────────────┘
```

### 2.2 Component Overview (Doc Section 1.2)

**[SLIDE 4 - Component Inventory]**

**Tableau des Composants (Doc Table 1.2) :**

| Component | Type | Port | Purpose | Instances |
|-----------|------|------|---------|-----------|
| **Orchestrator** | ECS Fargate | 8001 | Request coordination | 2 |
| **Extractor** | ECS Fargate | 8002 | Document extraction | 2 |
| **Validator** | ECS Fargate | 8003 | Content validation | 2 |
| **Archivist** | ECS Fargate | 8004 | Document archival | 2 |
| **Keycloak** | ECS Fargate | 8080 | OAuth2/OIDC Provider | 1 |
| **MCP Server** | ECS Fargate | 8000 | Resource Gateway | 1 |
| **ALB** | AWS Service | 80/443 | Load balancing | Multi-AZ |
| **RDS Aurora** | Managed DB | 5432 | Document metadata | Multi-AZ |
| **RDS Postgres** | Managed DB | 5432 | Keycloak data | Multi-AZ |

**Message Clé :** 

> "Tous les agents dans des subnets privés. Seul l'ALB expose un point d'entrée public."

**Transition :** "Voyons maintenant les 9 couches de sécurité (Section 2)..."

---

## 3. Security Layers (8 minutes) → **Section 2 du document**

### 3.1 Defense-in-Depth Architecture (Doc Section 2.1)

**[SLIDE 5 - 9 Security Layers Diagram]**

> "Le document définit 9 couches indépendantes. Voici le diagramme exact de la Section 2.1."

```
Layer 1: Network Isolation (VPC, SG, NACLs)
    ↓
Layer 2: Identity & Access (Keycloak OAuth2/OIDC)
    ↓
Layer 3: Authentication (JWT RS256 Verification)
    ↓
Layer 4: Authorization (RBAC with Keycloak Roles)
    ↓
Layer 5: Resource Access Control (MCP Server Gateway) ⭐ NOUVEAU v5.0
    ↓
Layer 6: Message Integrity (JWT Body Hash Binding)
    ↓
Layer 7: Input Validation (JSON Schema, Pydantic) ⭐ NOUVEAU v5.1
    ↓
Layer 8: Replay Protection (JWT jti Tracking)
    ↓
Layer 9: Rate Limiting (300 req/min per Principal)
```

### 3.2 Layer Responsibilities (Doc Section 2.2)

**[SLIDE 6 - Layer Responsibilities Table]**

**Tableau du Document (Section 2.2) :**

| Layer | Purpose | Technology | Threat Mitigated |
|-------|---------|------------|------------------|
| **L1** | Isolation, segmentation | VPC, SG, NACL | Network attacks, DDoS |
| **L2** | Centralized authentication | Keycloak | Unauthorized access |
| **L3** | Token verification | JWT RS256 | Impersonation, forged tokens |
| **L4** | Permission enforcement | RBAC | Privilege escalation |
| **L5** | Centralized S3/RDS gateway | **MCP Server** | Direct AWS access, credential sprawl |
| **L6** | Message tampering detection | JWT body hash | MITM, tampering |
| **L7** | Malformed input rejection | JSON Schema, Pydantic | Injection attacks, DoS |
| **L8** | Duplicate request detection | JWT jti + TTL cache | Replay attacks |
| **L9** | Abuse prevention | Sliding window | Resource exhaustion, DoS |

### 3.3 Complete Request Security Flow (Doc Section 2.3)

**[SLIDE 7 - Visual Security Flow]**

> "Le document Section 2.3 montre le parcours complet d'une requête. Voici le diagramme simplifié pour la présentation."

**Points de Contrôle par Couche (Doc Table 2.3) :**

| Couche | Contrôle | Critère Pass | Réponse Échec |
|--------|----------|--------------|---------------|
| **L1** | Réseau | IP/VPC autorisée | Connection refused |
| **L2** | Identité | JWT présent | 401 Unauthorized |
| **L3** | Auth | Signature RS256 valide | 401 Invalid Token |
| **L4** | Authz | Rôle RBAC correct | 403 Forbidden |
| **L5** | Ressources | MCP opérationnel | 503 Service Unavailable |
| **L6** | Intégrité | Hash match | 403 Tampering |
| **L7** | Validation | Schema valide | 400 Invalid Params |
| **L8** | Replay | jti unique | 403 Replay Detected |
| **L9** | Rate | < 300/min | 429 Rate Limit |

**Transition :** "Détaillons l'authentification (Section 3)..."

---

## 4. Authentication & Authorization (8 minutes) → **Section 3 du document**

### 4.1 Keycloak OAuth2/OIDC Flow (Doc Section 3.1)

**[SLIDE 8 - Keycloak Flow Diagram]**

> "Le diagramme de la Section 3.1 montre le flux complet Keycloak."

**Étapes :**

1. **Client → Keycloak** : POST /token avec {client_id, client_secret}
2. **Keycloak → Client** : Retourne JWT (access_token + refresh_token)
3. **Client → Orchestrator** : Request avec Authorization: Bearer JWT
4. **Orchestrator → Keycloak** : Vérifie JWT via JWKS
5. **Orchestrator** : Extrait roles, map RBAC, check permissions
6. **Orchestrator → Agent** : Forward request si autorisé

### 4.2 JWT Token Structure (Doc Section 3.2)

**[SLIDE 9 - JWT Structure]**

**Structure du Document :**

```json
{
  "header": {"alg": "RS256", "typ": "JWT", "kid": "keycloak-key-id"},
  "payload": {
    "exp": 1737845500,
    "iat": 1737845200,
    "jti": "abc123-token-id",
    "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
    "aud": "ca-a2a-agents",
    "sub": "user-uuid-1234",
    "realm_access": {
      "roles": ["admin", "orchestrator", "document-processor"]
    }
  }
}
```

**Claims Clés :**
- `exp`: Expiration (TTL 5 minutes)
- `jti`: JWT ID (pour replay protection)
- `realm_access.roles`: Rôles Keycloak

### 4.3 Role-Based Access Control (Doc Section 3.3)

**[SLIDE 10 - RBAC Mapping Table]**

**Tableau du Document (Section 3.3) :**

| Keycloak Role | A2A Principal | Allowed Methods | Use Case |
|---------------|---------------|-----------------|----------|
| `admin` | `admin` | `*` (all methods) | Full system access |
| `lambda` | `lambda` | `upload_document`, `process_document` | S3 events |
| `orchestrator` | `orchestrator` | `extract_document`, `validate_document`, `archive_document` | Agent coordination |
| `document-processor` | `document-processor` | `process_document`, `list_pending_documents`, `check_status` | Processing workflows |
| `viewer` | `viewer` | `list_documents`, `get_document`, `check_status` | Read-only |

### 4.4 Token Revocation (Doc Section 3.4)

**[SLIDE 11 - Hybrid Revocation Architecture]**

**Architecture du Document :**

```
Admin API
    ↓
1. Write to Cache (In-Memory) → ~1μs
2. Persist to PostgreSQL → ~10ms
    ↓
Request Validation
    ↓
1. Check Cache (99% hits) → ~1μs
2. If miss, check DB → ~10ms
3. Populate cache → Next check fast
```

**Table Schema (Doc Section 3.4) :**

```sql
CREATE TABLE revoked_tokens (
    jti VARCHAR(255) PRIMARY KEY,
    revoked_at TIMESTAMP,
    revoked_by VARCHAR(100),
    reason TEXT,
    expires_at TIMESTAMP
);
```

**Transition :** "Passons au MCP Server (Section 4)..."

---

## 5. Resource Access Layer - MCP Server (6 minutes) → **Section 4 du document**

### 5.1 Architecture Overview (Doc Section 4.1)

**[SLIDE 12 - MCP Server Gateway]**

> "La Section 4 du document introduit le MCP Server, la 5ème couche de sécurité."

**Avant (v4.0) vs Après (v5.0) :**

```
❌ AVANT:
Orchestrator ──┐
Extractor   ──┼──> RDS (80 connexions)
Validator   ──┤    S3  (4 IAM roles)
Archivist   ──┘

✅ MAINTENANT:
Orchestrator ──┐
Extractor   ──┼──> MCP Server :8000 ──> RDS (10 connexions)
Validator   ──┤                      └──> S3  (1 IAM role)
Archivist   ──┘
```

### 5.2 Security Benefits (Doc Section 4.2)

**[SLIDE 13 - Security Benefits Table]**

**Tableau du Document (Section 4.2) :**

| Benefit | Description | Impact |
|---------|-------------|--------|
| **Reduced Attack Surface** | Only MCP has AWS credentials | -75% IAM roles |
| **Centralized Audit** | All S3/RDS access in one place | +100% visibility |
| **Connection Pooling** | Shared PostgreSQL pool (max 10) | -88% DB connections |
| **Consistent Security** | Uniform retry, circuit breakers | Standardized |
| **Easier IAM Management** | Single task role to update | -4 policy updates/change |
| **Credential Isolation** | Agents never see passwords | Reduced sprawl |

### 5.3 Available Operations (Doc Section 4.4)

**[SLIDE 14 - MCP API Examples]**

**S3 Operations (Doc examples) :**

```bash
# List objects
POST /call_tool {"tool": "s3_list_objects", "arguments": {"prefix": "uploads/"}}

# Get object
POST /call_tool {"tool": "s3_get_object", "arguments": {"key": "doc.pdf"}}

# Put object
POST /call_tool {"tool": "s3_put_object", "arguments": {"key": "...", "body": "..."}}
```

**PostgreSQL Operations :**

```bash
# Query
POST /call_tool {"tool": "postgres_query", "arguments": {"query": "SELECT...", "params": []}}

# Execute
POST /call_tool {"tool": "postgres_execute", "arguments": {"query": "INSERT...", "params": []}}
```

**Transition :** "Voyons la sécurité réseau (Section 5)..."

---

## 6. Network Security (5 minutes) → **Section 5 du document**

### 6.1 VPC Architecture (Doc Section 5.1 renumbered as 4.1 in doc)

**[SLIDE 15 - VPC Layout]**

**Architecture du Document :**

```
VPC: 10.0.0.0/16
├── Public Subnets
│   ├── 10.0.1.0/24 (AZ-a) - ALB, NAT
│   └── 10.0.2.0/24 (AZ-b) - ALB
└── Private Subnets
    ├── 10.0.10.0/24 (AZ-a) - ECS Tasks
    └── 10.0.20.0/24 (AZ-b) - ECS Tasks, RDS
```

**Security Implications :**
- ✅ Zero public IPs on agents
- ✅ Outbound only via NAT
- ✅ Multi-AZ redundancy
- ✅ Private DNS (service discovery)

### 6.2 Security Groups (Doc Section 5.2 renumbered as 4.2)

**[SLIDE 16 - Security Groups Rules]**

**Tableau du Document :**

| Security Group | Inbound Rules | Purpose |
|----------------|---------------|---------|
| **ALB-SG** | 80/443 from 0.0.0.0/0 | Public HTTP/HTTPS |
| **Orchestrator-SG** | 8001 from ALB-SG | ALB → Orchestrator only |
| **Extractor-SG** | 8002 from Orch-SG | Orchestrator → Extractor |
| **Validator-SG** | 8003 from Orch-SG | Orchestrator → Validator |
| **Archivist-SG** | 8004 from Orch-SG | Orchestrator → Archivist |
| **Keycloak-SG** | 8080 from Agent-SGs | All agents → Keycloak |
| **MCP-SG** | 8000 from Agent-SGs | All agents → MCP |
| **RDS-SG** | 5432 from MCP-SG + KC-SG | Database access |

**Default Deny:** Toutes les SG ont implicit deny-all.

### 6.3 VPC Endpoints (Doc Section 5.3 renumbered as 4.3)

**[SLIDE 17 - VPC Endpoints Table]**

**Tableau du Document :**

| Service | Type | Purpose |
|---------|------|---------|
| **ecr.api** | Interface | Pull container images |
| **ecr.dkr** | Interface | Docker registry auth |
| **s3** | Gateway | S3 object storage |
| **logs** | Interface | CloudWatch Logs |
| **secretsmanager** | Interface | Secrets Manager |

**Bénéfice :** Trafic reste dans le réseau AWS (pas d'internet public).

**Transition :** "Parlons du chiffrement des données (Section 6)..."

---

## 7. Data Security (3 minutes) → **Section 6 du document**

### 7.1 Encryption at Rest (Doc Section 6.1 renumbered as 5.1)

**[SLIDE 18 - Encryption at Rest Table]**

**Tableau du Document :**

| Resource | Encryption | Key Management |
|----------|-----------|----------------|
| **RDS Aurora** | AES-256 | AWS KMS (default) |
| **RDS Postgres (Keycloak)** | AES-256 | AWS KMS (default) |
| **S3 Bucket** | SSE-S3 (AES-256) | AWS-managed |
| **EBS Volumes** | AES-256 | AWS KMS (default) |
| **Secrets Manager** | AES-256 | AWS KMS (dedicated) |
| **CloudWatch Logs** | AES-256 | AWS-managed |

### 7.2 Encryption in Transit (Doc Section 6.2 renumbered as 5.2)

**[SLIDE 19 - Encryption in Transit]**

**État Actuel (du Document) :**

- ✅ User → ALB: HTTPS (TLS 1.2+)
- ⚠️ ALB → Orchestrator: HTTP (dans VPC) - Risque faible
- ⚠️ Agent-to-Agent: HTTP (dans VPC) - Protégé par JWT
- ✅ Agents → RDS: TLS 1.2 (asyncpg avec SSL)
- ✅ Agents → AWS Services: HTTPS (boto3 default)

**Recommandation du Document :** Activer TLS entre ALB et agents pour defense-in-depth.

### 7.3 Secrets Management (Doc Section 6.3 renumbered as 5.3)

**[SLIDE 20 - Secrets Manager]**

**Secrets du Document :**

| Secret Name | Purpose | Rotation |
|-------------|---------|----------|
| `ca-a2a/db-password` | RDS Aurora master | Manual |
| `ca-a2a/keycloak-admin-password` | Keycloak admin | Manual |
| `ca-a2a/keycloak-db-password` | Keycloak RDS | Manual |
| `ca-a2a/keycloak-client-secret` | OAuth2 client | Manual |

**Aucun secret hardcodé** - Tous récupérés au runtime.

**Transition :** "Détaillons le protocole A2A (Section 7)..."

---

## 8. Protocol Security (A2A) (8 minutes) → **Section 7 du document**

### 8.1 JSON-RPC 2.0 Format (Doc Section 7.1)

**[SLIDE 21 - JSON-RPC Format]**

**Format du Document :**

```json
// Request
{
  "jsonrpc": "2.0",
  "id": "req-12345",
  "method": "process_document",
  "params": {"document_id": "doc-789", "s3_key": "uploads/invoice.pdf"}
}

// Response
{
  "jsonrpc": "2.0",
  "id": "req-12345",
  "result": {"status": "success", ...},
  "_meta": {"correlation_id": "...", "duration_ms": 250}
}
```

### 8.2 HTTP Headers Schema (Doc Section 7.2)

**[SLIDE 22 - Required Headers Table]**

**Tableau du Document (Section 7.2) :**

| Header | Type | Required | Description | Example |
|--------|------|----------|-------------|---------|
| `Content-Type` | String | ✅ Yes | Must be `application/json` | `application/json` |
| `Authorization` | String | ✅ Yes | Bearer JWT from Keycloak | `Bearer eyJhbGc...` |
| `X-Correlation-ID` | String | ⚠️ Optional | Request tracing ID | `2026-01-15T10:30:00Z...` |
| `User-Agent` | String | ⚠️ Optional | Client identifier | `CA-A2A-Client/1.0` |

### 8.3 JSON Schema Validation (Doc Section 7.3)

**[SLIDE 23 - JSON Schema Example]**

**Schema du Document (Section 7.3.1) :**

```json
// process_document schema
{
  "type": "object",
  "properties": {
    "s3_key": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9/_-][a-zA-Z0-9/_.-]*$",
      "not": {"pattern": "\\.\\."},  // ✓ Bloque ../
      "minLength": 1,
      "maxLength": 1024
    },
    "priority": {
      "type": "string",
      "enum": ["low", "normal", "high"]
    }
  },
  "required": ["s3_key"],
  "additionalProperties": false
}
```

**Sécurité :**
- ✅ Path traversal protection (`..` bloqué)
- ✅ Length limits (max 1024)
- ✅ No additional properties (mass assignment prevention)

### 8.4 Pydantic Models (Doc Section 7.4)

**[SLIDE 24 - Pydantic Example]**

**Code du Document (Section 7.4.1) :**

```python
class ProcessDocumentRequest(BaseModel):
    s3_key: str = Field(..., min_length=1, max_length=1024)
    priority: Literal["low", "normal", "high"] = Field(default="normal")
    
    @field_validator('s3_key')
    @classmethod
    def validate_s3_key(cls, v: str) -> str:
        if ".." in v:
            raise ValueError("Path traversal not allowed")
        if not v[0].isalnum():
            raise ValueError("Must start with alphanumeric")
        return v.strip()
```

**Double Validation :** JSON Schema (standard) + Pydantic (type-safe Python)

### 8.5 Content Validation Rules (Doc Section 7.5)

**[SLIDE 25 - Validation Flow Diagram]**

**6 Couches de Validation (du Document) :**

```
1. HTTP Headers → Valid?
2. JSON Parsing → Valid syntax?
3. JSON-RPC Structure → jsonrpc, id, method present?
4. JSON Schema → Pattern, type, length valid?
5. Pydantic Model → Type-safe, custom validators?
6. Business Rules → Application logic valid?
    ↓
Execute Method
```

**Statistiques Production (du Document) :**
- ~400 injections bloquées par jour
- 95% des erreurs détectées avant code métier

### 8.6 Error Code Reference (Doc Section 7.6)

**[SLIDE 26 - Error Codes Table]**

**Codes du Document (Section 7.6) :**

**JSON-RPC 2.0 Standard :**

| Code | Meaning | Trigger |
|------|---------|---------|
| `-32700` | Parse error | Invalid JSON syntax |
| `-32600` | Invalid Request | Missing jsonrpc field |
| `-32601` | Method not found | Unknown method |
| `-32602` | Invalid params | Schema/type validation failed |
| `-32603` | Internal error | Server exception |

**Security Custom :**

| Code | Meaning | Trigger |
|------|---------|---------|
| `-32010` | Unauthorized | JWT invalid/expired |
| `-32011` | Forbidden | RBAC insufficient |
| `-32012` | Rate limit exceeded | > 300 req/min |
| `-32013` | Replay detected | Duplicate jti |
| `-32014` | Token revoked | Blacklisted JWT |

**Transition :** "Voyons le monitoring (Section 8)..."

---

## 9. Monitoring & Audit (4 minutes) → **Section 8 du document**

### 9.1 CloudWatch Logs (Doc Section 8.1)

**[SLIDE 27 - Log Groups Table]**

**Tableau du Document :**

| Log Group | Purpose | Retention |
|-----------|---------|-----------|
| `/ecs/ca-a2a-orchestrator` | Orchestrator logs | 7 days |
| `/ecs/ca-a2a-extractor` | Extractor logs | 7 days |
| `/ecs/ca-a2a-validator` | Validator logs | 7 days |
| `/ecs/ca-a2a-archivist` | Archivist logs | 7 days |
| `/ecs/ca-a2a-keycloak` | Keycloak logs | 7 days |
| `/ecs/ca-a2a-mcp-server` | MCP Server logs | 7 days |

**Format Structuré (JSON) :**

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

### 9.2 Security Events Logged (Doc Section 8.2)

**[SLIDE 28 - Security Events Table]**

**Événements du Document :**

| Event Type | Trigger | Log Level |
|------------|---------|-----------|
| `authentication_success` | Valid JWT | INFO |
| `authentication_failure` | Invalid JWT | WARN |
| `authorization_failure` | Insufficient permissions | WARN |
| `rate_limit_exceeded` | Too many requests | WARN |
| `replay_detected` | Duplicate jti | WARN |
| `token_revoked` | Revoked token used | WARN |
| `invalid_input` | Schema validation failed | WARN |
| `method_executed` | Successful call | INFO |

**Queries CloudWatch Insights disponibles dans le document.**

### 9.3 Metrics Recommandées (Doc Section 8.3)

**[SLIDE 29 - Metrics Table]**

**Métriques du Document :**

| Metric | Unit | Dimensions | Purpose |
|--------|------|------------|---------|
| `RequestLatency` | Milliseconds | Agent, Method | Performance |
| `ErrorCount` | Count | Agent, ErrorType | Error tracking |
| `RequestCount` | Count | Agent | Throughput |
| `AuthenticationFailures` | Count | Agent | Security monitoring |
| `RateLimitViolations` | Count | Principal | Abuse detection |
| `TokenRevocationChecks` | Count | Agent | Revocation usage |

**Transition :** "Analysons le modèle de menaces (Section 9)..."

---

## 10. Threat Model & Defenses (3 minutes) → **Section 9 du document**

### 10.1 STRIDE Analysis (Doc Section 9.1)

**[SLIDE 30 - STRIDE Table]**

**Tableau du Document :**

| Threat | Attack Vector | Defense Layer | Mitigation |
|--------|---------------|---------------|------------|
| **Spoofing** | Impersonate agent/user | L2, L3 | Keycloak + JWT RS256 |
| **Tampering** | Modify request/response | L6 | JWT body hash |
| **Repudiation** | Deny actions | L8 | Audit logs with correlation IDs |
| **Information Disclosure** | Intercept traffic | L1, Data | VPC isolation + TLS |
| **Denial of Service** | Flood requests | L7, L9 | Input validation + rate limiting |
| **Elevation of Privilege** | Bypass RBAC | L4 | Keycloak roles + RBAC enforcement |

### 10.2 Key Attack Scenarios (Doc Section 9.2)

**[SLIDE 31 - Attack Scenarios Summary]**

**18 Scénarios Détaillés dans le Document :**

1. **Token Theft** → Défense : TTL 5 min, révocation, replay protection
2. **Replay Attack** → Défense : jti tracking, TTL cache
3. **Privilege Escalation** → Défense : RBAC enforcement, audit logs
4. **DDoS** → Défense : Rate limiting 300/min, ALB Shield, auto-scaling
5. **SQL Injection** → Défense : Parameterized queries, JSON Schema, Pydantic
6. **MITM** → Défense : VPC isolation, JWT signature, TLS
7. **JWT Algorithm Confusion** → Défense : Algorithm enforcement (RS256 only)
8. **Keycloak Compromise** → Défense : Strong password, network isolation, MFA
9. **Agent Impersonation** → Défense : Service discovery, JWT audience check, SG
10. **Time-Based Attacks** → Défense : Clock skew tolerance (30s), freshness check

...et 8 autres scénarios détaillés dans A2A_ATTACK_SCENARIOS_DETAILED.md

**Transition :** "Terminons avec la conclusion..."

---

## 11. Conclusion (2 minutes)

### 11.1 Récapitulatif

**[SLIDE 32 - Key Takeaways]**

**5 Messages Clés (alignés avec le document) :**

1. **Defense-in-Depth avec 9 Couches**
   - Chaque couche protège indépendamment
   - Pas de single point of failure
   - Conformité ISO 27001, SOC 2

2. **Keycloak Centralisé = Zero Trust**
   - OAuth2/OIDC avec JWT RS256
   - TTL court (5 minutes) + rotation
   - Révocation hybride (cache + DB)

3. **MCP Server = Game Changer Sécurité**
   - -88% connexions DB, -75% IAM roles
   - Audit centralisé, circuit breakers
   - Overhead acceptable (~25%)

4. **Validation Multi-Couches (v5.1)**
   - JSON Schema + Pydantic = double sécurité
   - Bloque ~400 injections/jour en production
   - 95% des erreurs détectées avant code métier

5. **Observabilité Poussée**
   - Logs structurés JSON avec correlation IDs
   - CloudWatch Insights queries
   - Incident response automatisé

### 11.2 Documentation Complète

**[SLIDE 33 - Resources]**

**Documentation Technique :**

1. **Architecture de Sécurité (ce document)**
   - `A2A_SECURITY_ARCHITECTURE.md` (2,577 lignes)
   - Version 5.1, à jour au 15/01/2026
   - 11 sections couvrant tous les aspects

2. **Scénarios d'Attaque Détaillés**
   - `A2A_ATTACK_SCENARIOS_DETAILED.md` (1,625 lignes)
   - 18 scénarios avec diagrammes Mermaid
   - Exemples code vulnérable → sécurisé

3. **Guide d'Implémentation MCP Server**
   - `MCP_SERVER_IMPLEMENTATION_GUIDE.md` (575 lignes)
   - Instructions de déploiement
   - Troubleshooting complet

4. **Présentation Technique (ce document)**
   - `PRESENTATION_ARCHITECTURE_SECURITE.md`
   - Aligné strictement avec A2A_SECURITY_ARCHITECTURE.md
   - Structure section par section

### 11.3 Questions & Réponses

**[SLIDE 34 - Questions]**

> "Merci pour votre attention. Je suis maintenant disponible pour répondre à vos questions."

**Questions Anticipées :**

1. **Q:** Pourquoi HTTP entre agents dans le VPC ?  
   **R:** Isolation VPC + signature JWT = sécurisé. TLS inter-agent recommandé pour defense-in-depth (Section 5.2).

2. **Q:** Performance du MCP Server ?  
   **R:** Overhead +25% latence, mais -88% connexions DB. Trade-off sécurité vs. performance accepté (Section 4.2).

3. **Q:** Gestion des tokens révoqués à grande échelle ?  
   **R:** Architecture hybride : cache (1μs) + PostgreSQL. Auto-cleanup toutes les 5 minutes. Testé à 10K révocations (Section 3.4).

4. **Q:** Plan disaster recovery ?  
   **R:** RDS snapshots quotidiens, multi-AZ, backup Keycloak DB. Détails dans Section 10 (Security Operations).

5. **Q:** Conformité RGPD ?  
   **R:** Chiffrement AES-256, audit trail, accès contrôlé RBAC. Droit à l'oubli nécessite implémentation API (Section 10.3).

---

**FIN DE LA PRÉSENTATION**

**Durée Totale : 75 minutes (60 min + 15 min Q&A)**

**Structure : 100% alignée avec A2A_SECURITY_ARCHITECTURE.md v5.1**
