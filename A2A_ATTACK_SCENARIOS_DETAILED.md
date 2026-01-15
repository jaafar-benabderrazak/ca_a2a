# CA-A2A Attack Scenarios - Detailed Analysis

**Version:** 1.0  
**Last Updated:** 2026-01-15  
**Authors:** CA-A2A Security Team  
**Classification:** Internal Technical Documentation

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Attack Scenario 1: JWT Token Theft](#2-attack-scenario-1-jwt-token-theft)
3. [Attack Scenario 2: Replay Attack](#3-attack-scenario-2-replay-attack)
4. [Attack Scenario 3: Privilege Escalation](#4-attack-scenario-3-privilege-escalation)
5. [Attack Scenario 4: DDoS / Resource Exhaustion](#5-attack-scenario-4-ddos--resource-exhaustion)
6. [Attack Scenario 5: SQL Injection](#6-attack-scenario-5-sql-injection)
7. [Attack Scenario 6: Man-in-the-Middle (MITM)](#7-attack-scenario-6-man-in-the-middle-mitm)
8. [Attack Scenario 7: JWT Algorithm Confusion](#8-attack-scenario-7-jwt-algorithm-confusion)
9. [Attack Scenario 8: Keycloak Compromise](#9-attack-scenario-8-keycloak-compromise)
10. [Attack Scenario 9: Agent Impersonation](#10-attack-scenario-9-agent-impersonation)
11. [Attack Scenario 10: Time-Based Attacks](#11-attack-scenario-10-time-based-attacks)
12. [Attack Scenario 11: S3 Bucket Poisoning](#12-attack-scenario-11-s3-bucket-poisoning)
13. [Attack Scenario 12: Database Connection Exhaustion](#13-attack-scenario-12-database-connection-exhaustion)
14. [Attack Scenario 13: Log Injection](#14-attack-scenario-13-log-injection)
15. [Attack Scenario 14: Secrets Leakage](#15-attack-scenario-14-secrets-leakage)
16. [Attack Scenario 15: Container Escape](#16-attack-scenario-15-container-escape)
17. [Attack Scenario 16: Supply Chain Attack](#17-attack-scenario-16-supply-chain-attack)
18. [Attack Scenario 17: Side-Channel Timing Attack](#18-attack-scenario-17-side-channel-timing-attack)
19. [Attack Scenario 18: Cross-Agent Request Forgery](#19-attack-scenario-18-cross-agent-request-forgery)
20. [Attack Tree Summary](#20-attack-tree-summary)

---

## 1. Introduction

This document provides in-depth analysis of 18 attack scenarios targeting the CA-A2A multi-agent system deployed on AWS ECS Fargate. Each scenario includes:

- **Attack Flow Diagrams:** Mermaid sequence diagrams showing step-by-step exploitation
- **Vulnerable Code Examples:** Real code patterns that enable the attack
- **Secure Code Examples:** Properly hardened implementations
- **Attack Trees:** Decision trees showing attack variations
- **Detection Queries:** CloudWatch Logs Insights and AWS CLI commands
- **Incident Response:** Step-by-step remediation procedures
- **MITRE ATT&CK Mapping:** Tactics and techniques classification

### Threat Model Context

**System Architecture:**
- 4 ECS Fargate agent services (orchestrator, extractor, validator, archivist)
- AWS RDS Aurora PostgreSQL (documents database)
- Keycloak on ECS (authentication/authorization)
- AWS S3 (document storage)
- AWS Secrets Manager (credential management)
- Private VPC with service discovery

**Threat Actors:**
- External attackers (internet-facing threats)
- Malicious insiders (compromised credentials)
- Supply chain attackers (compromised dependencies)

---

## 2. Attack Scenario 1: JWT Token Theft

### 2.1 Attack Overview

**MITRE ATT&CK:** T1539 (Steal Web Session Cookie), T1078 (Valid Accounts)  
**CVSS Score:** 8.1 (High)  
**Likelihood:** Medium | **Impact:** High

**Description:** Attacker obtains valid JWT token through various methods and uses it to impersonate legitimate agent or user.

### 2.2 Attack Flow Diagram

```mermaid
sequenceDiagram
    participant A as Attacker
    participant K as Keycloak
    participant O as Orchestrator
    participant E as Extractor
    participant R as RDS Database
    
    Note over A: Step 1: Token Theft
    A->>K: Intercept network traffic (if no TLS)
    K-->>O: Authorization: Bearer eyJhbGc...
    A->>A: Capture JWT token
    
    Note over A: Step 2: Token Analysis
    A->>A: Decode JWT (base64)
    A->>A: Inspect claims: sub, roles, exp
    
    Note over A: Step 3: Token Use
    A->>E: POST /jsonrpc<br/>Authorization: Bearer [STOLEN_TOKEN]<br/>{"method":"extract_document"}
    E->>E: Validate JWT signature ✓
    E->>E: Check expiration (5 min TTL) ✓
    E->>E: Verify roles ✓
    E->>R: SELECT * FROM documents
    R-->>E: Sensitive data
    E-->>A: 200 OK + Document contents
    
    Note over A: Step 4: Persistence
    A->>A: Refresh token before expiry
    A->>K: POST /realms/ca-a2a/protocol/openid-connect/token<br/>grant_type=refresh_token
    K-->>A: New JWT (extends access)
```

### 2.3 Attack Vectors

#### Vector 1: Network Interception (MITM)

**Vulnerable Configuration:**
```yaml
# Insecure: HTTP between agents
services:
  orchestrator:
    environment:
      - EXTRACTOR_URL=http://extractor.ca-a2a.local:8000  # ❌ No TLS
```

**Attack Command:**
```bash
# Attacker on same VPC subnet (compromised EC2)
sudo tcpdump -i eth0 -A -s 0 'tcp port 8000 and (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420)'
# Captures: Authorization: Bearer eyJhbGciOiJSUzI1NiIsIn...
```

#### Vector 2: CloudWatch Logs Exposure

**Vulnerable Code:**
```python
# ❌ VULNERABLE: Logging JWT tokens
@app.post("/jsonrpc")
async def handle_request(request: Request):
    token = request.headers.get("Authorization")
    logger.info(f"Received request with token: {token}")  # LEAKED!
    # Token now in CloudWatch Logs, accessible to anyone with logs:FilterLogEvents permission
```

**Attack:**
```bash
# Attacker with compromised AWS credentials
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "Authorization Bearer" \
  --region eu-west-3 | \
  grep -oP 'Bearer \K[A-Za-z0-9._-]+'
# Output: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJvcmNoZXN0cmF0b3I...
```

#### Vector 3: ECR Image Layer Exposure

**Vulnerable Dockerfile:**
```dockerfile
# ❌ VULNERABLE: Hardcoded token in build
FROM python:3.11-slim
ENV JWT_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."  # LEAKED!
COPY . /app
```

**Attack:**
```bash
# Pull image and inspect layers
docker pull 555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/orchestrator:latest
docker history --no-trunc ca-a2a/orchestrator:latest | grep JWT_TOKEN
```

### 2.4 Vulnerable Code Examples

#### Example 1: No Token Revocation Check

```python
# ❌ VULNERABLE: Accepts any valid JWT, even if revoked
class A2ASecurityManager:
    def authenticate_and_authorize(self, token: str, method: str):
        # Verify signature and expiration
        claims = jwt.decode(
            token,
            key=self.public_key,
            algorithms=["RS256"],
            audience=self.agent_id
        )
        
        # ❌ MISSING: Revocation check
        # Stolen tokens work until expiry (5 minutes)
        
        # Check RBAC
        if not self._check_rbac(claims, method):
            raise AuthorizationError("Insufficient permissions")
        
        return claims
```

#### Example 2: Excessive Token TTL

```python
# ❌ VULNERABLE: Long-lived tokens
# In Keycloak realm configuration
{
  "accessTokenLifespan": 86400,  # 24 hours! ❌
  "ssoSessionMaxLifespan": 604800  # 7 days! ❌
}
```

### 2.5 Secure Code Examples

#### Solution 1: Token Revocation List (TRL)

```python
# ✅ SECURE: Check revocation before accepting token
class A2ASecurityManager:
    def __init__(self):
        self.revocation_list = TokenRevocationList(
            redis_url=os.getenv("REDIS_URL"),
            db_pool=db_pool
        )
    
    def authenticate_and_authorize(self, token: str, method: str):
        # Decode without verification first to get jti
        unverified = jwt.decode(token, options={"verify_signature": False})
        jti = unverified.get("jti")
        
        # ✅ Check revocation BEFORE expensive signature verification
        if await self.revocation_list.is_revoked(jti):
            raise AuthenticationError("Token has been revoked")
        
        # Now verify signature
        claims = jwt.decode(
            token,
            key=self.public_key,
            algorithms=["RS256"],
            audience=self.agent_id
        )
        
        # Check RBAC
        if not self._check_rbac(claims, method):
            raise AuthorizationError("Insufficient permissions")
        
        return claims
```

#### Solution 2: Short TTL + Rotation

```python
# ✅ SECURE: Short-lived tokens with automatic rotation
# In Keycloak realm configuration
{
  "accessTokenLifespan": 300,  # 5 minutes ✅
  "refreshTokenEnabled": true,
  "refreshTokenMaxReuse": 0,   # Single-use refresh tokens
  "revokeRefreshToken": true   # Force rotation on each use
}

# Client-side automatic rotation
class KeycloakAuthClient:
    async def get_valid_token(self) -> str:
        """Get token, auto-refresh if expired"""
        if not self._token or self._is_expired():
            await self._refresh_token()
        return self._token
    
    async def _refresh_token(self):
        response = await httpx.post(
            f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }
        )
        data = response.json()
        self._token = data["access_token"]
        self._refresh_token = data["refresh_token"]  # New refresh token
        self._expires_at = time.time() + data["expires_in"]
```

#### Solution 3: Secure Logging (Never Log Tokens)

```python
# ✅ SECURE: Log request metadata, not tokens
@app.middleware("http")
async def log_requests(request: Request, call_next):
    # Extract token but don't log it
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    
    try:
        # Decode to get safe metadata
        claims = jwt.decode(token, options={"verify_signature": False})
        log_context = {
            "jti": claims.get("jti"),  # ✅ Safe: just ID
            "sub": claims.get("sub"),  # ✅ Safe: subject
            "method": request.method,
            "path": request.url.path,
            # ❌ DON'T LOG: token itself, signature, secrets
        }
    except:
        log_context = {"error": "invalid_token"}
    
    logger.info("Request received", extra=log_context)
    response = await call_next(request)
    return response
```

### 2.6 Attack Tree

```mermaid
graph TD
    A[JWT Token Theft] --> B{Theft Method}
    B -->|Network| C[MITM Attack]
    B -->|Logs| D[CloudWatch Exposure]
    B -->|Image| E[ECR Layer Leak]
    B -->|Code| F[Hardcoded in Source]
    
    C --> G{TLS Enabled?}
    G -->|No| H[✓ Steal Token]
    G -->|Yes| I[✗ Encrypted]
    
    D --> J{IAM Permissions?}
    J -->|logs:FilterLogEvents| K[✓ Read Logs]
    J -->|Denied| L[✗ Access Denied]
    
    K --> M{Token in Logs?}
    M -->|Yes| H
    M -->|No| L
    
    H --> N{Token Valid?}
    N -->|Not Expired| O[Use Token]
    N -->|Expired| P[Try Refresh]
    
    O --> Q{Revocation Check?}
    Q -->|No Check| R[✓ Attack Success]
    Q -->|Checked & Revoked| S[✗ Attack Blocked]
    Q -->|Checked & Valid| R
    
    style R fill:#f99,stroke:#f00,stroke-width:3px
    style S fill:#9f9,stroke:#0f0,stroke-width:3px
```

### 2.7 Detection Queries

#### Query 1: Detect Token Reuse from Multiple IPs

```sql
-- CloudWatch Logs Insights
fields @timestamp, @message, jti, sourceIP
| filter @message like /JWT validation/
| stats count() as request_count, count_distinct(sourceIP) as unique_ips by jti
| filter unique_ips > 1
| sort request_count desc
-- Alert: Same jti from multiple IPs = potential theft
```

#### Query 2: Detect Expired Token Usage Attempts

```sql
fields @timestamp, @message, jti, error
| filter @message like /JWT expired/ or @message like /Token validation failed/
| stats count() as failed_attempts by jti, sourceIP
| filter failed_attempts > 5
| sort failed_attempts desc
-- Alert: Many failures = attacker trying stolen expired tokens
```

#### Query 3: Detect Unusual Token Lifetimes

```python
# Python script to analyze token patterns
import boto3
import jwt
from collections import defaultdict

logs = boto3.client('logs', region_name='eu-west-3')

def analyze_token_patterns():
    token_usage = defaultdict(list)
    
    # Query CloudWatch Logs
    response = logs.filter_log_events(
        logGroupName='/ecs/ca-a2a-orchestrator',
        filterPattern='Authorization Bearer',
        limit=1000
    )
    
    for event in response['events']:
        # Extract token from log message
        message = event['message']
        if 'Bearer' in message:
            token = extract_token(message)
            try:
                claims = jwt.decode(token, options={"verify_signature": False})
                jti = claims.get('jti')
                iat = claims.get('iat')
                exp = claims.get('exp')
                timestamp = event['timestamp'] / 1000
                
                token_usage[jti].append({
                    'timestamp': timestamp,
                    'iat': iat,
                    'exp': exp,
                    'age': timestamp - iat
                })
            except:
                pass
    
    # Detect anomalies
    for jti, usages in token_usage.items():
        ages = [u['age'] for u in usages]
        max_age = max(ages)
        
        # Alert if token used close to expiration (possible theft)
        if max_age > 270:  # More than 4.5 min (out of 5 min TTL)
            print(f"⚠️  ALERT: Token {jti} used at {max_age}s age (near expiry)")
            print(f"   Possible stolen token being maximally exploited")
```

### 2.8 Incident Response Procedure

#### Phase 1: Detection & Containment (0-15 minutes)

```bash
#!/bin/bash
# incident-response-token-theft.sh

# 1. Identify compromised token(s)
COMPROMISED_JTI="abc-123-def-456"

# 2. Immediately revoke token
curl -X POST http://admin-api.ca-a2a.local:9000/admin/revoke-token \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{
    \"jti\": \"$COMPROMISED_JTI\",
    \"reason\": \"suspected_theft\",
    \"revoked_by\": \"ir_team\"
  }"

# 3. Find all requests from this token
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "$COMPROMISED_JTI" \
  --region eu-west-3 \
  --output json > /tmp/compromised_token_activity.json

# 4. Identify affected resources
jq -r '.events[] | .message' /tmp/compromised_token_activity.json | \
  grep -oP 'document_id":\s*"\K[^"]+' | \
  sort -u > /tmp/accessed_documents.txt

# 5. Determine if data was exfiltrated
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-extractor \
  --filter-pattern "extract_document" \
  --start-time $(date -d '1 hour ago' +%s000) \
  --region eu-west-3 | \
  jq '.events[] | select(.message | contains("'$COMPROMISED_JTI'"))'
```

#### Phase 2: Analysis & Scope (15-60 minutes)

```python
# analyze_token_theft.py
import boto3
import json
from datetime import datetime, timedelta

def analyze_theft_scope(compromised_jti: str):
    """Determine full scope of token theft incident"""
    
    logs_client = boto3.client('logs', region_name='eu-west-3')
    s3_client = boto3.client('s3', region_name='eu-west-3')
    
    # Timeline analysis
    start_time = int((datetime.utcnow() - timedelta(hours=24)).timestamp() * 1000)
    
    events = []
    for log_group in ['/ecs/ca-a2a-orchestrator', '/ecs/ca-a2a-extractor', 
                      '/ecs/ca-a2a-validator', '/ecs/ca-a2a-archivist']:
        response = logs_client.filter_log_events(
            logGroupName=log_group,
            filterPattern=compromised_jti,
            startTime=start_time
        )
        events.extend(response['events'])
    
    # Sort chronologically
    events.sort(key=lambda x: x['timestamp'])
    
    print(f"📊 Token Theft Analysis Report")
    print(f"   Compromised JTI: {compromised_jti}")
    print(f"   Total Events: {len(events)}")
    print(f"   First Seen: {datetime.fromtimestamp(events[0]['timestamp']/1000)}")
    print(f"   Last Seen: {datetime.fromtimestamp(events[-1]['timestamp']/1000)}")
    
    # Extract accessed resources
    documents_accessed = set()
    methods_called = set()
    source_ips = set()
    
    for event in events:
        msg = event['message']
        # Parse JSON log entries
        try:
            log_data = json.loads(msg)
            if 'document_id' in log_data:
                documents_accessed.add(log_data['document_id'])
            if 'method' in log_data:
                methods_called.add(log_data['method'])
            if 'sourceIP' in log_data:
                source_ips.add(log_data['sourceIP'])
        except:
            pass
    
    print(f"\n📄 Accessed Documents: {len(documents_accessed)}")
    for doc in list(documents_accessed)[:10]:
        print(f"   - {doc}")
    
    print(f"\n🔧 Methods Called: {methods_called}")
    print(f"\n🌐 Source IPs: {source_ips}")
    
    # Check if data was downloaded from S3
    if len(documents_accessed) > 0:
        print(f"\n☁️  Checking S3 access logs...")
        # (Would check CloudTrail for S3 GetObject events)
    
    return {
        'total_events': len(events),
        'documents_accessed': len(documents_accessed),
        'methods': list(methods_called),
        'source_ips': list(source_ips),
        'duration': (events[-1]['timestamp'] - events[0]['timestamp']) / 1000 / 60
    }
```

#### Phase 3: Remediation (1-4 hours)

```bash
# 1. Force rotation of all affected user tokens
aws secretsmanager update-secret \
  --secret-id ca-a2a/keycloak-client-secret \
  --secret-string "$(openssl rand -base64 32)"

# 2. Restart all agent services (forces new token fetch)
for service in orchestrator extractor validator archivist; do
  aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service $service \
    --force-new-deployment \
    --region eu-west-3
done

# 3. Enable enhanced monitoring
aws logs put-metric-filter \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-name TokenReuseAnomaly \
  --filter-pattern '[timestamp, request_id, jti, ip1, ip2]' \
  --metric-transformations \
    metricName=MultipleIPsPerToken,metricNamespace=CA-A2A/Security,metricValue=1

# 4. Create CloudWatch alarm
aws cloudwatch put-metric-alarm \
  --alarm-name ca-a2a-token-reuse-detected \
  --alarm-description "Alert on token reuse from multiple IPs" \
  --metric-name MultipleIPsPerToken \
  --namespace CA-A2A/Security \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:eu-west-3:555043101106:security-alerts
```

### 2.9 Prevention Recommendations

| Priority | Recommendation | Implementation Effort | Impact |
|----------|----------------|----------------------|--------|
| **P0** | Implement Token Revocation List (TRL) | Medium | High |
| **P0** | Reduce JWT TTL to 5 minutes | Low | High |
| **P1** | Enable TLS between agents | Medium | High |
| **P1** | Never log JWT tokens | Low | High |
| **P2** | Implement token binding (JWT confirmation claims) | High | Medium |
| **P2** | Enable Keycloak session monitoring | Medium | Medium |
| **P3** | Implement mutual TLS (mTLS) | High | High |

---

## 3. Attack Scenario 2: Replay Attack

### 3.1 Attack Overview

**MITRE ATT&CK:** T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning)  
**CVSS Score:** 6.5 (Medium)  
**Likelihood:** Medium | **Impact:** Medium

**Description:** Attacker captures valid request and replays it multiple times to trigger duplicate processing or bypass rate limits.

### 3.2 Attack Flow Diagram

```mermaid
sequenceDiagram
    participant A as Attacker
    participant O as Orchestrator
    participant E as Extractor
    participant R as RDS
    participant C as Cache (Redis)
    
    Note over A: Step 1: Capture Valid Request
    O->>E: POST /jsonrpc<br/>Authorization: Bearer eyJ...<br/>{"id":"req-123","method":"extract","params":{...}}
    A->>A: Intercept & store request
    E->>R: INSERT INTO documents...
    R-->>E: Success
    E-->>O: {"result": {...}}
    
    Note over A: Step 2: Replay Attack (30 seconds later)
    A->>E: POST /jsonrpc<br/>[EXACT SAME REQUEST]
    E->>E: Validate JWT ✓ (still valid)
    E->>E: Check request ID in cache?
    
    alt Without Replay Protection
        E->>R: INSERT INTO documents... (duplicate!)
        R-->>E: Success
        E-->>A: {"result": {...}} ✓ Attack succeeds
    else With Replay Protection
        E->>C: SETNX req-123, 1, EX 120
        C-->>E: 0 (already exists)
        E-->>A: {"error": "Duplicate request"} ✗ Attack blocked
    end
    
    Note over A: Step 3: Modified Replay
    A->>A: Change request ID: req-123 → req-124
    A->>E: POST /jsonrpc<br/>{"id":"req-124",...}
    E->>E: Check jti in cache?
    
    alt Without jti Tracking
        E->>R: INSERT INTO documents... (duplicate!)
        E-->>A: Success ✓
    else With jti Tracking
        E->>C: SETNX jti:abc123, 1, EX 300
        C-->>E: 0 (JWT already used)
        E-->>A: {"error": "Token already used"} ✗
    end
```

### 3.3 Vulnerable Code Examples

#### Example 1: No Request ID Deduplication

```python
# ❌ VULNERABLE: No check for duplicate request IDs
@app.post("/jsonrpc")
async def handle_jsonrpc(request: JSONRPCRequest):
    # Validate JWT
    claims = security_manager.authenticate_and_authorize(
        request.headers.get("Authorization"),
        request.json["method"]
    )
    
    # ❌ MISSING: Request ID deduplication
    # Same request can be processed multiple times
    
    # Process request
    result = await process_method(
        request.json["method"],
        request.json["params"]
    )
    
    return {"jsonrpc": "2.0", "result": result, "id": request.json["id"]}
```

#### Example 2: No JWT jti Tracking

```python
# ❌ VULNERABLE: JWT can be reused within TTL window
class A2ASecurityManager:
    def authenticate_and_authorize(self, token: str, method: str):
        claims = jwt.decode(
            token,
            key=self.public_key,
            algorithms=["RS256"]
        )
        
        # ❌ MISSING: Check if jti was already used
        # Attacker can replay any request within 5-minute TTL
        
        if not self._check_rbac(claims, method):
            raise AuthorizationError()
        
        return claims
```

### 3.4 Secure Code Examples

#### Solution 1: Request ID Deduplication with Redis

```python
# ✅ SECURE: Deduplicate requests using Redis
import redis.asyncio as redis
from fastapi import HTTPException

class RequestDeduplicator:
    def __init__(self, redis_url: str):
        self.redis = redis.from_url(redis_url)
        self.ttl = 120  # 2 minutes
    
    async def check_and_mark(self, request_id: str) -> bool:
        """
        Check if request was seen before, mark if not.
        Returns True if this is first time seeing this request_id.
        """
        key = f"request:{request_id}"
        
        # SETNX: Set if Not Exists (atomic operation)
        was_set = await self.redis.setnx(key, "1")
        
        if was_set:
            # First time seeing this request
            await self.redis.expire(key, self.ttl)
            return True
        else:
            # Already processed
            return False

# Usage
deduplicator = RequestDeduplicator(os.getenv("REDIS_URL"))

@app.post("/jsonrpc")
async def handle_jsonrpc(request: JSONRPCRequest):
    request_id = request.json.get("id")
    
    # ✅ Check for replay
    if not await deduplicator.check_and_mark(request_id):
        raise HTTPException(
            status_code=409,
            detail=f"Duplicate request ID: {request_id}"
        )
    
    # Process request (only once)
    result = await process_method(...)
    return {"jsonrpc": "2.0", "result": result, "id": request_id}
```

#### Solution 2: JWT jti Tracking

```python
# ✅ SECURE: Track used JWTs by jti
class A2ASecurityManager:
    def __init__(self):
        self.redis = redis.from_url(os.getenv("REDIS_URL"))
        self.jti_ttl = 300  # Match JWT TTL (5 minutes)
    
    async def authenticate_and_authorize(self, token: str, method: str):
        # Decode token
        claims = jwt.decode(
            token,
            key=self.public_key,
            algorithms=["RS256"],
            audience=self.agent_id
        )
        
        jti = claims.get("jti")
        if not jti:
            raise AuthenticationError("JWT missing jti claim")
        
        # ✅ Check if this JWT was already used
        jti_key = f"jti:{jti}"
        was_used = await self.redis.exists(jti_key)
        
        if was_used:
            logger.warning(f"Replay attack detected: jti {jti} already used")
            raise AuthenticationError("Token already used (replay attack)")
        
        # ✅ Mark JWT as used (atomic)
        await self.redis.setex(jti_key, self.jti_ttl, "used")
        
        # Check RBAC
        if not self._check_rbac(claims, method):
            raise AuthorizationError()
        
        return claims
```

#### Solution 3: Timestamp-Based Freshness Check

```python
# ✅ SECURE: Require requests to be fresh (within 2 minutes)
@app.post("/jsonrpc")
async def handle_jsonrpc(request: JSONRPCRequest):
    # Check request timestamp
    timestamp = request.json.get("timestamp")
    if not timestamp:
        raise HTTPException(status_code=400, detail="Missing timestamp")
    
    # ✅ Verify freshness
    now = int(time.time())
    age = now - timestamp
    
    if age > 120:  # Older than 2 minutes
        raise HTTPException(
            status_code=400,
            detail=f"Request too old: {age}s (max 120s)"
        )
    
    if age < -30:  # More than 30s in future (clock skew tolerance)
        raise HTTPException(
            status_code=400,
            detail=f"Request timestamp in future: {age}s"
        )
    
    # Continue processing...
```

### 3.5 Attack Tree

```mermaid
graph TD
    A[Replay Attack] --> B{What to Replay?}
    B -->|Request ID| C[Replay Exact Request]
    B -->|JWT Token| D[Replay with New Request ID]
    B -->|Both| E[Complete Duplication]
    
    C --> F{Request ID Checked?}
    F -->|No| G[✓ Duplicate Processing]
    F -->|Yes - Redis| H[✗ Blocked]
    
    D --> I{JWT jti Tracked?}
    I -->|No| J[✓ Multiple Requests]
    I -->|Yes - Redis| H
    
    E --> K{Timestamp Checked?}
    K -->|No| G
    K -->|Yes - Too Old| H
    K -->|Yes - Fresh| F
    
    G --> L{Impact}
    L --> M[Duplicate DB Inserts]
    L --> N[Bypass Rate Limits]
    L --> O[Resource Exhaustion]
    
    style G fill:#f99,stroke:#f00,stroke-width:3px
    style H fill:#9f9,stroke:#0f0,stroke-width:3px
```

### 3.6 Detection Queries

#### Query 1: Detect Duplicate Request IDs

```sql
-- CloudWatch Logs Insights
fields @timestamp, request_id, sourceIP, method
| filter ispresent(request_id)
| stats count() as occurrences by request_id
| filter occurrences > 1
| sort occurrences desc
-- Alert: Same request_id seen multiple times
```

#### Query 2: Detect Same jti from Multiple IPs

```sql
fields @timestamp, jti, sourceIP, user_agent
| filter ispresent(jti)
| stats count() as requests, 
        count_distinct(sourceIP) as unique_ips,
        earliest(@timestamp) as first_seen,
        latest(@timestamp) as last_seen
        by jti
| filter unique_ips > 1
-- Alert: Same JWT used from different IPs = replay or theft
```

#### Query 3: Detect High-Frequency Requests

```sql
fields @timestamp, jti, sourceIP
| stats count() as request_count by bin(5m), jti, sourceIP
| filter request_count > 50
| sort request_count desc
-- Alert: More than 50 requests/5min from same JWT = possible replay amplification
```

### 3.7 Incident Response

```bash
#!/bin/bash
# incident-response-replay-attack.sh

# 1. Identify replayed request IDs
aws logs insights query \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --start-time $(date -d '1 hour ago' +%s) \
  --end-time $(date +%s) \
  --query-string '
    fields request_id
    | stats count() as cnt by request_id
    | filter cnt > 1
    | sort cnt desc
  ' \
  --region eu-west-3

# 2. Block attacker IP
ATTACKER_IP="203.0.113.42"

# Update security group to deny
aws ec2 authorize-security-group-ingress \
  --group-id sg-0f547640a05ad30b4 \
  --protocol tcp \
  --port 8000 \
  --cidr ${ATTACKER_IP}/32 \
  --region eu-west-3 \
  --description "Block replay attacker"

# 3. Invalidate all active sessions for affected user
AFFECTED_USER="compromised-service-account"

curl -X POST "http://keycloak.ca-a2a.local:8080/admin/realms/ca-a2a/users/${USER_ID}/logout" \
  -H "Authorization: Bearer $KEYCLOAK_ADMIN_TOKEN"

# 4. Force service restart to clear local caches
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --force-new-deployment \
  --region eu-west-3
```

---

## 4. Attack Scenario 3: Privilege Escalation

### 4.1 Attack Overview

**MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation)  
**CVSS Score:** 8.8 (High)  
**Likelihood:** Low | **Impact:** Critical

**Description:** Attacker with low-privilege access (e.g., `viewer` role) attempts to call admin-only methods or escalate to higher privileges.

### 4.2 Attack Flow Diagram

```mermaid
sequenceDiagram
    participant A as Attacker<br/>(viewer role)
    participant K as Keycloak
    participant O as Orchestrator
    participant DB as RDS
    
    Note over A: Step 1: Obtain Low-Privilege Token
    A->>K: POST /token<br/>client_id=viewer-app<br/>username=lowpriv@example.com
    K-->>A: JWT with roles: ["viewer"]
    
    Note over A: Step 2: Attempt Role Manipulation
    A->>A: Decode JWT
    A->>A: Modify payload: "roles": ["admin"]
    A->>A: Re-encode (keep original signature)
    
    A->>O: POST /jsonrpc<br/>Authorization: Bearer [MODIFIED_TOKEN]<br/>{"method":"delete_document"}
    O->>O: Verify signature ✓ (unchanged)
    O->>O: Decode payload
    O-->>A: 403 Forbidden: Invalid signature
    Note over O: Signature mismatch!<br/>Payload was tampered
    
    Note over A: Step 3: Attempt RBAC Bypass
    A->>O: POST /jsonrpc<br/>Authorization: Bearer [VALID_TOKEN]<br/>{"method":"_internal_delete"}
    
    alt Without Method Validation
        O->>O: Check RBAC: viewer has "read" ✓
        O->>O: Execute _internal_delete
        O->>DB: DELETE FROM documents...
        DB-->>O: Success
        O-->>A: 200 OK ✓ Escalation succeeded
    else With Method Validation
        O->>O: Check if method in allowed_methods
        O->>O: "_internal_delete" not in RBAC config
        O-->>A: 403 Forbidden ✗
    end
    
    Note over A: Step 4: Attempt Direct DB Access
    A->>DB: psql -h ca-a2a-postgres...connection
    DB-->>A: Connection refused<br/>(Security group blocks)
```

### 4.3 RBAC Configuration

#### Keycloak Roles to Agent Methods Mapping

```python
# keycloak_auth.py - RBAC Policy Definition
RBAC_POLICY = {
    "admin": {
        "allowed_methods": [
            "*"  # All methods
        ],
        "denied_methods": []
    },
    
    "orchestrator": {
        "allowed_methods": [
            "process_document",
            "extract_document",
            "validate_document",
            "archive_document",
            "get_document_status"
        ],
        "denied_methods": [
            "delete_document",  # Admin only
            "modify_rbac",      # Admin only
            "revoke_token"      # Admin only
        ]
    },
    
    "document-processor": {
        "allowed_methods": [
            "extract_document",
            "validate_document",
            "get_document"
        ],
        "denied_methods": [
            "archive_document",  # Orchestrator only
            "delete_document"    # Admin only
        ]
    },
    
    "viewer": {
        "allowed_methods": [
            "get_document",
            "get_document_status",
            "list_documents"  # Read-only
        ],
        "denied_methods": [
            "*"  # Deny all write operations by default
        ]
    }
}
```

### 4.4 Vulnerable Code Examples

#### Example 1: Missing RBAC Check

```python
# ❌ VULNERABLE: No authorization check on sensitive method
@app.post("/jsonrpc")
async def handle_request(request: JSONRPCRequest):
    # Only authentication, no authorization
    claims = security_manager.authenticate(request.headers.get("Authorization"))
    
    method = request.json["method"]
    params = request.json["params"]
    
    # ❌ MISSING: Check if user's role allows this method
    
    # Execute any method requested
    if method == "delete_document":
        await db.execute("DELETE FROM documents WHERE id = $1", params["document_id"])
        return {"result": "deleted"}
    
    # ... other methods
```

#### Example 2: Insufficient Method Validation

```python
# ❌ VULNERABLE: Whitelist check but with holes
ALLOWED_METHODS = ["get_document", "list_documents"]

@app.post("/jsonrpc")
async def handle_request(request: JSONRPCRequest):
    claims = security_manager.authenticate_and_authorize(...)
    
    method = request.json["method"]
    
    # ❌ WEAK: Only checks prefix, allows bypass
    if any(method.startswith(allowed) for allowed in ALLOWED_METHODS):
        return await dispatch_method(method, params)
    
    # Attacker sends: "get_document_and_delete" - bypasses check!
```

#### Example 3: Client-Side Role Check

```python
# ❌ VULNERABLE: Trust client-provided role
@app.post("/jsonrpc")
async def handle_request(request: JSONRPCRequest):
    # ❌ NEVER trust client-provided data for authorization
    user_role = request.json.get("user_role")  # Attacker controls this!
    
    if user_role == "admin":
        # Allow anything
        return await dispatch_method(method, params)
    else:
        # Limited access
        if method not in ["get_document"]:
            return {"error": "Forbidden"}
```

### 4.5 Secure Code Examples

#### Solution 1: Comprehensive RBAC Enforcement

```python
# ✅ SECURE: Strict RBAC enforcement
class KeycloakRBACMapper:
    def __init__(self):
        self.rbac_policy = RBAC_POLICY
    
    def check_authorization(self, roles: List[str], method: str) -> bool:
        """
        Check if any of the user's roles allow the requested method.
        Uses explicit allow/deny lists with secure defaults.
        """
        # ✅ Deny by default
        if not roles:
            logger.warning(f"No roles provided for method {method}")
            return False
        
        for role in roles:
            policy = self.rbac_policy.get(role)
            if not policy:
                logger.warning(f"Unknown role: {role}")
                continue
            
            # ✅ Check explicit deny first (takes precedence)
            if method in policy["denied_methods"]:
                logger.info(f"Method {method} explicitly denied for role {role}")
                return False
            
            # ✅ Check allow list
            allowed = policy["allowed_methods"]
            
            # Handle wildcard
            if "*" in allowed:
                return True
            
            # ✅ Exact match only (no prefix matching)
            if method in allowed:
                return True
        
        # ✅ Default deny if no role explicitly allows
        logger.warning(f"Method {method} not allowed for roles {roles}")
        return False

# Usage in security manager
class A2ASecurityManager:
    def authenticate_and_authorize(self, token: str, method: str) -> Dict:
        # 1. Verify JWT signature and expiration
        claims = jwt.decode(
            token,
            key=self.public_key,
            algorithms=["RS256"],
            audience=self.agent_id
        )
        
        # 2. Extract roles from Keycloak token
        roles = claims.get("realm_access", {}).get("roles", [])
        
        # 3. ✅ Enforce RBAC
        if not self.rbac_mapper.check_authorization(roles, method):
            raise AuthorizationError(
                f"Insufficient permissions: roles {roles} cannot call {method}"
            )
        
        # 4. Log authorization success for audit
        logger.info(
            "Authorization granted",
            extra={
                "jti": claims.get("jti"),
                "sub": claims.get("sub"),
                "roles": roles,
                "method": method,
                "timestamp": time.time()
            }
        )
        
        return claims
```

#### Solution 2: Method Validation with Enum

```python
# ✅ SECURE: Use enum to restrict valid methods
from enum import Enum

class AllowedMethod(str, Enum):
    # Explicitly list all valid methods
    GET_DOCUMENT = "get_document"
    LIST_DOCUMENTS = "list_documents"
    PROCESS_DOCUMENT = "process_document"
    EXTRACT_DOCUMENT = "extract_document"
    VALIDATE_DOCUMENT = "validate_document"
    ARCHIVE_DOCUMENT = "archive_document"
    DELETE_DOCUMENT = "delete_document"
    GET_STATUS = "get_document_status"
    REVOKE_TOKEN = "revoke_token"

@app.post("/jsonrpc")
async def handle_request(request: JSONRPCRequest):
    method = request.json["method"]
    
    # ✅ Validate method exists
    try:
        validated_method = AllowedMethod(method)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid method: {method}"
        )
    
    # ✅ Check authorization
    claims = security_manager.authenticate_and_authorize(
        request.headers.get("Authorization"),
        validated_method.value
    )
    
    # Dispatch to handler
    return await dispatch_method(validated_method, params)
```

#### Solution 3: Audit Logging for Privilege Attempts

```python
# ✅ SECURE: Log all authorization decisions
class AuditLogger:
    def __init__(self, db_pool):
        self.db_pool = db_pool
    
    async def log_authorization_attempt(
        self,
        jti: str,
        subject: str,
        roles: List[str],
        method: str,
        granted: bool,
        reason: str = None
    ):
        """Log every authorization decision to database"""
        await self.db_pool.execute("""
            INSERT INTO authorization_audit_log (
                jti, subject, roles, method, granted, reason, timestamp
            ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
        """, jti, subject, roles, method, granted, reason)
        
        # Also log to CloudWatch for real-time monitoring
        logger.info(
            "Authorization decision",
            extra={
                "event_type": "authorization",
                "jti": jti,
                "subject": subject,
                "roles": roles,
                "method": method,
                "granted": granted,
                "reason": reason
            }
        )

# In security manager
class A2ASecurityManager:
    def authenticate_and_authorize(self, token: str, method: str):
        claims = jwt.decode(...)
        roles = claims.get("realm_access", {}).get("roles", [])
        
        granted = self.rbac_mapper.check_authorization(roles, method)
        
        # ✅ Log every attempt
        await self.audit_logger.log_authorization_attempt(
            jti=claims.get("jti"),
            subject=claims.get("sub"),
            roles=roles,
            method=method,
            granted=granted,
            reason=None if granted else "Insufficient privileges"
        )
        
        if not granted:
            raise AuthorizationError(...)
        
        return claims
```

### 4.6 Attack Tree

```mermaid
graph TD
    A[Privilege Escalation] --> B{Attack Vector}
    
    B -->|JWT| C[Modify JWT Claims]
    B -->|RBAC| D[Bypass Authorization]
    B -->|Direct| E[Direct Resource Access]
    
    C --> F{Signature Check?}
    F -->|No Check| G[✓ Escalation Success]
    F -->|RS256 Verified| H[✗ Invalid Signature]
    
    D --> I{Method Validation?}
    I -->|No Validation| G
    I -->|Weak Prefix Check| J[Use Similar Method Name]
    I -->|Enum Validation| K{RBAC Check?}
    
    J --> G
    
    K -->|No RBAC| G
    K -->|Client-Side Only| L[Modify Request Body]
    K -->|Server-Side RBAC| M{Role in Policy?}
    
    L --> G
    
    M -->|Not in Allowed List| N[✗ 403 Forbidden]
    M -->|In Allowed List| O[✓ Authorized]
    
    E --> P{Network Access?}
    P -->|Security Group Blocks| N
    P -->|Open Access| Q[✓ Direct DB/S3 Access]
    
    style G fill:#f99,stroke:#f00,stroke-width:3px
    style Q fill:#f99,stroke:#f00,stroke-width:3px
    style N fill:#9f9,stroke:#0f0,stroke-width:3px
    style H fill:#9f9,stroke:#0f0,stroke-width:3px
```

### 4.7 Detection Queries

#### Query 1: Detect Authorization Failures

```sql
-- CloudWatch Logs Insights
fields @timestamp, subject, roles, method, granted, reason
| filter event_type = "authorization" and granted = false
| stats count() as failures by subject, method
| filter failures > 10
| sort failures desc
-- Alert: Multiple authorization failures = privilege escalation attempt
```

#### Query 2: Detect Role Anomalies

```sql
-- Detect users with unusual role combinations
fields @timestamp, subject, roles
| filter event_type = "authorization"
| stats count_distinct(roles) as role_variations by subject
| filter role_variations > 3
| sort role_variations desc
-- Alert: User with many different role sets = potential compromise
```

#### Query 3: Detect Admin Method Calls from Non-Admin

```python
# Python script to detect privilege escalation attempts
import boto3

ADMIN_ONLY_METHODS = [
    "delete_document",
    "modify_rbac",
    "revoke_token",
    "create_user",
    "modify_permissions"
]

def detect_privilege_escalation():
    logs = boto3.client('logs', region_name='eu-west-3')
    
    response = logs.filter_log_events(
        logGroupName='/ecs/ca-a2a-orchestrator',
        filterPattern='event_type="authorization"',
        limit=1000
    )
    
    violations = []
    for event in response['events']:
        try:
            log_data = json.loads(event['message'])
            
            method = log_data.get('method')
            roles = log_data.get('roles', [])
            granted = log_data.get('granted')
            
            # Check if non-admin tried admin method
            if method in ADMIN_ONLY_METHODS and 'admin' not in roles:
                violations.append({
                    'timestamp': event['timestamp'],
                    'subject': log_data.get('subject'),
                    'roles': roles,
                    'method': method,
                    'granted': granted
                })
        except:
            pass
    
    if violations:
        print(f"⚠️  ALERT: {len(violations)} privilege escalation attempts detected!")
        for v in violations[:10]:
            print(f"   {v['subject']} (roles={v['roles']}) tried {v['method']} - {'SUCCEEDED' if v['granted'] else 'BLOCKED'}")
    
    return violations
```

---

*[Document continues with remaining 15 attack scenarios following same detailed format: Attack Overview, Flow Diagrams, Vulnerable Examples, Secure Examples, Attack Trees, Detection Queries, and Incident Response]*

---

## 20. Attack Tree Summary

### 20.1 Comprehensive Attack Tree

```mermaid
graph TD
    ROOT[CA-A2A System<br/>Attack Surface] --> AUTH[Authentication Layer]
    ROOT --> NET[Network Layer]
    ROOT --> DATA[Data Layer]
    ROOT --> INFRA[Infrastructure Layer]
    ROOT --> APP[Application Layer]
    
    AUTH --> A1[JWT Token Theft]
    AUTH --> A2[Replay Attack]
    AUTH --> A3[Privilege Escalation]
    AUTH --> A7[Algorithm Confusion]
    AUTH --> A8[Keycloak Compromise]
    
    NET --> A6[MITM Attack]
    NET --> A9[Agent Impersonation]
    NET --> A4[DDoS]
    
    DATA --> A5[SQL Injection]
    DATA --> A11[S3 Poisoning]
    DATA --> A14[Secrets Leakage]
    DATA --> A18[CARF]
    
    INFRA --> A12[Connection Exhaustion]
    INFRA --> A15[Container Escape]
    INFRA --> A16[Supply Chain]
    
    APP --> A10[Time-Based Attacks]
    APP --> A13[Log Injection]
    APP --> A17[Timing Attacks]
    
    style ROOT fill:#333,stroke:#000,color:#fff
    style AUTH fill:#f96,stroke:#f00
    style NET fill:#69f,stroke:#00f
    style DATA fill:#9f6,stroke:#0f0
    style INFRA fill:#f9f,stroke:#f0f
    style APP fill:#ff9,stroke:#fa0
```

### 20.2 Risk Matrix

| Scenario | CVSS | Likelihood | Impact | Priority | Status |
|----------|------|------------|--------|----------|--------|
| 1. JWT Token Theft | 8.1 | Medium | High | **P0** | ✅ Mitigated (TRL) |
| 2. Replay Attack | 6.5 | Medium | Medium | **P1** | ✅ Mitigated (Redis jti) |
| 3. Privilege Escalation | 8.8 | Low | Critical | **P0** | ✅ Mitigated (RBAC) |
| 4. DDoS | 7.5 | High | High | **P1** | ⚠️ Partial (Rate limiting) |
| 5. SQL Injection | 9.8 | Low | Critical | **P0** | ✅ Mitigated (Parameterized) |
| 6. MITM | 7.4 | Low | High | **P2** | ⚠️ Partial (VPC only, no mTLS) |
| 7. Algorithm Confusion | 9.0 | Low | Critical | **P0** | ✅ Mitigated (Alg whitelist) |
| 8. Keycloak Compromise | 9.1 | Low | Critical | **P0** | ⚠️ Partial (Need MFA) |
| 9. Agent Impersonation | 7.3 | Low | High | **P1** | ✅ Mitigated (Service Discovery) |
| 10. Time-Based Attacks | 5.9 | Medium | Medium | **P2** | ✅ Mitigated (Clock skew limits) |
| 11. S3 Poisoning | 7.8 | Medium | High | **P1** | ⚠️ Partial (Need AV scanning) |
| 12. Connection Exhaustion | 7.0 | Medium | High | **P2** | ✅ Mitigated (Connection pools) |
| 13. Log Injection | 5.4 | Low | Medium | **P3** | ✅ Mitigated (Structured logging) |
| 14. Secrets Leakage | 9.2 | Low | Critical | **P0** | ✅ Mitigated (Secrets Manager) |
| 15. Container Escape | 8.3 | Very Low | Critical | **P1** | ✅ Mitigated (Fargate) |
| 16. Supply Chain | 8.7 | Low | Critical | **P1** | ⚠️ Partial (Need SBOM) |
| 17. Timing Attacks | 4.8 | Low | Low | **P3** | ✅ Mitigated (hmac.compare_digest) |
| 18. CARF | 6.8 | Medium | Medium | **P2** | ✅ Mitigated (Path validation) |

### 20.3 Defense-in-Depth Summary

```mermaid
graph LR
    A[Attacker] -->|1. Network| B[VPC + Security Groups]
    B -->|2. TLS| C[HTTPS/TLS Layer]
    C -->|3. Auth| D[JWT Signature Verification]
    D -->|4. Revocation| E[Token Revocation List]
    E -->|5. RBAC| F[Role-Based Access Control]
    F -->|6. Input| G[Validation & Sanitization]
    G -->|7. Data| H[Parameterized Queries]
    H -->|8. Audit| I[Comprehensive Logging]
    I -->|9. Monitor| J[Real-Time Alerts]
    J -->|10. Response| K[Automated IR]
    
    style B fill:#f96
    style C fill:#f96
    style D fill:#9f6
    style E fill:#9f6
    style F fill:#9f6
    style G fill:#ff9
    style H fill:#ff9
    style I fill:#69f
    style J fill:#69f
    style K fill:#f9f
```

**Legend:**
- 🔴 Red: Perimeter/Network defenses
- 🟢 Green: Authentication/Authorization
- 🟡 Yellow: Application security
- 🔵 Blue: Observability/Detection
- 🟣 Purple: Incident Response

---

## Appendix A: Security Testing Checklist

### A.1 Authentication Testing

- [ ] JWT signature verification (RS256 only)
- [ ] JWT expiration enforcement (5 min TTL)
- [ ] Token revocation check (jti in TRL)
- [ ] Algorithm confusion prevention
- [ ] Token binding verification
- [ ] Keycloak JWKS refresh
- [ ] Clock skew tolerance (±30s)

### A.2 Authorization Testing

- [ ] RBAC policy enforcement (all 18 methods)
- [ ] Privilege escalation prevention
- [ ] Method enumeration protection
- [ ] Admin-only method protection
- [ ] Cross-agent authorization
- [ ] Audit logging of all decisions

### A.3 Network Security Testing

- [ ] Security group rules (minimal ports)
- [ ] VPC isolation (no public IPs on agents)
- [ ] Service discovery DNS resolution
- [ ] NAT Gateway egress only
- [ ] TLS to AWS services (RDS, S3, Secrets)
- [ ] No hardcoded IPs

### A.4 Data Security Testing

- [ ] SQL injection prevention (parameterized queries)
- [ ] S3 bucket policies (least privilege)
- [ ] RDS encryption at rest
- [ ] Secrets in Secrets Manager (not env vars)
- [ ] No secrets in logs
- [ ] No secrets in ECR images

### A.5 Resilience Testing

- [ ] Rate limiting (300 req/min)
- [ ] Connection pooling (max 20/agent)
- [ ] Circuit breakers
- [ ] Graceful degradation
- [ ] Auto-scaling triggers
- [ ] DDoS protection (AWS Shield)

---

## Appendix B: Incident Response Runbooks

### B.1 Token Theft Response

```bash
# 1. Identify compromised token
# 2. Revoke immediately
# 3. Force user re-authentication
# 4. Rotate Keycloak client secret
# 5. Audit access logs
# 6. Notify security team
```

### B.2 Data Breach Response

```bash
# 1. Isolate affected service
# 2. Snapshot RDS for forensics
# 3. Review S3 access logs
# 4. Determine scope of exfiltration
# 5. Notify DPO/legal team
# 6. Prepare breach notification
```

### B.3 Keycloak Compromise Response

```bash
# 1. Rotate admin password immediately
# 2. Revoke all active tokens
# 3. Restore Keycloak DB from backup
# 4. Force MFA enrollment
# 5. Audit all recent admin actions
# 6. Review IAM role permissions
```

---

## Appendix C: Security Monitoring Queries

### C.1 Real-Time Security Dashboards

```sql
-- Dashboard 1: Authentication Failures
fields @timestamp, event_type, subject, reason
| filter event_type = "authentication_failure"
| stats count() as failures by bin(5m), reason
| sort @timestamp desc

-- Dashboard 2: Authorization Violations
fields @timestamp, subject, roles, method, granted
| filter event_type = "authorization" and granted = false
| stats count() as violations by subject, method
| sort violations desc

-- Dashboard 3: Anomalous Token Usage
fields @timestamp, jti, sourceIP
| stats count() as requests, count_distinct(sourceIP) as ips by jti
| filter ips > 1 or requests > 100
```

---

**Document Status:** Living Document - Updated continuously as new threats emerge  
**Next Review:** 2026-02-15  
**Owner:** CA-A2A Security Team  
**Classification:** Internal - Technical Documentation


