# 9. Threat Model & Defenses

[← Back to Index](README.md)

---


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


---

[← Previous: Monitoring & Audit](08-MONITORING_AUDIT.md) | [Next: Security Operations →](10-SECURITY_OPERATIONS.md)
