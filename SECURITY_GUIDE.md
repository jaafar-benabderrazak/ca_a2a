# Security Implementation Guide

## Overview

This guide covers the complete security implementation for the CA A2A multi-agent system, including:

- **Authentication** (JWT tokens and API keys)
- **Authorization** (Permission-based access control)
- **Rate Limiting** (Prevent abuse)
- **Audit Logging** (Track security events)
- **Transport Security** (HTTPS/TLS)
- **Network Security** (AWS VPC, Security Groups)

---

## Quick Start

### 1. **Development Mode** (No Authentication)

For quick testing and development:

```bash
# In your .env file
ENABLE_AUTHENTICATION=false
ENABLE_RATE_LIMITING=false
```

Agents will accept all requests without authentication.

### 2. **Basic Security** (API Keys)

Simple authentication with API keys:

```bash
# Generate API keys for all agents
python security_tools.py setup-all-agents

# This creates agent_credentials.env with:
ORCHESTRATOR_API_KEY=orchestrator-<random>
EXTRACTOR_API_KEY=extractor-<random>
VALIDATOR_API_KEY=validator-<random>
ARCHIVIST_API_KEY=archivist-<random>

# Copy to .env
cat agent_credentials.env >> .env

# Enable authentication
ENABLE_AUTHENTICATION=true
```

### 3. **Production Security** (JWT + Rate Limiting)

Full security with JWT tokens:

```bash
# 1. Generate secure secrets
python security_tools.py generate-secret --length 64

# 2. Update .env
JWT_SECRET_KEY=<generated-secret>
ENABLE_AUTHENTICATION=true
ENABLE_RATE_LIMITING=true

# 3. Generate JWT tokens for agents
python security_tools.py generate-jwt orchestrator --expires 8760 # 1 year

# 4. Distribute tokens to agents
AGENT_JWT_TOKEN=<generated-token>
```

---

## Architecture

### Authentication Flow

```
┌─────────────┐ ┌─────────────┐
│ Agent A │ │ Agent B │
│ │ │ │
│ Has JWT or │ POST /message │ Verifies │
│ API Key │ ─────────────────> │ credentials │
│ │ Authorization: │ │
│ │ Bearer <token> │ or │
└─────────────┘ └─────────────┘
 │
 ↓
 ┌─────────────┐
 │ Security │
 │ Manager │
 │ │
 │ • Authn │
 │ • Authz │
 │ • Rate Limit│
 │ • Audit Log │
 └─────────────┘
```

### Security Layers

```
┌─────────────────────────────────────────────────┐
│ Layer 1: Network Security (AWS VPC) │
│ • Private subnets │
│ • Security groups │
│ • VPC endpoints │
└─────────────────────────────────────────────────┘
 ↓
┌─────────────────────────────────────────────────┐
│ Layer 2: Transport Security (HTTPS/TLS) │
│ • SSL/TLS encryption │
│ • Certificate validation │
└─────────────────────────────────────────────────┘
 ↓
┌─────────────────────────────────────────────────┐
│ Layer 3: Authentication (Who are you?) │
│ • JWT tokens │
│ • API keys │
│ • mTLS certificates │
└─────────────────────────────────────────────────┘
 ↓
┌─────────────────────────────────────────────────┐
│ Layer 4: Authorization (What can you do?) │
│ • Permission checks │
│ • Role-based access control │
└─────────────────────────────────────────────────┘
 ↓
┌─────────────────────────────────────────────────┐
│ Layer 5: Rate Limiting (Abuse prevention) │
│ • Requests per minute │
│ • Requests per hour │
└─────────────────────────────────────────────────┘
 ↓
┌─────────────────────────────────────────────────┐
│ Layer 6: Audit Logging (What happened?) │
│ • Authentication attempts │
│ • Authorization failures │
│ • Rate limit violations │
└─────────────────────────────────────────────────┘
```

---

## Implementation Details

### 1. JWT Authentication

**How it works:**

1. Generate JWT token with agent ID and permissions
2. Agent includes token in `Authorization: Bearer <token>` header
3. Receiving agent verifies signature and expiration
4. Extract permissions from token payload

**Generate token:**

```python
from security import JWTManager

jwt_manager = JWTManager(secret_key='your-secret')
token = jwt_manager.generate_token(
 agent_id='orchestrator',
 permissions=['*'], # or specific methods
 expires_hours=24
)
```

**Verify token:**

```python
success, auth_context, error = jwt_manager.verify_token(token)
if success:
 print(f"Agent: {auth_context.agent_id}")
 print(f"Permissions: {auth_context.permissions}")
```

**JWT Payload:**

```json
{
 "agent_id": "orchestrator",
 "permissions": ["*"],
 "iat": 1703001600,
 "exp": 1703088000,
 "iss": "ca-a2a-system",
 "aud": "ca-a2a-agents"
}
```

### 2. API Key Authentication

**How it works:**

1. Generate random API key for each agent
2. Store key (or hash) in memory or database
3. Agent includes key in `X-API-Key` header
4. Receiving agent looks up key and associated permissions

**Register API key:**

```python
from security import APIKeyManager

api_key_manager = APIKeyManager()
api_key_manager.register_api_key(
 api_key='orchestrator-abc123xyz789',
 agent_id='orchestrator',
 permissions=['*']
)
```

**In-memory vs Database:**

```python
# Development: In-memory cache (fast, simple)
api_key_manager = APIKeyManager()

# Production: Database-backed (persistent, scalable)
api_key_manager = APIKeyManager(db_pool=postgres_pool)
```

### 3. Authorization (Permissions)

**Permission Schemes:**

```python
# 1. Wildcard (full access)
permissions = ['*']

# 2. Specific methods
permissions = ['extract_document', 'validate_document', 'get_document']

# 3. Pattern matching (future)
permissions = ['extract_*', 'get_*']
```

**Check permission:**

```python
from security import SecurityManager

security_manager = SecurityManager()

# ... after authentication ...
allowed = security_manager.check_permission(auth_context, 'extract_document')
if not allowed:
 return error_response(403, "Permission denied")
```

### 4. Rate Limiting

**Configuration:**

```python
# In config.py or .env
RATE_LIMIT_RPM=60 # 60 requests per minute
RATE_LIMIT_RPH=1000 # 1000 requests per hour
```

**How it works:**

```python
from security import RateLimiter

rate_limiter = RateLimiter(
 requests_per_minute=60,
 requests_per_hour=1000
)

allowed, error = rate_limiter.check_rate_limit(agent_id='orchestrator')
if not allowed:
 return error_response(429, f"Rate limit exceeded: {error}")
```

**Get usage stats:**

```python
stats = rate_limiter.get_usage_stats('orchestrator')
# Returns:
# {
# 'requests_last_minute': 45,
# 'requests_last_hour': 523,
# 'rpm_limit': 60,
# 'rph_limit': 1000
# }
```

### 5. Audit Logging

**What is logged:**

- Authentication attempts (success/failure)
- Authorization failures
- Rate limit violations
- Method calls with agent ID
- Source IP addresses

**Example logs:**

```json
{
 "event": "authentication_attempt",
 "agent_id": "orchestrator",
 "auth_method": "jwt",
 "success": true,
 "timestamp": "2024-12-21T10:30:00Z",
 "source_ip": "10.0.1.50"
}

{
 "event": "authorization_failure",
 "agent_id": "extractor",
 "method": "delete_document",
 "required_permission": "delete_document",
 "timestamp": "2024-12-21T10:31:00Z"
}

{
 "event": "rate_limit_exceeded",
 "agent_id": "validator",
 "limit_type": "60 requests per minute",
 "timestamp": "2024-12-21T10:32:00Z"
}
```

**Storage options:**

```python
# 1. CloudWatch Logs (recommended for AWS)
auditor = SecurityAuditor(db_pool=None) # Logs to CloudWatch via logger

# 2. Database
auditor = SecurityAuditor(db_pool=postgres_pool)

# 3. File
# Configure via logging.basicConfig()
```

### 6. Request Signing (HMAC)

**Optional:** Add HMAC signature to prevent tampering.

```python
from security import RequestSigner

signer = RequestSigner(secret_key='signature-secret')

# Sign request
signature = signer.sign_request('POST', '/message', request_body)
headers['X-Signature'] = signature

# Verify signature
valid, error = signer.verify_signature(
 headers['X-Signature'],
 'POST',
 '/message',
 request_body
)
```

---

## Configuration

### Environment Variables

See `env.security.example` for complete configuration.

**Required:**

```bash
# Enable security features
ENABLE_AUTHENTICATION=true

# JWT secret (CHANGE IN PRODUCTION!)
JWT_SECRET_KEY=<random-64-char-string>

# Agent credentials
AGENT_JWT_TOKEN=<token>
# OR
AGENT_API_KEY=<key>
```

**Optional:**

```bash
# Rate limiting
ENABLE_RATE_LIMITING=true
RATE_LIMIT_RPM=60
RATE_LIMIT_RPH=1000

# Request signing
ENABLE_REQUEST_SIGNING=false
SIGNATURE_SECRET_KEY=<secret>

# SSL/TLS
ENABLE_SSL=true
SSL_CERT_PATH=/path/to/cert.pem
SSL_KEY_PATH=/path/to/key.pem
```

### Database Schema

For production API key storage:

```sql
CREATE TABLE api_keys (
 id SERIAL PRIMARY KEY,
 key_hash VARCHAR(64) UNIQUE NOT NULL,
 agent_id VARCHAR(100) NOT NULL,
 permissions TEXT[] NOT NULL,
 metadata JSONB,
 is_active BOOLEAN DEFAULT true,
 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 last_used TIMESTAMP,
 expires_at TIMESTAMP
);

CREATE TABLE security_audit_logs (
 id SERIAL PRIMARY KEY,
 event_type VARCHAR(50) NOT NULL,
 agent_id VARCHAR(100),
 details JSONB,
 timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## Usage Examples

### Example 1: Agent with Authentication

```python
from base_agent import BaseAgent
from config import AGENTS_CONFIG

class MyAgent(BaseAgent):
 def __init__(self):
 config = AGENTS_CONFIG['orchestrator']
 super().__init__(
 name='Orchestrator',
 host=config['host'],
 port=config['port'],
 enable_auth=True, # Enable authentication
 enable_rate_limiting=True # Enable rate limiting
 )
 
 # ... rest of implementation
```

### Example 2: Calling Another Agent

```python
# Credentials automatically loaded from environment
# AGENT_JWT_TOKEN or AGENT_API_KEY

from a2a_protocol import A2AMessage

message = A2AMessage.create_request(
 method='extract_document',
 params={'s3_key': 'documents/invoice.pdf'}
)

# send_message_to_agent automatically includes auth headers
result = await self.send_message_to_agent(
 'http://extractor:8002',
 message
)
```

### Example 3: Testing with curl

```bash
# Without authentication
curl -X POST http://localhost:8002/message \
 -H "Content-Type: application/json" \
 -d '{"jsonrpc":"2.0","id":"1","method":"extract_document","params":{"s3_key":"test.pdf"}}'

# With JWT token
curl -X POST http://localhost:8002/message \
 -H "Content-Type: application/json" \
 -H "Authorization: Bearer <jwt-token>" \
 -d '{"jsonrpc":"2.0","id":"1","method":"extract_document","params":{"s3_key":"test.pdf"}}'

# With API key
curl -X POST http://localhost:8002/message \
 -H "Content-Type: application/json" \
 -H "X-API-Key: extractor-abc123xyz789" \
 -d '{"jsonrpc":"2.0","id":"1","method":"extract_document","params":{"s3_key":"test.pdf"}}'
```

### Example 4: Generate Credentials

```bash
# Setup all agent credentials at once
python security_tools.py setup-all-agents

# Generate individual JWT token
python security_tools.py generate-jwt orchestrator \
 --permissions extract_document validate_document \
 --expires 720 # 30 days

# Generate API key
python security_tools.py generate-api-key extractor

# Verify a token
python security_tools.py verify-jwt <token>
```

---

## Security Best Practices

### DO:

1. **Rotate secrets regularly** (every 90 days minimum)
2. **Use strong random secrets** (64+ characters)
3. **Store production secrets in AWS Secrets Manager**
4. **Enable HTTPS/TLS** for all communication
5. **Use JWT tokens for production** (more secure than API keys)
6. **Monitor audit logs** for suspicious activity
7. **Set appropriate rate limits** based on expected usage
8. **Use different secrets** for dev/staging/production
9. **Enable authentication** in staging and production
10. **Test security** regularly

### DON'T:

1. **Don't commit `.env` files** to version control
2. **Don't share secrets** via email, chat, or unsecured channels
3. **Don't use weak or predictable secrets** (e.g., "password123")
4. **Don't disable authentication** in production
5. **Don't reuse secrets** across environments
6. **Don't hardcode secrets** in source code
7. **Don't ignore rate limit violations** (investigate them)
8. **Don't skip regular security audits**
9. **Don't grant wildcard permissions** unnecessarily
10. **Don't log sensitive data** (tokens, keys, passwords)

---

## Troubleshooting

### Authentication Failed

```
Error: Authentication failed: Invalid token
```

**Solutions:**
1. Check `AGENT_JWT_TOKEN` or `AGENT_API_KEY` is set
2. Verify token hasn't expired: `python security_tools.py verify-jwt <token>`
3. Ensure `JWT_SECRET_KEY` matches on both agents
4. Check for typos in token/key

### Rate Limit Exceeded

```
Error: Rate limit exceeded: 60 requests per minute
```

**Solutions:**
1. Check if legitimate spike or abuse
2. Increase limits in `.env`: `RATE_LIMIT_RPM=120`
3. Review audit logs: `grep "rate_limit_exceeded" logs/`
4. Implement exponential backoff in client

### Permission Denied

```
Error: Permission denied for method: delete_document
```

**Solutions:**
1. Check agent's permissions: `python security_tools.py verify-jwt <token>`
2. Grant permission: regenerate token with `delete_document` permission
3. Or use wildcard: `--permissions '*'`

### SSL/TLS Errors

```
Error: SSL certificate verification failed
```

**Solutions:**
1. Verify certificate paths in `.env`
2. Use valid certificates (not expired)
3. For development, disable SSL: `ENABLE_SSL=false`
4. Or disable verification: `SSL_VERIFY=false` (NOT for production!)

---

## AWS Integration

### Store Secrets in AWS Secrets Manager

```bash
# Store JWT secret
aws secretsmanager create-secret \
 --name ca-a2a/production/jwt-secret \
 --secret-string <your-secret>

# Store API keys
aws secretsmanager create-secret \
 --name ca-a2a/production/agent-keys \
 --secret-string '{"orchestrator":"key1","extractor":"key2"}'

# Retrieve in code
import boto3

secrets = boto3.client('secretsmanager')
response = secrets.get_secret_value(SecretId='ca-a2a/production/jwt-secret')
jwt_secret = response['SecretString']
```

### Update IAM Roles

```json
{
 "Effect": "Allow",
 "Action": [
 "secretsmanager:GetSecretValue"
 ],
 "Resource": [
 "arn:aws:secretsmanager:*:*:secret:ca-a2a/production/*"
 ]
}
```

### Enable CloudWatch Audit Logging

Security audit logs automatically go to CloudWatch when using Python logging:

```python
import logging

# Configure CloudWatch handler
logging.basicConfig(level=logging.INFO)
# Logs will appear in CloudWatch Logs group: /aws/ecs/ca-a2a-<agent>
```

---

## Migration Guide

### From No Security to Basic Security

```bash
# 1. Generate credentials
python security_tools.py setup-all-agents

# 2. Update .env
cat agent_credentials.env >> .env
ENABLE_AUTHENTICATION=true

# 3. Restart agents
docker-compose restart
# or
python run_agents.py
```

### From API Keys to JWT

```bash
# 1. Generate JWT tokens
python security_tools.py setup-all-agents

# 2. Update .env (remove API keys, add JWT tokens)
# Replace:
AGENT_API_KEY=...
# With:
AGENT_JWT_TOKEN=...

# 3. Restart agents
```

### From Development to Production

```bash
# 1. Generate production secrets
python security_tools.py generate-secret --length 64

# 2. Store in AWS Secrets Manager
aws secretsmanager create-secret --name ca-a2a/production/jwt-secret --secret-string <secret>

# 3. Update ECS task definitions to use AWS Secrets
# 4. Enable all security features
ENABLE_AUTHENTICATION=true
ENABLE_RATE_LIMITING=true
ENABLE_SSL=true
ENABLE_AUDIT_LOGGING=true

# 5. Deploy
./deploy.sh
```

---

## Performance Impact

| Feature | CPU Impact | Memory Impact | Latency Added |
|---------|-----------|---------------|---------------|
| JWT Verification | ~0.1ms | Negligible | ~0.1ms |
| API Key Lookup (memory) | <0.01ms | ~1KB per key | <0.01ms |
| API Key Lookup (DB) | ~1-5ms | Negligible | ~1-5ms |
| Rate Limiting | <0.01ms | ~100 bytes per agent | <0.01ms |
| Audit Logging | ~0.1-1ms | Varies | Async |
| Request Signing | ~0.5ms | Negligible | ~0.5ms |

**Total overhead:** ~1-2ms per request (negligible for most use cases)

---

## References

- [JWT.io](https://jwt.io/) - JWT token debugger
- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [Python Secrets Module](https://docs.python.org/3/library/secrets.html)

---

## Support

For issues or questions:
1. Check this guide first
2. Review audit logs
3. Test with `security_tools.py`
4. Check agent logs for detailed error messages
