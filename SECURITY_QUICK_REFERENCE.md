# 🔐 Security Quick Reference

## 🚀 Quick Commands

```bash
# === SETUP (One-time) ===

# Generate all agent credentials at once
python security_tools.py setup-all-agents

# Generate individual credentials
python security_tools.py generate-jwt orchestrator --permissions '*'
python security_tools.py generate-api-key extractor

# Generate secure secret (for JWT_SECRET_KEY)
python security_tools.py generate-secret --length 64

# === TESTING ===

# Verify a JWT token
python security_tools.py verify-jwt <token>

# Run security tests
pytest test_security.py -v
./test_security.ps1

# === USAGE ===

# Test with curl (JWT)
curl -X POST http://localhost:8001/message \
  -H "Authorization: Bearer <jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"get_agent_registry","params":{}}'

# Test with curl (API Key)
curl -X POST http://localhost:8001/message \
  -H "X-API-Key: orchestrator-abc123xyz789" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"get_agent_registry","params":{}}'
```

---

## 📝 Environment Variables

### Essential
```bash
# Enable/disable security
ENABLE_AUTHENTICATION=true
ENABLE_RATE_LIMITING=true

# JWT secret (CHANGE IN PRODUCTION!)
JWT_SECRET_KEY=your-secret-key-here

# Agent credentials (choose one)
AGENT_JWT_TOKEN=eyJhbGc...        # Recommended for production
AGENT_API_KEY=agent-name-key123   # Simple for development
```

### Optional
```bash
# Rate limiting
RATE_LIMIT_RPM=60
RATE_LIMIT_RPH=1000

# SSL/TLS
ENABLE_SSL=true
SSL_CERT_PATH=/path/to/cert.pem
SSL_KEY_PATH=/path/to/key.pem

# Request signing
ENABLE_REQUEST_SIGNING=false
SIGNATURE_SECRET_KEY=your-signature-secret
```

---

## 🔑 Authentication Methods

### 1. JWT Token (Production)
```python
# Generate
from security import JWTManager

jwt_manager = JWTManager('your-secret-key')
token = jwt_manager.generate_token(
    agent_id='orchestrator',
    permissions=['*'],
    expires_hours=24
)

# Use in request
headers = {'Authorization': f'Bearer {token}'}
```

### 2. API Key (Development)
```python
# Register
from security import APIKeyManager

api_key_manager = APIKeyManager()
api_key_manager.register_api_key(
    api_key='orchestrator-abc123',
    agent_id='orchestrator',
    permissions=['*']
)

# Use in request
headers = {'X-API-Key': 'orchestrator-abc123'}
```

---

## 🛡️ Enable Security in Agent

```python
from base_agent import BaseAgent

class MyAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name='MyAgent',
            host='localhost',
            port=8001,
            enable_auth=True,          # Enable authentication
            enable_rate_limiting=True  # Enable rate limiting
        )
```

---

## 📊 HTTP Status Codes

| Code | Meaning | Cause |
|------|---------|-------|
| 200 | OK | Request successful |
| 401 | Unauthorized | Missing or invalid credentials |
| 403 | Forbidden | No permission for method |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Error | Server error |

---

## 🔍 Troubleshooting

### Authentication Failed
```bash
# Check token is valid
python security_tools.py verify-jwt <token>

# Check environment variable is set
echo $AGENT_JWT_TOKEN    # Linux/Mac
echo $env:AGENT_JWT_TOKEN # Windows PowerShell
```

### Rate Limit Exceeded
```bash
# Increase limits in .env
RATE_LIMIT_RPM=120
RATE_LIMIT_RPH=2000

# Restart agent
```

### Permission Denied
```bash
# Check permissions
python security_tools.py verify-jwt <token>

# Grant full permissions
python security_tools.py generate-jwt <agent-id> --permissions '*'
```

---

## 📚 File Reference

| File | Purpose |
|------|---------|
| `security.py` | Core security module |
| `security_tools.py` | CLI tools |
| `SECURITY_GUIDE.md` | Complete documentation |
| `SECURITY_COMPLETE.md` | Implementation summary |
| `env.security.example` | Configuration template |
| `test_security.py` | Automated tests |
| `test_security.ps1` | Integration tests |

---

## 🎯 Common Tasks

### Setup Development Environment
```bash
cp env.security.example .env
# Edit .env: ENABLE_AUTHENTICATION=false
python run_agents.py
```

### Setup with Basic Security
```bash
python security_tools.py setup-all-agents
cat agent_credentials.env >> .env
# Edit .env: ENABLE_AUTHENTICATION=true
python run_agents.py
```

### Setup for Production
```bash
# Generate secret
python security_tools.py generate-secret > secret.txt

# Store in AWS Secrets Manager
aws secretsmanager create-secret \
  --name ca-a2a/production/jwt-secret \
  --secret-string $(cat secret.txt)

# Generate agent tokens
python security_tools.py generate-jwt orchestrator --expires 8760 > orch_token.txt
# ... repeat for other agents

# Deploy
./deploy.sh
```

---

## 💡 Best Practices

### ✅ DO
- Rotate secrets every 90 days
- Use JWT for production
- Enable rate limiting
- Monitor audit logs
- Use HTTPS in production
- Store secrets in AWS Secrets Manager

### ❌ DON'T
- Commit .env files
- Use weak secrets
- Share secrets via email
- Disable auth in production
- Ignore rate limit violations
- Log sensitive data

---

## 🔗 Quick Links

- **Full Guide:** `SECURITY_GUIDE.md`
- **Setup:** `env.security.example`
- **Tools Help:** `python security_tools.py --help`
- **Tests:** `pytest test_security.py -v`

---

## 🆘 Emergency

### Lockout Recovery
```bash
# Disable authentication temporarily
ENABLE_AUTHENTICATION=false python run_agents.py

# Generate new credentials
python security_tools.py setup-all-agents

# Re-enable authentication
ENABLE_AUTHENTICATION=true
```

### Reset Everything
```bash
# Delete credentials file
rm agent_credentials.env

# Generate new credentials
python security_tools.py setup-all-agents

# Update .env
cat agent_credentials.env >> .env
```

---

**Need more help?** Read `SECURITY_GUIDE.md` for comprehensive documentation.
