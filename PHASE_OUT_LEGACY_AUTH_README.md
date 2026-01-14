# Authentication System Update - Phase Out Legacy Auth

**Date:** January 14, 2026  
**Version:** 3.0  
**Status:** Migration Planning

---

## Quick Overview

The CA-A2A authentication system has been updated to **remove legacy authentication methods** (API Keys, Legacy JWT) and use **only Keycloak OAuth2/OIDC**.

### Files Added

| File | Purpose |
|------|---------|
| `a2a_security_keycloak_only.py` | Simplified security manager (Keycloak OAuth2 only) |
| `MIGRATION_GUIDE_KEYCLOAK_ONLY.md` | Step-by-step migration instructions for clients |
| `AUTHENTICATION_ARCHITECTURE_UPDATE.md` | Architecture changes and technical details |
| `PHASE_OUT_LEGACY_AUTH_README.md` | This file - quick reference |

### What's Changing

✅ **Keep:** Keycloak OAuth2/OIDC (RS256 JWT)  
❌ **Remove:** API Keys  
❌ **Remove:** Legacy JWT (HS256 with shared secrets)

### Why This Change?

1. **Simplified codebase** - 36% code reduction
2. **Enhanced security** - RS256 asymmetric signing, no shared secrets
3. **Better UX** - SSO, MFA, password reset, self-service
4. **Compliance** - OAuth 2.0 & OpenID Connect standards
5. **Operational** - Centralized management, dynamic RBAC, federation ready

---

## Quick Start for Developers

### Current State (v2.1 - Hybrid Mode)

Agents support 3 authentication methods:
```bash
# Method 1: API Key
curl -H "X-API-Key: abc123" ...

# Method 2: Legacy JWT (HS256)
curl -H "Authorization: Bearer <legacy-jwt>" ...

# Method 3: Keycloak JWT (RS256)
curl -H "Authorization: Bearer <keycloak-jwt>" ...
```

### Target State (v3.0 - Keycloak Only)

Agents support only Keycloak OAuth2:
```bash
# Get token from Keycloak
TOKEN=$(curl -X POST "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=ca-a2a-agents" \
  -d "client_secret=$SECRET" \
  -d "username=$USER" \
  -d "password=$PASS" | jq -r '.access_token')

# Use token in API call
curl -H "Authorization: Bearer $TOKEN" ...
```

---

## Migration Checklist

### For System Administrators

- [ ] Read `MIGRATION_GUIDE_KEYCLOAK_ONLY.md`
- [ ] Verify Keycloak is deployed and configured
- [ ] Create service account credentials in Keycloak
- [ ] Store service passwords in AWS Secrets Manager
- [ ] Test Keycloak authentication: `./test-keycloak-auth.sh`

### For Client Developers

- [ ] Update client code to use Keycloak OAuth2 (see migration guide)
- [ ] Implement token caching (tokens expire in 5 minutes)
- [ ] Implement token refresh logic
- [ ] Test in staging environment
- [ ] Remove API key / legacy JWT code

### For DevOps/Infrastructure

- [ ] Update ECS task definitions (remove legacy env vars)
- [ ] Add Keycloak environment variables
- [ ] Add Keycloak secrets references
- [ ] Update Lambda functions to use Keycloak
- [ ] Deploy updated agents: `./Rebuild-All-Agents-NoPrompt.ps1`
- [ ] Monitor CloudWatch logs for authentication errors

---

## Timeline

| Phase | Duration | Target Date | Status |
|-------|----------|-------------|--------|
| **Planning & Documentation** | 1 day | Jan 14, 2026 | ✅ Complete |
| **Client Code Updates** | 2-3 weeks | Jan 20 - Feb 10, 2026 | ⏳ Pending |
| **Staging Deployment** | 1 day | Feb 10, 2026 | ⏳ Pending |
| **Production Deployment** | 1 day | Feb 15, 2026 | ⏳ Pending |
| **Monitoring & Verification** | 1 week | Feb 15-22, 2026 | ⏳ Pending |

**Next Milestone:** Client code migration (Jan 20 - Feb 10, 2026)

---

## Documentation

| Document | Description | When to Read |
|----------|-------------|--------------|
| **MIGRATION_GUIDE_KEYCLOAK_ONLY.md** | Complete migration instructions | **Read first** - Before starting migration |
| **AUTHENTICATION_ARCHITECTURE_UPDATE.md** | Technical details and API changes | For developers updating client code |
| **KEYCLOAK_INTEGRATION_GUIDE.md** | Keycloak setup and configuration | For admins configuring Keycloak |
| **KEYCLOAK_QUICK_START.md** | Quick Keycloak reference | For quick lookups |
| **test-keycloak-auth.sh** | Automated test script | For testing after migration |

---

## Example Code Updates

### Lambda Function (Before → After)

**Before (API Key):**
```python
import requests

API_KEY = "abc123"

response = requests.post(
    "http://orchestrator:8001/message",
    headers={"X-API-Key": API_KEY},
    json={"jsonrpc": "2.0", "method": "process_document", "params": {...}, "id": 1}
)
```

**After (Keycloak OAuth2 with Token Caching):**
```python
import requests
import time
import boto3

class KeycloakTokenCache:
    def __init__(self):
        secrets = boto3.client('secretsmanager', region_name='eu-west-3')
        self.client_secret = secrets.get_secret_value(SecretId='ca-a2a/keycloak-client-secret')['SecretString']
        self.password = secrets.get_secret_value(SecretId='ca-a2a/keycloak-lambda-service-password')['SecretString']
        self.access_token = None
        self.refresh_token = None
        self.expires_at = 0
    
    def get_token(self):
        if self.access_token and time.time() < (self.expires_at - 30):
            return self.access_token
        
        response = requests.post(
            "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "ca-a2a-agents",
                "client_secret": self.client_secret,
                "username": "lambda-service",
                "password": self.password
            }
        )
        data = response.json()
        self.access_token = data['access_token']
        self.refresh_token = data['refresh_token']
        self.expires_at = time.time() + data['expires_in']
        return self.access_token

token_cache = KeycloakTokenCache()

def lambda_handler(event, context):
    token = token_cache.get_token()
    
    response = requests.post(
        "http://orchestrator:8001/message",
        headers={"Authorization": f"Bearer {token}"},
        json={"jsonrpc": "2.0", "method": "process_document", "params": event, "id": 1}
    )
    return response.json()
```

---

## Testing

### Verify Keycloak is Working
```bash
./test-keycloak-auth.sh
```

### Test Agent Authentication
```bash
# Get token
TOKEN=$(curl -s -X POST "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=ca-a2a-agents" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "username=admin-user" \
  -d "password=$PASSWORD" | jq -r '.access_token')

# Call agent
curl -X POST "http://orchestrator.ca-a2a.local:8001/message" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","method":"list_skills","params":{},"id":1}'

# Expected: {"jsonrpc":"2.0","result":{"skills":[...]},"id":1}
```

### Monitor Logs
```bash
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3 | grep -i "auth\|keycloak\|error"
```

---

## Rollback Plan

If critical issues arise during migration:

```bash
# 1. Restore legacy authentication code
mv a2a_security_legacy_backup.py a2a_security.py

# 2. Re-add legacy environment variables
# - A2A_API_KEYS_JSON
# - A2A_JWT_PUBLIC_KEY_PEM
# - A2A_USE_KEYCLOAK=true

# 3. Redeploy agents
./Rebuild-All-Agents-NoPrompt.ps1

# 4. Update ECS services
aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --force-new-deployment --region eu-west-3
```

---

## Support & Questions

- **Migration Issues:** See `MIGRATION_GUIDE_KEYCLOAK_ONLY.md`
- **Keycloak Setup:** See `KEYCLOAK_INTEGRATION_GUIDE.md`
- **Testing:** Run `./test-keycloak-auth.sh`
- **Logs:** Check CloudWatch `/ecs/ca-a2a-*` log groups
- **Rollback:** Follow rollback plan above

---

## Key Benefits

✅ **Simpler Code** - 36% reduction (515 → 330 lines)  
✅ **Better Security** - RS256, no shared secrets, automatic key rotation  
✅ **Modern Standards** - OAuth 2.0, OpenID Connect 1.0  
✅ **Better UX** - SSO, MFA, password reset  
✅ **Centralized Management** - Keycloak admin console  
✅ **Dynamic RBAC** - Update roles without redeployment

---

## Next Steps

1. **Review documentation** - Read `MIGRATION_GUIDE_KEYCLOAK_ONLY.md`
2. **Plan migration** - Identify all clients using API keys/legacy JWT
3. **Update code** - Implement Keycloak OAuth2 in all clients
4. **Test in staging** - Verify authentication works
5. **Deploy to production** - Schedule migration window
6. **Monitor** - Watch logs for authentication errors

**Questions?** See documentation links above or check CloudWatch logs.

