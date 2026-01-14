# Migration Guide: Phase Out Legacy Authentication

**Date**: January 14, 2026  
**Version**: 3.0  
**Breaking Changes**: Yes - Legacy authentication removed

---

## Executive Summary

This migration removes legacy authentication methods (API Keys and HS256 JWT) in favor of **Keycloak OAuth2/OIDC only**.

### What's Changing

| Authentication Method | Status | Action Required |
|----------------------|--------|-----------------|
| **Keycloak OAuth2/OIDC** | ✅ **Required** | **Migrate all clients** |
| API Keys | ❌ **Removed** | **Must migrate to Keycloak** |
| Legacy JWT (HS256) | ❌ **Removed** | **Must migrate to Keycloak** |

### Benefits

✅ **Simplified codebase** - Single authentication path  
✅ **Enhanced security** - RS256 asymmetric signing, MFA support  
✅ **Centralized management** - User/role management in Keycloak  
✅ **Industry standards** - OAuth 2.0, OpenID Connect 1.0  
✅ **Dynamic RBAC** - Real-time role updates without redeployment  
✅ **Better audit trail** - Comprehensive authentication logging

---

## Migration Steps

### Phase 1: Deploy Keycloak (If Not Already Done)

```bash
# 1. Deploy Keycloak service
./deploy-keycloak.sh

# 2. Configure realm, client, users, roles
./configure-keycloak.sh

# 3. Test Keycloak authentication
./test-keycloak-auth.sh
```

### Phase 2: Migrate Existing Clients

#### For Lambda Functions (formerly using API Keys)

**Before (API Key):**
```python
# Lambda function
import boto3
import requests

API_KEY = "abc123xyz"  # Static API key

response = requests.post(
    "http://orchestrator.ca-a2a.local:8001/message",
    headers={"X-API-Key": API_KEY},
    json={"jsonrpc": "2.0", "method": "process_document", "params": {"s3_key": "doc.pdf"}, "id": 1}
)
```

**After (Keycloak OAuth2):**
```python
# Lambda function
import boto3
import requests

# Get Keycloak credentials from Secrets Manager
secrets_client = boto3.client('secretsmanager', region_name='eu-west-3')
client_secret = secrets_client.get_secret_value(SecretId='ca-a2a/keycloak-client-secret')['SecretString']
service_password = secrets_client.get_secret_value(SecretId='ca-a2a/keycloak-lambda-service-password')['SecretString']

# Authenticate with Keycloak (cache this token!)
token_response = requests.post(
    "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token",
    data={
        "grant_type": "password",
        "client_id": "ca-a2a-agents",
        "client_secret": client_secret,
        "username": "lambda-service",
        "password": service_password
    }
)
access_token = token_response.json()['access_token']

# Call agent with Keycloak JWT
response = requests.post(
    "http://orchestrator.ca-a2a.local:8001/message",
    headers={"Authorization": f"Bearer {access_token}"},
    json={"jsonrpc": "2.0", "method": "process_document", "params": {"s3_key": "doc.pdf"}, "id": 1}
)
```

**Token Caching (Important):**
```python
import time

class KeycloakTokenCache:
    def __init__(self, keycloak_url, client_id, client_secret, username, password):
        self.keycloak_url = keycloak_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.access_token = None
        self.refresh_token = None
        self.expires_at = 0
    
    def get_token(self):
        """Get valid access token (fetches new token if expired)"""
        now = time.time()
        
        # If token is still valid (with 30s buffer), return it
        if self.access_token and now < (self.expires_at - 30):
            return self.access_token
        
        # Try to refresh token if we have a refresh token
        if self.refresh_token:
            try:
                return self._refresh_token()
            except Exception:
                pass  # Fall through to password grant
        
        # Get new token via password grant
        return self._password_grant()
    
    def _password_grant(self):
        response = requests.post(
            f"{self.keycloak_url}/realms/ca-a2a/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "username": self.username,
                "password": self.password
            }
        )
        response.raise_for_status()
        data = response.json()
        
        self.access_token = data['access_token']
        self.refresh_token = data['refresh_token']
        self.expires_at = time.time() + data['expires_in']
        
        return self.access_token
    
    def _refresh_token(self):
        response = requests.post(
            f"{self.keycloak_url}/realms/ca-a2a/protocol/openid-connect/token",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token
            }
        )
        response.raise_for_status()
        data = response.json()
        
        self.access_token = data['access_token']
        self.refresh_token = data['refresh_token']
        self.expires_at = time.time() + data['expires_in']
        
        return self.access_token

# Usage in Lambda
token_cache = KeycloakTokenCache(
    keycloak_url="http://keycloak.ca-a2a.local:8080",
    client_id="ca-a2a-agents",
    client_secret=client_secret,
    username="lambda-service",
    password=service_password
)

def lambda_handler(event, context):
    # Get valid token (automatically refreshes if needed)
    access_token = token_cache.get_token()
    
    # Use token for API calls
    response = requests.post(
        "http://orchestrator.ca-a2a.local:8001/message",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"jsonrpc": "2.0", "method": "process_document", "params": event, "id": 1}
    )
    return response.json()
```

#### For Service-to-Service Calls

**Before (Legacy JWT):**
```python
# Agent calling another agent
import jwt

# Generate legacy JWT
token = jwt.encode(
    {"sub": "orchestrator", "exp": time.time() + 120},
    os.getenv("JWT_SECRET"),
    algorithm="HS256"
)

response = requests.post(
    "http://extractor.ca-a2a.local:8002/message",
    headers={"Authorization": f"Bearer {token}"},
    json={"jsonrpc": "2.0", "method": "extract_document", "params": {"s3_key": "doc.pdf"}, "id": 1}
)
```

**After (Keycloak OAuth2 - Service Account):**
```python
# Agent calling another agent
# Use service account (orchestrator-service)

# Authenticate with Keycloak (cache this!)
token_response = requests.post(
    "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token",
    data={
        "grant_type": "password",
        "client_id": "ca-a2a-agents",
        "client_secret": os.getenv("KEYCLOAK_CLIENT_SECRET"),
        "username": "orchestrator-service",
        "password": os.getenv("KEYCLOAK_ORCHESTRATOR_PASSWORD")
    }
)
access_token = token_response.json()['access_token']

response = requests.post(
    "http://extractor.ca-a2a.local:8002/message",
    headers={"Authorization": f"Bearer {access_token}"},
    json={"jsonrpc": "2.0", "method": "extract_document", "params": {"s3_key": "doc.pdf"}, "id": 1}
)
```

### Phase 3: Update Agent Configuration

**Remove legacy environment variables:**
```bash
# OLD - Remove these
A2A_API_KEYS_JSON='{"lambda":"abc123"}'
A2A_JWT_PUBLIC_KEY_PEM="-----BEGIN PUBLIC KEY-----..."
A2A_JWT_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----..."
A2A_JWT_ISSUER="ca-a2a"
A2A_JWT_ALG="HS256"

# NEW - Keep only Keycloak config
KEYCLOAK_URL=http://keycloak.ca-a2a.local:8080
KEYCLOAK_REALM=ca-a2a
KEYCLOAK_CLIENT_ID=ca-a2a-agents
KEYCLOAK_CACHE_TTL=3600
```

**Update secrets in AWS Secrets Manager:**
```bash
# Create service account passwords
aws secretsmanager create-secret \
  --name ca-a2a/keycloak-lambda-service-password \
  --secret-string "$(openssl rand -base64 32)" \
  --region eu-west-3

aws secretsmanager create-secret \
  --name ca-a2a/keycloak-orchestrator-service-password \
  --secret-string "$(openssl rand -base64 32)" \
  --region eu-west-3
```

### Phase 4: Deploy Updated Agents

**Update agent code:**
```bash
# Replace a2a_security.py with Keycloak-only version
mv a2a_security.py a2a_security_legacy_backup.py
mv a2a_security_keycloak_only.py a2a_security.py

# Rebuild and deploy agents
./Rebuild-All-Agents-NoPrompt.ps1
```

**Update ECS task definitions:**
```json
{
  "containerDefinitions": [{
    "environment": [
      {"name": "KEYCLOAK_URL", "value": "http://keycloak.ca-a2a.local:8080"},
      {"name": "KEYCLOAK_REALM", "value": "ca-a2a"},
      {"name": "KEYCLOAK_CLIENT_ID", "value": "ca-a2a-agents"},
      {"name": "KEYCLOAK_CACHE_TTL", "value": "3600"}
    ],
    "secrets": [
      {
        "name": "KEYCLOAK_CLIENT_SECRET",
        "valueFrom": "arn:aws:secretsmanager:eu-west-3:555043101106:secret:ca-a2a/keycloak-client-secret-xxxxx"
      },
      {
        "name": "KEYCLOAK_ORCHESTRATOR_PASSWORD",
        "valueFrom": "arn:aws:secretsmanager:eu-west-3:555043101106:secret:ca-a2a/keycloak-orchestrator-service-password-xxxxx"
      }
    ]
  }]
}
```

### Phase 5: Verify and Test

```bash
# 1. Test Keycloak authentication
./test-keycloak-auth.sh

# 2. Test end-to-end pipeline
./test-complete-pipeline-simple.sh

# 3. Monitor logs for any authentication errors
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3 | grep -i "auth\|error"
```

---

## Rollback Plan

If issues arise, you can temporarily rollback:

```bash
# 1. Restore legacy authentication code
mv a2a_security_legacy_backup.py a2a_security.py

# 2. Redeploy agents with legacy env vars
# (Add back A2A_API_KEYS_JSON, A2A_JWT_PUBLIC_KEY_PEM, etc.)

# 3. Update task definitions
aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --force-new-deployment
```

---

## Breaking Changes Summary

### Removed Environment Variables
- `A2A_API_KEYS_JSON` - API keys no longer supported
- `A2A_JWT_PUBLIC_KEY_PEM` - Legacy JWT no longer supported
- `A2A_JWT_PRIVATE_KEY_PEM` - Legacy JWT no longer supported
- `A2A_JWT_ISSUER` - Legacy JWT no longer supported
- `A2A_JWT_ALG` - Legacy JWT no longer supported
- `A2A_RBAC_POLICY_JSON` - Static RBAC replaced by Keycloak roles
- `A2A_USE_KEYCLOAK` - Keycloak is now mandatory (no flag needed)

### Removed Headers
- `X-API-Key` - No longer accepted
- `Authorization: ApiKey <key>` - No longer accepted

### Required Headers
- `Authorization: Bearer <keycloak-jwt>` - **Required for all requests**

### API Changes
All clients must now:
1. Authenticate with Keycloak to obtain JWT token
2. Include `Authorization: Bearer <token>` header in all requests
3. Refresh tokens before expiry (5-minute lifespan)

---

## Timeline

| Phase | Duration | Status |
|-------|----------|--------|
| **Phase 1:** Deploy Keycloak | 1 day | ✅ Complete |
| **Phase 2:** Migrate clients | 2-3 weeks | 🔄 In Progress |
| **Phase 3:** Update agent config | 1 day | ⏳ Pending |
| **Phase 4:** Deploy updated agents | 1 day | ⏳ Pending |
| **Phase 5:** Verify and monitor | 1 week | ⏳ Pending |

**Target Completion Date:** February 15, 2026

---

## Support

For issues or questions during migration:
- **Documentation:** See [KEYCLOAK_INTEGRATION_GUIDE.md](./KEYCLOAK_INTEGRATION_GUIDE.md)
- **Testing:** Run `./test-keycloak-auth.sh` to verify setup
- **Logs:** Check CloudWatch logs for authentication errors
- **Rollback:** Follow rollback plan if critical issues arise

---

## Conclusion

This migration simplifies the authentication architecture while enhancing security with modern OAuth2/OIDC standards. All clients must migrate to Keycloak authentication before the legacy methods are removed from production.

**Next Steps:**
1. Review this migration guide
2. Test Keycloak authentication in dev/staging environment
3. Update client code to use Keycloak OAuth2
4. Schedule production migration window
5. Deploy updated agents and monitor

