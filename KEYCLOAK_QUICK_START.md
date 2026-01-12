# Keycloak Quick Start Guide

Get Keycloak OAuth2 authentication running in 15 minutes.

## Prerequisites

- ✅ CA-A2A infrastructure deployed (`deploy.sh` completed)
- ✅ AWS CloudShell or VPC access
- ✅ AWS CLI configured

## Step-by-Step Deployment

### 1. Deploy Keycloak (5 minutes)

```bash
cd ca_a2a
chmod +x deploy-keycloak.sh configure-keycloak.sh update-agents-keycloak.sh test-keycloak-auth.sh
./deploy-keycloak.sh
```

Wait for "KEYCLOAK DEPLOYMENT COMPLETE" message.

### 2. Configure Keycloak Realm (3 minutes)

**Note:** This must run from within VPC. If in CloudShell, use ECS Exec:

```bash
# Get Keycloak task ID
TASK_ID=$(aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --service-name keycloak \
    --region eu-west-3 \
    --query 'taskArns[0]' \
    --output text | cut -d'/' -f3)

# Execute configuration from Keycloak container
aws ecs execute-command \
    --cluster ca-a2a-cluster \
    --task $TASK_ID \
    --container keycloak \
    --interactive \
    --command "/bin/bash" \
    --region eu-west-3

# Inside container, download and run config script
curl -O https://raw.githubusercontent.com/your-repo/ca_a2a/main/configure-keycloak.sh
chmod +x configure-keycloak.sh
./configure-keycloak.sh
exit
```

### 3. Update Agent Services (5 minutes)

```bash
./update-agents-keycloak.sh
# When prompted, type 'y' to deploy now
```

### 4. Test Authentication (2 minutes)

```bash
./test-keycloak-auth.sh
```

Expected output:
```
✓ Token Endpoint: Working
✓ JWKS Endpoint: Accessible
✓ Token Issuance: Successful
✓ Token Refresh: Working
✓ Service Integration: Tested

Keycloak authentication is properly configured!
```

## Quick Test - Python Client

```python
# test-keycloak-quick.py
import os
import requests

# Get credentials from Secrets Manager
import subprocess
client_secret = subprocess.check_output([
    "aws", "secretsmanager", "get-secret-value",
    "--secret-id", "ca-a2a/keycloak-client-secret",
    "--query", "SecretString",
    "--output", "text",
    "--region", "eu-west-3"
]).decode().strip()

password = subprocess.check_output([
    "aws", "secretsmanager", "get-secret-value",
    "--secret-id", "ca-a2a/keycloak-admin-user-password",
    "--query", "SecretString",
    "--output", "text",
    "--region", "eu-west-3"
]).decode().strip()

# Get token
token_resp = requests.post(
    "http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token",
    data={
        "grant_type": "password",
        "client_id": "ca-a2a-agents",
        "client_secret": client_secret,
        "username": "admin-user",
        "password": password
    }
).json()

access_token = token_resp["access_token"]
print(f"✓ Access token obtained: {access_token[:50]}...")

# Call orchestrator
response = requests.post(
    "http://orchestrator.ca-a2a.local:8001/message",
    headers={"Authorization": f"Bearer {access_token}"},
    json={"jsonrpc": "2.0", "id": 1, "method": "list_skills", "params": {}}
).json()

print(f"✓ Orchestrator response: {response['result']}")
```

Run:
```bash
python3 test-keycloak-quick.py
```

## Configuration Overview

### Created Resources

| Resource | Name | Purpose |
|----------|------|---------|
| **ECS Service** | `keycloak` | Keycloak server (Fargate) |
| **Service Discovery** | `keycloak.ca-a2a.local` | DNS name for agents |
| **RDS Database** | `keycloak` | Keycloak data storage |
| **Security Group** | `ca-a2a-keycloak-sg` | Network isolation |
| **CloudWatch Logs** | `/ecs/ca-a2a-keycloak` | Keycloak logs |
| **Secrets** | `ca-a2a/keycloak-admin-password` | Admin credentials |
| **Secrets** | `ca-a2a/keycloak-client-secret` | Client secret |
| **Secrets** | `ca-a2a/keycloak-admin-user-password` | Test user credentials |

### Created Users & Roles

| User | Role | Purpose |
|------|------|---------|
| `admin-user` | `admin` | Full access (for testing) |
| `lambda-service` | `lambda` | Lambda function access |
| `orchestrator-service` | `orchestrator` | Orchestrator agent access |

### Environment Variables (Added to Agents)

```bash
A2A_USE_KEYCLOAK=true
KEYCLOAK_URL=http://keycloak.ca-a2a.local:8080
KEYCLOAK_REALM=ca-a2a
KEYCLOAK_CLIENT_ID=ca-a2a-agents
KEYCLOAK_CACHE_TTL=3600
```

## Common Commands

### View Keycloak Logs
```bash
aws logs tail /ecs/ca-a2a-keycloak --follow --region eu-west-3
```

### Get Admin Password
```bash
aws secretsmanager get-secret-value \
    --secret-id ca-a2a/keycloak-admin-password \
    --query SecretString --output text --region eu-west-3
```

### Get Client Secret
```bash
aws secretsmanager get-secret-value \
    --secret-id ca-a2a/keycloak-client-secret \
    --query SecretString --output text --region eu-west-3
```

### Restart Keycloak Service
```bash
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service keycloak \
    --force-new-deployment \
    --region eu-west-3
```

### Check Keycloak Service Status
```bash
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services keycloak \
    --region eu-west-3 \
    --query 'services[0].{Status:status,Running:runningCount,Desired:desiredCount}'
```

## Troubleshooting

### Issue: "Cannot reach Keycloak"
**Solution:** Keycloak is private. Run tests from CloudShell or ECS task.

### Issue: "Invalid signature"
**Solution:** Verify `KEYCLOAK_URL` matches in agent task definitions.

### Issue: "Permission denied"
**Check:** User has correct role assigned in Keycloak.

## Next Steps

1. ✅ **Production Setup:**
   - Add ALB for external access
   - Configure HTTPS with ACM certificate
   - Enable MFA in Keycloak

2. ✅ **User Management:**
   - Create additional users via Keycloak admin console
   - Assign roles based on job function
   - Configure password policies

3. ✅ **Integration:**
   - Update Lambda functions to use Keycloak tokens
   - Integrate with frontend applications
   - Add SSO for admin console

4. ✅ **Monitoring:**
   - Set up CloudWatch alarms for Keycloak health
   - Configure log retention policies
   - Enable CloudTrail for secret access audit

## Documentation

- **Full Guide:** [KEYCLOAK_INTEGRATION_GUIDE.md](KEYCLOAK_INTEGRATION_GUIDE.md)
- **API Reference:** [keycloak_auth.py](keycloak_auth.py)
- **Client Example:** [keycloak_client_example.py](keycloak_client_example.py)
- **Test Suite:** [test_keycloak_integration.py](test_keycloak_integration.py)

---

**Keycloak is now integrated with CA-A2A!** 🎉

All agents now support OAuth2/OIDC authentication with centralized user management, MFA, and audit logging.

