# 11. Implementation Reference

[← Back to Index](README.md)

---


### 11.1 Key Files

| File | Purpose | Lines |
|------|---------|-------|
| `a2a_security.py` | Core security manager, JWT, RBAC, rate limiting | 515 |
| `keycloak_auth.py` | Keycloak JWT validation, RBAC mapper | 280 |
| `a2a_security_enhanced.py` | Token revocation, request signing, mTLS | 650 |
| `admin_api.py` | Admin API for token revocation | 350 |
| `base_agent.py` | Agent base class with security integration | 395 |
| `deploy-keycloak.sh` | Keycloak deployment script | 250 |
| `configure-keycloak.sh` | Keycloak realm/client setup | 180 |

### 11.2 Environment Variables

**Security Configuration:**

```bash
# Authentication
A2A_REQUIRE_AUTH=true
A2A_USE_KEYCLOAK=true
KEYCLOAK_URL=http://keycloak.ca-a2a.local:8080
KEYCLOAK_REALM=ca-a2a
KEYCLOAK_CLIENT_ID=ca-a2a-agents
KEYCLOAK_CACHE_TTL=3600

# RBAC
A2A_RBAC_POLICY_JSON='{"allow":{"admin":["*"],"lambda":["upload_document"]},"deny":{}}'

# Rate Limiting
A2A_ENABLE_RATE_LIMIT=true
A2A_RATE_LIMIT_PER_MINUTE=300

# Replay Protection
A2A_ENABLE_REPLAY_PROTECTION=true
A2A_REPLAY_TTL_SECONDS=120

# JWT (if using native JWT instead of Keycloak)
A2A_JWT_ISSUER=ca-a2a
A2A_JWT_ALG=RS256
A2A_JWT_PUBLIC_KEY_PEM=/path/to/public.pem
A2A_JWT_PRIVATE_KEY_PEM=/path/to/private.pem
A2A_JWT_MAX_SKEW_SECONDS=30
A2A_JWT_MAX_TOKEN_AGE_SECONDS=120

# Secrets
POSTGRES_PASSWORD=<retrieved-from-secrets-manager>
KEYCLOAK_ADMIN_PASSWORD=<retrieved-from-secrets-manager>
KEYCLOAK_CLIENT_SECRET=<retrieved-from-secrets-manager>
```

### 11.3 Deployment Commands

**Deploy Keycloak:**
```bash
cd /path/to/ca_a2a
./deploy-keycloak.sh
./configure-keycloak.sh
```

**Update Agents with Keycloak:**
```bash
./update-agents-keycloak.sh
```

**Test Authentication:**
```bash
./test-keycloak-auth.sh
```

**View Security Metrics:**
```bash
# Admin API (deploy separately or run locally)
python admin_api.py

# Get security stats
curl http://localhost:9000/admin/security-stats \
  -H "Authorization: Bearer $ADMIN_JWT"
```

---

## Appendix A: Security Checklist

### Pre-Production Deployment

- [ ] **Network Security**
  - [ ] VPC with private subnets configured
  - [ ] Security groups follow least-privilege
  - [ ] NAT Gateway for outbound access only
  - [ ] VPC endpoints for AWS services
  - [ ] No public IPs on agent tasks

- [ ] **Authentication & Authorization**
  - [ ] Keycloak deployed and configured
  - [ ] Realms and clients created
  - [ ] Roles defined and mapped to RBAC
  - [ ] Client secrets stored in Secrets Manager
  - [ ] JWT signature verification enabled

- [ ] **Data Security**
  - [ ] RDS encryption at rest enabled
  - [ ] S3 bucket encryption enabled
  - [ ] Secrets Manager for all credentials
  - [ ] TLS for RDS connections configured
  - [ ] Backups enabled with retention policy

- [ ] **Application Security**
  - [ ] Rate limiting enabled (300/min)
  - [ ] Replay protection enabled (120s TTL)
  - [ ] Input validation with JSON Schema
  - [ ] Token revocation system deployed
  - [ ] Audit logging to CloudWatch

- [ ] **Monitoring & Alerting**
  - [ ] CloudWatch Logs retention set (7 days)
  - [ ] CloudWatch alarms for errors
  - [ ] Security audit log monitoring
  - [ ] Metrics for authentication failures
  - [ ] Dashboard for security events

- [ ] **Compliance**
  - [ ] Data retention policy documented
  - [ ] Incident response plan defined
  - [ ] Security review schedule established
  - [ ] Vulnerability scanning enabled
  - [ ] Penetration testing completed

### Post-Deployment Verification

```bash
# 1. Verify all agents are running
aws ecs list-tasks --cluster ca-a2a-cluster --region eu-west-3

# 2. Test authentication
./test-keycloak-auth.sh

# 3. Check CloudWatch Logs
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3

# 4. Verify security groups
aws ec2 describe-security-groups \
  --filters "Name=vpc-id,Values=vpc-086392a3eed899f72" \
  --region eu-west-3

# 5. Test rate limiting
for i in {1..350}; do 
  curl -X POST http://alb-url/message \
    -H "Authorization: Bearer $JWT" \
    -d '{"jsonrpc":"2.0","method":"list_documents","params":{},"id":'$i'}'
done
# Should see 429 after 300 requests
```

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **A2A** | Agent-to-Agent: Communication protocol for autonomous agents |
| **ALB** | Application Load Balancer: AWS load balancing service |
| **ECS** | Elastic Container Service: AWS container orchestration |
| **Fargate** | Serverless compute engine for containers |
| **JWKS** | JSON Web Key Set: Public keys for JWT verification |
| **JWT** | JSON Web Token: Compact, URL-safe token format |
| **jti** | JWT ID: Unique identifier claim in JWT |
| **OAuth2** | Open standard for access delegation |
| **OIDC** | OpenID Connect: Identity layer on top of OAuth2 |
| **RBAC** | Role-Based Access Control: Access control based on roles |
| **RS256** | RSA Signature with SHA-256: JWT signing algorithm |
| **VPC** | Virtual Private Cloud: Isolated network in AWS |

---

**End of Document**


---

[← Previous: Security Operations](10-SECURITY_OPERATIONS.md)
