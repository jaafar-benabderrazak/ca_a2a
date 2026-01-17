# CA-A2A Security Operations

**Version:** 6.0  
**Last Updated:** January 17, 2026

---

## Incident Response

### Security Incident Types

| Incident | Detection | Response Time | Action |
|----------|-----------|---------------|--------|
| **Token Theft** | Unusual location/pattern | < 15 min | Revoke token via Admin API |
| **Authentication Failure Spike** | > 10 failures/min | < 5 min | Investigate + block IP if needed |
| **Unauthorized Access Attempt** | RBAC denial logged | < 30 min | Review permissions |
| **Data Breach Suspected** | Unusual data access pattern | < 1 hour | Investigate + rotate credentials |

### Response Playbooks

**Token Revocation:**
```bash
# 1. Identify compromised token JTI
aws logs filter-pattern "jti=abc123" --log-group /ecs/ca-a2a-orchestrator

# 2. Revoke token
curl -X POST https://orchestrator.ca-a2a.local:8001/admin/revoke-token \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"jti": "abc123", "reason": "Security breach", "revoked_by": "admin@example.com"}'

# 3. Verify revocation
curl https://orchestrator.ca-a2a.local:8001/admin/revoked-tokens | jq '.[] | select(.jti=="abc123")'

# 4. Monitor for usage attempts
aws logs filter-pattern "token_revoked jti=abc123" --log-group /ecs/ca-a2a-orchestrator --follow
```

---

## Security Maintenance

### Weekly Tasks
- ✅ Review authentication failure logs
- ✅ Check rate limit violations
- ✅ Monitor CloudWatch alarms
- ✅ Review new CVEs in dependencies

### Monthly Tasks
- ✅ Rotate Secrets Manager secrets
- ✅ Review IAM permissions (least privilege)
- ✅ Update security documentation
- ✅ Run penetration tests (optional)

### Quarterly Tasks
- ✅ Security audit (external)
- ✅ Dependency updates (major versions)
- ✅ Review and update threat model
- ✅ Disaster recovery drill

---

## Access Control

### Admin Access

**Admin Roles:**
- **Security Admin:** Token revocation, audit log access
- **Ops Admin:** Deploy code, scale services
- **Read-Only Admin:** View logs, metrics (no changes)

**Admin API Endpoints:**
```bash
# Token management
POST /admin/revoke-token
GET /admin/revoked-tokens
DELETE /admin/cleanup-expired-tokens

# Security stats
GET /admin/security-stats
GET /admin/authentication-failures

# Health & metrics
GET /admin/health
GET /admin/metrics
```

---

## Key Rotation

### Keycloak Signing Keys
- **Frequency:** Every 90 days
- **Process:** Keycloak admin console → Realm Settings → Keys → Rotate
- **Impact:** Old tokens remain valid until expiration (15 min)

### AWS Secrets
- **Frequency:** Automatic (Secrets Manager)
- **Manual:** Use `aws secretsmanager rotate-secret`

### TLS Certificates
- **ALB:** AWS Certificate Manager (automatic renewal)
- **mTLS:** Manual generation (client certs expire after 1 year)

---

## Backup & Recovery

### Database Backups
- **Frequency:** Automated daily snapshots
- **Retention:** 30 days
- **Recovery Time Objective (RTO):** < 1 hour
- **Recovery Point Objective (RPO):** < 24 hours

### Configuration Backup
- **ECS Task Definitions:** Versioned in Git
- **IAM Policies:** Versioned in Git
- **Keycloak Configuration:** Manual export (quarterly)

---

## Security Contacts

| Role | Responsibility | On-Call |
|------|----------------|---------|
| **Security Team** | Incident response, threat analysis | 24/7 |
| **Ops Team** | Infrastructure, deployments | Business hours |
| **Dev Team** | Code fixes, security patches | Business hours |

---

## Compliance Checklist

- ✅ Audit logging enabled (CloudWatch + CloudTrail)
- ✅ Encryption at rest (AES-256)
- ✅ Encryption in transit (TLS 1.2+)
- ✅ Access control (IAM + RBAC)
- ✅ Secret rotation (Secrets Manager)
- ✅ Vulnerability scanning (automated)
- ✅ Penetration testing (annual)
- ✅ Incident response plan (documented)

---

**Related:** [Monitoring & Audit](MONITORING_AUDIT.md), [Threat Model](THREAT_MODEL_DEFENSES.md)
