# CA-A2A Data Security

**Version:** 6.0  
**Last Updated:** January 17, 2026

---

## Encryption at Rest

| Resource | Encryption | Key Management |
|----------|-----------|----------------|
| **RDS Aurora PostgreSQL** | AES-256 | AWS KMS (default key) |
| **RDS PostgreSQL (Keycloak)** | AES-256 | AWS KMS (default key) |
| **S3 Bucket** | SSE-S3 (AES-256) | AWS-managed keys |
| **EBS Volumes (ECS)** | AES-256 | AWS KMS (default key) |
| **Secrets Manager** | AES-256 | AWS KMS (dedicated key) |
| **CloudWatch Logs** | AES-256 | AWS-managed keys |

---

## Encryption in Transit

| Connection | Protocol | Encryption |
|------------|----------|------------|
| **User → ALB** | HTTPS | TLS 1.2+ |
| **ALB → Orchestrator** | HTTP | Within VPC (private network) |
| **Agent → Agent** | HTTP | Within VPC (private network) |
| **Agent → Keycloak** | HTTP | Within VPC |
| **Agent → RDS** | PostgreSQL | SSL/TLS (enforced) |
| **Agent → S3** | HTTPS | TLS 1.2+ |

**Note:** Internal traffic uses HTTP within VPC (private network) for performance. TLS used for external connections and sensitive services (RDS, S3).

---

## Secrets Management

### AWS Secrets Manager

**Stored Secrets:**
- Database passwords (RDS, Keycloak)
- Keycloak admin password
- Keycloak client secret
- API keys (if used)

**Access:**
```python
# ECS task definitions retrieve secrets at runtime
{
  "name": "POSTGRES_PASSWORD",
  "valueFrom": "arn:aws:secretsmanager:eu-west-3:555043101106:secret:ca-a2a/db-password-aqPsNn"
}
```

**Security:**
- ✅ Automatic rotation (every 90 days)
- ✅ IAM-based access control
- ✅ CloudTrail audit logging
- ✅ No hardcoded secrets in code or config

---

## Data Retention

| Data Type | Retention Period | Backup |
|-----------|------------------|--------|
| **Document Metadata** | Indefinite | Daily snapshots (30 days) |
| **S3 Documents** | Configurable (lifecycle policy) | Versioning enabled |
| **CloudWatch Logs** | 7 days | N/A |
| **Audit Logs** | 90 days | Daily exports to S3 |
| **Revoked Tokens** | Until token expiration | N/A (transient data) |

---

**Related:** [System Architecture](SYSTEM_ARCHITECTURE.md), [Security Layers](SECURITY_LAYERS_DEFENSE_IN_DEPTH.md)
