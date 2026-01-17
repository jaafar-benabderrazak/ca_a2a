# 10. Security Operations

[← Back to Index](README.md)

---


### 10.1 Incident Response

**Token Compromise Procedure:**

```bash
# 1. Identify compromised token's jti
jti="abc123-compromised-token"

# 2. Revoke token via Admin API
curl -X POST http://admin-api:9000/admin/revoke-token \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d "{
    \"jti\": \"$jti\",
    \"reason\": \"Security incident - suspected compromise\",
    \"revoked_by\": \"security-team\"
  }"

# 3. Verify revocation
curl http://admin-api:9000/admin/revoked-tokens \
  -H "Authorization: Bearer $ADMIN_JWT" | jq '.tokens[] | select(.jti=="'$jti'")'

# 4. Investigate in CloudWatch Logs
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "$jti" \
  --start-time $(date -d '24 hours ago' +%s)000 \
  --region eu-west-3
```

### 10.2 Security Auditing

**Weekly Security Review Checklist:**

- [ ] Review CloudWatch Logs for authentication failures
- [ ] Check revoked tokens list for anomalies
- [ ] Verify no tokens with excessive TTL
- [ ] Review rate limit violations by principal
- [ ] Check for unusual traffic patterns in ALB logs
- [ ] Verify all secrets rotated within policy (90 days)
- [ ] Review IAM role permissions (least privilege)
- [ ] Check security group rules for unnecessary access

**Automated Monitoring:**

```bash
# Script: security-audit.sh
#!/bin/bash

echo "=== Security Audit Report ==="
echo "Date: $(date)"
echo ""

# Check authentication failures (last 24h)
echo "1. Authentication Failures:"
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "authentication_failure" \
  --start-time $(date -d '24 hours ago' +%s)000 \
  --region eu-west-3 \
  --query 'length(events)' \
  --output text

# Check rate limit violations
echo "2. Rate Limit Violations:"
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "rate_limit_exceeded" \
  --start-time $(date -d '24 hours ago' +%s)000 \
  --region eu-west-3 \
  --query 'length(events)' \
  --output text

# Check revoked tokens count
echo "3. Active Revoked Tokens:"
curl -s http://admin-api:9000/admin/security-stats \
  -H "Authorization: Bearer $ADMIN_JWT" \
  | jq '.active_revoked_tokens'

echo ""
echo "=== End of Report ==="
```

### 10.3 Compliance

**GDPR Considerations:**

| Requirement | Implementation |
|-------------|----------------|
| **Data Encryption** | ✅ AES-256 at rest, TLS in transit |
| **Access Control** | ✅ RBAC with Keycloak roles |
| **Audit Trail** | ✅ CloudWatch Logs with 7-day retention |
| **Right to be Forgotten** | ⚠️ Manual deletion via SQL (implement API endpoint) |
| **Data Minimization** | ✅ Only essential fields stored |
| **Pseudonymization** | ⚠️ User emails stored in Keycloak (consider hashing) |

**PCI-DSS Considerations (if processing payment data):**

| Requirement | Implementation |
|-------------|----------------|
| **Network Segmentation** | ✅ VPC with private subnets |
| **Strong Access Control** | ✅ Multi-factor via Keycloak (optional) |
| **Encryption** | ✅ At rest and in transit |
| **Logging & Monitoring** | ✅ CloudWatch Logs + audit trail |
| **Vulnerability Management** | ⚠️ Regular container image updates (automate) |

---


---

[← Previous: Threat Model & Defenses](09-THREAT_MODEL_DEFENSES.md) | [Next: Implementation Reference →](11-IMPLEMENTATION_REFERENCE.md)
