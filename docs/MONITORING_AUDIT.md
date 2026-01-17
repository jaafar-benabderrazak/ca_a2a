# CA-A2A Monitoring & Audit

**Version:** 6.0  
**Last Updated:** January 17, 2026

---

## CloudWatch Logs

### Log Groups

| Log Group | Purpose | Retention |
|-----------|---------|-----------|
| `/ecs/ca-a2a-orchestrator` | Orchestrator logs | 7 days |
| `/ecs/ca-a2a-extractor` | Extractor logs | 7 days |
| `/ecs/ca-a2a-validator` | Validator logs | 7 days |
| `/ecs/ca-a2a-archivist` | Archivist logs | 7 days |
| `/ecs/ca-a2a-keycloak` | Keycloak logs | 7 days |
| `/ecs/ca-a2a-mcp-server` | MCP Server logs | 7 days |

---

## Security Events Logged

| Event Type | Trigger | Log Level | Alert? |
|------------|---------|-----------|--------|
| `authentication_success` | Valid JWT verified | INFO | No |
| `authentication_failure` | Invalid JWT | WARN | Yes (> 5/min) |
| `authorization_failure` | Insufficient permissions | WARN | Yes (> 3/min) |
| `rate_limit_exceeded` | Too many requests | WARN | Yes |
| `replay_detected` | Duplicate JWT jti | WARN | Yes |
| `token_revoked` | Revoked token used | WARN | Yes |
| `invalid_input` | Schema validation failed | WARN | No |
| `method_executed` | Successful method call | INFO | No |

---

## Structured Logging Format

```json
{
  "timestamp": "2026-01-17T10:30:00Z",
  "level": "INFO",
  "agent": "orchestrator",
  "event_type": "request",
  "correlation_id": "2026-01-17T10:30:00Z-a1b2c3d4",
  "method": "process_document",
  "principal": "document-processor",
  "duration_ms": 250,
  "success": true,
  "jwt_jti": "abc123...",
  "source_ip": "10.0.11.45"
}
```

---

## Query Examples

### CloudWatch Insights

```sql
-- Authentication failures in last hour
fields @timestamp, principal, error_message
| filter event_type = "authentication_failure"
| sort @timestamp desc
| limit 50

-- Slow requests (> 1 second)
fields @timestamp, method, duration_ms, agent
| filter duration_ms > 1000
| sort duration_ms desc
| limit 20

-- Rate limit violations by principal
fields principal, count(*) as violations
| filter event_type = "rate_limit_exceeded"
| stats count() by principal
| sort violations desc
```

---

## Metrics & Alarms

### CloudWatch Metrics

| Metric | Threshold | Action |
|--------|-----------|--------|
| **CPU Utilization** | > 70% for 3 min | Scale up ECS tasks |
| **Memory Utilization** | > 80% for 3 min | Scale up ECS tasks |
| **Authentication Failures** | > 10/min | SNS alert to security team |
| **5xx Error Rate** | > 1% | SNS alert to ops team |
| **Request Latency** | p99 > 2s | Investigate performance |

### SNS Topics

- `ca-a2a-security-alerts`: Security events
- `ca-a2a-ops-alerts`: Operational issues
- `ca-a2a-cost-alerts`: Budget thresholds

---

## Audit Trail

### What is Logged?

✅ All authentication attempts (success/failure)  
✅ All authorization decisions  
✅ All API method calls with parameters  
✅ All token revocations  
✅ All configuration changes (CloudTrail)  
✅ All AWS API calls (CloudTrail)

### Audit Log Storage

- **CloudWatch Logs:** 7 days (hot storage)
- **S3 Export:** 90 days (cold storage)
- **CloudTrail:** 90 days (AWS API calls)

---

## Compliance

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| **Audit Logging** | CloudWatch + CloudTrail | ✅ |
| **Log Retention** | 90 days (S3 exports) | ✅ |
| **Encryption at Rest** | AES-256 (all logs) | ✅ |
| **Access Control** | IAM policies (read-only) | ✅ |
| **Tamper-Proof** | S3 Object Lock (optional) | ⚠️ Optional |

---

**Related:** [Security Operations](SECURITY_OPERATIONS.md), [Threat Model](THREAT_MODEL_DEFENSES.md)
