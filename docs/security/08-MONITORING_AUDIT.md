# 8. Monitoring & Audit

[← Back to Index](README.md)

---


### 8.1 CloudWatch Logs

**Log Groups:**

| Log Group | Purpose | Retention |
|-----------|---------|-----------|
| `/ecs/ca-a2a-orchestrator` | Orchestrator logs | 7 days |
| `/ecs/ca-a2a-extractor` | Extractor logs | 7 days |
| `/ecs/ca-a2a-validator` | Validator logs | 7 days |
| `/ecs/ca-a2a-archivist` | Archivist logs | 7 days |
| `/ecs/ca-a2a-keycloak` | Keycloak logs | 7 days |

**Structured Logging Format:**
```json
{
  "timestamp": "2026-01-15T10:30:00Z",
  "level": "INFO",
  "agent": "orchestrator",
  "event_type": "request",
  "correlation_id": "2026-01-15T10:30:00Z-a1b2c3d4",
  "method": "process_document",
  "principal": "document-processor",
  "duration_ms": 250,
  "success": true
}
```

### 8.2 Security Events Logged

| Event Type | Trigger | Log Level |
|------------|---------|-----------|
| `authentication_success` | Valid JWT verified | INFO |
| `authentication_failure` | Invalid JWT | WARN |
| `authorization_failure` | Insufficient permissions | WARN |
| `rate_limit_exceeded` | Too many requests | WARN |
| `replay_detected` | Duplicate JWT jti | WARN |
| `token_revoked` | Attempt with revoked token | WARN |
| `invalid_input` | Schema validation failed | WARN |
| `method_executed` | Successful method call | INFO |

**Query Examples:**

```bash
# View all authentication failures in last hour
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "authentication_failure" \
  --start-time $(date -d '1 hour ago' +%s)000 \
  --region eu-west-3

# Count rate limit violations by principal
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "rate_limit_exceeded" \
  --region eu-west-3 \
  | jq '.events[].message | fromjson | .principal' | sort | uniq -c
```

### 8.3 Metrics (Recommended)

**CloudWatch Custom Metrics to Implement:**

| Metric | Unit | Dimensions | Purpose |
|--------|------|------------|---------|
| `RequestLatency` | Milliseconds | Agent, Method | Performance monitoring |
| `ErrorCount` | Count | Agent, ErrorType | Error rate tracking |
| `RequestCount` | Count | Agent | Throughput monitoring |
| `AuthenticationFailures` | Count | Agent | Security monitoring |
| `RateLimitViolations` | Count | Principal | Abuse detection |
| `TokenRevocationChecks` | Count | Agent | Revocation usage |

---


---

[← Previous: Protocol Security (A2A)](07-PROTOCOL_SECURITY.md) | [Next: Threat Model & Defenses →](09-THREAT_MODEL_DEFENSES.md)
