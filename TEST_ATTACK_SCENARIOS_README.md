# CA-A2A Attack Scenario Testing Suite

## Overview

Comprehensive penetration testing suite based on the 18 attack scenarios documented in `A2A_ATTACK_SCENARIOS_DETAILED.md`.

This test suite validates security controls against real-world attack patterns using automated exploit attempts.

⚠️ **WARNING**: This file contains REAL attack code. Use only in controlled testing environments.

---

## Attack Scenarios Covered

### Authentication & Authorization (Scenarios 1-3)
- ✅ **Scenario 1**: JWT Token Theft
- ✅ **Scenario 2**: Replay Attack
- ✅ **Scenario 3**: Privilege Escalation

### Resource & Availability (Scenario 4)
- ✅ **Scenario 4**: DDoS / Resource Exhaustion

### Injection Attacks (Scenarios 5, 8-10)
- ✅ **Scenario 5**: SQL Injection
- ✅ **Scenario 8**: Path Traversal
- ✅ **Scenario 9**: XSS Injection
- ✅ **Scenario 10**: Command Injection

### Network & Protocol (Scenarios 6-7)
- ✅ **Scenario 6**: Man-in-the-Middle (MITM)
- ✅ **Scenario 7**: JWT Algorithm Confusion

### Additional Scenarios (11-18)
- ⏭️ **Scenario 11**: S3 Bucket Poisoning (manual test required)
- ⏭️ **Scenario 12**: Database Connection Exhaustion (load test)
- ⏭️ **Scenario 13**: Log Injection (integrated in other tests)
- ⏭️ **Scenario 14**: Secrets Leakage (static analysis required)
- ⏭️ **Scenario 15**: Container Escape (requires privileged access)
- ⏭️ **Scenario 16**: Supply Chain Attack (dependency scanning)
- ⏭️ **Scenario 17**: Side-Channel Timing Attack (statistical analysis)
- ⏭️ **Scenario 18**: Cross-Agent Request Forgery (integrated test)

---

## Prerequisites

### Python Dependencies
```bash
pip install pytest requests PyJWT cryptography
```

### Environment Setup

1. **Local Testing** (Development)
   ```bash
   # Update orchestrator_url fixture in test file
   # Default: http://localhost:8001
   ```

2. **AWS ECS Testing** (Staging/Production)
   ```bash
   # Use AWS Systems Manager Session Manager or VPN
   # Connect to VPC and test against internal URLs
   
   export ORCHESTRATOR_URL="http://orchestrator.ca-a2a.local:8001"
   export TEST_JWT_TOKEN="<valid-token-from-keycloak>"
   ```

3. **Obtain Test Credentials**
   ```bash
   # Get valid JWT token from Keycloak
   curl -X POST https://keycloak.ca-a2a.local/realms/ca-a2a/protocol/openid-connect/token \
     -d "client_id=ca-a2a-agents" \
     -d "client_secret=<secret>" \
     -d "grant_type=client_credentials"
   ```

---

## Running Tests

### Run All Attack Scenarios
```bash
pytest test_attack_scenarios.py -v
```

### Run Specific Scenario
```bash
# Test JWT token theft
pytest test_attack_scenarios.py::TestScenario01_JWTTokenTheft -v

# Test SQL injection
pytest test_attack_scenarios.py::TestScenario05_SQLInjection -v

# Test privilege escalation
pytest test_attack_scenarios.py::TestScenario03_PrivilegeEscalation -v
```

### Run with Detailed Output
```bash
pytest test_attack_scenarios.py -v -s --tb=short
```

### Generate HTML Report
```bash
pip install pytest-html
pytest test_attack_scenarios.py --html=attack_report.html --self-contained-html
```

### Run in Parallel (Faster)
```bash
pip install pytest-xdist
pytest test_attack_scenarios.py -n 4  # 4 parallel workers
```

---

## Expected Results

### ✅ Security Controls Working
```
test_stolen_token_reuse PASSED                           [  5%] ✅ Token accepted - Check correlation ID logging
test_expired_token_rejection PASSED                      [ 10%] ✅ Expired token correctly rejected
test_duplicate_request_replay PASSED                     [ 15%] ✅ Replay attack correctly prevented
test_sql_injection_in_document_id['; DROP TABLE...] PASSED [ 20%] ✅ SQL injection blocked by input validation
test_rate_limiting PASSED                                [ 25%] ✅ Rate limiting active: 50 succeeded, then blocked
test_path_traversal_in_filename[../../../etc/passwd] PASSED [ 30%] ✅ Path traversal blocked
```

### ❌ Vulnerabilities Detected
```
test_unauthorized_method_access FAILED                   [ 35%] ❌ RBAC not enforced
test_large_payload_rejection FAILED                      [ 40%] ❌ Large payload accepted
test_none_algorithm_bypass FAILED                        [ 45%] ❌ 'none' algorithm accepted
```

---

## Interpreting Results

### Test Status Meanings

| Status | Meaning | Action Required |
|--------|---------|-----------------|
| ✅ PASSED | Security control is working | ✓ Good - No action |
| ❌ FAILED | Vulnerability detected | ⚠️ **URGENT** - Fix immediately |
| ⏭️ SKIPPED | Test requires manual execution | ℹ️ Review documentation |
| 🔄 XFAIL | Known issue, expected to fail | 📝 Track in issue tracker |

### Example Failed Test Analysis

**Scenario**: `test_sql_injection_in_document_id FAILED`

**Problem**: SQL injection payload accepted by system

**Root Cause**: JSON Schema validation not enforcing proper regex patterns

**Fix**:
```python
# In a2a_security_enhanced.py
SCHEMAS = {
    "get_document": {
        "properties": {
            "document_id": {
                "type": "string",
                "pattern": "^[a-zA-Z0-9_-]+$",  # Add this
                "maxLength": 100
            }
        }
    }
}
```

**Verification**: Re-run test → should PASS

---

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Security Testing

on: [push, pull_request]

jobs:
  attack-scenarios:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest test_attack_scenarios.py -v --junitxml=attack-results.xml
      - uses: actions/upload-artifact@v2
        if: always()
        with:
          name: attack-test-results
          path: attack-results.xml
```

### AWS CodeBuild Example
```yaml
version: 0.2

phases:
  install:
    commands:
      - pip install pytest requests PyJWT
  build:
    commands:
      - pytest test_attack_scenarios.py -v --junitxml=results.xml
  
reports:
  attack-scenarios:
    files:
      - results.xml
    file-format: JUNITXML
```

---

## Manual Testing Scenarios

Some scenarios require manual testing or specialized tools:

### Scenario 11: S3 Bucket Poisoning
```bash
# Test S3 bucket permissions
aws s3 ls s3://ca-a2a-documents/ --region eu-west-3
aws s3api get-bucket-acl --bucket ca-a2a-documents --region eu-west-3

# Expected: Access denied (bucket is private)
```

### Scenario 12: Database Connection Exhaustion
```bash
# Use k6 or Locust for load testing
k6 run --vus 1000 --duration 30s load-test.js

# Monitor RDS connections
aws cloudwatch get-metric-statistics \
  --namespace AWS/RDS \
  --metric-name DatabaseConnections \
  --dimensions Name=DBClusterIdentifier,Value=documents-db \
  --start-time $(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 60 \
  --statistics Average,Maximum \
  --region eu-west-3
```

### Scenario 14: Secrets Leakage
```bash
# Scan for secrets in logs
aws logs filter-pattern "password" \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --start-time $(date -d '1 hour ago' +%s)000 \
  --region eu-west-3

# Expected: No matches (secrets should not be logged)
```

### Scenario 15: Container Escape
```bash
# Requires privileged access to ECS task
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task <task-id> \
  --container orchestrator \
  --interactive \
  --command "/bin/sh" \
  --region eu-west-3

# Once inside, try container escape techniques
# Expected: All attempts should fail (Fargate is hardened)
```

---

## Troubleshooting

### Connection Refused
**Problem**: `requests.exceptions.ConnectionError: Connection refused`

**Cause**: Service not running or URL incorrect

**Fix**:
```bash
# Check service status
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region eu-west-3 \
  --query 'services[0].{Status:status,Running:runningCount,Desired:desiredCount}'

# Check logs
aws logs tail /ecs/ca-a2a-orchestrator --since 5m --region eu-west-3
```

### Authentication Failed
**Problem**: `401 Unauthorized` on all tests

**Cause**: Invalid or expired JWT token

**Fix**:
```bash
# Get new token from Keycloak
export TEST_JWT_TOKEN=$(curl -s -X POST \
  http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token \
  -d "client_id=ca-a2a-agents" \
  -d "client_secret=<secret>" \
  -d "grant_type=client_credentials" | jq -r '.access_token')
```

### Rate Limiting Test Fails
**Problem**: `test_rate_limiting FAILED` - No rate limiting observed

**Cause**: Rate limiting not configured

**Fix**:
```python
# In base_agent.py, add rate limiting middleware
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/jsonrpc")
@limiter.limit("300/minute")  # 300 requests per minute
async def jsonrpc_handler(request: Request):
    ...
```

---

## Security Considerations

### Test Environment Isolation
- ⚠️ **NEVER run these tests against production**
- ✅ Use dedicated testing environment
- ✅ Sanitize logs after testing
- ✅ Rotate credentials after testing

### Data Privacy
- Tests use synthetic data only
- No real user credentials
- No production documents

### Responsible Disclosure
If tests reveal vulnerabilities:
1. ❌ Do NOT share publicly
2. ✅ Document in private issue tracker
3. ✅ Notify security team immediately
4. ✅ Fix before next deployment

---

## Contributing

### Adding New Attack Scenarios

1. **Document the attack** in `A2A_ATTACK_SCENARIOS_DETAILED.md`
2. **Create test class** following naming convention:
   ```python
   class TestScenario##_AttackName:
       """Test attack scenario description"""
   ```
3. **Add test methods** with clear attack descriptions
4. **Update this README** with new scenario
5. **Submit PR** with test results

### Test Quality Guidelines

- ✅ Each test should be independent
- ✅ Use descriptive names and docstrings
- ✅ Include logger.info() for test progress
- ✅ Assert expected security behavior
- ✅ Clean up test data after execution

---

## References

- **Attack Documentation**: `A2A_ATTACK_SCENARIOS_DETAILED.md`
- **Security Architecture**: `A2A_SECURITY_ARCHITECTURE.md`
- **Deployment Guide**: `DEPLOYMENT_GUIDE_V5.1.md`
- **MITRE ATT&CK Framework**: https://attack.mitre.org/

---

## Support

For questions or issues:
- **Repository**: https://github.com/jaafar-benabderrazak/ca_a2a
- **Security Issues**: Create private issue in repository
- **Documentation**: See `A2A_SECURITY_ARCHITECTURE.md`

---

**Last Updated**: 2026-01-16  
**Version**: 1.0  
**Author**: CA-A2A Security Team

