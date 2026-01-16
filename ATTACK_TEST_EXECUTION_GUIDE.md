# Attack Scenario Testing - Complete Execution Guide
=====================================================

## Quick Start

### 1. Test Environment Setup

Run the setup script to verify your environment:

```bash
# Local testing
TEST_ENV=local python setup_test_environment.py

# AWS testing
TEST_ENV=aws python setup_test_environment.py
```

### 2. Run Tests

**Option A: Local Development Environment**

```bash
# With Keycloak running locally
TEST_ENV=local TEST_PASSWORD=your-password pytest test_attack_scenarios.py -v
```

**Option B: AWS ECS Environment (Bash)**

```bash
# With pre-configured token
./run_attack_tests_aws.sh --token "eyJhbGc..."

# With Keycloak credentials
./run_attack_tests_aws.sh --username admin --password secret

# Generate HTML report
./run_attack_tests_aws.sh --token "..." --html
```

**Option C: AWS ECS Environment (PowerShell)**

```powershell
# With pre-configured token
.\Run-AttackTests-AWS.ps1 -Token "eyJhbGc..."

# With Keycloak credentials  
.\Run-AttackTests-AWS.ps1 -Username admin -Password secret

# Generate HTML report
.\Run-AttackTests-AWS.ps1 -Token "..." -GenerateHTML
```

---

## Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `TEST_ENV` | Environment type | `local`, `aws`, or `custom` |
| `ORCHESTRATOR_URL` | Orchestrator endpoint | `http://your-alb.elb.amazonaws.com` |
| `KEYCLOAK_URL` | Keycloak server URL | `http://keycloak.ca-a2a.local:8080` |
| `KEYCLOAK_REALM` | Keycloak realm | `ca-a2a` |
| `KEYCLOAK_CLIENT_ID` | Client ID | `ca-a2a-agents` |
| `KEYCLOAK_CLIENT_SECRET` | Client secret (optional) | `your-secret` |
| `TEST_USERNAME` | Test user | `test-user` |
| `TEST_PASSWORD` | Test password | `your-password` |
| `TEST_JWT_TOKEN` | Pre-obtained token | `eyJhbGc...` |
| `SKIP_ON_CONNECTION_ERROR` | Skip if unavailable | `true` or `false` |
| `TEST_TIMEOUT` | Request timeout (seconds) | `10` |
| `TEST_VERBOSE` | Verbose output | `true` or `false` |

### Configuration Files

**`test_config.py`**: Central configuration management
- Loads environment-specific settings
- Provides sensible defaults
- Supports local, AWS, and custom environments

**`test_helpers.py`**: Helper utilities
- `KeycloakTokenHelper`: Obtains JWT tokens
- `ServiceHealthChecker`: Validates service availability
- Mock data generators

---

## Step-by-Step Guide

### Step 1: Obtain JWT Token

**Method 1: Using Keycloak directly**

```bash
curl -X POST http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token \
  -d "client_id=ca-a2a-agents" \
  -d "username=test-user" \
  -d "password=your-password" \
  -d "grant_type=password" | jq -r '.access_token'
```

**Method 2: Using test helper**

```python
from test_helpers import KeycloakTokenHelper
from test_config import get_test_config

# Set TEST_PASSWORD environment variable
token_helper = KeycloakTokenHelper()
token = token_helper.get_valid_token()
print(f"Token: {token}")
```

**Method 3: Set environment variable**

```bash
export TEST_JWT_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Step 2: Verify Service Availability

```bash
# Check orchestrator health
curl http://your-orchestrator-url/health

# Run health check script
python setup_test_environment.py
```

### Step 3: Run Specific Test Scenarios

```bash
# Test JWT token theft
pytest test_attack_scenarios.py::TestScenario01_JWTTokenTheft -v

# Test SQL injection
pytest test_attack_scenarios.py::TestScenario05_SQLInjection -v

# Test replay attacks
pytest test_attack_scenarios.py::TestScenario02_ReplayAttack -v

# Test privilege escalation
pytest test_attack_scenarios.py::TestScenario03_PrivilegeEscalation -v
```

### Step 4: Generate Reports

```bash
# HTML report
pytest test_attack_scenarios.py --html=attack_report.html --self-contained-html

# JUnit XML (for CI/CD)
pytest test_attack_scenarios.py --junitxml=attack_results.xml

# JSON report (with pytest-json-report)
pip install pytest-json-report
pytest test_attack_scenarios.py --json-report --json-report-file=attack_results.json
```

---

## AWS Deployment Testing

### Prerequisites

1. **AWS CLI configured** with appropriate credentials
2. **VPC access** to ECS services (via VPN or Session Manager)
3. **ALB DNS name** from `ca-a2a-config.env`

### Testing from Windows (PowerShell)

```powershell
# 1. Load AWS configuration
Get-Content ca-a2a-config.env | ForEach-Object {
    if ($_ -match '^export\s+([^=]+)=(.*)$') {
        $name = $matches[1]
        $value = $matches[2] -replace '"', ''
        Set-Item -Path "env:$name" -Value $value
    }
}

# 2. Set test environment
$env:TEST_ENV = "aws"
$env:ORCHESTRATOR_URL = "http://$env:ALB_DNS"
$env:TEST_JWT_TOKEN = "your-token"

# 3. Run tests
pytest test_attack_scenarios.py -v
```

### Testing from AWS CloudShell

```bash
# 1. Upload test files
aws s3 cp test_attack_scenarios.py s3://your-bucket/
aws s3 cp test_config.py s3://your-bucket/
aws s3 cp test_helpers.py s3://your-bucket/

# 2. Start CloudShell and download
aws s3 cp s3://your-bucket/test_attack_scenarios.py .
aws s3 cp s3://your-bucket/test_config.py .
aws s3 cp s3://your-bucket/test_helpers.py .

# 3. Install dependencies
pip install pytest requests PyJWT[crypto]

# 4. Run tests
TEST_ENV=aws ./run_attack_tests_aws.sh --token "..."
```

### Testing via Session Manager

```bash
# 1. Connect to ECS task
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task <task-id> \
  --container orchestrator \
  --interactive \
  --command "/bin/bash" \
  --region eu-west-3

# 2. Inside container, install test tools
pip install pytest requests PyJWT[crypto]

# 3. Run tests against localhost
TEST_ENV=local ORCHESTRATOR_URL=http://localhost:8001 pytest test_attack_scenarios.py -v
```

---

## Interpreting Results

### Test Output Examples

**✅ Pass: Security control working**
```
test_expired_token_rejection PASSED                      [10%]
INFO: [SCENARIO 1.2] Testing expired token rejection
INFO: ✅ Expired token correctly rejected
```

**❌ Fail: Vulnerability detected**
```
test_none_algorithm_bypass FAILED                        [45%]
INFO: [SCENARIO 7.1] Testing 'none' algorithm rejection
AssertionError: 'none' algorithm should be rejected
```

**⏭️ Skip: Service unavailable**
```
test_stolen_token_reuse SKIPPED                          [ 5%]
REASON: No valid JWT token available. Set TEST_JWT_TOKEN or TEST_PASSWORD
```

### Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | All tests passed | ✅ Security controls validated |
| 1 | Some tests failed | ⚠️ Fix vulnerabilities |
| 2 | Test interrupted | 🔄 Re-run tests |
| 3 | Internal error | 🐛 Check test code |
| 4 | pytest usage error | 📖 Check pytest args |
| 5 | No tests collected | ⚙️ Check test selection |

---

## Common Issues

### Issue 1: Connection Refused

**Error**: `ConnectionRefusedError: [WinError 10061]`

**Solution**:
```bash
# Check service status
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region eu-west-3

# Check ALB health
aws elbv2 describe-target-health \
  --target-group-arn $TG_ARN \
  --region eu-west-3
```

### Issue 2: Authentication Failed

**Error**: `401 Unauthorized`

**Solution**:
```bash
# Get fresh token
export TEST_JWT_TOKEN=$(python -c "
from test_helpers import KeycloakTokenHelper
helper = KeycloakTokenHelper()
print(helper.get_valid_token())
")

# Or set password
export TEST_PASSWORD="your-password"
```

### Issue 3: Import Errors

**Error**: `ModuleNotFoundError: No module named 'test_config'`

**Solution**:
```bash
# Ensure test files in same directory
ls -la test_*.py

# Add to PYTHONPATH if needed
export PYTHONPATH=$PYTHONPATH:$(pwd)
```

### Issue 4: Keycloak Unreachable

**Error**: `Keycloak is not reachable`

**Solution**:
```bash
# Option 1: Use pre-configured token
export TEST_JWT_TOKEN="eyJhbGc..."

# Option 2: Update Keycloak URL
export KEYCLOAK_URL="http://your-keycloak-host:8080"

# Option 3: Skip Keycloak health check
export SKIP_ON_CONNECTION_ERROR=true
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Attack Scenario Tests

on: [push, pull_request]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run attack tests
        env:
          TEST_ENV: aws
          ORCHESTRATOR_URL: ${{ secrets.ORCHESTRATOR_URL }}
          TEST_JWT_TOKEN: ${{ secrets.TEST_JWT_TOKEN }}
        run: pytest test_attack_scenarios.py -v --junitxml=results.xml
      
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: attack-test-results
          path: results.xml
```

### AWS CodeBuild

```yaml
version: 0.2

phases:
  install:
    commands:
      - pip install pytest requests PyJWT[crypto]
  
  build:
    commands:
      - export TEST_ENV=aws
      - export ORCHESTRATOR_URL=http://$ALB_DNS
      - pytest test_attack_scenarios.py -v --junitxml=results.xml

reports:
  attack-scenarios:
    files:
      - results.xml
    file-format: JUNITXML
```

---

## Best Practices

1. **Test in isolation**: Use dedicated testing environment, never production
2. **Rotate credentials**: Change test passwords after testing
3. **Review failures immediately**: Security failures = real vulnerabilities
4. **Run regularly**: Include in CI/CD pipeline
5. **Document findings**: Track vulnerabilities in issue tracker
6. **Clean up**: Remove test data and temp files after execution

---

## Support

**Issues**: Open GitHub issue with:
- Test output (sanitized, no secrets)
- Environment configuration (TEST_ENV, URLs)
- Expected vs actual behavior

**Security Issues**: Report privately to security team

---

**Version**: 2.0  
**Last Updated**: 2026-01-16  
**Author**: CA-A2A Security Team

