# Running Attack Tests in AWS CloudShell

## Why CloudShell?

AWS CloudShell provides:
- ✅ Direct VPC connectivity to ECS services
- ✅ Pre-installed AWS CLI and Python
- ✅ No VPN or bastion host needed
- ✅ Secure, temporary environment
- ✅ Direct access to internal service endpoints

---

## Quick Start

### Step 1: Open CloudShell

1. Log into AWS Console (eu-west-3 region)
2. Click CloudShell icon (top-right, next to search bar)
3. Wait for environment to initialize

### Step 2: Upload Test Files

**Option A: Upload via CloudShell UI**
```bash
# Click Actions → Upload files
# Upload these files:
- test_config.py
- test_helpers.py
- test_attack_scenarios.py
- setup_test_environment.py
- run_attack_tests_cloudshell.sh
```

**Option B: Clone from Git**
```bash
git clone https://github.com/jaafar-benabderrazak/ca_a2a.git
cd ca_a2a
```

**Option C: Copy from S3**
```bash
aws s3 cp s3://your-bucket/test_config.py .
aws s3 cp s3://your-bucket/test_helpers.py .
aws s3 cp s3://your-bucket/test_attack_scenarios.py .
aws s3 cp s3://your-bucket/setup_test_environment.py .
aws s3 cp s3://your-bucket/run_attack_tests_cloudshell.sh .
chmod +x run_attack_tests_cloudshell.sh
```

### Step 3: Get JWT Token

**Method 1: From Keycloak (if accessible)**
```bash
# Try to get token from Keycloak
TOKEN=$(curl -s -X POST http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token \
  -d "client_id=ca-a2a-agents" \
  -d "username=test-user" \
  -d "password=your-password" \
  -d "grant_type=password" | jq -r '.access_token')

# Verify token obtained
if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    export TEST_JWT_TOKEN=$TOKEN
    echo "✓ Token obtained"
else
    echo "✗ Token not obtained"
fi
```

**Method 2: From AWS Secrets Manager**
```bash
# If token is stored in Secrets Manager
export TEST_JWT_TOKEN=$(aws secretsmanager get-secret-value \
  --secret-id ca-a2a/test-jwt-token \
  --query SecretString \
  --output text \
  --region eu-west-3)
```

**Method 3: Manual Entry**
```bash
# Paste token directly
export TEST_JWT_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Step 4: Run Tests

```bash
# Make script executable
chmod +x run_attack_tests_cloudshell.sh

# Run tests
./run_attack_tests_cloudshell.sh

# Or with HTML report
./run_attack_tests_cloudshell.sh --html
```

---

## Manual Execution

If you prefer manual control:

```bash
# 1. Install dependencies
pip install pytest requests PyJWT[crypto] cryptography

# 2. Configure environment
export TEST_ENV=aws
export AWS_REGION=eu-west-3

# 3. Discover orchestrator endpoint
export ALB_DNS=$(aws elbv2 describe-load-balancers \
  --region eu-west-3 \
  --query 'LoadBalancers[?contains(LoadBalancerName, `ca-a2a`)].DNSName' \
  --output text)

export ORCHESTRATOR_URL="http://$ALB_DNS"

# Or use internal DNS
export ORCHESTRATOR_URL="http://orchestrator.ca-a2a.local:8001"

# 4. Set authentication
export TEST_JWT_TOKEN="your-token"

# 5. Validate setup
python3 setup_test_environment.py

# 6. Run tests
pytest test_attack_scenarios.py -v

# 7. Run specific scenario
pytest test_attack_scenarios.py::TestScenario01_JWTTokenTheft -v

# 8. Generate HTML report
pytest test_attack_scenarios.py --html=report.html --self-contained-html
```

---

## Troubleshooting in CloudShell

### Issue 1: Connection Refused

**Problem**: `Connection refused - service not running`

**Check ECS Service Status**:
```bash
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region eu-west-3 \
  --query 'services[0].{Status:status,Running:runningCount,Desired:desiredCount}'
```

**Check Target Health**:
```bash
TG_ARN=$(aws elbv2 describe-target-groups \
  --region eu-west-3 \
  --query 'TargetGroups[?contains(TargetGroupName, `ca-a2a`)].TargetGroupArn' \
  --output text)

aws elbv2 describe-target-health \
  --target-group-arn $TG_ARN \
  --region eu-west-3
```

**Try Internal DNS**:
```bash
# If ALB doesn't work, try internal service DNS
export ORCHESTRATOR_URL="http://orchestrator.ca-a2a.local:8001"

# Test connectivity
curl -v http://orchestrator.ca-a2a.local:8001/health
```

### Issue 2: No JWT Token

**Problem**: `JWT Token: NOT OBTAINED`

**Solution 1: Get from running Lambda**:
```bash
# If Lambda has token generation endpoint
aws lambda invoke \
  --function-name ca-a2a-get-test-token \
  --region eu-west-3 \
  response.json

export TEST_JWT_TOKEN=$(jq -r '.token' response.json)
```

**Solution 2: Create test user in Keycloak**:
```bash
# This requires Keycloak admin access
# Follow KEYCLOAK_INTEGRATION_GUIDE.md
```

**Solution 3: Use existing user credentials**:
```bash
# If you have user credentials
export TEST_USERNAME=admin
export TEST_PASSWORD=admin-password

# Run setup (will auto-authenticate)
python3 setup_test_environment.py
```

### Issue 3: Security Group Blocks Access

**Problem**: Connection timeout

**Check Security Groups**:
```bash
# Get orchestrator security group
SG_ID=$(aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region eu-west-3 \
  --query 'services[0].networkConfiguration.awsvpcConfiguration.securityGroups[0]' \
  --output text)

# View security group rules
aws ec2 describe-security-groups \
  --group-ids $SG_ID \
  --region eu-west-3
```

**Temporary Fix** (allow CloudShell IP):
```bash
# Get CloudShell IP
MY_IP=$(curl -s http://checkip.amazonaws.com)

# Add inbound rule (TEMPORARY - remove after testing)
aws ec2 authorize-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 8001 \
  --cidr $MY_IP/32 \
  --region eu-west-3

# IMPORTANT: Remove after testing
aws ec2 revoke-security-group-ingress \
  --group-id $SG_ID \
  --protocol tcp \
  --port 8001 \
  --cidr $MY_IP/32 \
  --region eu-west-3
```

### Issue 4: Keycloak Not Accessible

**Problem**: `Keycloak is not reachable`

**Solution**: Use pre-obtained token
```bash
# Skip Keycloak, use direct token
export TEST_JWT_TOKEN="your-pre-obtained-token"

# Or skip connection errors
export SKIP_ON_CONNECTION_ERROR=true
```

---

## Expected Results

### When Working Properly

```
================================================================================
SERVICE HEALTH CHECK
================================================================================
ORCHESTRATOR         [OK] HEALTHY         Orchestrator is healthy
KEYCLOAK             [OK] HEALTHY         Keycloak is healthy
================================================================================

[OK] JWT Token:       Successfully obtained
     Token Length:    1024 characters
     Username:        test-user
     Roles:           admin, document-processor

[OK] Environment Status:  READY FOR TESTING
```

### Test Execution

```
test_attack_scenarios.py::TestScenario01_JWTTokenTheft::test_stolen_token_reuse PASSED
test_attack_scenarios.py::TestScenario01_JWTTokenTheft::test_expired_token_rejection PASSED
test_attack_scenarios.py::TestScenario02_ReplayAttack::test_duplicate_request_replay PASSED
...
================================= 35 passed in 45.2s ==================================
```

---

## Downloading Test Reports

After generating HTML report:

```bash
# Download file via CloudShell
# Actions → Download file → attack_report_*.html

# Or upload to S3
aws s3 cp attack_report_*.html s3://your-bucket/test-reports/
```

---

## CloudShell Limitations

- **Timeout**: Sessions timeout after 20 minutes of inactivity
- **Storage**: 1GB persistent storage per region
- **Compute**: Limited CPU/memory
- **Network**: May have different IP on each session

**Workaround**: Save progress frequently
```bash
# Save test results
pytest test_attack_scenarios.py --junitxml=results.xml
aws s3 cp results.xml s3://your-bucket/
```

---

## Best Practices

1. **Test in isolated environment**: Don't run against production
2. **Clean up after testing**: Remove temporary security group rules
3. **Rotate credentials**: Change test passwords after testing
4. **Document findings**: Save test reports and vulnerabilities found
5. **Run regularly**: Schedule periodic security tests

---

## Quick Reference Commands

```bash
# Full automated run
./run_attack_tests_cloudshell.sh

# Manual run with custom URL
export ORCHESTRATOR_URL=http://your-custom-url
python3 -m pytest test_attack_scenarios.py -v

# Run single scenario
pytest test_attack_scenarios.py::TestScenario05_SQLInjection -v

# Run with verbose output
pytest test_attack_scenarios.py -v -s

# Generate report
pytest test_attack_scenarios.py --html=report.html --self-contained-html

# Check ECS status
aws ecs describe-services --cluster ca-a2a-cluster --services orchestrator

# View logs
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3
```

---

**Version**: 2.0  
**Last Updated**: 2026-01-16  
**Region**: eu-west-3

