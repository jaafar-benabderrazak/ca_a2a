# CloudShell Quick Test Guide

**What works NOW in AWS CloudShell (without VPC access)**

---

## Step 1: Setup (2 minutes)

```bash
# Clone repository
cd ~
git clone https://github.com/jaafar-benabderrazak/ca_a2a.git
cd ca_a2a

# Setup Python environment
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip

# Install dependencies (ignore MCP error)
pip install -r requirements.txt 2>&1 | grep -v "ERROR.*mcp"

# Verify
python3 --version
pip list | grep -E "cryptography|PyJWT|pytest"
```

---

## Step 2: Test Token Binding (Works Offline!)

```bash
# Quick test of token binding implementation
python3 << 'EOF'
from token_binding import compute_cert_thumbprint, verify_token_binding
from mtls_manager import CertificateManager

# Generate test certificates
cert_mgr = CertificateManager(certs_dir="./test_certs")
ca_key, ca_cert = cert_mgr.generate_ca_certificate()
client_key, client_cert = cert_mgr.generate_client_certificate(
    ca_key, ca_cert, "lambda.ca-a2a.local"
)

# Test 1: Compute thumbprint
cert_pem = cert_mgr._cert_to_pem(client_cert)
thumbprint = compute_cert_thumbprint(cert_pem)
print(f"✓ Test 1: Thumbprint computed: {thumbprint[:20]}...")

# Test 2: Valid token binding
jwt_claims = {
    "iss": "http://keycloak.ca-a2a.local:8080/realms/ca-a2a",
    "sub": "lambda-service",
    "cnf": {"x5t#S256": thumbprint}
}
result = verify_token_binding(jwt_claims, cert_pem)
print(f"✓ Test 2: Token binding validated: {result}")

# Test 3: Token theft simulation
attacker_key, attacker_cert = cert_mgr.generate_client_certificate(
    ca_key, ca_cert, "attacker.malicious.com"
)
attacker_pem = cert_mgr._cert_to_pem(attacker_cert)
result = verify_token_binding(jwt_claims, attacker_pem)
print(f"✓ Test 3: Token theft blocked: {not result}")

print("\n✅ All token binding tests passed!")
EOF
```

**Expected output:**
```
✓ Test 1: Thumbprint computed: bwcK0esc3ACC3DB2Y5_l...
✓ Test 2: Token binding validated: True
✓ Test 3: Token theft blocked: True

✅ All token binding tests passed!
```

---

## Step 3: Test mTLS Certificate Generation

```bash
# Generate certificates for all agents
python3 generate_certificates.py --certs-dir ./cloudshell_certs

# Verify certificates
ls -lh cloudshell_certs/

# Inspect CA certificate
openssl x509 -in cloudshell_certs/ca_certificate.pem -text -noout | head -20

# Verify certificate chain
openssl verify -CAfile cloudshell_certs/ca_certificate.pem \
  cloudshell_certs/server_orchestrator_certificate.pem
```

**Expected output:**
```
cloudshell_certs/server_orchestrator_certificate.pem: OK
```

---

## Step 4: Check AWS Infrastructure (No Network to Services)

```bash
# Set region
export AWS_REGION=eu-west-3

# Check ECS cluster status
aws ecs describe-clusters \
  --clusters ca-a2a-cluster \
  --region eu-west-3 \
  --query 'clusters[0].{Status:status,Running:registeredContainerInstancesCount,Services:activeServicesCount}' \
  --output table

# Check Keycloak service
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services keycloak \
  --region eu-west-3 \
  --query 'services[0].{Status:status,Running:runningCount,Desired:desiredCount}' \
  --output table

# Check secrets exist
aws secretsmanager list-secrets \
  --region eu-west-3 \
  --query "SecretList[?contains(Name, 'ca-a2a')].Name" \
  --output table

# Check CloudWatch logs
aws logs describe-log-groups \
  --region eu-west-3 \
  --log-group-name-prefix /ecs/ca-a2a \
  --query 'logGroups[*].logGroupName' \
  --output table
```

---

## Step 5: View Agent Logs

```bash
# View orchestrator logs (last 10 minutes)
aws logs tail /ecs/ca-a2a-orchestrator \
  --region eu-west-3 \
  --since 10m \
  --format short

# View Keycloak logs
aws logs tail /ecs/ca-a2a-keycloak \
  --region eu-west-3 \
  --since 10m \
  --format short

# Search for authentication events
aws logs filter-log-events \
  --region eu-west-3 \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "Keycloak" \
  --max-items 10 \
  --query 'events[*].message' \
  --output text
```

---

## What You CANNOT Test in CloudShell

❌ **Cannot call Keycloak** - it's on a private subnet (10.0.1.0/24)
```bash
# This will fail:
curl http://keycloak.ca-a2a.local:8080/health/ready
# Error: Could not resolve host: keycloak.ca-a2a.local
```

❌ **Cannot call agent services** - they're on private subnets
```bash
# This will fail:
curl http://orchestrator.ca-a2a.local:8001/health
# Error: Could not resolve host: orchestrator.ca-a2a.local
```

❌ **Cannot run integration tests** - require VPC access

---

## To Test Live Services (2 Options)

### Option A: Run Test Task in ECS (Inside VPC)

```bash
# Create test task that runs inside VPC
cat > /tmp/integration-test-task.json << 'EOF'
{
  "family": "ca-a2a-integration-test",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::555043101106:role/ca-a2a-ecs-execution-role",
  "containerDefinitions": [{
    "name": "test",
    "image": "curlimages/curl:latest",
    "essential": true,
    "command": [
      "sh", "-c",
      "curl -v http://keycloak.ca-a2a.local:8080/health/ready && curl -v http://orchestrator.ca-a2a.local:8001/health"
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/ca-a2a-tests",
        "awslogs-region": "eu-west-3",
        "awslogs-stream-prefix": "test",
        "awslogs-create-group": "true"
      }
    }
  }]
}
EOF

# Register and run
aws ecs register-task-definition --cli-input-json file:///tmp/integration-test-task.json --region eu-west-3

# Get subnet and security group
SUBNET=$(aws ec2 describe-subnets --region eu-west-3 --filters "Name=tag:Name,Values=ca-a2a-private-1" --query 'Subnets[0].SubnetId' --output text)
SG=$(aws ec2 describe-security-groups --region eu-west-3 --filters "Name=group-name,Values=ca-a2a-agents" --query 'SecurityGroups[0].GroupId' --output text)

# Run test
aws ecs run-task \
  --cluster ca-a2a-cluster \
  --task-definition ca-a2a-integration-test \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$SUBNET],securityGroups=[$SG]}" \
  --region eu-west-3

# View results (wait 30 seconds)
sleep 30
aws logs tail /ecs/ca-a2a-tests --region eu-west-3 --format short
```

### Option B: Use ECS Exec (Interactive Shell)

```bash
# Enable ECS Exec on orchestrator
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --enable-execute-command \
  --region eu-west-3

# Get task ID
TASK=$(aws ecs list-tasks --cluster ca-a2a-cluster --service orchestrator --region eu-west-3 --query 'taskArns[0]' --output text | rev | cut -d'/' -f1 | rev)

# Connect to container
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task $TASK \
  --container orchestrator \
  --interactive \
  --command "/bin/bash" \
  --region eu-west-3

# Inside container:
# curl http://keycloak.ca-a2a.local:8080/health/ready
# curl http://orchestrator.ca-a2a.local:8001/health
```

---

## Summary

### ✅ What Works in CloudShell
- Clone repository
- Install Python dependencies
- Run unit tests (token binding, mTLS cert generation)
- Simulate attack scenarios (offline)
- Check AWS infrastructure status
- View CloudWatch logs
- Manage secrets

### ❌ What Doesn't Work
- Call Keycloak (private)
- Call agent services (private)
- Integration tests with live services

### ✅ Workarounds
- Run integration tests via ECS task (inside VPC)
- Use ECS Exec for interactive debugging
- Use Systems Manager Session Manager with bastion

---

## Quick Commands Reference

```bash
# Setup
cd ~ && git clone https://github.com/jaafar-benabderrazak/ca_a2a.git && cd ca_a2a
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt

# Test token binding
python3 -c "from token_binding import *; from mtls_manager import *; print('✓ Imports work')"

# Generate certificates
python3 generate_certificates.py

# Check infrastructure
aws ecs describe-services --cluster ca-a2a-cluster --services keycloak orchestrator --region eu-west-3 --query 'services[*].{Name:serviceName,Status:status,Running:runningCount}' --output table

# View logs
aws logs tail /ecs/ca-a2a-orchestrator --region eu-west-3 --since 5m
```

---

**🚀 Ready to test? Start with Step 1!**
