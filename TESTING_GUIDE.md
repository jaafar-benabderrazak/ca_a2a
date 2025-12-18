# 🧪 Testing Guide - AWS CloudShell & CLI

**Version:** 1.0  
**Last Updated:** December 18, 2025

---

## 🚀 Quick Start - AWS CloudShell

AWS CloudShell is the easiest way to test the API since it runs inside the AWS network.

### Step 1: Open AWS CloudShell

1. Log into AWS Console: https://console.aws.amazon.com
2. Switch to **eu-west-3** region (Paris)
3. Click the **CloudShell** icon (terminal icon) in the top navigation bar
4. Wait for CloudShell to initialize (~30 seconds)

### Step 2: Run Automated Test

Copy and paste this entire block into CloudShell:

```bash
# Set variables
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Test 1: Health Check
echo "=== Testing Health Endpoint ==="
curl -s "$ALB_URL/health" | jq '.'
echo ""

# Test 2: Agent Card
echo "=== Testing Agent Card ==="
curl -s "$ALB_URL/card" | jq '{name: .agent_name, version: .version, skills: (.skills | length)}'
echo ""

# Test 3: Process Document
echo "=== Processing Document ==="
curl -s -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/sample_invoice.pdf"}' | jq '.'
echo ""

echo "✓ All tests completed!"
```

### Expected Output

**Health Check:**
```json
{
  "status": "healthy",
  "agent": "Orchestrator",
  "version": "1.0.0",
  "timestamp": "2025-12-18T18:00:00Z"
}
```

**Agent Card:**
```json
{
  "name": "Orchestrator",
  "version": "1.0.0",
  "skills": 6
}
```

**Document Processing:**
```json
{
  "status": "processing",
  "document_id": "123",
  "s3_key": "incoming/sample_invoice.pdf",
  "workflow_id": "wf-abc123"
}
```

---

## 📋 Manual Testing Steps

### Test 1: Verify Infrastructure

```bash
# Check ECS services
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist \
  --region eu-west-3 \
  --query 'services[*].[serviceName,status,runningCount,desiredCount]' \
  --output table
```

**Expected:** All services ACTIVE with 2/2 running

```bash
# Check ALB health
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region eu-west-3 \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State]' \
  --output table
```

**Expected:** Both targets "healthy"

### Test 2: Upload Test Documents

```bash
# Create test directory
mkdir -p ~/test-docs
cd ~/test-docs

# Create sample invoice (text version for quick test)
cat > invoice.txt << 'EOF'
INVOICE #INV-2025-001
Date: 2025-12-18
From: Tech Services SARL
To: Acme Corporation

Services:
- Cloud Infrastructure: €5,000.00
- AWS ECS Configuration: €3,500.00
- Database Migration: €2,500.00

Subtotal: €11,000.00
Tax (20%): €2,200.00
Total: €13,200.00
EOF

# Upload to S3
aws s3 cp invoice.txt s3://ca-a2a-documents-555043101106/incoming/ --region eu-west-3

# Verify upload
aws s3 ls s3://ca-a2a-documents-555043101106/incoming/ --region eu-west-3
```

### Test 3: Process via API

```bash
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Process the document
curl -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/invoice.txt"}' | jq '.'
```

### Test 4: Monitor Processing

```bash
# Watch orchestrator logs (Ctrl+C to exit)
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 5m \
  --follow \
  --region eu-west-3
```

**Look for:**
- "Processing document: incoming/invoice.txt"
- "Delegating to Extractor"
- "Extraction completed"
- "Document processed successfully"

### Test 5: Check Results in Database

```bash
# Get RDS endpoint
RDS_ENDPOINT=$(aws rds describe-db-instances \
  --db-instance-identifier ca-a2a-postgres \
  --region eu-west-3 \
  --query 'DBInstances[0].Endpoint.Address' \
  --output text)

echo "RDS Endpoint: $RDS_ENDPOINT"

# Get database password from Secrets Manager
DB_PASSWORD=$(aws secretsmanager get-secret-value \
  --secret-id ca-a2a/db-password \
  --region eu-west-3 \
  --query 'SecretString' \
  --output text | jq -r '.password')

echo "Database password retrieved (use for psql connection)"
```

---

## 🔧 AWS CLI Testing Commands

### Infrastructure Checks

```bash
# List all ECS tasks
aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --region eu-west-3 \
  --output table

# Get task details
aws ecs describe-tasks \
  --cluster ca-a2a-cluster \
  --tasks $(aws ecs list-tasks --cluster ca-a2a-cluster --region eu-west-3 --query 'taskArns[0]' --output text) \
  --region eu-west-3 \
  --query 'tasks[0].{TaskArn:taskArn,Status:lastStatus,CPU:cpu,Memory:memory}'

# Check CloudWatch log groups
aws logs describe-log-groups \
  --log-group-name-prefix /ecs/ca-a2a \
  --region eu-west-3 \
  --query 'logGroups[*].logGroupName' \
  --output table
```

### S3 Operations

```bash
# List all folders
aws s3 ls s3://ca-a2a-documents-555043101106/ --region eu-west-3

# Count files in each folder
echo "Incoming:"
aws s3 ls s3://ca-a2a-documents-555043101106/incoming/ --region eu-west-3 | wc -l

echo "Processing:"
aws s3 ls s3://ca-a2a-documents-555043101106/processing/ --region eu-west-3 | wc -l

echo "Processed:"
aws s3 ls s3://ca-a2a-documents-555043101106/processed/ --region eu-west-3 | wc -l

# Download processed file
aws s3 cp s3://ca-a2a-documents-555043101106/processed/sample_invoice.pdf . --region eu-west-3
```

### CloudWatch Logs

```bash
# Get recent logs from orchestrator
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --start-time $(date -d '10 minutes ago' +%s)000 \
  --region eu-west-3 \
  --query 'events[*].message' \
  --output text | tail -20

# Search for errors
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "ERROR" \
  --start-time $(date -d '1 hour ago' +%s)000 \
  --region eu-west-3

# Get processing metrics
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "processed successfully" \
  --start-time $(date -d '1 day ago' +%s)000 \
  --region eu-west-3 \
  --query 'events | length(@)'
```

---

## 📊 Performance Testing

### Load Test with Multiple Documents

```bash
# Upload 10 test files
for i in {1..10}; do
  echo "Test document $i" > test-$i.txt
  aws s3 cp test-$i.txt s3://ca-a2a-documents-555043101106/incoming/ --region eu-west-3
done

# Process all files
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"
for i in {1..10}; do
  echo "Processing test-$i.txt..."
  curl -s -X POST "$ALB_URL/process" \
    -H "Content-Type: application/json" \
    -d "{\"s3_key\": \"incoming/test-$i.txt\"}" | jq -c '.'
done

# Monitor processing
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 1m \
  --follow \
  --region eu-west-3
```

### Measure Response Times

```bash
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Measure health endpoint
time curl -s "$ALB_URL/health" > /dev/null

# Measure card endpoint  
time curl -s "$ALB_URL/card" > /dev/null

# Measure process endpoint
time curl -s -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/test.txt"}' > /dev/null
```

---

## 🐛 Troubleshooting Commands

### Check Service Health

```bash
# Get service events
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region eu-west-3 \
  --query 'services[0].events[0:5].[createdAt,message]' \
  --output table

# Check task health
aws ecs describe-tasks \
  --cluster ca-a2a-cluster \
  --tasks $(aws ecs list-tasks --cluster ca-a2a-cluster --service orchestrator --region eu-west-3 --query 'taskArns[0]' --output text) \
  --region eu-west-3 \
  --query 'tasks[0].{Status:lastStatus,Health:healthStatus,Containers:containers[*].{Name:name,Status:lastStatus}}'
```

### Check Network Connectivity

```bash
# Test ALB from CloudShell
curl -v http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health

# Check security groups
aws ec2 describe-security-groups \
  --group-ids sg-05db73131090f365a \
  --region eu-west-3 \
  --query 'SecurityGroups[0].IpPermissions[*].{Port:FromPort,Source:IpRanges[0].CidrIp}'
```

### Check Database Connectivity

```bash
# Test RDS endpoint resolution
nslookup ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com

# Check RDS status
aws rds describe-db-instances \
  --db-instance-identifier ca-a2a-postgres \
  --region eu-west-3 \
  --query 'DBInstances[0].{Status:DBInstanceStatus,Endpoint:Endpoint.Address,Port:Endpoint.Port}'
```

---

## 📝 Test Checklist

Use this checklist when running tests:

```
Infrastructure:
☐ All ECS services show ACTIVE status
☐ All tasks show 2/2 running
☐ ALB targets are healthy
☐ RDS instance is available

API Endpoints:
☐ /health returns 200 OK
☐ /card returns agent information
☐ /process accepts requests

Document Processing:
☐ Documents upload to S3 successfully
☐ API triggers processing
☐ Logs show extraction activity
☐ Documents move to processed/
☐ Database contains records

Monitoring:
☐ CloudWatch logs are being written
☐ No ERROR messages in logs
☐ Processing completes within expected time

Performance:
☐ Health check response < 100ms
☐ Document processing < 30s
☐ No timeout errors
```

---

## 📞 Support

- **AWS Account:** 555043101106
- **Region:** eu-west-3
- **Project:** CA-A2A  
- **Contact:** j.benabderrazak@reply.com

---

## 📚 Related Documentation

- [End-to-End Demo Guide](./END_TO_END_DEMO.md)
- [AWS Architecture](./AWS_ARCHITECTURE.md)
- [Scenario Flows](./SCENARIO_FLOWS.md)

