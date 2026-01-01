# 🧪 End-to-End Testing Guide - CloudShell

**Quick Start Guide for Testing CA-A2A Pipeline**

---

## 🚀 Quick Start (2 Minutes)

### Option 1: Run Full Test Suite

```bash
# 1. Upload test script to CloudShell
# (Copy e2e-test-suite.sh content and save it in CloudShell)

# 2. Make executable
chmod +x e2e-test-suite.sh

# 3. Run all tests
./e2e-test-suite.sh
```

---

## 📋 Manual Testing (Step by Step)

### Step 1: Verify Infrastructure (30 seconds)

```bash
export AWS_REGION=eu-west-3

# Check services
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist \
  --region $AWS_REGION \
  --query 'services[*].[serviceName,status,runningCount,desiredCount]' \
  --output table

# Check ALB health
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region $AWS_REGION \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State]' \
  --output table
```

**Expected:** All services ACTIVE, targets healthy

---

### Step 2: Test API Endpoints (1 minute)

```bash
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Test health
echo "Testing /health..."
curl -s "$ALB_URL/health" | jq '.'

# Test agent card
echo "Testing /card..."
curl -s "$ALB_URL/card" | jq '{name: .agent_name, version: .version, skills: (.skills | length)}'
```

**Expected:** JSON responses with status "healthy"

---

### Step 3: Create Test Documents (2 minutes)

```bash
# Create test directory
mkdir -p ~/test-docs
cd ~/test-docs

# Create Invoice Test
cat > invoice_test.txt << 'EOF'
INVOICE #INV-TEST-001
Date: 2025-12-18
From: Tech Services LLC
To: Demo Client Inc

Services:
- Consulting: €5,000.00
- Development: €8,000.00
- Support: €2,000.00

Subtotal: €15,000.00
Tax (20%): €3,000.00
Total: €18,000.00
EOF

# Create CSV Test
cat > employees_test.csv << 'EOF'
Employee_ID,Name,Department,Salary,Email
E001,John Doe,Engineering,75000,john@test.com
E002,Jane Smith,Sales,65000,jane@test.com
E003,Bob Johnson,HR,70000,bob@test.com
EOF

# Create Contract Test
cat > contract_test.txt << 'EOF'
SERVICE AGREEMENT

Contract ID: SA-2025-001
Effective: 2025-12-18
Term: 12 months
Monthly Fee: €5,000

Parties:
Provider: Tech Corp
Client: Demo Inc

Services: Cloud Management
Termination Notice: 30 days
EOF

ls -lh
```

---

### Step 4: Upload to S3 (1 minute)

```bash
BUCKET="ca-a2a-documents-555043101106"

# Upload all test files
for file in *.txt *.csv; do
  echo "Uploading $file..."
  aws s3 cp "$file" "s3://$BUCKET/incoming/" --region eu-west-3
done

# Verify
aws s3 ls "s3://$BUCKET/incoming/" --region eu-west-3
```

---

### Step 5: Process Documents (5 minutes)

#### Scenario A: Invoice Processing

```bash
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

echo "=== Processing Invoice ==="
curl -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/invoice_test.txt"}' | jq '.'

# Wait for processing
echo "Waiting 20 seconds..."
sleep 20
```

#### Scenario B: CSV Processing

```bash
echo "=== Processing CSV ==="
curl -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/employees_test.csv"}' | jq '.'

sleep 15
```

#### Scenario C: Contract Processing

```bash
echo "=== Processing Contract ==="
curl -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/contract_test.txt"}' | jq '.'

sleep 20
```

---

### Step 6: Monitor Processing (2 minutes)

```bash
# Watch orchestrator logs in real-time
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 5m \
  --follow \
  --region eu-west-3

# Press Ctrl+C to stop
```

**Look for:**
- "Processing document"
- "Delegating to Extractor"
- "Extraction completed"
- "Document processed successfully"

---

### Step 7: Check Results

#### A. Check Logs Summary

```bash
# Get recent activity
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --start-time $(($(date +%s) - 600))000 \
  --region eu-west-3 \
  --query 'events[*].message' \
  --output text | grep -i "process\|document" | head -20
```

#### B. Check S3 Processed Files

```bash
# List processed documents
aws s3 ls s3://$BUCKET/processed/ --region eu-west-3 --recursive

# Check for failures
aws s3 ls s3://$BUCKET/failed/ --region eu-west-3 --recursive
```

#### C. Check Database

```bash
# Get running task
TASK_ID=$(aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --region eu-west-3 \
  --query 'taskArns[0]' \
  --output text | cut -d'/' -f3)

# Connect to container
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task $TASK_ID \
  --container orchestrator \
  --command "/bin/bash" \
  --interactive \
  --region eu-west-3
```

**Inside container, run:**

```python
python3 << 'EOF'
import asyncio, asyncpg, os

async def check():
    conn = await asyncpg.connect(
        host=os.getenv('POSTGRES_HOST'), port=5432,
        user=os.getenv('POSTGRES_USER'),
        password=os.getenv('POSTGRES_PASSWORD'),
        database='documents_db', ssl='require'
    )
    
    # Count documents
    count = await conn.fetchval('SELECT COUNT(*) FROM documents')
    print(f'\nTotal documents: {count}\n')
    
    # Show recent
    docs = await conn.fetch('''
        SELECT id, filename, status, created_at 
        FROM documents 
        ORDER BY created_at DESC 
        LIMIT 5
    ''')
    
    for doc in docs:
        print(f"{doc['id']}: {doc['filename']} - {doc['status']}")
    
    # Processing logs
    log_count = await conn.fetchval('SELECT COUNT(*) FROM processing_logs')
    print(f'\nTotal logs: {log_count}\n')
    
    await conn.close()

asyncio.run(check())
EOF
```

**Exit container:**
```bash
exit
```

---

## 🎯 Test Scenarios

### Scenario 1: Financial Document (Invoice)
- **Document Type:** Invoice (TXT/PDF)
- **Expected Time:** 10-15 seconds
- **Workflow:** Extract → Validate calculations → Archive
- **Success Criteria:** Total = Subtotal + Tax

### Scenario 2: Structured Data (CSV)
- **Document Type:** Employee Data (CSV)
- **Expected Time:** 5-10 seconds
- **Workflow:** Parse → Validate format → Store
- **Success Criteria:** All rows valid, email format correct

### Scenario 3: Legal Document (Contract)
- **Document Type:** Contract (TXT/PDF)
- **Expected Time:** 15-20 seconds
- **Workflow:** Extract metadata → Check clauses → Archive
- **Success Criteria:** Required clauses present

---

## ✅ Success Checklist

After running tests, verify:

- [ ] All 4 ECS services are ACTIVE
- [ ] ALB targets are healthy
- [ ] API /health returns 200 OK
- [ ] Documents uploaded to S3 incoming/
- [ ] Processing API returns valid responses
- [ ] CloudWatch logs show processing activity
- [ ] Documents moved to processed/ folder
- [ ] Database contains document records
- [ ] No errors in CloudWatch Logs

---

## 🐛 Troubleshooting

### Issue: API Timeout

```bash
# Check target health
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region eu-west-3

# Restart orchestrator
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --force-new-deployment \
  --region eu-west-3
```

### Issue: No Processing Activity

```bash
# Check orchestrator logs for errors
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "ERROR" \
  --start-time $(($(date +%s) - 1800))000 \
  --region eu-west-3
```

### Issue: Database Connection Failed

```bash
# Check RDS status
aws rds describe-db-instances \
  --db-instance-identifier ca-a2a-postgres \
  --region eu-west-3 \
  --query 'DBInstances[0].{Status:DBInstanceStatus,Endpoint:Endpoint.Address}'
```

---

## 📊 Performance Metrics

| Metric | Target | Acceptable |
|--------|--------|------------|
| API Response Time | < 100ms | < 500ms |
| Document Processing | < 20s | < 60s |
| ALB Health Check | < 5s | < 10s |
| Success Rate | > 95% | > 80% |

---

## 📞 Support

- **AWS Account:** 555043101106
- **Region:** eu-west-3
- **Project:** CA-A2A
- **Contact:** j.benabderrazak@reply.com

---

## 📚 Related Documentation

- [END_TO_END_DEMO.md](./END_TO_END_DEMO.md) - Complete demo guide
- [AWS_ARCHITECTURE.md](./AWS_ARCHITECTURE.md) - Infrastructure details
- [SCENARIO_FLOWS.md](./SCENARIO_FLOWS.md) - Processing workflows
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Common issues

---

**Ready to test? Start with Step 1 above!** 🚀

