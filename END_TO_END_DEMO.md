# 🚀 End-to-End Demo Guide - CA-A2A Document Processing Pipeline

**Version**: 1.0  
**Last Updated**: December 18, 2025  
**Estimated Time**: 20 minutes

---

## 📋 Prerequisites

- AWS Account with SSO configured
- AWS CLI installed and configured
- Access to AWS Console (eu-west-3 region)
- Sample documents (provided in `demo_data/`)

---

## 🎯 Demo Objectives

This demo will showcase:
1. ✅ Document upload to S3
2. ✅ API-driven document processing
3. ✅ Multi-agent workflow coordination
4. ✅ Database persistence and querying
5. ✅ Real-time monitoring via CloudWatch

---

## 🏗️ Architecture Overview

```
┌──────────┐
│  User    │
└────┬─────┘
     │
     │ 1. Upload document to S3
     ▼
┌─────────────┐
│  S3 Bucket  │
│  incoming/  │
└─────┬───────┘
      │
      │ 2. Trigger via API
      ▼
┌─────────────────────┐
│  ALB                │
│  Port 80            │
└──────────┬──────────┘
           │
           │ 3. Route to Orchestrator
           ▼
┌────────────────────┐
│  Orchestrator      │◄────┐
│  (ECS Fargate)     │     │
└──────┬─────────────┘     │
       │                    │ 4. Coordinate
       │                    │    workflow
   ┌───┴────┬────────┐     │
   ▼        ▼        ▼     │
┌────────┐ ┌──────┐ ┌─────┴───┐
│Extract │ │Valid │ │Archivist│
│  Agent │ │Agent │ │  Agent  │
└────┬───┘ └───┬──┘ └────┬────┘
     │         │         │
     └─────────┴─────────┘
               │
               │ 5. Store results
               ▼
        ┌──────────────┐
        │  PostgreSQL  │
        │  (RDS)       │
        └──────────────┘
```

---

## 📝 Step-by-Step Demo

### Step 1: Verify Infrastructure

```bash
# Set AWS profile
export AWS_PROFILE=reply-sso
export AWS_REGION=eu-west-3

# Check ECS services
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist \
  --query 'services[*].[serviceName,status,runningCount,desiredCount]' \
  --output table
```

**Expected Output:**
```
--------------------------------------------
|           DescribeServices               |
+---------------+---------+-------+-------+
| orchestrator  | ACTIVE  |   2   |   2   |
| extractor     | ACTIVE  |   2   |   2   |
| validator     | ACTIVE  |   2   |   2   |
| archivist     | ACTIVE  |   2   |   2   |
+---------------+---------+-------+-------+
```

---

### Step 2: Upload Sample Documents to S3

```bash
# Upload sample invoice
aws s3 cp demo_data/sample_invoice.pdf \
  s3://ca-a2a-documents-555043101106/incoming/ \
  --region eu-west-3

# Upload sample contract
aws s3 cp demo_data/sample_contract.pdf \
  s3://ca-a2a-documents-555043101106/incoming/ \
  --region eu-west-3

# Upload employee data
aws s3 cp demo_data/employee_data.csv \
  s3://ca-a2a-documents-555043101106/incoming/ \
  --region eu-west-3

# Verify uploads
aws s3 ls s3://ca-a2a-documents-555043101106/incoming/ --region eu-west-3
```

**Expected Output:**
```
2025-12-18 17:36:29       2767 sample_invoice.pdf
2025-12-18 17:36:34       3513 sample_contract.pdf
2025-12-18 17:36:40        955 employee_data.csv
```

---

### Step 3: Test API Endpoints

#### 3a. Health Check

```bash
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Test health endpoint
curl $ALB_URL/health | jq '.'
```

**Expected Response:**
```json
{
  "status": "healthy",
  "agent": "Orchestrator",
  "version": "1.0.0",
  "timestamp": "2025-12-18T17:56:00Z"
}
```

#### 3b. Get Agent Card

```bash
# Get agent capabilities
curl $ALB_URL/card | jq '{name: .agent_name, version: .version, skills: .skills | length}'
```

**Expected Response:**
```json
{
  "name": "Orchestrator",
  "version": "1.0.0",
  "skills": 6
}
```

---

### Step 4: Process Documents via API

#### 4a. Process Invoice

```bash
# Process sample invoice
curl -X POST $ALB_URL/process \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/sample_invoice.pdf"}' | jq '.'
```

**Expected Response:**
```json
{
  "status": "processing",
  "document_id": "123",
  "s3_key": "incoming/sample_invoice.pdf",
  "workflow": "extraction -> validation -> archival",
  "estimated_time": "30s"
}
```

#### 4b. Process Contract

```bash
curl -X POST $ALB_URL/process \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/sample_contract.pdf"}' | jq '.'
```

#### 4c. Process CSV

```bash
curl -X POST $ALB_URL/process \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/employee_data.csv"}' | jq '.'
```

---

### Step 5: Monitor Processing in Real-Time

#### 5a. Watch Orchestrator Logs

```bash
# Follow orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 5m \
  --follow \
  --region eu-west-3 \
  --profile reply-sso
```

**Look for:**
- `Processing document: incoming/sample_invoice.pdf`
- `Delegating to Extractor agent`
- `Extraction completed successfully`
- `Delegating to Validator agent`
- `Validation completed successfully`
- `Delegating to Archivist agent`
- `Document processed successfully`

#### 5b. Watch Extractor Logs

```bash
# Follow extractor logs
aws logs tail /ecs/ca-a2a-extractor \
  --since 5m \
  --follow \
  --region eu-west-3 \
  --profile reply-sso
```

**Look for:**
- `Downloaded file from S3: incoming/sample_invoice.pdf`
- `Extracted 15 text blocks`
- `Identified document type: INVOICE`
- `Extracted fields: total=€15,600.00, tax=€2,600.00`

---

### Step 6: Verify Results in Database

#### Option A: Using AWS CloudShell

```python
# Run this Python script in CloudShell
python3 << 'EOF'
import boto3
import json

# Get DB password from Secrets Manager
sm = boto3.client('secretsmanager', region_name='eu-west-3')
secret = sm.get_secret_value(SecretId='ca-a2a/db-password')
db_pass = json.loads(secret['SecretString'])['password']

# Connect and query (requires psycopg2 installation)
print(f"Database password retrieved: {db_pass[:3]}***")
print("Use this to connect via psql or Python client")
EOF
```

#### Option B: Using ECS Exec

```bash
# Get a running task ID
TASK_ID=$(aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service-name orchestrator \
  --region eu-west-3 \
  --query 'taskArns[0]' \
  --output text | cut -d'/' -f3)

# Exec into the task
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task $TASK_ID \
  --container orchestrator \
  --command "/bin/bash" \
  --interactive \
  --region eu-west-3
```

**Inside the container:**
```python
python3 << 'EOF'
import asyncio
import asyncpg
import os

async def check_db():
    conn = await asyncpg.connect(
        host=os.getenv('POSTGRES_HOST'),
        port=5432,
        user=os.getenv('POSTGRES_USER'),
        password=os.getenv('POSTGRES_PASSWORD'),
        database='documents_db',
        ssl='require'
    )
    
    # Count documents
    count = await conn.fetchval('SELECT COUNT(*) FROM documents')
    print(f"Total documents: {count}")
    
    # Show recent documents
    docs = await conn.fetch('''
        SELECT filename, file_type, status, created_at 
        FROM documents 
        ORDER BY created_at DESC 
        LIMIT 5
    ''')
    
    for doc in docs:
        print(f"- {doc['filename']}: {doc['status']} ({doc['file_type']})")
    
    await conn.close()

asyncio.run(check_db())
EOF
```

**Expected Output:**
```
Total documents: 3
- sample_invoice.pdf: completed (PDF)
- sample_contract.pdf: completed (PDF)
- employee_data.csv: completed (CSV)
```

---

### Step 7: Check CloudWatch Metrics

#### Via AWS Console:
1. Navigate to CloudWatch → Dashboards
2. Select or create dashboard for `ca-a2a-cluster`
3. Add widgets for:
   - ECS Service CPU/Memory utilization
   - ALB Request count
   - RDS Connections
   - CloudWatch Logs insights

#### Via AWS CLI:
```bash
# Get ECS service metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/ECS \
  --metric-name CPUUtilization \
  --dimensions Name=ServiceName,Value=orchestrator Name=ClusterName,Value=ca-a2a-cluster \
  --start-time $(date -u -d '5 minutes ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average \
  --region eu-west-3
```

---

## 🎭 Demo Scenarios

### Scenario 1: Invoice Processing (Financial Documents)

**Use Case:** Automated invoice data extraction for accounting

**Steps:**
1. Upload invoice PDF to S3
2. Call `/process` API with invoice S3 key
3. Extractor identifies document type as "INVOICE"
4. Extracts: Invoice number, date, line items, subtotal, tax, total
5. Validator checks: Total = Subtotal + Tax
6. Archivist moves to `processed/invoices/`
7. Database stores extracted data with status "validated"

**Expected Time:** 10-15 seconds

---

### Scenario 2: Contract Review (Legal Documents)

**Use Case:** Contract metadata extraction and compliance checking

**Steps:**
1. Upload contract PDF to S3
2. Call `/process` API
3. Extractor identifies "CONTRACT" type
4. Extracts: Parties, effective date, termination clauses, compensation
5. Validator checks for required clauses
6. Archivist categorizes by contract type
7. Database stores with compliance flags

**Expected Time:** 15-20 seconds

---

### Scenario 3: Bulk CSV Processing (Structured Data)

**Use Case:** Employee data import and validation

**Steps:**
1. Upload CSV file to S3
2. Call `/process` API
3. Extractor parses CSV structure
4. Validates: Email format, salary range, required fields
5. Archivist stores validated records
6. Database stores with row-level validation results

**Expected Time:** 5-10 seconds

---

## 📊 Success Criteria

✅ All 4 ECS services running (8 tasks total)  
✅ ALB health checks passing (HTTP 200)  
✅ Documents uploaded to S3 successfully  
✅ API returns 200 OK for all requests  
✅ CloudWatch logs show processing activity  
✅ Database contains processed documents  
✅ All processing completed within expected time  

---

## 🐛 Troubleshooting

### Issue: API returns 503

**Cause:** Targets unhealthy  
**Solution:**
```bash
# Check target health
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region eu-west-3
```

### Issue: Document processing stuck

**Cause:** Agent communication failure  
**Solution:**
```bash
# Check logs for errors
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "ERROR" \
  --start-time $(date -d '10 minutes ago' +%s)000 \
  --region eu-west-3
```

### Issue: Database connection failed

**Cause:** Security group or SSL issue  
**Solution:**
```bash
# Verify RDS security group allows ECS SG
aws ec2 describe-security-groups \
  --group-ids sg-0dfffbf7f98f77a4c \
  --query 'SecurityGroups[0].IpPermissions' \
  --region eu-west-3
```

---

## 📞 Support

- **AWS Account:** 555043101106
- **Region:** eu-west-3 (Paris)
- **Project:** CA-A2A
- **Contact:** j.benabderrazak@reply.com

---

## 📚 Additional Resources

- [AWS Architecture Documentation](./AWS_ARCHITECTURE.md)
- [Scenario Flows](./SCENARIO_FLOWS.md)
- [API Testing Guide](./API_TESTING_GUIDE.md)
- [Troubleshooting Guide](./TROUBLESHOOTING.md)

---

**Last tested:** December 18, 2025  
**Status:** ✅ All tests passing

