# 🚀 API Testing Guide - Orchestrator Service

## ✅ Service Status

**ALB Endpoint**: `http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com`

**Service**: ✅ ACTIVE (2/2 tasks running)  
**Targets**: ✅ HEALTHY (both targets passing health checks)  
**ALB Scheme**: internet-facing  
**ALB State**: active

---

## 📡 Available Endpoints

### 1. Health Check
```bash
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "agent": "Orchestrator",
  "version": "1.0.0"
}
```

### 2. Agent Card
```bash
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/card
```

**Expected Response:**
```json
{
  "agent_name": "Orchestrator",
  "version": "1.0.0",
  "description": "Coordinates multi-agent document processing workflows",
  "skills": [
    {
      "name": "process_document",
      "description": "Orchestrate document processing workflow"
    },
    ...
  ]
}
```

### 3. Process Document (Main API)
```bash
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/process \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/sample_invoice.pdf"}'
```

**Expected Response:**
```json
{
  "status": "processing",
  "document_id": "123",
  "s3_key": "incoming/sample_invoice.pdf"
}
```

---

## 🧪 End-to-End Test Script

### For Git Bash / WSL:

```bash
#!/bin/bash
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

echo "=========================================="
echo "Testing Orchestrator API"
echo "=========================================="
echo ""

# Test 1: Health Check
echo "[1/4] Testing /health endpoint..."
curl -s "$ALB_URL/health" | jq '.'
echo ""

# Test 2: Agent Card
echo "[2/4] Testing /card endpoint..."
curl -s "$ALB_URL/card" | jq '.agent_name, .version, .skills | length'
echo ""

# Test 3: Process sample_invoice.pdf
echo "[3/4] Processing sample_invoice.pdf..."
curl -s -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/sample_invoice.pdf"}' | jq '.'
echo ""

# Test 4: Process employee_data.csv
echo "[4/4] Processing employee_data.csv..."
curl -s -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/employee_data.csv"}' | jq '.'
echo ""

echo "=========================================="
echo "Test Complete!"
echo "=========================================="
```

### For PowerShell:

```powershell
$ALB_URL = "http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Testing Orchestrator API"
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Health Check
Write-Host "[1/4] Testing /health endpoint..." -ForegroundColor Yellow
Invoke-RestMethod -Uri "$ALB_URL/health" -Method GET | ConvertTo-Json
Write-Host ""

# Test 2: Agent Card
Write-Host "[2/4] Testing /card endpoint..." -ForegroundColor Yellow
$card = Invoke-RestMethod -Uri "$ALB_URL/card" -Method GET
Write-Host "Agent: $($card.agent_name) v$($card.version)"
Write-Host "Skills: $($card.skills.Count)"
Write-Host ""

# Test 3: Process sample_invoice.pdf
Write-Host "[3/4] Processing sample_invoice.pdf..." -ForegroundColor Yellow
$body = @{s3_key = "incoming/sample_invoice.pdf"} | ConvertTo-Json
Invoke-RestMethod -Uri "$ALB_URL/process" -Method POST -Body $body -ContentType "application/json" | ConvertTo-Json
Write-Host ""

# Test 4: Process employee_data.csv
Write-Host "[4/4] Processing employee_data.csv..." -ForegroundColor Yellow
$body = @{s3_key = "incoming/employee_data.csv"} | ConvertTo-Json
Invoke-RestMethod -Uri "$ALB_URL/process" -Method POST -Body $body -ContentType "application/json" | ConvertTo-Json
Write-Host ""

Write-Host "==========================================" -ForegroundColor Green
Write-Host "Test Complete!"
Write-Host "==========================================" -ForegroundColor Green
```

---

## 📊 Checking Processing Results

After triggering document processing, check the database:

```bash
# From within an ECS task (using ECS Exec):
python -c "
import asyncio, asyncpg, os
async def check():
    conn = await asyncpg.connect(
        host=os.getenv('POSTGRES_HOST'),
        port=5432,
        user=os.getenv('POSTGRES_USER'),
        password=os.getenv('POSTGRES_PASSWORD'),
        database='documents_db',
        ssl='require'
    )
    docs = await conn.fetch('SELECT * FROM documents ORDER BY created_at DESC LIMIT 5')
    for doc in docs:
        print(f\"{doc['filename']}: {doc['status']}\")
    await conn.close()
asyncio.run(check())
"
```

Or use AWS CLI to check CloudWatch Logs:

```bash
# Watch orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator --since 5m --follow --region eu-west-3 --profile reply-sso

# Watch extractor logs
aws logs tail /ecs/ca-a2a-extractor --since 5m --follow --region eu-west-3 --profile reply-sso
```

---

## 🔍 Troubleshooting

### Connection Refused
- **Issue**: Cannot connect to ALB
- **Check**: ALB security group allows inbound on port 80
- **Fix**: 
  ```bash
  aws ec2 authorize-security-group-ingress \
    --group-id sg-xxx \
    --protocol tcp \
    --port 80 \
    --cidr 0.0.0.0/0
  ```

### 503 Service Unavailable
- **Issue**: Targets are unhealthy
- **Check**: Target health in console or CLI
- **Fix**: Check ECS task logs for startup errors

### Timeout
- **Issue**: Tasks taking too long to respond
- **Check**: Target group health check settings
- **Fix**: Increase health check timeout or adjust grace period

---

## 📞 Support

- **AWS Account**: 555043101106
- **Region**: eu-west-3
- **Project**: CA-A2A
- **ALB**: ca-a2a-alb
- **Target Group**: ca-a2a-orch-tg

---

**Created**: December 18, 2025  
**Status**: ✅ Ready for testing

