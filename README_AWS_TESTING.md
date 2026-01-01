# AWS Deployment Testing - Quick Start

## 🚀 Quick Test Commands

### 1. Validate Infrastructure
```powershell
# Check that all AWS resources are properly configured
.\validate_aws_infrastructure.ps1
```

### 2. Test Deployment
```powershell
# Run comprehensive deployment tests
.\test_aws_deployment.ps1 -AlbDnsName "your-alb-dns.amazonaws.com"

# Or let it auto-detect
.\test_aws_deployment.ps1
```

### 3. Manual Quick Test
```powershell
# Get ALB DNS
$alb = aws elbv2 describe-load-balancers --names ca-a2a-alb --query 'LoadBalancers[0].DNSName' --output text

# Test health
curl http://$alb/health

# Test agent card
curl http://$alb/card | jq
```

---

## 📋 Test Scripts Overview

### `validate_aws_infrastructure.ps1`
**Purpose**: Validates all AWS resources exist and are configured correctly  
**Time**: ~2 minutes  
**Checks**:
- ✅ AWS credentials
- ✅ VPC and networking
- ✅ RDS database
- ✅ S3 bucket
- ✅ ECR repositories with images
- ✅ ECS cluster and services
- ✅ Load balancer and target groups
- ✅ Service discovery (Cloud Map)
- ✅ CloudWatch logs
- ✅ IAM roles

**Run before deployment testing to ensure infrastructure is ready.**

---

### `test_aws_deployment.ps1`
**Purpose**: Tests the deployed application end-to-end  
**Time**: ~3 minutes  
**Tests**:
- ✅ Health checks
- ✅ Agent cards and skills
- ✅ Agent discovery
- ✅ S3 upload
- ✅ Document processing pipeline
- ✅ Task status tracking
- ✅ Performance metrics
- ✅ CloudWatch logs

**Run after deployment to verify everything works.**

---

## 🎯 Testing Workflow

### Step 1: Pre-Deployment Validation
```powershell
# 1. Test locally first
python run_agents.py
# Ctrl+C after verifying all agents start

# 2. Build Docker images
docker-compose build

# 3. Test with Docker Compose
docker-compose up -d
curl http://localhost:8001/health
docker-compose down
```

### Step 2: Deploy to AWS
```powershell
# Option A: Using AWS Copilot (fastest)
copilot app init ca-a2a
copilot deploy --all

# Option B: Manual deployment
# See AWS_DEPLOYMENT.md for detailed steps
```

### Step 3: Validate Infrastructure
```powershell
# Run validation script
.\validate_aws_infrastructure.ps1

# Expected output:
# Total Checks: 30+
# Passed: 30+
# Failed: 0
# Success Rate: 100%
```

### Step 4: Test Deployment
```powershell
# Run deployment tests
.\test_aws_deployment.ps1

# Expected output:
# Tests Passed: 8 / 8
# ✓ All tests passed! Deployment is working correctly.
```

### Step 5: Manual Verification
```powershell
# Get ALB DNS
$alb = aws elbv2 describe-load-balancers --names ca-a2a-alb --query 'LoadBalancers[0].DNSName' --output text

# Process a test document
curl -X POST http://$alb/message `
  -H "Content-Type: application/json" `
  -d '{
    "jsonrpc": "2.0",
    "id": "test-1",
    "method": "process_document",
    "params": {
      "s3_key": "test-documents/test.pdf",
      "priority": "normal"
    }
  }'

# Check task status (use task_id from response)
curl -X POST http://$alb/message `
  -H "Content-Type: application/json" `
  -d '{
    "jsonrpc": "2.0",
    "id": "test-2",
    "method": "get_task_status",
    "params": {
      "task_id": "your-task-id"
    }
  }'
```

---

## 🐛 Troubleshooting

### Issue: Infrastructure validation fails

**Solution**: Check the specific failed resources and fix them.

Common issues:
- VPC not created → Run VPC creation from AWS_DEPLOYMENT.md
- RDS not available → Check RDS status: `aws rds describe-db-instances`
- ECR images missing → Build and push images
- ECS services not running → Check task logs

### Issue: Deployment tests fail

**Solution**: Check CloudWatch logs for errors.

```powershell
# View orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator --follow

# Check task status
aws ecs list-tasks --cluster ca-a2a-cluster --service-name orchestrator
aws ecs describe-tasks --cluster ca-a2a-cluster --tasks <task-arn>
```

### Issue: Health check returns 503

**Possible causes**:
- Dependencies unhealthy (RDS, S3)
- Task still starting up (wait 60 seconds)
- Security groups blocking traffic
- Service discovery not working

**Check**:
```powershell
# Check target health
$tg = aws elbv2 describe-target-groups --names ca-a2a-orchestrator-tg --query 'TargetGroups[0].TargetGroupArn' --output text
aws elbv2 describe-target-health --target-group-arn $tg
```

### Issue: Agent discovery returns 0 agents

**Possible causes**:
- Service discovery not configured
- Backend services not running
- Security groups blocking inter-agent communication

**Check**:
```powershell
# Check backend services
aws ecs list-services --cluster ca-a2a-cluster
aws ecs describe-services --cluster ca-a2a-cluster --services extractor validator archivist

# Check Cloud Map registrations
$ns = aws servicediscovery list-namespaces --query 'Namespaces[?Name==`local`].Id' --output text
aws servicediscovery list-services --filters Name=NAMESPACE_ID,Values=$ns
```

---

## 📊 Understanding Test Results

### Infrastructure Validation

**100% Success Rate**: ✅ Ready for deployment testing  
**80-99% Success Rate**: ⚠️ Some issues, but may work  
**< 80% Success Rate**: ❌ Fix infrastructure before proceeding

### Deployment Tests

**8/8 Passed**: ✅ Deployment fully functional  
**6-7/8 Passed**: ⚠️ Minor issues, investigate failures  
**< 6/8 Passed**: ❌ Major issues, check logs and infrastructure

---

## 📈 Performance Benchmarks

### Expected Response Times

| Endpoint | Target | Acceptable | Slow |
|----------|--------|------------|------|
| `/health` | < 100ms | < 500ms | > 1s |
| `/status` | < 200ms | < 1s | > 2s |
| `/card` | < 300ms | < 1s | > 2s |
| `process_document` | < 5s | < 15s | > 30s |

### Expected Resource Usage

| Agent | CPU | Memory | Typical |
|-------|-----|--------|---------|
| Orchestrator | 0.5 vCPU | 512 MB | 20-30% CPU |
| Extractor | 0.5 vCPU | 1024 MB | 30-50% CPU |
| Validator | 0.25 vCPU | 512 MB | 10-20% CPU |
| Archivist | 0.25 vCPU | 512 MB | 10-20% CPU |

---

## 🎓 Next Steps After Successful Testing

1. **Enable Auto-Scaling**
   ```bash
   aws application-autoscaling register-scalable-target ...
   ```

2. **Configure Monitoring Alarms**
   ```bash
   aws cloudwatch put-metric-alarm ...
   ```

3. **Set Up CI/CD Pipeline**
   - GitHub Actions
   - AWS CodePipeline
   - Jenkins

4. **Load Testing**
   ```bash
   # Using Apache Bench
   ab -n 1000 -c 10 http://$alb/health
   ```

5. **Production Hardening**
   - Enable HTTPS with ACM certificate
   - Add WAF rules
   - Configure backup policies
   - Set up disaster recovery

---

## 📚 Related Documentation

- **Complete Guide**: `AWS_DEPLOYMENT_TESTING.md`
- **Deployment Steps**: `AWS_DEPLOYMENT.md`
- **Production Checklist**: `DEPLOYMENT_CHECKLIST.md`
- **Best Practices**: `A2A_BEST_PRACTICES.md`

---

## 💰 Cost Monitoring

After deployment, monitor costs:

```powershell
# Get current month costs
aws ce get-cost-and-usage `
  --time-period Start=2025-12-01,End=2025-12-31 `
  --granularity DAILY `
  --metrics UnblendedCost `
  --group-by Type=SERVICE
```

**Expected Monthly Cost**: ~$115/month (see AWS_DEPLOYMENT.md for breakdown)

---

## 🧹 Cleanup

When done testing:

```powershell
# Using Copilot
copilot app delete

# Or manually
.\cleanup_aws_resources.ps1  # (if you create this script)
```

---

**Happy Testing! 🚀**

For questions or issues, check the logs:
```powershell
aws logs tail /ecs/ca-a2a-orchestrator --follow
```
