# AWS Testing - Quick Reference

**Last Updated:** January 1, 2026

---

## 🚀 Quick Start (Choose One)

### Option 1: AWS CloudShell (Recommended - No Setup Required)

1. **Open AWS Console** → Switch to **eu-west-3** region
2. **Click CloudShell icon** (terminal icon in top bar)
3. **Run test script:**

```bash
# Download and run
curl -s https://raw.githubusercontent.com/your-org/ca_a2a/main/test-aws-complete.sh | bash

# Or manually:
cat > test-aws-complete.sh << 'EOF'
# ... paste script content ...
EOF
chmod +x test-aws-complete.sh
./test-aws-complete.sh
```

### Option 2: Local Terminal (Requires AWS CLI)

```bash
# Ensure AWS CLI is configured
aws configure sso
aws sso login

# Run test script
bash test-aws-complete.sh
```

### Option 3: Quick Manual Tests

```bash
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Test 1: Health Check
curl -s "$ALB_URL/health" | jq '.'

# Test 2: Agent Card
curl -s "$ALB_URL/card" | jq '.'

# Test 3: Process Document
curl -s -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/test.txt"}' | jq '.'
```

---

## 📊 Test Categories (45+ Tests)

| Category | Tests | What It Checks |
|----------|-------|----------------|
| **Infrastructure** | 7 | ECS, ALB, RDS, S3, VPC |
| **API Endpoints** | 6 | Health, card, skills, status |
| **Document Processing** | 3 | Upload, process, verify |
| **Security** | 5 | Auth, validation, IAM |
| **Performance** | 3 | Response times, CPU |
| **Monitoring** | 4 | Logs, errors, alarms |
| **Data Persistence** | 4 | Backups, versioning |
| **Integration** | 3 | Agent connectivity |
| **Scalability** | 3 | Scaling, multi-AZ |
| **TOTAL** | **38+** | **Complete coverage** |

---

## ✅ Expected Output

```bash
==========================================
  CA A2A AWS Comprehensive Test Suite
==========================================
Region:  eu-west-3
Cluster: ca-a2a-cluster
Date:    Thu Jan 1 2026
==========================================

=== 1. INFRASTRUCTURE HEALTH TESTS ===

[TEST 1] ECS Cluster Exists
✓ PASS

[TEST 2] All 4 ECS Services Running
✓ PASS

[TEST 3] Orchestrator Service Has 2 Tasks
✓ PASS

[TEST 4] ALB Target Group Has Healthy Targets
✓ PASS

[TEST 5] RDS Database Is Available
✓ PASS

[TEST 6] S3 Bucket Exists
✓ PASS

[TEST 7] VPC Endpoints Exist
✓ PASS

=== 2. API ENDPOINT TESTS ===

[TEST 8] Health Endpoint Responds
✓ PASS

[TEST 9] Health Status Is 'healthy'
✓ PASS

... (30+ more tests) ...

==========================================
           TEST SUMMARY
==========================================
Total Tests:  38
Passed:       38
Failed:       0
Success Rate: 100%
==========================================

✓ All tests passed! Deployment is healthy.

Next steps:
  1. Test with real documents
  2. Monitor CloudWatch metrics
  3. Review application logs
```

---

## 🔍 Individual Test Commands

### Infrastructure

```bash
# Check ECS services
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist \
  --region eu-west-3 \
  --query 'services[*].[serviceName,status,runningCount]' \
  --output table

# Check ALB health
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779 \
  --region eu-west-3 \
  --query 'TargetHealthDescriptions[*].[Target.Id,TargetHealth.State]' \
  --output table

# Check RDS status
aws rds describe-db-instances \
  --db-instance-identifier ca-a2a-postgres \
  --region eu-west-3 \
  --query 'DBInstances[0].[DBInstanceStatus,Endpoint.Address]' \
  --output table
```

### API Tests

```bash
ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Health check
curl -s "$ALB_URL/health"

# Agent card with skills
curl -s "$ALB_URL/card" | jq '{
  name: .agent_name,
  version: .version,
  skills: .skills[].skill_id
}'

# Performance metrics
curl -s "$ALB_URL/status" | jq '.performance'
```

### Document Processing

```bash
# Create test document
echo "Test invoice content" > test.txt

# Upload to S3
aws s3 cp test.txt s3://ca-a2a-documents-555043101106/incoming/ \
  --region eu-west-3

# Process via API
curl -X POST "$ALB_URL/process" \
  -H "Content-Type: application/json" \
  -d '{"s3_key": "incoming/test.txt"}' | jq '.'

# Check logs
aws logs tail /ecs/ca-a2a-orchestrator \
  --since 2m \
  --region eu-west-3
```

### Monitoring

```bash
# Recent logs
aws logs tail /ecs/ca-a2a-orchestrator \
  --follow \
  --region eu-west-3

# Search for errors
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "ERROR" \
  --start-time $(date -d '1 hour ago' +%s)000 \
  --region eu-west-3

# CPU metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/ECS \
  --metric-name CPUUtilization \
  --dimensions Name=ClusterName,Value=ca-a2a-cluster \
  --start-time $(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average \
  --region eu-west-3
```

---

## 🐛 Troubleshooting

### Service Not Running

```bash
# Check service events
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator \
  --region eu-west-3 \
  --query 'services[0].events[0:5]'

# Force new deployment
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --force-new-deployment \
  --region eu-west-3
```

### ALB Not Responding

```bash
# Check ALB status
aws elbv2 describe-load-balancers \
  --region eu-west-3 \
  --query 'LoadBalancers[?LoadBalancerName==`ca-a2a-alb`]'

# Check security groups
aws ec2 describe-security-groups \
  --group-ids sg-05db73131090f365a \
  --region eu-west-3 \
  --query 'SecurityGroups[0].IpPermissions'
```

### Processing Errors

```bash
# Check orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator \
  --follow \
  --region eu-west-3

# Check task logs
aws logs tail /ecs/ca-a2a-extractor \
  --since 5m \
  --region eu-west-3
```

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| `AWS_COMPREHENSIVE_TESTS.md` | Complete test documentation |
| `test-aws-complete.sh` | Automated test script |
| `TESTING_GUIDE.md` | General testing guide |
| `END_TO_END_DEMO.md` | Demo walkthrough |
| `TROUBLESHOOTING.md` | Common issues |

---

## 🎯 Test Checklist

Use this before production deployment:

```
Infrastructure:
☐ All ECS services ACTIVE
☐ All tasks running (2/2 per service)
☐ ALB targets healthy
☐ RDS available
☐ S3 bucket accessible

API:
☐ Health endpoint returns 200
☐ Agent card shows all skills
☐ Process endpoint accepts requests

Processing:
☐ Documents upload to S3
☐ API triggers processing
☐ Documents move to processed/
☐ Logs show activity

Security:
☐ IAM roles attached
☐ Security groups configured
☐ No critical errors in logs

Monitoring:
☐ CloudWatch logs working
☐ Metrics available
☐ Alarms configured (optional)
```

---

## 💡 Pro Tips

1. **Use CloudShell** - It's already authenticated and has `jq` installed
2. **Run tests after changes** - Verify deployments didn't break anything
3. **Monitor logs during tests** - Open a second terminal with `aws logs tail --follow`
4. **Save test output** - Redirect to file: `./test-aws-complete.sh > test-results.txt 2>&1`
5. **Test with real data** - Use actual documents from your use case

---

## 📞 Support

**AWS Account:** 555043101106  
**Region:** eu-west-3 (Paris)  
**Project:** CA-A2A  

**Quick Links:**
- [AWS Console](https://console.aws.amazon.com)
- [ECS Cluster](https://eu-west-3.console.aws.amazon.com/ecs/home?region=eu-west-3#/clusters/ca-a2a-cluster)
- [CloudWatch Logs](https://eu-west-3.console.aws.amazon.com/cloudwatch/home?region=eu-west-3#logsV2:log-groups)

---

**Version:** 1.0  
**Status:** ✅ Ready to Use

