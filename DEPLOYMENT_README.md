# AWS Deployment - No Git Required

This directory contains everything needed to deploy the CA A2A Multi-Agent Pipeline to AWS using **only AWS CLI**, without requiring git access.

## 📦 What You Need

### Files Required

Transfer these files to your deployment machine (via USB, SCP, cloud storage, etc.):

```
ca_a2a/
├── deploy-manual.sh          ← Main deployment script
├── cleanup-aws.sh            ← Cleanup script
├── MANUAL_DEPLOYMENT.md      ← Full deployment guide
├── QUICK_REFERENCE.md        ← Command reference
├── requirements.txt          ← Python dependencies
└── *.py                      ← All Python files (agents, protocols, etc.)
```

### Tools Required

- AWS CLI v2
- Docker 20+
- jq (JSON processor)

## 🚀 Quick Start (3 Steps)

### Step 1: Configure AWS

```bash
# Set AWS credentials
aws configure
# Enter: Access Key, Secret Key, Region (us-east-1), Format (json)

# Set region and optional password
export AWS_REGION="us-east-1"
export DB_PASSWORD="YourSecurePassword123!"  # Optional, auto-generated if not set
```

### Step 2: Deploy

```bash
cd ca_a2a
chmod +x deploy-manual.sh
./deploy-manual.sh
```

**Deployment time:** 15-20 minutes

The script will create:
- ✓ VPC with public/private subnets across 2 AZs
- ✓ NAT Gateway, Internet Gateway, Route Tables
- ✓ Security Groups (ALB, ECS, RDS)
- ✓ S3 bucket (encrypted, versioned)
- ✓ RDS PostgreSQL database
- ✓ ECR repositories
- ✓ Docker images (built locally and pushed)
- ✓ ECS Fargate cluster
- ✓ Service Discovery (AWS Cloud Map)
- ✓ Application Load Balancer
- ✓ 4 ECS services (orchestrator, extractor, validator, archivist)
- ✓ CloudWatch log groups
- ✓ IAM roles and policies

### Step 3: Test

```bash
# Get endpoint
ALB_DNS=$(aws elbv2 describe-load-balancers --names ca-a2a-alb --query 'LoadBalancers[0].DNSName' --output text)

# Test health
curl http://$ALB_DNS/health

# View logs
aws logs tail /ecs/ca-a2a-orchestrator --follow
```

## 📚 Documentation

| File | Description |
|------|-------------|
| **MANUAL_DEPLOYMENT.md** | Complete step-by-step deployment guide |
| **QUICK_REFERENCE.md** | Command reference for daily operations |
| **deploy-manual.sh** | Automated deployment script |
| **cleanup-aws.sh** | Resource cleanup script |

## 💡 Key Features

### No Git Required
- All files transferred manually (USB, SCP, etc.)
- Docker images built from local files
- No `git clone` needed

### AWS CLI Only
- Uses only standard AWS CLI commands
- No Terraform, CloudFormation, or other tools
- Easy to audit and customize

### Production Ready
- Multi-AZ deployment
- Private subnets for agents
- NAT Gateway for secure internet access
- Encrypted S3 and RDS
- CloudWatch logging
- Health checks and auto-recovery

### Cost Optimized
- Fargate for serverless compute
- Right-sized resources
- 7-day log retention
- Estimated cost: ~$115-173/month

## 🔧 Common Operations

### View Status
```bash
aws ecs describe-services --cluster ca-a2a-cluster --services orchestrator extractor validator archivist
```

### Scale Services
```bash
aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --desired-count 4
```

### Update Images
```bash
# Rebuild
docker build -f Dockerfile.orchestrator -t ${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/orchestrator:latest .
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/orchestrator:latest

# Deploy
aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --force-new-deployment
```

### View Logs
```bash
aws logs tail /ecs/ca-a2a-orchestrator --follow
```

### Cleanup
```bash
./cleanup-aws.sh
```

## 🎯 Deployment Workflow

```
Local Machine
    │
    ├─► Transfer files (no git) ─────┐
    │                                  │
    ├─► Configure AWS CLI ────────────┤
    │                                  │
    └─► Run deploy-manual.sh ─────────┤
                                       ▼
                                   AWS Cloud
                                       │
                                       ├─► VPC & Networking
                                       ├─► S3 Bucket
                                       ├─► RDS PostgreSQL
                                       ├─► Build Docker Images
                                       ├─► Push to ECR
                                       ├─► Deploy ECS Services
                                       └─► Configure ALB
                                           │
                                           ▼
                                   Application Running
                                   http://<alb-dns>/health
```

## 📊 Architecture

```
Internet
    │
    ▼
┌─────────────────────────────────────────┐
│         Application Load Balancer        │
│              (Public Subnets)            │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│          ECS Fargate Services            │
│         (Private Subnets)                │
│                                          │
│  ┌──────────┐  ┌──────────┐            │
│  │Orchestr. │─►│Extractor │            │
│  └────┬─────┘  └────┬─────┘            │
│       │             │                   │
│       ▼             ▼                   │
│  ┌──────────┐  ┌──────────┐            │
│  │Validator │  │Archivist │            │
│  └────┬─────┘  └────┬─────┘            │
│       │             │                   │
└───────┼─────────────┼───────────────────┘
        │             │
        ▼             ▼
   ┌────────┐    ┌────────┐
   │   S3   │    │  RDS   │
   │ Bucket │    │Postgres│
   └────────┘    └────────┘
```

## 🛡️ Security Features

- **Network Isolation:** Agents in private subnets, no direct internet access
- **NAT Gateway:** Secure outbound internet access for agents
- **Encrypted Storage:** S3 (AES256) and RDS (at-rest encryption)
- **Secrets Management:** AWS Secrets Manager for credentials
- **Security Groups:** Least-privilege access controls
- **IAM Roles:** Fine-grained permissions for each service
- **No Public Access:** S3 bucket public access blocked
- **HTTPS Ready:** Add SSL certificate to ALB for HTTPS

## 💰 Cost Breakdown

**Default Configuration (~$173/month):**
- ECS Fargate (8 tasks): $60
- RDS (db.t3.medium): $50
- NAT Gateway: $35
- ALB: $20
- S3: $3
- CloudWatch: $5

**Cost-Optimized Configuration (~$83/month):**
- ECS Fargate (4 tasks): $30
- RDS (db.t3.small): $25
- ALB: $20
- S3: $3
- CloudWatch: $5

To optimize:
```bash
# Scale down to 1 task per service
for service in orchestrator extractor validator archivist; do
    aws ecs update-service --cluster ca-a2a-cluster --service $service --desired-count 1
done

# Use smaller RDS (manual change in AWS Console or modify deploy script)
```

## 🔍 Verification Checklist

After deployment:

- [ ] Health check returns `{"status": "healthy"}`
- [ ] All 4 ECS services show running tasks
- [ ] RDS database is available
- [ ] S3 bucket exists and is encrypted
- [ ] CloudWatch logs are being written
- [ ] ALB targets are healthy
- [ ] Service discovery is working

```bash
# Quick health check
ALB_DNS=$(aws elbv2 describe-load-balancers --names ca-a2a-alb --query 'LoadBalancers[0].DNSName' --output text)
curl http://$ALB_DNS/health && echo "✓ Healthy" || echo "✗ Unhealthy"
```

## 🆘 Troubleshooting

### Tasks Not Starting
```bash
# Check task logs
aws ecs describe-tasks --cluster ca-a2a-cluster --tasks $(aws ecs list-tasks --cluster ca-a2a-cluster --service-name orchestrator --query 'taskArns[0]' --output text)

# View CloudWatch logs
aws logs tail /ecs/ca-a2a-orchestrator --follow
```

### ALB Health Checks Failing
```bash
# Check target health
TG_ARN=$(aws elbv2 describe-target-groups --names ca-a2a-orch-tg --query 'TargetGroups[0].TargetGroupArn' --output text)
aws elbv2 describe-target-health --target-group-arn $TG_ARN
```

### Database Connection Issues
```bash
# Verify security group allows ECS → RDS
# Verify RDS is in private subnets
# Check RDS endpoint
aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --query 'DBInstances[0].Endpoint'
```

### High Costs
```bash
# Check current costs
aws ce get-cost-and-usage \
    --time-period Start=$(date +%Y-%m-01),End=$(date +%Y-%m-%d) \
    --granularity MONTHLY \
    --metrics UnblendedCost \
    --group-by Type=SERVICE
```

## 📞 Support Resources

- **Full Guide:** MANUAL_DEPLOYMENT.md
- **Commands:** QUICK_REFERENCE.md
- **AWS Docs:** https://docs.aws.amazon.com/
- **ECS Best Practices:** https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/

## 🎓 Next Steps

1. **Initialize Database:**
   - Connect to ECS task
   - Run `python init_db.py init`

2. **Upload Test Documents:**
   ```bash
   aws s3 cp test.pdf s3://$S3_BUCKET/test.pdf
   ```

3. **Process Document:**
   ```bash
   curl -X POST http://$ALB_DNS/process \
       -H "Content-Type: application/json" \
       -d '{"document_path": "s3://'$S3_BUCKET'/test.pdf"}'
   ```

4. **Set up HTTPS:**
   - Request ACM certificate
   - Add HTTPS listener to ALB

5. **Enable Monitoring:**
   - Create CloudWatch dashboards
   - Set up alarms

6. **Implement Auto-Scaling:**
   - Configure ECS auto-scaling policies
   - Set up target tracking

---

**Ready to deploy?** Run `./deploy-manual.sh` and you'll have a production-ready multi-agent system in ~20 minutes!
