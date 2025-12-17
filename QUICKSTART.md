# ⚡ Quick Start - Deploy in 2 Minutes

The **simplest way** to deploy CA A2A Multi-Agent Pipeline to AWS.

## Step 1: Setup (One Time)

```bash
# Configure AWS (choose one):

# Option A: AWS SSO (for organizations)
aws configure sso
aws sso login

# Option B: AWS Credentials (for personal accounts)
aws configure
```

## Step 2: Deploy

```bash
cd ca_a2a

# Check prerequisites
./check.sh

# Deploy everything
./deploy.sh
```

**Wait ~30 minutes** ☕

## Step 3: Test

```bash
# Get your endpoint
source deployment-config.txt
echo $ALB_DNS

# Test it
curl http://$ALB_DNS/health
```

## ✅ Done!

Your multi-agent pipeline is now running in AWS:
- 4 microservices
- PostgreSQL database
- S3 storage
- Load balancer
- Auto-scaling
- CloudWatch monitoring

## 💰 Costs

**Default:** ~€150-180/month
**Optimized:** ~€80-100/month

Scale down for lower costs:
```bash
for service in orchestrator extractor validator archivist; do
    aws ecs update-service --cluster ca-a2a-cluster --service $service --desired-count 1
done
```

## 🎯 What Next?

**View logs:**
```bash
aws logs tail /ecs/ca-a2a-orchestrator --follow
```

**Scale up:**
```bash
aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --desired-count 4
```

**Update code:**
```bash
# Make changes, then:
./deploy.sh
```

**Delete everything:**
```bash
./cleanup-aws.sh
```

## 📚 More Info

- **Full guide:** [DEPLOY.md](DEPLOY.md)
- **SSO setup:** [DEPLOY_WITH_SSO.md](DEPLOY_WITH_SSO.md)
- **Manual steps:** [MANUAL_DEPLOYMENT.md](MANUAL_DEPLOYMENT.md)
- **Commands:** [QUICK_REFERENCE.md](QUICK_REFERENCE.md)

## 🆘 Troubleshooting

**"AWS credentials not configured"**
```bash
aws sso login
# or
aws configure
```

**"Docker not found"**
- Install Docker Desktop
- Script will deploy infrastructure, run Phase 2 later

**"Health check failed"**
```bash
# Wait 2-3 minutes, then check logs
aws logs tail /ecs/ca-a2a-orchestrator --follow
```

---

**Need help?** See [DEPLOY.md](DEPLOY.md) for detailed instructions.
