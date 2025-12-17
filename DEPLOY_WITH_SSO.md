

# Deploy to AWS with SSO Authentication

Complete guide for deploying CA A2A Multi-Agent Pipeline using AWS SSO authentication.

## Your SSO Configuration

```
SSO Start URL: https://d-9067ecc24e.awsapps.com/start/#
SSO Region:     us-east-1
Deploy Region:  eu-west-3 (Paris)
```

## Overview

This deployment is split into **two phases** due to Docker requirements:

- **Phase 1:** Infrastructure setup (no Docker required) - Can run anywhere with AWS CLI
- **Phase 2:** Docker image build and ECS deployment - Requires Docker on local machine

## Prerequisites

### On Any Machine (for Phase 1)
- ✅ AWS CLI v2
- ✅ Active AWS SSO session
- ✅ jq (optional, for JSON parsing)

### On Local Machine (for Phase 2)
- ✅ AWS CLI v2
- ✅ Docker Desktop or Docker Engine running
- ✅ Active AWS SSO session
- ✅ All project files (*.py, requirements.txt, etc.)

## Installation

### Install AWS CLI v2

**Linux:**
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

**macOS:**
```bash
brew install awscli
# or
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /
```

**Windows:**
Download and install from: https://awscli.amazonaws.com/AWSCLIV2.msi

### Install Docker

**macOS:**
```bash
brew install --cask docker
# or download Docker Desktop from docker.com
```

**Linux (Ubuntu/Debian):**
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
# Logout and login again
```

**Windows:**
Download Docker Desktop from: https://www.docker.com/products/docker-desktop

## Step-by-Step Deployment

### Step 1: Configure AWS SSO

On your **local machine** where you'll run the deployment:

```bash
# Configure SSO profile
aws configure sso

# When prompted, enter:
# SSO start URL: https://d-9067ecc24e.awsapps.com/start/#
# SSO Region: us-east-1
# CLI default region: eu-west-3
# CLI output format: json
# CLI profile name: ca-a2a (or any name you prefer)
```

### Step 2: Login to AWS SSO

```bash
# Login using your SSO profile
aws sso login --profile ca-a2a

# This will open a browser window for authentication
# Login with your AWS SSO credentials
```

### Step 3: Verify SSO Session

```bash
# Verify you're authenticated
aws sts get-caller-identity --profile ca-a2a

# Expected output:
# {
#     "UserId": "...",
#     "Account": "123456789012",
#     "Arn": "arn:aws:sts::123456789012:..."
# }
```

### Step 4: Run Phase 1 (Infrastructure)

Phase 1 creates all AWS infrastructure **except** the Docker containers.

```bash
cd ca_a2a

# Make script executable
chmod +x deploy-sso-phase1.sh

# Optional: Set custom database password
export DB_PASSWORD="YourSecurePassword123!"

# Run Phase 1
AWS_PROFILE=ca-a2a ./deploy-sso-phase1.sh
```

**What Phase 1 creates:**
- ✅ VPC with public/private subnets (Multi-AZ)
- ✅ Internet Gateway and NAT Gateway
- ✅ Security Groups (ALB, ECS, RDS)
- ✅ S3 bucket (encrypted, versioned)
- ✅ RDS PostgreSQL database (db.t3.medium)
- ✅ ECR repositories (for Docker images)
- ✅ IAM roles and policies
- ✅ ECS cluster
- ✅ Application Load Balancer
- ✅ CloudWatch log groups
- ✅ Service Discovery (AWS Cloud Map)

**Time:** ~10-15 minutes (RDS takes the longest)

**Output:** Configuration saved to `/tmp/ca-a2a-config.env`

### Step 5: Transfer Configuration (if needed)

If running Phase 2 on a different machine:

```bash
# Copy configuration file
scp /tmp/ca-a2a-config.env you@local-machine:~/ca_a2a/ca-a2a-config.env
```

### Step 6: Run Phase 2 (Docker + ECS)

Phase 2 builds Docker images and deploys ECS services.

**On your local machine with Docker:**

```bash
cd ca_a2a

# Ensure Docker is running
docker ps

# Make script executable
chmod +x deploy-sso-phase2.sh

# Login to SSO (if not already logged in)
aws sso login --profile ca-a2a

# Run Phase 2
AWS_PROFILE=ca-a2a ./deploy-sso-phase2.sh
```

**What Phase 2 does:**
- ✅ Builds 4 Docker images (orchestrator, extractor, validator, archivist)
- ✅ Pushes images to ECR
- ✅ Registers ECS task definitions
- ✅ Creates ECS services with auto-scaling
- ✅ Configures service discovery
- ✅ Deploys 2 tasks per service (8 tasks total)

**Time:** ~10-15 minutes (Docker build + ECS deployment)

## Verification

### Check Deployment Status

```bash
# Get ALB endpoint
ALB_DNS=$(aws elbv2 describe-load-balancers \
    --names ca-a2a-alb \
    --region eu-west-3 \
    --profile ca-a2a \
    --query 'LoadBalancers[0].DNSName' --output text)

echo "Endpoint: http://$ALB_DNS"

# Test health check (wait 2-3 minutes for services to start)
curl http://$ALB_DNS/health

# Expected: {"status": "healthy"}
```

### Check ECS Services

```bash
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator extractor validator archivist \
    --region eu-west-3 \
    --profile ca-a2a \
    --query 'services[].{Name:serviceName,Running:runningCount,Desired:desiredCount,Status:status}'
```

### View Logs

```bash
# Orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator \
    --follow \
    --region eu-west-3 \
    --profile ca-a2a

# All agents in parallel
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3 --profile ca-a2a &
aws logs tail /ecs/ca-a2a-extractor --follow --region eu-west-3 --profile ca-a2a &
aws logs tail /ecs/ca-a2a-validator --follow --region eu-west-3 --profile ca-a2a &
aws logs tail /ecs/ca-a2a-archivist --follow --region eu-west-3 --profile ca-a2a &
```

### Test Document Processing

```bash
# Get S3 bucket name
S3_BUCKET=$(aws s3 ls --region eu-west-3 --profile ca-a2a | grep ca-a2a-documents | awk '{print $3}')

# Upload test document
echo "Test document content" > test.pdf
aws s3 cp test.pdf s3://$S3_BUCKET/test.pdf --region eu-west-3 --profile ca-a2a

# Process document
curl -X POST http://$ALB_DNS/process \
    -H "Content-Type: application/json" \
    -d "{\"document_path\": \"s3://$S3_BUCKET/test.pdf\"}"
```

## Common Operations

### Update Application Code

```bash
# 1. Make code changes
# 2. Rebuild and push images
cd ca_a2a
aws ecr get-login-password --region eu-west-3 --profile ca-a2a | \
    docker login --username AWS --password-stdin $(aws sts get-caller-identity --query Account --output text).dkr.ecr.eu-west-3.amazonaws.com

# Rebuild specific agent (example: orchestrator)
docker build -f Dockerfile.orchestrator \
    -t $(aws sts get-caller-identity --query Account --output text).dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/orchestrator:latest .
docker push $(aws sts get-caller-identity --query Account --output text).dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/orchestrator:latest

# 3. Force new deployment
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service orchestrator \
    --force-new-deployment \
    --region eu-west-3 \
    --profile ca-a2a
```

### Scale Services

```bash
# Scale orchestrator to 4 tasks
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service orchestrator \
    --desired-count 4 \
    --region eu-west-3 \
    --profile ca-a2a

# Scale all services
for service in orchestrator extractor validator archivist; do
    aws ecs update-service \
        --cluster ca-a2a-cluster \
        --service $service \
        --desired-count 3 \
        --region eu-west-3 \
        --profile ca-a2a
done
```

### Database Access

```bash
# Get RDS endpoint
RDS_ENDPOINT=$(aws rds describe-db-instances \
    --db-instance-identifier ca-a2a-postgres \
    --region eu-west-3 \
    --profile ca-a2a \
    --query 'DBInstances[0].Endpoint.Address' --output text)

# Get database password
DB_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id ca-a2a/db-password \
    --region eu-west-3 \
    --profile ca-a2a \
    --query 'SecretString' --output text)

echo "RDS Endpoint: $RDS_ENDPOINT"
echo "Password: $DB_PASSWORD"

# Connect from ECS task (exec into container)
TASK_ID=$(aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --service-name orchestrator \
    --region eu-west-3 \
    --profile ca-a2a \
    --query 'taskArns[0]' --output text)

aws ecs execute-command \
    --cluster ca-a2a-cluster \
    --task $TASK_ID \
    --container orchestrator \
    --interactive \
    --command "/bin/bash" \
    --region eu-west-3 \
    --profile ca-a2a
```

## Monitoring

### CloudWatch Metrics

```bash
# CPU utilization (last hour)
aws cloudwatch get-metric-statistics \
    --namespace AWS/ECS \
    --metric-name CPUUtilization \
    --dimensions Name=ServiceName,Value=orchestrator Name=ClusterName,Value=ca-a2a-cluster \
    --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 300 \
    --statistics Average \
    --region eu-west-3 \
    --profile ca-a2a
```

### Cost Monitoring

```bash
# Current month costs
aws ce get-cost-and-usage \
    --time-period Start=$(date +%Y-%m-01),End=$(date +%Y-%m-%d) \
    --granularity MONTHLY \
    --metrics UnblendedCost \
    --group-by Type=SERVICE \
    --region us-east-1 \
    --profile ca-a2a
```

## Cleanup

To remove all AWS resources:

```bash
# Use the cleanup script
chmod +x cleanup-aws.sh
AWS_REGION=eu-west-3 AWS_PROFILE=ca-a2a ./cleanup-aws.sh
```

Or manually:

```bash
# Delete ECS services
for service in orchestrator extractor validator archivist; do
    aws ecs update-service \
        --cluster ca-a2a-cluster \
        --service $service \
        --desired-count 0 \
        --region eu-west-3 \
        --profile ca-a2a

    aws ecs delete-service \
        --cluster ca-a2a-cluster \
        --service $service \
        --force \
        --region eu-west-3 \
        --profile ca-a2a
done

# Delete RDS (skip final snapshot)
aws rds delete-db-instance \
    --db-instance-identifier ca-a2a-postgres \
    --skip-final-snapshot \
    --region eu-west-3 \
    --profile ca-a2a

# Empty and delete S3 bucket
S3_BUCKET=$(aws s3 ls --region eu-west-3 --profile ca-a2a | grep ca-a2a-documents | awk '{print $3}')
aws s3 rm s3://$S3_BUCKET --recursive --region eu-west-3 --profile ca-a2a
aws s3 rb s3://$S3_BUCKET --region eu-west-3 --profile ca-a2a

# Continue with other resources (see cleanup-aws.sh for full list)
```

## Troubleshooting

### SSO Session Expired

```bash
# Re-authenticate
aws sso login --profile ca-a2a

# Verify
aws sts get-caller-identity --profile ca-a2a
```

### Docker Not Running

```bash
# Check Docker status
docker ps

# Start Docker (macOS)
open -a Docker

# Start Docker (Linux)
sudo systemctl start docker
```

### ECS Tasks Not Starting

```bash
# Get task failure reason
TASK_ARN=$(aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --desired-status STOPPED \
    --region eu-west-3 \
    --profile ca-a2a \
    --query 'taskArns[0]' --output text)

aws ecs describe-tasks \
    --cluster ca-a2a-cluster \
    --tasks $TASK_ARN \
    --region eu-west-3 \
    --profile ca-a2a \
    --query 'tasks[0].stoppedReason'

# Check logs
aws logs tail /ecs/ca-a2a-orchestrator \
    --region eu-west-3 \
    --profile ca-a2a
```

### Health Checks Failing

```bash
# Check target health
TG_ARN=$(aws elbv2 describe-target-groups \
    --names ca-a2a-orch-tg \
    --region eu-west-3 \
    --profile ca-a2a \
    --query 'TargetGroups[0].TargetGroupArn' --output text)

aws elbv2 describe-target-health \
    --target-group-arn $TG_ARN \
    --region eu-west-3 \
    --profile ca-a2a
```

## Cost Estimate (eu-west-3)

**Monthly costs with default configuration:**

| Service | Configuration | Cost (EUR) |
|---------|--------------|------------|
| ECS Fargate | 8 tasks × 0.5 vCPU × 1GB × 730h | ~€60 |
| RDS PostgreSQL | db.t3.medium, 20GB | ~€55 |
| ALB | 1 ALB + data transfer | ~€22 |
| NAT Gateway | Data transfer | ~€38 |
| S3 | 100GB storage | ~€3 |
| CloudWatch | 10GB logs | ~€5 |
| **Total** | | **~€183/month** |

**Cost optimization:**
- Scale to 1 task per service: **-€30**
- Use db.t3.small: **-€27**
- Use Fargate Spot (70% cheaper): **-€42**
- **Optimized total: ~€84/month**

## Architecture

```
Internet
    │
    ▼
┌─────────────────────────────────┐
│   Application Load Balancer      │  Public Subnets
│   (eu-west-3a, eu-west-3b)      │  (eu-west-3)
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│      ECS Fargate Services        │  Private Subnets
│                                  │  (Multi-AZ)
│  ┌──────────┐  ┌──────────┐    │
│  │Orchestr. │→│Extractor │    │
│  └────┬─────┘  └────┬─────┘    │
│       ↓             ↓            │
│  ┌──────────┐  ┌──────────┐    │
│  │Validator │  │Archivist │    │
│  └────┬─────┘  └────┬─────┘    │
└───────┼─────────────┼───────────┘
        │             │
        ↓             ↓
   ┌────────┐    ┌────────┐
   │   S3   │    │  RDS   │
   │ Bucket │    │Postgres│
   └────────┘    └────────┘
```

## Support

- **AWS SSO Issues:** Contact your AWS administrator
- **Deployment Issues:** Check logs with `aws logs tail`
- **Application Issues:** Review ECS task logs
- **Cost Concerns:** Use AWS Cost Explorer in console

## Next Steps

1. **Initialize Database:**
   - Run `python init_db.py init` from an ECS task

2. **Set up HTTPS:**
   - Request ACM certificate
   - Add HTTPS listener to ALB

3. **Configure Auto-Scaling:**
   - Set up CPU/memory-based scaling policies

4. **Enable Monitoring:**
   - Create CloudWatch dashboards
   - Set up alarms for errors/high costs

5. **Implement CI/CD:**
   - Automate Docker builds
   - Auto-deploy on code changes

---

**Deployment Version:** 2.0 (SSO-based)
**Region:** eu-west-3 (Paris)
**Last Updated:** December 2025
