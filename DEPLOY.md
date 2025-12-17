# Deploy CA A2A to AWS - Simple 3-Step Guide

Deploy the complete multi-agent document processing pipeline to AWS in 3 easy steps.

## Prerequisites

You need:
- ✅ AWS account with admin access
- ✅ AWS CLI v2 installed
- ✅ Docker Desktop running (for full deployment)

**Don't have these?** [Jump to setup instructions](#setup)

## 🚀 Quick Deploy (3 Steps)

### Step 1: Configure AWS

```bash
# Option A: Using AWS SSO (recommended)
aws configure sso
# Enter your SSO start URL and settings
aws sso login

# Option B: Using AWS credentials
aws configure
# Enter your Access Key ID and Secret Access Key
```

### Step 2: (Optional) Set your region

```bash
# Copy and edit configuration
cp .env.example .env
nano .env  # Set AWS_REGION=eu-west-3 or your preferred region
```

### Step 3: Deploy!

```bash
cd ca_a2a
chmod +x deploy.sh
./deploy.sh
```

**That's it!** ☕ Grab a coffee - deployment takes ~20-30 minutes.

The script will:
- ✅ Check all prerequisites automatically
- ✅ Create all AWS infrastructure (VPC, RDS, S3, etc.)
- ✅ Build and deploy Docker containers (if Docker available)
- ✅ Set up monitoring and logging
- ✅ Give you the endpoint URL when done

## 📊 What You Get

After deployment:

```
🌐 Load Balancer URL: http://ca-a2a-alb-xxxxxxxxx.eu-west-3.elb.amazonaws.com

✓ 4 Microservices running in ECS Fargate
✓ PostgreSQL database (RDS)
✓ S3 bucket for documents
✓ Multi-AZ deployment for high availability
✓ CloudWatch logging
✓ Auto-scaling enabled
```

## 🧪 Test Your Deployment

```bash
# Get your endpoint (saved in deployment-config.txt)
ALB_DNS=$(grep ALB_DNS deployment-config.txt | cut -d= -f2)

# Test health
curl http://$ALB_DNS/health

# View agent info
curl http://$ALB_DNS/card | jq

# Process a document
curl -X POST http://$ALB_DNS/process \
    -H "Content-Type: application/json" \
    -d '{"document_path": "s3://your-bucket/file.pdf"}'
```

## 💰 Cost

**Default deployment:** ~€150-180/month

Includes:
- 8 Fargate tasks (2 per agent)
- RDS PostgreSQL db.t3.medium
- Application Load Balancer
- NAT Gateway
- S3 storage
- CloudWatch logs

**To reduce costs:** Scale down to 1 task per agent = ~€80-100/month

## 🛠️ Common Operations

### View Logs
```bash
aws logs tail /ecs/ca-a2a-orchestrator --follow
```

### Scale Services
```bash
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service orchestrator \
    --desired-count 4
```

### Update Code
```bash
# Make your changes, then:
./deploy.sh  # Rebuilds and redeploys
```

### Delete Everything
```bash
./cleanup-aws.sh
```

## 🔧 Troubleshooting

### "Docker not found"
The script will deploy infrastructure only. You'll need Docker for Phase 2:
1. Install Docker Desktop
2. Run: `./deploy-sso-phase2.sh`

### "AWS credentials not configured"
```bash
# Run SSO login
aws sso login

# Or configure credentials
aws configure
```

### "Services not starting"
Wait 2-3 minutes for containers to initialize, then check logs:
```bash
aws logs tail /ecs/ca-a2a-orchestrator --follow
```

### "Health check failed"
Check ECS task status:
```bash
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator
```

## 📁 Configuration Files

- `.env` - Your deployment settings
- `deployment-config.txt` - Generated after deployment (resource IDs, endpoints)
- `deploy.sh` - Main deployment script
- `cleanup-aws.sh` - Remove all resources

## 🌍 Multi-Region Deployment

Deploy to multiple regions:

```bash
# Paris
AWS_REGION=eu-west-3 ./deploy.sh

# Ireland
AWS_REGION=eu-west-1 ./deploy.sh

# US East
AWS_REGION=us-east-1 ./deploy.sh
```

---

## Setup

### Install AWS CLI v2

**macOS:**
```bash
brew install awscli
```

**Linux:**
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

**Windows:**
Download from: https://awscli.amazonaws.com/AWSCLIV2.msi

### Install Docker

**macOS:**
```bash
brew install --cask docker
# Then start Docker Desktop from Applications
```

**Linux:**
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
# Log out and back in
```

**Windows:**
Download from: https://www.docker.com/products/docker-desktop

### Verify Installation

```bash
aws --version
# Expected: aws-cli/2.x.x

docker --version
# Expected: Docker version 20.x.x

docker ps
# Should show running containers (or empty list)
```

### Get AWS Credentials

**Option 1: AWS SSO (Recommended for organizations)**
Ask your AWS administrator for:
- SSO start URL
- SSO region
- Account access

**Option 2: IAM User (Individual accounts)**
1. Go to AWS Console → IAM → Users
2. Create user with AdministratorAccess
3. Create access keys
4. Run: `aws configure`

---

## Advanced Options

### Custom Configuration

Edit `.env` file:
```bash
AWS_REGION=eu-west-3
AWS_PROFILE=my-sso-profile
DB_PASSWORD=MySecurePassword123!
PROJECT_NAME=my-project
```

### Deploy Infrastructure Only

If you don't have Docker, deploy infrastructure first:
```bash
./deploy-sso-phase1.sh
```

Later, on a machine with Docker:
```bash
./deploy-sso-phase2.sh
```

### Use Existing VPC

Edit `deploy.sh` and set VPC_ID at the top.

### Enable HTTPS

After deployment:
1. Request ACM certificate in AWS Console
2. Add HTTPS listener to ALB
3. Update security group to allow port 443

---

## Support

- **Deployment issues:** Check `aws logs tail /ecs/ca-a2a-orchestrator`
- **AWS help:** https://docs.aws.amazon.com/
- **Cost questions:** Use AWS Cost Explorer in console

---

## What's Next?

After successful deployment:

1. **Initialize Database:**
   ```bash
   # Connect to ECS task and run init
   TASK_ID=$(aws ecs list-tasks --cluster ca-a2a-cluster --service orchestrator --query 'taskArns[0]' --output text)
   aws ecs execute-command --cluster ca-a2a-cluster --task $TASK_ID --container orchestrator --interactive --command "/bin/bash"
   # Inside container: python init_db.py init
   ```

2. **Upload Test Documents:**
   ```bash
   aws s3 cp test.pdf s3://$(grep S3_BUCKET deployment-config.txt | cut -d= -f2)/
   ```

3. **Set Up Monitoring:**
   - Create CloudWatch dashboard
   - Set up billing alerts
   - Configure auto-scaling policies

4. **Enable CI/CD:**
   - Connect GitHub repository
   - Auto-deploy on commits

---

**Ready to deploy?** Just run `./deploy.sh` and let it handle everything! 🚀
