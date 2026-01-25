# CA-A2A AWS CDK Deployment Guide

## 🚀 Quick Start (AWS Cloud Shell)

### Prerequisites
✅ All pre-installed in Cloud Shell:
- Python 3.9+
- AWS CDK 2.110+
- AWS CLI configured

### Step 1: Setup (One Time)

```bash
cd ca_a2a/cdk

# Install Python dependencies
python3 -m pip install -r requirements.txt --user

# Bootstrap CDK (only needed once per account/region)
cdk bootstrap
```

### Step 2: Preview Deployment

```bash
# See what will be created
cdk diff
```

### Step 3: Deploy

```bash
# Deploy the entire stack
cdk deploy

# Or deploy with auto-approval (skip confirmation)
cdk deploy --require-approval never
```

**That's it!** ✅ 

The deployment takes ~15-20 minutes and creates:
- ✅ VPC with public/private subnets across 2 AZs
- ✅ NAT Gateway for private subnet internet access
- ✅ Security groups with least-privilege rules
- ✅ Aurora PostgreSQL cluster (Multi-AZ)
- ✅ Keycloak PostgreSQL database
- ✅ S3 bucket with encryption and versioning
- ✅ Secrets Manager for all credentials
- ✅ ECS Cluster
- ✅ Application Load Balancer
- ✅ CloudWatch Log Groups

---

## 📊 Common Commands

```bash
# List all stacks
cdk list

# Show synthesized CloudFormation template
cdk synth

# Compare deployed stack with current state
cdk diff

# Deploy with specific parameters
cdk deploy --parameters ProjectName=ca-a2a

# Destroy the stack
cdk destroy

# Watch mode (auto-redeploy on changes)
cdk watch
```

---

## 🔧 Configuration

Edit configuration in `cdk.json` context:

```json
{
  "context": {
    "project_name": "ca-a2a",
    "environment": "prod",
    "region": "us-east-1"
  }
}
```

Or pass as command-line context:

```bash
cdk deploy -c project_name=ca-a2a -c environment=prod -c region=us-east-1
```

---

## 📋 Stack Outputs

After deployment, CDK outputs important values:

```
Outputs:
ca-a2a-prod.VpcId = vpc-xxxx
ca-a2a-prod.AlbDnsName = ca-a2a-alb-xxxx.us-east-1.elb.amazonaws.com
ca-a2a-prod.AuroraClusterEndpoint = ca-a2a-documents-db.cluster-xxxx.us-east-1.rds.amazonaws.com
ca-a2a-prod.KeycloakDbEndpoint = ca-a2a-keycloak-db.xxxx.us-east-1.rds.amazonaws.com
ca-a2a-prod.DocumentsBucketName = ca-a2a-documents-555043101106
ca-a2a-prod.EcsClusterName = ca-a2a-cluster
```

---

## 🔍 Verify Deployment

```bash
# Check stack status
aws cloudformation describe-stacks \
  --stack-name ca-a2a-prod \
  --query 'Stacks[0].StackStatus' \
  --output text

# List all resources
aws cloudformation list-stack-resources \
  --stack-name ca-a2a-prod \
  --query 'StackResourceSummaries[*].[ResourceType,PhysicalResourceId,ResourceStatus]' \
  --output table

# Check RDS status
aws rds describe-db-clusters \
  --db-cluster-identifier ca-a2a-documents-db \
  --region us-east-1

# Check ECS cluster
aws ecs describe-clusters \
  --clusters ca-a2a-cluster \
  --region us-east-1
```

---

## 🔄 Update Infrastructure

1. **Modify** the CDK code in `stacks/ca_a2a_stack.py`
2. **Preview** changes: `cdk diff`
3. **Apply** changes: `cdk deploy`

CDK automatically:
- ✅ Determines what needs to change
- ✅ Updates only affected resources
- ✅ Maintains dependencies
- ✅ Rolls back on error

---

## 🗑️ Cleanup

```bash
# Destroy everything
cdk destroy

# Force destroy without confirmation
cdk destroy --force
```

**Note**: Some resources like S3 buckets and RDS snapshots are retained for safety.

---

## 🆚 CDK vs Bash Script

| Feature | Bash Script | AWS CDK |
|---------|-------------|---------|
| **State Management** | ❌ Manual | ✅ Automatic |
| **Dependency Handling** | ❌ Manual | ✅ Automatic |
| **Updates** | ❌ Complex | ✅ Simple |
| **Rollback** | ❌ Manual | ✅ Automatic |
| **Preview Changes** | ❌ No | ✅ Yes (`cdk diff`) |
| **Type Safety** | ❌ No | ✅ Yes (Python) |
| **Reusability** | ❌ Low | ✅ High |
| **VPC Mismatches** | ❌ Possible | ✅ Impossible |

---

## 🐛 Troubleshooting

### Error: "CDK bootstrap required"
```bash
cdk bootstrap aws://ACCOUNT-ID/us-east-1
```

### Error: "Resource already exists"
- CDK handles this automatically
- Use `cdk import` if you need to import existing resources

### Error: "Insufficient permissions"
- Ensure your Cloud Shell has necessary IAM permissions
- Check CloudFormation events: `aws cloudformation describe-stack-events --stack-name ca-a2a-prod`

### Check deployment logs
```bash
# CloudFormation events
aws cloudformation describe-stack-events \
  --stack-name ca-a2a-prod \
  --max-items 20

# CDK verbose output
cdk deploy --verbose
```

---

## 📚 Next Steps

After infrastructure deployment:

1. **Deploy Docker Images** to ECR
2. **Create ECS Task Definitions**
3. **Deploy ECS Services**
4. **Configure Keycloak** via ALB endpoint
5. **Test End-to-End** using verification scripts

---

## 🔐 Security Features Implemented

✅ All security features from `a2a_security_architecture.md`:

- **Layer 1**: Network isolation (VPC, private subnets)
- **Layer 2**: Security groups with least-privilege
- **Layer 3**: Secrets Manager for credentials
- **Layer 4**: Encryption at rest (RDS, S3)
- **Layer 5**: Encryption in transit (TLS)
- **Layer 6**: Egress hardening (security group rules)
- **Layer 7**: CloudWatch logging
- **Layer 8**: IAM roles with minimal permissions
- **Layer 9**: Multi-AZ redundancy

---

## 💡 Tips

- Use `cdk watch` during development for auto-redeploy
- Always run `cdk diff` before `cdk deploy` to preview changes
- Tag your resources via CDK tags (already configured)
- Use `cdk destroy` for clean removal (handles dependencies)

---

**Deployment made easy with AWS CDK!** 🎉

