# CA-A2A CDK Deployment

AWS CDK infrastructure deployment for the CA-A2A Multi-Agent System.

## Quick Start

### Prerequisites

- AWS CLI configured with appropriate credentials
- AWS CDK installed (`npm install -g aws-cdk`)
- Python 3.9+
- Docker (for building container images)

### Deploy Infrastructure

```bash
# From the cdk/ directory
cd cdk

# Deploy (auto-bootstraps if needed)
./quickstart.sh deploy

# Or manually:
pip install -r requirements.txt
cdk bootstrap
cdk deploy -c region=eu-west-3
```

### Deploy Services

After CDK deploys the infrastructure:

```bash
# Build and deploy Docker containers
./deploy-services.sh
```

## Configuration

### Context Variables

Pass via command line or set in `cdk.json`:

| Variable | Default | Description |
|----------|---------|-------------|
| `project_name` | ca-a2a | Project name prefix |
| `environment` | prod | Environment (prod/staging/dev) |
| `region` | eu-west-3 | AWS region |
| `existing_vpc_id` | - | Import existing VPC |
| `existing_cluster_name` | - | Import existing ECS cluster |
| `skip_secrets` | false | Skip creating secrets |
| `skip_rds` | false | Skip creating RDS databases |

### Environment Variables

```bash
export PROJECT_NAME=ca-a2a
export ENVIRONMENT=prod
export AWS_REGION=eu-west-3
```

## Commands

```bash
# Preview changes
./quickstart.sh diff

# Deploy infrastructure
./quickstart.sh deploy

# Destroy (use with caution!)
./quickstart.sh destroy

# Manual CDK commands
cdk synth                    # Generate CloudFormation
cdk diff                     # Show changes
cdk deploy --require-approval never
cdk destroy --force
```

## Infrastructure Created

### Network
- VPC with public/private subnets (2 AZs)
- NAT Gateway
- VPC Endpoints (ECR, S3, Logs, Secrets Manager)
- Security Groups

### Compute
- ECS Fargate Cluster
- ECR Repositories (per service)
- IAM Roles (task execution, task)

### Storage
- Aurora PostgreSQL (documents database)
- RDS PostgreSQL (Keycloak database)
- S3 Bucket (encrypted, versioned)

### Security
- Secrets Manager (auto-generated passwords)
- Security Groups (least privilege)
- VPC Endpoints (private connectivity)

### Monitoring
- CloudWatch Log Groups (7-day retention)
- Container Insights enabled

## Estimated Cost

~$270/month for production deployment:
- ECS Fargate: ~$80/month
- RDS Aurora + PostgreSQL: ~$130/month
- VPC/NAT/ALB: ~$50/month
- S3/Logs: ~$10/month

## Troubleshooting

### Bootstrap Issues

```bash
# Re-bootstrap with explicit account/region
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
cdk bootstrap aws://$ACCOUNT_ID/eu-west-3
```

### Resource Conflicts

If resources already exist:

```bash
# Import existing VPC
cdk deploy -c existing_vpc_id=vpc-xxx

# Import existing cluster
cdk deploy -c existing_cluster_name=ca-a2a-cluster

# Skip conflicting resources
cdk deploy -c skip_secrets=true -c skip_rds=true
```

### View Stack Outputs

```bash
# After deployment
cat outputs.json

# Or from AWS
aws cloudformation describe-stacks \
    --stack-name ca-a2a-prod \
    --query 'Stacks[0].Outputs' \
    --output table
```
