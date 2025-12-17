# Quick Reference - AWS Deployment

Quick command reference for managing CA A2A deployment on AWS.

## Initial Deployment

```bash
# Configure AWS
export AWS_REGION="us-east-1"
export DB_PASSWORD="YourSecurePassword123!"

# Deploy everything
chmod +x deploy-manual.sh
./deploy-manual.sh
```

## Common Operations

### Check Deployment Status

```bash
# List all ECS services
aws ecs list-services --cluster ca-a2a-cluster

# Check service status
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator extractor validator archivist

# Get ALB endpoint
aws elbv2 describe-load-balancers \
    --names ca-a2a-alb \
    --query 'LoadBalancers[0].DNSName' --output text
```

### Test Endpoints

```bash
# Get ALB DNS
ALB_DNS=$(aws elbv2 describe-load-balancers --names ca-a2a-alb --query 'LoadBalancers[0].DNSName' --output text)

# Health check
curl http://$ALB_DNS/health

# Status
curl http://$ALB_DNS/status | jq

# Agent card
curl http://$ALB_DNS/card | jq

# Process document
curl -X POST http://$ALB_DNS/process \
    -H "Content-Type: application/json" \
    -d '{"document_path": "s3://bucket/file.pdf"}'
```

### View Logs

```bash
# Real-time logs
aws logs tail /ecs/ca-a2a-orchestrator --follow
aws logs tail /ecs/ca-a2a-extractor --follow
aws logs tail /ecs/ca-a2a-validator --follow
aws logs tail /ecs/ca-a2a-archivist --follow

# Search for errors
aws logs filter-log-events \
    --log-group-name /ecs/ca-a2a-orchestrator \
    --filter-pattern "ERROR" \
    --start-time $(date -u -d '1 hour ago' +%s000)

# Get logs from specific time
aws logs filter-log-events \
    --log-group-name /ecs/ca-a2a-orchestrator \
    --start-time $(date -u -d '2 hours ago' +%s000) \
    --end-time $(date -u +%s000)
```

### Scale Services

```bash
# Scale up
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service orchestrator \
    --desired-count 4

# Scale down
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service orchestrator \
    --desired-count 1

# Scale all services
for service in orchestrator extractor validator archivist; do
    aws ecs update-service \
        --cluster ca-a2a-cluster \
        --service $service \
        --desired-count 2
done
```

### Update Docker Images

```bash
# Login to ECR
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
aws ecr get-login-password --region us-east-1 | \
    docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com

# Build and push
AGENT="orchestrator"  # or extractor, validator, archivist
IMAGE_URI="${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/${AGENT}:latest"

docker build -f Dockerfile.${AGENT} -t $IMAGE_URI .
docker push $IMAGE_URI

# Force deployment
aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service $AGENT \
    --force-new-deployment
```

### Database Operations

```bash
# Get RDS endpoint
RDS_ENDPOINT=$(aws rds describe-db-instances \
    --db-instance-identifier ca-a2a-postgres \
    --query 'DBInstances[0].Endpoint.Address' --output text)

echo "RDS Endpoint: $RDS_ENDPOINT"

# Get database password from secrets
DB_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id ca-a2a/db-password \
    --query 'SecretString' --output text)

# Connect from local (requires VPN or bastion)
psql -h $RDS_ENDPOINT -U postgres -d documents_db

# Connect from ECS task
TASK_ID=$(aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --service-name orchestrator \
    --query 'taskArns[0]' --output text)

aws ecs execute-command \
    --cluster ca-a2a-cluster \
    --task $TASK_ID \
    --container orchestrator \
    --interactive \
    --command "/bin/bash"
```

### S3 Operations

```bash
# Get bucket name
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
S3_BUCKET="ca-a2a-documents-${AWS_ACCOUNT_ID}"

# List documents
aws s3 ls s3://$S3_BUCKET/ --recursive

# Upload document
aws s3 cp test.pdf s3://$S3_BUCKET/test.pdf

# Download document
aws s3 cp s3://$S3_BUCKET/test.pdf ./test.pdf

# Sync directory
aws s3 sync ./documents/ s3://$S3_BUCKET/documents/
```

### Monitoring

```bash
# CPU utilization (last hour)
aws cloudwatch get-metric-statistics \
    --namespace AWS/ECS \
    --metric-name CPUUtilization \
    --dimensions Name=ServiceName,Value=orchestrator Name=ClusterName,Value=ca-a2a-cluster \
    --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 300 \
    --statistics Average

# Memory utilization
aws cloudwatch get-metric-statistics \
    --namespace AWS/ECS \
    --metric-name MemoryUtilization \
    --dimensions Name=ServiceName,Value=orchestrator Name=ClusterName,Value=ca-a2a-cluster \
    --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 300 \
    --statistics Average

# Task count
aws ecs describe-services \
    --cluster ca-a2a-cluster \
    --services orchestrator \
    --query 'services[0].{Desired:desiredCount,Running:runningCount,Pending:pendingCount}'
```

### Troubleshooting

```bash
# Get failed tasks
aws ecs list-tasks \
    --cluster ca-a2a-cluster \
    --desired-status STOPPED \
    --query 'taskArns[0]' --output text

# Describe task failure
TASK_ARN="<task-arn-from-above>"
aws ecs describe-tasks \
    --cluster ca-a2a-cluster \
    --tasks $TASK_ARN \
    --query 'tasks[0].stoppedReason'

# Check ALB target health
TG_ARN=$(aws elbv2 describe-target-groups \
    --names ca-a2a-orch-tg \
    --query 'TargetGroups[0].TargetGroupArn' --output text)

aws elbv2 describe-target-health \
    --target-group-arn $TG_ARN

# Check service discovery
NAMESPACE_ID=$(aws servicediscovery list-namespaces \
    --query "Namespaces[?Name=='local'].Id" --output text)

aws servicediscovery list-services \
    --filters Name=NAMESPACE_ID,Values=$NAMESPACE_ID

# Get service instances
SERVICE_ID=$(aws servicediscovery list-services \
    --query "Services[?Name=='extractor'].Id" --output text)

aws servicediscovery list-instances --service-id $SERVICE_ID
```

### Cost Management

```bash
# Get current month costs
aws ce get-cost-and-usage \
    --time-period Start=$(date +%Y-%m-01),End=$(date +%Y-%m-%d) \
    --granularity MONTHLY \
    --metrics UnblendedCost \
    --group-by Type=SERVICE

# Get daily costs (last 7 days)
aws ce get-cost-and-usage \
    --time-period Start=$(date -u -d '7 days ago' +%Y-%m-%d),End=$(date -u +%Y-%m-%d) \
    --granularity DAILY \
    --metrics UnblendedCost

# Get cost by resource tags
aws ce get-cost-and-usage \
    --time-period Start=$(date +%Y-%m-01),End=$(date +%Y-%m-%d) \
    --granularity MONTHLY \
    --metrics UnblendedCost \
    --group-by Type=TAG,Key=Name
```

### Cleanup

```bash
# Delete everything
chmod +x cleanup-aws.sh
./cleanup-aws.sh

# Or manually stop services
for service in orchestrator extractor validator archivist; do
    aws ecs update-service \
        --cluster ca-a2a-cluster \
        --service $service \
        --desired-count 0
done
```

## Environment Variables

Save these for reuse:

```bash
# Export to file
cat > ~/.ca-a2a-env <<EOF
export AWS_REGION="us-east-1"
export AWS_ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
export S3_BUCKET="ca-a2a-documents-\${AWS_ACCOUNT_ID}"
export VPC_ID="<vpc-id>"
export RDS_ENDPOINT="<rds-endpoint>"
export ALB_DNS="<alb-dns>"
EOF

# Load when needed
source ~/.ca-a2a-env
```

## Common Workflows

### Add New Document Type Support

1. Update extractor agent code
2. Build and push new image
3. Force deployment:
```bash
aws ecs update-service --cluster ca-a2a-cluster --service extractor --force-new-deployment
```

### Increase Processing Capacity

```bash
# Scale all agents
for service in orchestrator extractor validator archivist; do
    aws ecs update-service \
        --cluster ca-a2a-cluster \
        --service $service \
        --desired-count 4
done
```

### View Real-Time Processing

```bash
# Watch logs from all agents
aws logs tail /ecs/ca-a2a-orchestrator --follow &
aws logs tail /ecs/ca-a2a-extractor --follow &
aws logs tail /ecs/ca-a2a-validator --follow &
aws logs tail /ecs/ca-a2a-archivist --follow &
```

### Backup Database

```bash
# Create RDS snapshot
aws rds create-db-snapshot \
    --db-instance-identifier ca-a2a-postgres \
    --db-snapshot-identifier ca-a2a-backup-$(date +%Y%m%d-%H%M%S)

# List snapshots
aws rds describe-db-snapshots \
    --db-instance-identifier ca-a2a-postgres
```

### Restore from Backup

```bash
# Restore from snapshot
aws rds restore-db-instance-from-db-snapshot \
    --db-instance-identifier ca-a2a-postgres-restored \
    --db-snapshot-identifier <snapshot-id>
```

## Quick Health Check

```bash
#!/bin/bash
# health-check.sh

ALB_DNS=$(aws elbv2 describe-load-balancers --names ca-a2a-alb --query 'LoadBalancers[0].DNSName' --output text)

echo "Checking CA A2A Health..."
echo "========================="

# Check orchestrator
if curl -sf http://$ALB_DNS/health > /dev/null; then
    echo "✓ Orchestrator: Healthy"
else
    echo "✗ Orchestrator: Unhealthy"
fi

# Check ECS services
for service in orchestrator extractor validator archivist; do
    STATUS=$(aws ecs describe-services \
        --cluster ca-a2a-cluster \
        --services $service \
        --query 'services[0].{Running:runningCount,Desired:desiredCount}' \
        --output text)

    RUNNING=$(echo $STATUS | awk '{print $1}')
    DESIRED=$(echo $STATUS | awk '{print $2}')

    if [ "$RUNNING" == "$DESIRED" ]; then
        echo "✓ $service: $RUNNING/$DESIRED tasks"
    else
        echo "⚠ $service: $RUNNING/$DESIRED tasks"
    fi
done

# Check RDS
RDS_STATUS=$(aws rds describe-db-instances \
    --db-instance-identifier ca-a2a-postgres \
    --query 'DBInstances[0].DBInstanceStatus' \
    --output text)

if [ "$RDS_STATUS" == "available" ]; then
    echo "✓ Database: Available"
else
    echo "⚠ Database: $RDS_STATUS"
fi

echo "========================="
echo "Endpoint: http://$ALB_DNS"
```

## Useful Aliases

Add to `~/.bashrc` or `~/.zshrc`:

```bash
alias ca2a-logs='aws logs tail /ecs/ca-a2a-orchestrator --follow'
alias ca2a-status='aws ecs describe-services --cluster ca-a2a-cluster --services orchestrator extractor validator archivist'
alias ca2a-scale='f(){ aws ecs update-service --cluster ca-a2a-cluster --service $1 --desired-count $2; }; f'
alias ca2a-deploy='f(){ aws ecs update-service --cluster ca-a2a-cluster --service $1 --force-new-deployment; }; f'
alias ca2a-endpoint='aws elbv2 describe-load-balancers --names ca-a2a-alb --query "LoadBalancers[0].DNSName" --output text'
```

Usage:
```bash
ca2a-logs                    # View logs
ca2a-status                  # Check status
ca2a-scale orchestrator 4    # Scale orchestrator to 4 tasks
ca2a-deploy extractor        # Deploy new extractor version
ca2a-endpoint               # Get ALB endpoint
```
