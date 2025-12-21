# AWS Deployment Testing Guide

## 📋 Overview

This guide walks you through testing your multi-agent system deployment on AWS ECS Fargate, from infrastructure setup to end-to-end validation.

---

## 🎯 Pre-Deployment Checklist

### 1. AWS Prerequisites

```bash
# Verify AWS CLI is installed and configured
aws --version
aws sts get-caller-identity

# Set your AWS region
export AWS_REGION=us-east-1

# Verify you have necessary permissions
aws iam get-user
```

Required AWS permissions:
- ✅ ECS (create clusters, task definitions, services)
- ✅ ECR (create repositories, push images)
- ✅ VPC (create VPC, subnets, security groups)
- ✅ RDS (create database instances)
- ✅ S3 (create buckets, upload files)
- ✅ CloudWatch (logs, metrics)
- ✅ IAM (create roles, policies)
- ✅ EC2 (load balancers, target groups)

### 2. Local Prerequisites

```bash
# Docker is installed and running
docker --version
docker ps

# Python dependencies installed
pip install -r requirements.txt

# All agents can start locally
python run_agents.py
# Press Ctrl+C after verifying all 4 agents start
```

---

## 🚀 Deployment Methods

### Method 1: AWS Copilot (Recommended - Fastest)

**Time: ~15 minutes**

```bash
# 1. Install AWS Copilot
# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/aws/copilot-cli/releases/latest/download/copilot-windows.exe" -OutFile "copilot.exe"
.\copilot.exe --version

# 2. Initialize application
copilot app init ca-a2a

# 3. Create environment
copilot env init --name production --profile default

# 4. Deploy database
copilot storage init --name documents-db --storage-type Aurora --engine PostgreSQL

# 5. Deploy orchestrator (public-facing)
copilot svc init --name orchestrator --svc-type "Load Balanced Web Service" --dockerfile ./Dockerfile --port 8001

# 6. Deploy backend agents
copilot svc init --name extractor --svc-type "Backend Service" --dockerfile ./Dockerfile --port 8002
copilot svc init --name validator --svc-type "Backend Service" --dockerfile ./Dockerfile --port 8003
copilot svc init --name archivist --svc-type "Backend Service" --dockerfile ./Dockerfile --port 8004

# 7. Deploy everything
copilot deploy --all

# 8. Get orchestrator URL
copilot svc show --name orchestrator
```

**✅ Pros:** Fully automated, production-ready, includes service discovery

---

### Method 2: Manual ECS Deployment (Full Control)

**Time: ~2 hours**

See `AWS_DEPLOYMENT.md` for detailed step-by-step instructions.

---

### Method 3: Docker Compose (Local Testing Only)

**Time: ~5 minutes**

```bash
# Test locally before AWS deployment
docker-compose up -d

# Verify all services
docker-compose ps

# Test orchestrator
curl http://localhost:8001/health

# Stop
docker-compose down
```

---

## 🧪 Testing Phases

### Phase 1: Infrastructure Validation

#### 1.1 Verify VPC and Networking

```bash
# List VPCs
aws ec2 describe-vpcs --query 'Vpcs[*].[VpcId,CidrBlock,Tags[?Key==`Name`].Value|[0]]' --output table

# List subnets
aws ec2 describe-subnets --query 'Subnets[*].[SubnetId,VpcId,CidrBlock,AvailabilityZone]' --output table

# List security groups
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName,VpcId]' --output table
```

#### 1.2 Verify RDS Database

```bash
# List RDS instances
aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,DBInstanceStatus,Endpoint.Address,Engine]' --output table

# Test connection (from local machine with proper security group)
# Get endpoint
DB_ENDPOINT=$(aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --query 'DBInstances[0].Endpoint.Address' --output text)

echo "Database endpoint: $DB_ENDPOINT"

# Test connection (requires psql)
psql -h $DB_ENDPOINT -U postgres -d documents_db -c "SELECT version();"
```

#### 1.3 Verify S3 Bucket

```bash
# List buckets
aws s3 ls | grep ca-a2a

# Set bucket name
S3_BUCKET="ca-a2a-documents-$(aws sts get-caller-identity --query Account --output text)"

# Upload test document
echo "Test content" > test.txt
aws s3 cp test.txt s3://$S3_BUCKET/test-documents/test.txt

# Verify upload
aws s3 ls s3://$S3_BUCKET/test-documents/
```

#### 1.4 Verify ECR Repositories

```bash
# List repositories
aws ecr describe-repositories --query 'repositories[*].[repositoryName,repositoryUri]' --output table

# Expected repositories:
# - ca-a2a/orchestrator
# - ca-a2a/extractor
# - ca-a2a/validator
# - ca-a2a/archivist
```

---

### Phase 2: Container Image Testing

#### 2.1 Build Images Locally

```bash
# Build all agent images
docker build -t ca-a2a/orchestrator --build-arg AGENT_SCRIPT=orchestrator_agent.py .
docker build -t ca-a2a/extractor --build-arg AGENT_SCRIPT=extractor_agent.py .
docker build -t ca-a2a/validator --build-arg AGENT_SCRIPT=validator_agent.py .
docker build -t ca-a2a/archivist --build-arg AGENT_SCRIPT=archivist_agent.py .

# Verify images
docker images | grep ca-a2a
```

#### 2.2 Test Images Locally

```bash
# Test orchestrator container
docker run -d --name test-orchestrator -p 8001:8001 \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -e S3_BUCKET_NAME=$S3_BUCKET \
  -e POSTGRES_HOST=$DB_ENDPOINT \
  -e POSTGRES_PASSWORD=your_password \
  ca-a2a/orchestrator

# Wait for startup
sleep 10

# Test health
curl http://localhost:8001/health

# Check logs
docker logs test-orchestrator

# Cleanup
docker stop test-orchestrator
docker rm test-orchestrator
```

#### 2.3 Push Images to ECR

```bash
# Get AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION=us-east-1

# Login to ECR
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# Tag and push all images
for agent in orchestrator extractor validator archivist; do
  echo "Pushing $agent..."
  docker tag ca-a2a/$agent:latest $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/ca-a2a/$agent:latest
  docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/ca-a2a/$agent:latest
done

# Verify images in ECR
aws ecr list-images --repository-name ca-a2a/orchestrator
```

---

### Phase 3: ECS Service Validation

#### 3.1 Check ECS Cluster

```bash
# List clusters
aws ecs list-clusters

# Describe cluster
aws ecs describe-clusters --clusters ca-a2a-cluster

# List services
aws ecs list-services --cluster ca-a2a-cluster
```

#### 3.2 Check Task Definitions

```bash
# List task definitions
aws ecs list-task-definitions --family-prefix ca-a2a

# Describe orchestrator task
aws ecs describe-task-definition --task-definition ca-a2a-orchestrator:latest
```

#### 3.3 Check Running Tasks

```bash
# List tasks in cluster
aws ecs list-tasks --cluster ca-a2a-cluster

# Get task details
TASK_ARN=$(aws ecs list-tasks --cluster ca-a2a-cluster --service-name orchestrator --query 'taskArns[0]' --output text)

aws ecs describe-tasks --cluster ca-a2a-cluster --tasks $TASK_ARN

# Check task status
aws ecs describe-tasks --cluster ca-a2a-cluster --tasks $TASK_ARN --query 'tasks[0].[lastStatus,healthStatus,containers[0].name,containers[0].healthStatus]'
```

#### 3.4 View Container Logs

```bash
# Get log stream name
LOG_GROUP="/ecs/ca-a2a-orchestrator"

aws logs tail $LOG_GROUP --follow

# Or specific time range
aws logs filter-log-events --log-group-name $LOG_GROUP --start-time $(date -d '10 minutes ago' +%s)000
```

---

### Phase 4: Load Balancer Testing

#### 4.1 Get ALB DNS Name

```bash
# List load balancers
aws elbv2 describe-load-balancers --query 'LoadBalancers[*].[LoadBalancerName,DNSName,State.Code]' --output table

# Get specific ALB
ALB_DNS=$(aws elbv2 describe-load-balancers --names ca-a2a-alb --query 'LoadBalancers[0].DNSName' --output text)

echo "Orchestrator URL: http://$ALB_DNS"
```

#### 4.2 Test Load Balancer

```bash
# Health check
curl http://$ALB_DNS/health

# Expected response:
# {"status":"healthy","agent":"Orchestrator","version":"1.0.0",...}

# Get agent card
curl http://$ALB_DNS/card | jq

# Get status
curl http://$ALB_DNS/status | jq
```

#### 4.3 Check Target Group Health

```bash
# List target groups
aws elbv2 describe-target-groups --query 'TargetGroups[*].[TargetGroupName,HealthCheckPath,HealthCheckIntervalSeconds]' --output table

# Get target health
TG_ARN=$(aws elbv2 describe-target-groups --names ca-a2a-orchestrator-tg --query 'TargetGroups[0].TargetGroupArn' --output text)

aws elbv2 describe-target-health --target-group-arn $TG_ARN
```

---

### Phase 5: Service Discovery Testing

#### 5.1 Verify Cloud Map Namespace

```bash
# List namespaces
aws servicediscovery list-namespaces

# Get namespace details
NAMESPACE_ID=$(aws servicediscovery list-namespaces --query 'Namespaces[?Name==`local`].Id' --output text)

aws servicediscovery get-namespace --id $NAMESPACE_ID
```

#### 5.2 Verify Service Registrations

```bash
# List services in namespace
aws servicediscovery list-services --filters Name=NAMESPACE_ID,Values=$NAMESPACE_ID

# Check if agents are registered
for service in extractor validator archivist; do
  echo "Checking $service..."
  aws servicediscovery list-instances --service-id $(aws servicediscovery list-services --filters Name=NAMESPACE_ID,Values=$NAMESPACE_ID --query "Services[?Name=='$service'].Id" --output text)
done
```

#### 5.3 Test DNS Resolution (from within ECS)

```bash
# This requires ECS Exec enabled or running a test container
# Example: test from orchestrator container

# Get orchestrator task
TASK_ID=$(aws ecs list-tasks --cluster ca-a2a-cluster --service-name orchestrator --query 'taskArns[0]' --output text)

# Execute command in container (requires ECS Exec enabled)
aws ecs execute-command --cluster ca-a2a-cluster \
  --task $TASK_ID \
  --container orchestrator \
  --interactive \
  --command "/bin/bash"

# Inside container:
# curl http://extractor.local:8002/health
# curl http://validator.local:8003/health
# curl http://archivist.local:8004/health
```

---

### Phase 6: End-to-End Testing

#### 6.1 Upload Test Document to S3

```bash
# Create a test PDF (requires a sample PDF)
# Or download one
curl -o test-document.pdf "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf"

# Upload to S3
aws s3 cp test-document.pdf s3://$S3_BUCKET/test-documents/test-document.pdf

# Verify upload
aws s3 ls s3://$S3_BUCKET/test-documents/
```

#### 6.2 Process Document via Orchestrator

```bash
# Process document
curl -X POST http://$ALB_DNS/message \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: test-$(date +%s)" \
  -d '{
    "jsonrpc": "2.0",
    "id": "test-1",
    "method": "process_document",
    "params": {
      "s3_key": "test-documents/test-document.pdf",
      "priority": "normal"
    }
  }' | jq

# Save task_id from response
TASK_ID="<task_id_from_response>"
```

#### 6.3 Check Task Status

```bash
# Check status
curl -X POST http://$ALB_DNS/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "test-2",
    "method": "get_task_status",
    "params": {
      "task_id": "'$TASK_ID'"
    }
  }' | jq

# Expected stages:
# - extraction: completed
# - validation: completed
# - archiving: completed
```

#### 6.4 Verify in Database

```bash
# Connect to RDS and check
psql -h $DB_ENDPOINT -U postgres -d documents_db -c "
  SELECT id, s3_key, document_type, validation_score, status 
  FROM documents 
  ORDER BY created_at DESC 
  LIMIT 5;
"

# Check processing logs
psql -h $DB_ENDPOINT -U postgres -d documents_db -c "
  SELECT agent_name, action, status, timestamp 
  FROM processing_logs 
  WHERE document_id = (SELECT id FROM documents ORDER BY created_at DESC LIMIT 1)
  ORDER BY timestamp;
"
```

---

### Phase 7: Agent Discovery Testing

#### 7.1 Test Agent Discovery

```bash
# Trigger agent discovery
curl -X POST http://$ALB_DNS/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "test-3",
    "method": "discover_agents",
    "params": {}
  }' | jq

# Expected response:
# {
#   "discovered_agents": 3,
#   "total_skills": 15+,
#   "available_skills": ["extract_document", "validate_document", ...]
# }
```

#### 7.2 Get Agent Registry

```bash
curl -X POST http://$ALB_DNS/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "test-4",
    "method": "get_agent_registry",
    "params": {}
  }' | jq
```

---

### Phase 8: Performance Testing

#### 8.1 Load Test Setup

```bash
# Install Apache Bench (if not installed)
# Windows: Download from https://www.apachelounge.com/download/
# Linux: apt-get install apache2-utils

# Simple load test
ab -n 100 -c 10 -T 'application/json' \
  -p request.json \
  http://$ALB_DNS/message

# request.json:
# {
#   "jsonrpc": "2.0",
#   "id": "load-test",
#   "method": "process_document",
#   "params": {"s3_key": "test-documents/test-document.pdf"}
# }
```

#### 8.2 Monitor CloudWatch Metrics

```bash
# CPU utilization
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
```

---

### Phase 9: Failure Testing

#### 9.1 Test Agent Restart

```bash
# Stop a task (should auto-restart)
TASK_ARN=$(aws ecs list-tasks --cluster ca-a2a-cluster --service-name extractor --query 'taskArns[0]' --output text)

aws ecs stop-task --cluster ca-a2a-cluster --task $TASK_ARN

# Wait and verify new task starts
sleep 30
aws ecs list-tasks --cluster ca-a2a-cluster --service-name extractor
```

#### 9.2 Test Database Connection Loss

```bash
# Temporarily modify security group to block PostgreSQL
# Then restore and verify recovery

# Check health endpoint should show degraded
curl http://$ALB_DNS/health
```

#### 9.3 Test S3 Access Loss

```bash
# Similar to database test
# Temporarily remove S3 permissions from task role
# Verify circuit breaker opens and recovers
```

---

## 📊 Monitoring Dashboard Setup

### Create CloudWatch Dashboard

```bash
# Create dashboard
aws cloudwatch put-dashboard --dashboard-name ca-a2a-monitoring --dashboard-body file://dashboard.json
```

`dashboard.json`:
```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/ECS", "CPUUtilization", {"stat": "Average"}],
          [".", "MemoryUtilization", {"stat": "Average"}]
        ],
        "period": 300,
        "stat": "Average",
        "region": "us-east-1",
        "title": "ECS Resource Utilization"
      }
    },
    {
      "type": "log",
      "properties": {
        "query": "fields @timestamp, agent, method, duration_ms, success\n| filter agent = 'Orchestrator'\n| stats avg(duration_ms) by method",
        "region": "us-east-1",
        "title": "Average Latency by Method"
      }
    }
  ]
}
```

---

## ✅ Validation Checklist

### Infrastructure
- [ ] VPC created with public/private subnets
- [ ] Security groups configured correctly
- [ ] RDS instance running and accessible
- [ ] S3 bucket created with versioning
- [ ] ECR repositories created

### Deployment
- [ ] All 4 container images built and pushed to ECR
- [ ] ECS cluster created
- [ ] Task definitions registered
- [ ] Services created and running
- [ ] Load balancer configured
- [ ] Target groups healthy

### Service Discovery
- [ ] Cloud Map namespace created
- [ ] All agents registered in service discovery
- [ ] DNS resolution working (extractor.local, etc.)

### Functionality
- [ ] Orchestrator health check returns 200
- [ ] Can retrieve agent cards from all agents
- [ ] Agent discovery finds all 3 backend agents
- [ ] Can upload documents to S3
- [ ] Can process document end-to-end
- [ ] Document appears in database
- [ ] Processing logs recorded

### Monitoring
- [ ] CloudWatch logs receiving data
- [ ] CloudWatch metrics visible
- [ ] Can query logs with Logs Insights
- [ ] Alarms configured (if needed)

### Performance
- [ ] Average latency < 5 seconds
- [ ] No errors in logs
- [ ] Circuit breakers functioning
- [ ] Retry logic working
- [ ] Idempotency preventing duplicates

---

## 🐛 Troubleshooting

### Issue: Tasks Not Starting

```bash
# Check task stopped reason
aws ecs describe-tasks --cluster ca-a2a-cluster --tasks $TASK_ARN --query 'tasks[0].stoppedReason'

# Common causes:
# - Invalid environment variables
# - Missing IAM permissions
# - Image pull errors
# - Port conflicts
```

### Issue: Health Checks Failing

```bash
# Check task logs
aws logs tail /ecs/ca-a2a-orchestrator --follow

# Check security group allows ALB → ECS communication
# Verify health check path is correct (/health)
```

### Issue: Can't Connect to RDS

```bash
# Verify security group allows ECS → RDS (port 5432)
# Check RDS is in same VPC
# Verify credentials in Secrets Manager
```

### Issue: Service Discovery Not Working

```bash
# Verify Cloud Map namespace exists
# Check service registrations
# Verify tasks have awsvpc network mode
# Check ECS service is configured with service discovery
```

---

## 💰 Cost Monitoring

```bash
# Get cost estimate
aws ce get-cost-and-usage \
  --time-period Start=2025-12-01,End=2025-12-14 \
  --granularity DAILY \
  --metrics UnblendedCost \
  --filter file://filter.json

# filter.json:
{
  "Tags": {
    "Key": "Application",
    "Values": ["ca-a2a"]
  }
}
```

---

## 🧹 Cleanup (When Done Testing)

```bash
# Delete ECS services
aws ecs delete-service --cluster ca-a2a-cluster --service orchestrator --force
aws ecs delete-service --cluster ca-a2a-cluster --service extractor --force
aws ecs delete-service --cluster ca-a2a-cluster --service validator --force
aws ecs delete-service --cluster ca-a2a-cluster --service archivist --force

# Delete cluster
aws ecs delete-cluster --cluster ca-a2a-cluster

# Delete RDS instance
aws rds delete-db-instance --db-instance-identifier ca-a2a-postgres --skip-final-snapshot

# Delete S3 bucket (must be empty)
aws s3 rm s3://$S3_BUCKET --recursive
aws s3 rb s3://$S3_BUCKET

# Delete ECR images
for repo in orchestrator extractor validator archivist; do
  aws ecr delete-repository --repository-name ca-a2a/$repo --force
done

# Or use Copilot cleanup
copilot app delete
```

---

## 📝 Notes

- **First deployment takes ~15-20 minutes**
- **Test in dev environment first**
- **Monitor costs daily during testing**
- **Use AWS Free Tier where possible**
- **Tag all resources for cost tracking**

---

## 🎯 Success Criteria

Your deployment is successful when:

✅ All 4 agents are running in ECS  
✅ Load balancer returns 200 on /health  
✅ Agent discovery finds all backend agents  
✅ Can process a document end-to-end  
✅ Document stored in PostgreSQL  
✅ Logs visible in CloudWatch  
✅ No errors in agent logs  
✅ Average latency < 5 seconds  
✅ Circuit breakers functioning  
✅ Retry logic working  

---

**Good luck with your AWS deployment! 🚀**
