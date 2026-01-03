# AWS Deployment Guide for CA A2A Multi-Agent System

## Table of Contents
1. [Overview](#overview)
2. [Architecture on AWS](#architecture-on-aws)
3. [Agent Card Integration](#agent-card-integration)
4. [Deployment Options](#deployment-options)
5. [Step-by-Step Deployment](#step-by-step-deployment)
6. [Service Discovery](#service-discovery)
7. [Monitoring & Observability](#monitoring--observability)
8. [Cost Estimation](#cost-estimation)
9. [Best Practices](#best-practices)

---

## Overview

The CA A2A (Content Analysis Agent-to-Agent) system is a distributed multi-agent document processing pipeline designed for cloud deployment. This guide provides comprehensive instructions for deploying the system on AWS with full agent card and capability discovery support.

### System Components

- **4 Specialized Agents**: Orchestrator, Extractor, Validator, Archivist
- **Agent Card System**: Self-describing agents with capability discovery
- **Storage**: AWS S3 for documents, RDS PostgreSQL for metadata
- **Communication**: JSON-RPC 2.0 over HTTP (A2A protocol)

---

## Architecture on AWS

### Recommended Architecture (ECS Fargate)

```
┌─────────────────────────────────────────────────────────────────┐
│                         AWS Cloud                                │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    VPC (10.0.0.0/16)                      │  │
│  │                                                            │  │
│  │  ┌────────────────────┐  ┌────────────────────┐          │  │
│  │  │  Public Subnet     │  │  Private Subnet     │          │  │
│  │  │                    │  │                     │          │  │
│  │  │  ┌──────────────┐ │  │  ┌───────────────┐ │          │  │
│  │  │  │     ALB      │ │  │  │ Orchestrator  │ │          │  │
│  │  │  │   (Port 80)  │─┼──┼─▶│   (Port 8001) │ │          │  │
│  │  │  └──────────────┘ │  │  └───────────────┘ │          │  │
│  │  │                    │  │          │          │          │  │
│  │  └────────────────────┘  │          │          │          │  │
│  │                           │          ▼          │          │  │
│  │                           │  ┌───────────────┐ │          │  │
│  │  ┌────────────────────┐  │  │  Extractor    │ │          │  │
│  │  │  Cloud Map         │◀─┼──│  (Port 8002)  │ │          │  │
│  │  │  (Service          │  │  └───────────────┘ │          │  │
│  │  │   Discovery)       │  │          │          │          │  │
│  │  └────────────────────┘  │          ▼          │          │  │
│  │                           │  ┌───────────────┐ │          │  │
│  │  ┌────────────────────┐  │  │  Validator    │ │          │  │
│  │  │   S3 Bucket        │◀─┼──│  (Port 8003)  │ │          │  │
│  │  │   (Documents)      │  │  └───────────────┘ │          │  │
│  │  └────────────────────┘  │          │          │          │  │
│  │                           │          ▼          │          │  │
│  │  ┌────────────────────┐  │  ┌───────────────┐ │          │  │
│  │  │  RDS PostgreSQL    │◀─┼──│  Archivist    │ │          │  │
│  │  │  (Port 5432)       │  │  │  (Port 8004)  │ │          │  │
│  │  └────────────────────┘  │  └───────────────┘ │          │  │
│  │                           │                     │          │  │
│  └───────────────────────────┴─────────────────────┘          │  │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           CloudWatch Logs & Metrics                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Agent Card Integration

### What are Agent Cards?

Agent Cards provide self-description and capability discovery for each agent. Each agent exposes its card at the `/card` endpoint.

#### Agent Card Structure

```json
{
  "agent_id": "extractor-12345",
  "name": "Extractor",
  "version": "1.0.0",
  "description": "Extracts structured data from PDF and CSV documents",
  "status": "active",
  "endpoint": "http://extractor.local:8002",
  "skills": [
    {
      "skill_id": "extract_document",
      "name": "Document Extraction",
      "description": "Extract structured data from PDF or CSV",
      "method": "extract_document",
      "input_schema": {...},
      "output_schema": {...},
      "tags": ["extraction", "pdf", "csv"],
      "avg_processing_time_ms": 2500
    }
  ],
  "resources": {
    "memory_mb": 1024,
    "cpu_cores": 1.0,
    "storage_required": false
  },
  "dependencies": {
    "services": ["s3"],
    "libraries": ["PyPDF2", "pdfplumber", "pandas"]
  },
  "endpoints": {
    "health_check": "/health",
    "metrics": "/status",
    "card": "/card",
    "skills": "/skills"
  }
}
```

### Benefits for AWS Deployment

1. **Service Discovery**: Automatic agent discovery using AWS Cloud Map
2. **Health Checks**: ALB/Target Groups use `/health` endpoint
3. **Auto-Scaling**: Scale based on agent capabilities and load
4. **API Documentation**: Auto-generate from agent cards
5. **Monitoring**: CloudWatch metrics from agent status

---

## Deployment Options

### Option 1: ECS Fargate (Recommended)

**Best for**: Production deployments, serverless operations

**Pros**:
- No server management
- Built-in service discovery
- Auto-scaling
- Cost-effective for moderate traffic

**Cons**:
- Cold start delays
- Less control over infrastructure

### Option 2: EKS (Kubernetes)

**Best for**: Complex orchestration, multi-cloud strategy

**Pros**:
- Powerful orchestration
- Portable across clouds
- Advanced networking

**Cons**:
- Higher complexity
- More expensive (control plane cost)

### Option 3: Lambda + API Gateway

**Best for**: Sporadic workloads, extreme cost optimization

**Pros**:
- Pay per invocation
- Automatic scaling
- No idle costs

**Cons**:
- Requires architecture changes
- Cold start issues
- Execution time limits

---

## Step-by-Step Deployment

### Prerequisites

```bash
# Install required tools
aws --version                    # AWS CLI v2
docker --version                 # Docker 20+
git --version                    # Git

# Configure AWS credentials
aws configure
```

### Phase 1: Infrastructure Setup

#### 1.1 Create VPC and Networking

```bash
# Using AWS CLI
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=ca-a2a-vpc}]'

# Create subnets
aws ec2 create-subnet --vpc-id <vpc-id> --cidr-block 10.0.1.0/24 --availability-zone us-east-1a
aws ec2 create-subnet --vpc-id <vpc-id> --cidr-block 10.0.2.0/24 --availability-zone us-east-1b

# Create internet gateway
aws ec2 create-internet-gateway
aws ec2 attach-internet-gateway --vpc-id <vpc-id> --internet-gateway-id <igw-id>
```

#### 1.2 Create RDS PostgreSQL Instance

```bash
aws rds create-db-instance \
  --db-instance-identifier ca-a2a-postgres \
  --db-instance-class db.t3.medium \
  --engine postgres \
  --engine-version 15.4 \
  --master-username postgres \
  --master-user-password <SECURE_PASSWORD> \
  --allocated-storage 20 \
  --vpc-security-group-ids <sg-id> \
  --db-subnet-group-name ca-a2a-db-subnet \
  --backup-retention-period 7 \
  --storage-encrypted \
  --enable-cloudwatch-logs-exports '["postgresql"]'
```

#### 1.3 Create S3 Bucket

```bash
aws s3 mb s3://ca-a2a-documents-<account-id> --region us-east-1

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket ca-a2a-documents-<account-id> \
  --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket ca-a2a-documents-<account-id> \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'
```

### Phase 2: Container Images

#### 2.1 Create ECR Repositories

```bash
# Create repositories for each agent
for agent in orchestrator extractor validator archivist; do
  aws ecr create-repository --repository-name ca-a2a/$agent
done
```

#### 2.2 Build and Push Images

```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com

# Build images for each agent
cd /path/to/ca_a2a

# Orchestrator
docker build -t ca-a2a/orchestrator \
  --build-arg AGENT_SCRIPT=orchestrator_agent.py .
docker tag ca-a2a/orchestrator:latest \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/orchestrator:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/orchestrator:latest

# Extractor
docker build -t ca-a2a/extractor \
  --build-arg AGENT_SCRIPT=extractor_agent.py .
docker tag ca-a2a/extractor:latest \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/extractor:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/extractor:latest

# Validator
docker build -t ca-a2a/validator \
  --build-arg AGENT_SCRIPT=validator_agent.py .
docker tag ca-a2a/validator:latest \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/validator:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/validator:latest

# Archivist
docker build -t ca-a2a/archivist \
  --build-arg AGENT_SCRIPT=archivist_agent.py .
docker tag ca-a2a/archivist:latest \
  <account-id>.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/archivist:latest
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/archivist:latest
```

### Phase 3: ECS Setup

#### 3.1 Create ECS Cluster

```bash
aws ecs create-cluster --cluster-name ca-a2a-cluster --capacity-providers FARGATE FARGATE_SPOT
```

#### 3.2 Create Task Execution Role

```bash
aws iam create-role --role-name ecsTaskExecutionRole \
  --assume-role-policy-document file://trust-policy.json

aws iam attach-role-policy --role-name ecsTaskExecutionRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
```

#### 3.3 Create Task Definitions

**orchestrator-task.json**:
```json
{
  "family": "ca-a2a-orchestrator",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::<account>:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::<account>:role/ca-a2a-task-role",
  "containerDefinitions": [{
    "name": "orchestrator",
    "image": "<account>.dkr.ecr.us-east-1.amazonaws.com/ca-a2a/orchestrator:latest",
    "portMappings": [{
      "containerPort": 8001,
      "protocol": "tcp"
    }],
    "environment": [
      {"name": "ORCHESTRATOR_HOST", "value": "0.0.0.0"},
      {"name": "EXTRACTOR_HOST", "value": "extractor.local"},
      {"name": "VALIDATOR_HOST", "value": "validator.local"},
      {"name": "ARCHIVIST_HOST", "value": "archivist.local"},
      {"name": "POSTGRES_HOST", "value": "<rds-endpoint>"},
      {"name": "POSTGRES_DB", "value": "documents_db"}
    ],
    "secrets": [
      {"name": "POSTGRES_PASSWORD", "valueFrom": "arn:aws:secretsmanager:..."},
      {"name": "AWS_ACCESS_KEY_ID", "valueFrom": "arn:aws:secretsmanager:..."},
      {"name": "AWS_SECRET_ACCESS_KEY", "valueFrom": "arn:aws:secretsmanager:..."}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/ca-a2a-orchestrator",
        "awslogs-region": "us-east-1",
        "awslogs-stream-prefix": "ecs"
      }
    },
    "healthCheck": {
      "command": ["CMD-SHELL", "curl -f http://localhost:8001/health || exit 1"],
      "interval": 30,
      "timeout": 5,
      "retries": 3,
      "startPeriod": 60
    }
  }]
}
```

Register task definitions:
```bash
aws ecs register-task-definition --cli-input-json file://orchestrator-task.json
aws ecs register-task-definition --cli-input-json file://extractor-task.json
aws ecs register-task-definition --cli-input-json file://validator-task.json
aws ecs register-task-definition --cli-input-json file://archivist-task.json
```

#### 3.4 Create Application Load Balancer

```bash
# Create ALB
aws elbv2 create-load-balancer \
  --name ca-a2a-alb \
  --subnets <subnet-1> <subnet-2> \
  --security-groups <sg-id> \
  --scheme internet-facing \
  --type application

# Create target group (for orchestrator)
aws elbv2 create-target-group \
  --name ca-a2a-orchestrator-tg \
  --protocol HTTP \
  --port 8001 \
  --vpc-id <vpc-id> \
  --target-type ip \
  --health-check-path /health \
  --health-check-interval-seconds 30

# Create listener
aws elbv2 create-listener \
  --load-balancer-arn <alb-arn> \
  --protocol HTTP \
  --port 80 \
  --default-actions Type=forward,TargetGroupArn=<tg-arn>
```

---

## Service Discovery

### AWS Cloud Map Integration

#### Create Service Discovery Namespace

```bash
aws servicediscovery create-private-dns-namespace \
  --name local \
  --vpc <vpc-id> \
  --description "Service discovery for CA A2A agents"
```

#### Create Services

```bash
# Extractor
aws servicediscovery create-service \
  --name extractor \
  --namespace-id <namespace-id> \
  --dns-config 'NamespaceId=<namespace-id>,DnsRecords=[{Type=A,TTL=60}]' \
  --health-check-custom-config FailureThreshold=1

# Validator
aws servicediscovery create-service \
  --name validator \
  --namespace-id <namespace-id> \
  --dns-config 'NamespaceId=<namespace-id>,DnsRecords=[{Type=A,TTL=60}]'

# Archivist
aws servicediscovery create-service \
  --name archivist \
  --namespace-id <namespace-id> \
  --dns-config 'NamespaceId=<namespace-id>,DnsRecords=[{Type=A,TTL=60}]'
```

#### Create ECS Services with Service Discovery

```bash
aws ecs create-service \
  --cluster ca-a2a-cluster \
  --service-name orchestrator \
  --task-definition ca-a2a-orchestrator \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[<subnet-ids>],securityGroups=[<sg-id>],assignPublicIp=DISABLED}" \
  --load-balancers "targetGroupArn=<tg-arn>,containerName=orchestrator,containerPort=8001"

aws ecs create-service \
  --cluster ca-a2a-cluster \
  --service-name extractor \
  --task-definition ca-a2a-extractor \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[<subnet-ids>],securityGroups=[<sg-id>]}" \
  --service-registries "registryArn=<service-discovery-arn>"
```

### Agent Discovery Flow

1. **Orchestrator starts** → Queries `/card` endpoint of each agent
2. **Agent responds** with full capability card
3. **Orchestrator registers** agent in AgentRegistry
4. **Dynamic routing** based on skills

```python
# Orchestrator discovers agents at startup
await orchestrator._discover_agents()

# Returns registry with all agent capabilities
registry = await orchestrator.handle_get_agent_registry({})
# {
#   "total_agents": 3,
#   "active_agents": 3,
#   "total_skills": 15,
#   "available_skills": ["extract_document", "validate_document", ...]
# }
```

---

## Monitoring & Observability

### CloudWatch Integration

#### 1. Container Insights

```bash
aws ecs update-cluster-settings \
  --cluster ca-a2a-cluster \
  --settings name=containerInsights,value=enabled
```

#### 2. Custom Metrics from Agent Cards

Each agent exposes metrics at `/status`:

```json
{
  "agent": "Extractor",
  "status": "running",
  "supported_formats": [".pdf", ".csv"],
  "uptime_seconds": 3600
}
```

Create CloudWatch custom metrics:

```python
import boto3
cloudwatch = boto3.client('cloudwatch')

cloudwatch.put_metric_data(
    Namespace='CA_A2A',
    MetricData=[
        {
            'MetricName': 'ActiveTasks',
            'Value': orchestrator_status['active_tasks'],
            'Unit': 'Count'
        }
    ]
)
```

#### 3. CloudWatch Alarms

```bash
# High error rate alarm
aws cloudwatch put-metric-alarm \
  --alarm-name ca-a2a-high-errors \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --metric-name Errors \
  --namespace AWS/ECS \
  --period 300 \
  --statistic Sum \
  --threshold 10
```

### X-Ray Distributed Tracing

Add to task definition:

```json
{
  "name": "xray-daemon",
  "image": "amazon/aws-xray-daemon",
  "cpu": 32,
  "memoryReservation": 256,
  "portMappings": [{
    "containerPort": 2000,
    "protocol": "udp"
  }]
}
```

### Log Aggregation

All agents send logs to CloudWatch:

```bash
# View orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator --follow

# Search for errors
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "ERROR"
```

---

## Cost Estimation

### Monthly Costs (us-east-1, moderate usage)

| Service | Configuration | Monthly Cost |
|---------|--------------|--------------|
| ECS Fargate (4 tasks) | 0.5 vCPU, 1GB RAM each | $30 |
| RDS PostgreSQL | db.t3.medium, 20GB | $50 |
| Application Load Balancer | 1 ALB | $20 |
| S3 Storage | 100GB, 10K requests | $5 |
| CloudWatch Logs | 10GB ingestion | $5 |
| Data Transfer | 50GB out | $5 |
| **Total** | | **~$115/month** |

### Cost Optimization Tips

1. **Use Fargate Spot** for non-critical agents (70% cheaper)
2. **RDS Reserved Instances** (40% savings for 1-year commitment)
3. **S3 Lifecycle Policies** to archive old documents to Glacier
4. **CloudWatch Log Retention** - set to 7-30 days
5. **Auto-scaling** - scale down during off-peak hours

---

## Best Practices

### Security

1. **Use AWS Secrets Manager** for all credentials
```bash
aws secretsmanager create-secret \
  --name ca-a2a/postgres-password \
  --secret-string "your-secure-password"
```

2. **Least Privilege IAM Roles**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket"
    ],
    "Resource": [
      "arn:aws:s3:::ca-a2a-documents-*/*",
      "arn:aws:s3:::ca-a2a-documents-*"
    ]
  }]
}
```

3. **VPC Endpoints** for S3 (avoid internet gateway)
```bash
aws ec2 create-vpc-endpoint \
  --vpc-id <vpc-id> \
  --service-name com.amazonaws.us-east-1.s3 \
  --route-table-ids <route-table-id>
```

4. **SSL/TLS** on ALB
```bash
aws elbv2 create-listener \
  --load-balancer-arn <alb-arn> \
  --protocol HTTPS \
  --port 443 \
  --certificates CertificateArn=<acm-cert-arn> \
  --default-actions Type=forward,TargetGroupArn=<tg-arn>
```

### High Availability

1. **Multi-AZ Deployment**
   - Deploy tasks across 2+ availability zones
   - RDS Multi-AZ for automatic failover

2. **Auto-Scaling**
```bash
aws application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --resource-id service/ca-a2a-cluster/orchestrator \
  --scalable-dimension ecs:service:DesiredCount \
  --min-capacity 2 \
  --max-capacity 10

aws application-autoscaling put-scaling-policy \
  --policy-name cpu-scaling \
  --service-namespace ecs \
  --resource-id service/ca-a2a-cluster/orchestrator \
  --scalable-dimension ecs:service:DesiredCount \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 70.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ECSServiceAverageCPUUtilization"
    }
  }'
```

3. **Health Checks**
   - ALB health checks use `/health` endpoint
   - Grace period: 60 seconds
   - Interval: 30 seconds
   - Healthy threshold: 2
   - Unhealthy threshold: 3

### Performance

1. **Connection Pooling**
   - PostgreSQL: Set `max_connections` based on agent count
   - asyncpg pools configured in `mcp_protocol.py`

2. **Caching**
   - Add ElastiCache Redis for frequently accessed documents
   - Cache agent discovery results

3. **Batch Processing**
   - Use SQS for document queuing
   - Process in batches during off-peak hours

---

## Quick Start with AWS Copilot

The fastest way to deploy:

```bash
# Install Copilot
brew install aws/tap/copilot-cli

# Initialize
cd /path/to/ca_a2a
copilot app init ca-a2a

# Deploy orchestrator (public-facing)
copilot svc init --name orchestrator \
  --svc-type "Load Balanced Web Service" \
  --dockerfile ./Dockerfile \
  --port 8001

# Deploy backend agents
copilot svc init --name extractor --svc-type "Backend Service" --port 8002
copilot svc init --name validator --svc-type "Backend Service" --port 8003
copilot svc init --name archivist --svc-type "Backend Service" --port 8004

# Add database
copilot storage init --name documents-db \
  --storage-type Aurora \
  --engine PostgreSQL

# Deploy everything
copilot deploy --all
```

Copilot automatically creates:
- VPC with public/private subnets
- ALB for orchestrator
- ECS Fargate services
- Service discovery
- CloudWatch logs
- IAM roles

---

## Troubleshooting

### Agent Discovery Issues

```bash
# Check if agents are reachable
curl http://extractor.local:8002/card
curl http://extractor.local:8002/health

# Check Cloud Map registration
aws servicediscovery list-services --namespace-id <namespace-id>

# View orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator --follow | grep "discovery"
```

### Database Connection Issues

```bash
# Test RDS connectivity from ECS task
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task <task-id> \
  --container orchestrator \
  --interactive \
  --command "/bin/bash"

# Inside container
apt-get update && apt-get install -y postgresql-client
psql -h <rds-endpoint> -U postgres -d documents_db
```

### Performance Issues

```bash
# Check ECS metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/ECS \
  --metric-name CPUUtilization \
  --dimensions Name=ServiceName,Value=orchestrator \
  --start-time 2025-12-13T00:00:00Z \
  --end-time 2025-12-13T23:59:59Z \
  --period 3600 \
  --statistics Average
```

---

## Next Steps

1. **Set up CI/CD** with GitHub Actions or AWS CodePipeline
2. **Implement API Gateway** for authentication/rate limiting
3. **Add ElastiCache** for caching layer
4. **Configure Auto Scaling** based on agent metrics
5. **Set up AWS Backup** for RDS and S3
6. **Implement AWS WAF** for ALB protection
7. **Add X-Ray tracing** for distributed tracing

---

## Support & Resources

- **AWS Documentation**: https://docs.aws.amazon.com/
- **ECS Best Practices**: https://docs.aws.amazon.com/AmazonECS/latest/bestpracticesguide/
- **Agent Card API**: See `/card` endpoint on each agent
- **Architecture Diagram**: See `ARCHITECTURE.md`

---

**Last Updated**: December 2025  
**Version**: 1.0.0
