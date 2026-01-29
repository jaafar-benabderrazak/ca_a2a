# CA-A2A Complete CloudShell Deployment Guide

**Version:** 5.1.0  
**Date:** January 25, 2026  
**Author:** Jaafar Benabderrazak

---

## 📋 Overview

This guide provides step-by-step instructions for deploying the complete CA-A2A multi-agent system with all security features from the `a2a_security_architecture.md` document.

### Security Features Implemented

✅ **9-Layer Defense-in-Depth Architecture:**
1. **Layer 1:** Network Isolation (VPC, Security Groups, NACLs)
2. **Layer 2:** Identity & Access (Keycloak OAuth2/OIDC)
3. **Layer 3:** Authentication (JWT RS256 Signature Verification)
4. **Layer 4:** Authorization (RBAC with Keycloak Roles)
5. **Layer 5:** Resource Access Control (MCP Server Gateway)
6. **Layer 6:** Message Integrity (JWT Body Hash Binding)
7. **Layer 7:** Input Validation (JSON Schema, Pydantic Models)
8. **Layer 8:** Replay Protection (JWT jti Nonce Tracking)
9. **Layer 9:** Rate Limiting (Sliding Window Per Principal)

✅ **Additional Security Features:**
- Token Revocation with hybrid storage (PostgreSQL + in-memory cache)
- Network isolation (Private VPC, no public IPs on agents)
- Encryption at rest & in transit (AES-256, TLS)
- Comprehensive audit logging (CloudWatch)
- Least-privilege IAM roles
- VPC Endpoints for private AWS service access
- Security group egress hardening

---

## 🚀 Quick Start (5 Minutes to Deploy)

### Prerequisites

- AWS Account with admin access
- AWS CloudShell access (or local terminal with AWS CLI)
- Git installed

### One-Command Deployment

```bash
# 1. Clone the repository
git clone <your-repo-url>
cd ca_a2a

# 2. Make script executable
chmod +x cloudshell-complete-deploy.sh

# 3. Run the deployment
./cloudshell-complete-deploy.sh
```

### What Gets Deployed

The script automatically deploys:

**Infrastructure (Phase 1-9):**
- VPC with public/private subnets (Multi-AZ)
- NAT Gateway
- Security Groups (least-privilege)
- VPC Endpoints (ECR, S3, Logs, Secrets Manager)
- Application Load Balancer
- RDS Aurora PostgreSQL cluster
- RDS PostgreSQL for Keycloak
- S3 bucket with encryption
- CloudWatch Logs
- Service Discovery

**Security (Throughout):**
- RSA-2048 JWT keys
- Client API keys
- Database passwords
- All secrets in AWS Secrets Manager
- KMS encryption

**Preparation for Phase 10-12:**
- IAM roles
- ECR repositories
- ECS cluster
- Database schema files

---

## 📖 Detailed Step-by-Step Guide

### Phase 1: Infrastructure Deployment

```bash
# Run the complete deployment script
./cloudshell-complete-deploy.sh
```

**Expected Output:**
```
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   CA-A2A Multi-Agent System - Complete Deployment                    ║
║   Version 5.1.0 - Full Security Implementation                       ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝

[INFO] Configuration loaded:
  • Project: ca-a2a
  • Region: eu-west-3
  • Environment: prod
  • Deployment Date: 20260125-143022

...
```

**Duration:** ~15-20 minutes (most time spent waiting for RDS)

**What to Save:**
- Client API Key (displayed at end)
- Configuration file location
- ALB DNS name

### Phase 2: Source Configuration

After deployment completes, source the configuration:

```bash
# Source the configuration
source /tmp/ca-a2a-deployment-config.env

# Verify configuration
echo "VPC ID: $VPC_ID"
echo "ALB DNS: $ALB_DNS"
echo "S3 Bucket: $S3_BUCKET"
```

### Phase 3: Build and Push Docker Images

Since CloudShell doesn't have Docker, we'll use AWS CodeBuild or a local machine:

#### Option A: Using Local Machine (Recommended)

```bash
# 1. Clone repo on local machine
git clone <your-repo-url>
cd ca_a2a

# 2. Login to ECR
aws ecr get-login-password --region eu-west-3 | \
  docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.eu-west-3.amazonaws.com

# 3. Build and push all images
for service in orchestrator extractor validator archivist mcp-server; do
  echo "Building ${service}..."
  docker build -f Dockerfile.${service} -t ca-a2a/${service}:latest .
  docker tag ca-a2a/${service}:latest ${AWS_ACCOUNT_ID}.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/${service}:latest
  docker push ${AWS_ACCOUNT_ID}.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/${service}:latest
done

# 4. Build Keycloak (official image with customizations)
docker pull quay.io/keycloak/keycloak:23.0
docker tag quay.io/keycloak/keycloak:23.0 ${AWS_ACCOUNT_ID}.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/keycloak:latest
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/keycloak:latest
```

#### Option B: Using AWS CodeBuild

```bash
# Create buildspec.yml
cat > buildspec.yml <<'EOF'
version: 0.2
phases:
  pre_build:
    commands:
      - echo Logging in to Amazon ECR...
      - aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
  build:
    commands:
      - echo Building Docker images...
      - for service in orchestrator extractor validator archivist mcp-server; do
          docker build -f Dockerfile.$service -t ca-a2a/$service:latest .;
          docker tag ca-a2a/$service:latest $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/ca-a2a/$service:latest;
        done
  post_build:
    commands:
      - echo Pushing Docker images...
      - for service in orchestrator extractor validator archivist mcp-server; do
          docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/ca-a2a/$service:latest;
        done
EOF

# Create and run CodeBuild project (commands in CloudShell)
# ... (CodeBuild setup commands)
```

### Phase 4: Register ECS Task Definitions

```bash
# Update task definitions with correct values
cd task-definitions

# For each task definition, update:
# - executionRoleArn
# - taskRoleArn
# - image URIs
# - secrets ARNs

# Register task definitions
for service in orchestrator extractor validator archivist keycloak mcp-server; do
  echo "Registering ${service} task definition..."
  aws ecs register-task-definition \
    --cli-input-json file://${service}-task.json \
    --region eu-west-3
done
```

### Phase 5: Create ECS Services

#### Deploy MCP Server First (Required Dependency)

```bash
# Get service discovery service ID for MCP
MCP_SD_ID=$(aws servicediscovery list-services \
  --region eu-west-3 \
  --query "Services[?Name=='mcp-server'].Id | [0]" \
  --output text)

MCP_SD_ARN=$(aws servicediscovery get-service \
  --id $MCP_SD_ID \
  --region eu-west-3 \
  --query 'Service.Arn' \
  --output text)

# Create MCP Server service
aws ecs create-service \
  --cluster ca-a2a-cluster \
  --service-name mcp-server \
  --task-definition ca-a2a-mcp-server \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={
    subnets=[$PRIVATE_SUBNET_1,$PRIVATE_SUBNET_2],
    securityGroups=[$MCP_SERVER_SG],
    assignPublicIp=DISABLED
  }" \
  --service-registries "[{
    \"registryArn\": \"$MCP_SD_ARN\"
  }]" \
  --enable-execute-command \
  --region eu-west-3

# Wait for MCP Server to be healthy
aws ecs wait services-stable \
  --cluster ca-a2a-cluster \
  --services mcp-server \
  --region eu-west-3
```

#### Deploy Keycloak

```bash
# Similar process for Keycloak
KEYCLOAK_SD_ID=$(aws servicediscovery list-services \
  --region eu-west-3 \
  --query "Services[?Name=='keycloak'].Id | [0]" \
  --output text)

KEYCLOAK_SD_ARN=$(aws servicediscovery get-service \
  --id $KEYCLOAK_SD_ID \
  --region eu-west-3 \
  --query 'Service.Arn' \
  --output text)

aws ecs create-service \
  --cluster ca-a2a-cluster \
  --service-name keycloak \
  --task-definition ca-a2a-keycloak \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={
    subnets=[$PRIVATE_SUBNET_1,$PRIVATE_SUBNET_2],
    securityGroups=[$KEYCLOAK_SG],
    assignPublicIp=DISABLED
  }" \
  --service-registries "[{
    \"registryArn\": \"$KEYCLOAK_SD_ARN\"
  }]" \
  --enable-execute-command \
  --region eu-west-3

aws ecs wait services-stable \
  --cluster ca-a2a-cluster \
  --services keycloak \
  --region eu-west-3
```

#### Deploy Agent Services

```bash
# Deploy Orchestrator (connected to ALB)
aws ecs create-service \
  --cluster ca-a2a-cluster \
  --service-name orchestrator \
  --task-definition ca-a2a-orchestrator \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={
    subnets=[$PRIVATE_SUBNET_1,$PRIVATE_SUBNET_2],
    securityGroups=[$ORCHESTRATOR_SG],
    assignPublicIp=DISABLED
  }" \
  --load-balancers "[{
    \"targetGroupArn\": \"$TG_ARN\",
    \"containerName\": \"orchestrator\",
    \"containerPort\": 8001
  }]" \
  --enable-execute-command \
  --region eu-west-3

# Deploy other agents (extractor, validator, archivist)
for service in extractor validator archivist; do
  SG_VAR="${service^^}_SG"
  SD_ID=$(aws servicediscovery list-services \
    --region eu-west-3 \
    --query "Services[?Name=='$service'].Id | [0]" \
    --output text)
  
  SD_ARN=$(aws servicediscovery get-service \
    --id $SD_ID \
    --region eu-west-3 \
    --query 'Service.Arn' \
    --output text)
  
  aws ecs create-service \
    --cluster ca-a2a-cluster \
    --service-name $service \
    --task-definition ca-a2a-$service \
    --desired-count 2 \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={
      subnets=[$PRIVATE_SUBNET_1,$PRIVATE_SUBNET_2],
      securityGroups=[${!SG_VAR}],
      assignPublicIp=DISABLED
    }" \
    --service-registries "[{
      \"registryArn\": \"$SD_ARN\"
    }]" \
    --enable-execute-command \
    --region eu-west-3
done

# Wait for all services to be stable
aws ecs wait services-stable \
  --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist \
  --region eu-west-3
```

### Phase 6: Initialize Database Schema

```bash
# Option 1: Using ECS Exec (from CloudShell)
# Get a running task ID for MCP server
TASK_ARN=$(aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service-name mcp-server \
  --region eu-west-3 \
  --query 'taskArns[0]' \
  --output text)

# Execute schema initialization
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task ${TASK_ARN} \
  --container mcp-server \
  --interactive \
  --command "/bin/bash" \
  --region eu-west-3

# Inside the container, run:
# psql -h $RDS_ENDPOINT -U postgres -d documents -f /tmp/init_schema.sql
```

```bash
# Option 2: Using Python script from S3
# Download the schema from S3 and apply it
aws s3 cp s3://${S3_BUCKET}/migrations/init_documents_db.sql /tmp/
# Apply using psql from a bastion or ECS Exec
```

### Phase 7: Configure Keycloak

```bash
# Run Keycloak configuration script
./configure-keycloak.sh
```

**This script will:**
1. Create realm `ca-a2a`
2. Create client `ca-a2a-agents`
3. Create roles: admin, lambda, orchestrator, document-processor, viewer
4. Configure JWT settings (RS256, 5-minute TTL)
5. Export realm configuration

### Phase 8: Test the Deployment

```bash
# 1. Test health endpoint (no auth required)
curl http://${ALB_DNS}/health

# Expected response:
# {"status":"healthy","agent":"orchestrator","timestamp":"2026-01-25T14:30:00Z"}

# 2. Get agent card
curl http://${ALB_DNS}/card

# 3. Test with API key (if A2A auth enabled)
curl -X POST http://${ALB_DNS}/message \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${A2A_CLIENT_API_KEY}" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {"limit": 10},
    "id": 1
  }'

# 4. Test with Keycloak JWT
# First, get a token from Keycloak
KEYCLOAK_TOKEN=$(curl -X POST \
  http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=ca-a2a-agents" \
  -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
  -d "grant_type=client_credentials" \
  -d "scope=openid" \
  | jq -r '.access_token')

# Use the token
curl -X POST http://${ALB_DNS}/message \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${KEYCLOAK_TOKEN}" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {
      "s3_key": "uploads/test.pdf",
      "document_type": "invoice"
    },
    "id": 2
  }'
```

---

## 🔒 Security Verification Checklist

### Layer 1: Network Isolation

```bash
# Verify no public IPs on agents
aws ecs describe-tasks \
  --cluster ca-a2a-cluster \
  --tasks $(aws ecs list-tasks --cluster ca-a2a-cluster --region eu-west-3 --query 'taskArns' --output text) \
  --region eu-west-3 \
  --query 'tasks[*].attachments[0].details[?name==`networkInterfaceId`].value' \
  --output text | xargs -I {} aws ec2 describe-network-interfaces --network-interface-ids {} --query 'NetworkInterfaces[*].Association.PublicIp' --output text

# Expected: None or empty (no public IPs)
```

```bash
# Verify security group rules
aws ec2 describe-security-groups \
  --group-ids $ORCHESTRATOR_SG \
  --region eu-west-3 \
  --query 'SecurityGroups[0].IpPermissions'
```

### Layer 2-3: Keycloak Authentication

```bash
# Verify Keycloak is accessible internally
TASK_ARN=$(aws ecs list-tasks --cluster ca-a2a-cluster --service-name orchestrator --region eu-west-3 --query 'taskArns[0]' --output text)

aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task ${TASK_ARN} \
  --container orchestrator \
  --interactive \
  --command "curl http://keycloak.ca-a2a.local:8080/realms/ca-a2a/.well-known/openid-configuration" \
  --region eu-west-3
```

### Layer 5: MCP Server Gateway

```bash
# Verify MCP Server is accessible
# Check service discovery
aws servicediscovery list-instances \
  --service-id $(aws servicediscovery list-services --region eu-west-3 --query "Services[?Name=='mcp-server'].Id | [0]" --output text) \
  --region eu-west-3

# Test from orchestrator
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task ${TASK_ARN} \
  --container orchestrator \
  --interactive \
  --command "curl http://mcp-server.ca-a2a.local:8000/health" \
  --region eu-west-3
```

### Layer 8: Token Revocation

```bash
# Verify revoked_tokens table exists
# (Use ECS Exec to connect to database)
psql -h $RDS_ENDPOINT -U postgres -d documents -c "\dt revoked_tokens"
```

### Layer 9: Rate Limiting

```bash
# Test rate limiting (send 350 requests)
for i in {1..350}; do
  curl -X POST http://${ALB_DNS}/message \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${KEYCLOAK_TOKEN}" \
    -d '{"jsonrpc":"2.0","method":"list_pending_documents","params":{},"id":'$i'}' &
done

# Expected: First 300 succeed, rest return 429 Too Many Requests
```

---

## 📊 Monitoring & Observability

### CloudWatch Logs

```bash
# View orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3

# View MCP server logs
aws logs tail /ecs/ca-a2a-mcp-server --follow --region eu-west-3

# Search for authentication failures
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "authentication_failure" \
  --start-time $(date -d '1 hour ago' +%s)000 \
  --region eu-west-3
```

### ECS Service Status

```bash
# Check all services
aws ecs describe-services \
  --cluster ca-a2a-cluster \
  --services orchestrator extractor validator archivist keycloak mcp-server \
  --region eu-west-3 \
  --query 'services[*].[serviceName,status,runningCount,desiredCount]' \
  --output table
```

### Database Monitoring

```bash
# Check RDS metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/RDS \
  --metric-name DatabaseConnections \
  --dimensions Name=DBClusterIdentifier,Value=ca-a2a-documents-db \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Average \
  --region eu-west-3
```

---

## 🔧 Troubleshooting

### Issue: ECS Tasks Not Starting

```bash
# Check task definition
aws ecs describe-task-definition \
  --task-definition ca-a2a-orchestrator \
  --region eu-west-3

# Check stopped tasks for errors
aws ecs describe-tasks \
  --cluster ca-a2a-cluster \
  --tasks $(aws ecs list-tasks --cluster ca-a2a-cluster --desired-status STOPPED --region eu-west-3 --query 'taskArns[0]' --output text) \
  --region eu-west-3 \
  --query 'tasks[0].stoppedReason'
```

### Issue: ALB Returns 503

```bash
# Check target health
aws elbv2 describe-target-health \
  --target-group-arn $TG_ARN \
  --region eu-west-3

# Check orchestrator logs
aws logs tail /ecs/ca-a2a-orchestrator --since 10m --region eu-west-3
```

### Issue: MCP Server Unreachable

```bash
# Check service discovery instances
aws servicediscovery list-instances \
  --service-id $(aws servicediscovery list-services --region eu-west-3 --query "Services[?Name=='mcp-server'].Id | [0]" --output text) \
  --region eu-west-3

# Check MCP server logs
aws logs tail /ecs/ca-a2a-mcp-server --since 10m --region eu-west-3
```

---

## 🗑️ Cleanup

To delete the entire deployment:

```bash
# Delete ECS services
for service in orchestrator extractor validator archivist keycloak mcp-server; do
  aws ecs update-service \
    --cluster ca-a2a-cluster \
    --service $service \
    --desired-count 0 \
    --region eu-west-3
  
  aws ecs delete-service \
    --cluster ca-a2a-cluster \
    --service $service \
    --force \
    --region eu-west-3
done

# Delete RDS instances and clusters
aws rds delete-db-instance \
  --db-instance-identifier ca-a2a-documents-db-instance-1 \
  --skip-final-snapshot \
  --region eu-west-3

aws rds delete-db-cluster \
  --db-cluster-identifier ca-a2a-documents-db \
  --skip-final-snapshot \
  --region eu-west-3

aws rds delete-db-instance \
  --db-instance-identifier ca-a2a-keycloak-db \
  --skip-final-snapshot \
  --region eu-west-3

# Delete S3 bucket (after emptying)
aws s3 rm s3://${S3_BUCKET} --recursive --region eu-west-3
aws s3 rb s3://${S3_BUCKET} --region eu-west-3

# Delete VPC (will cascade delete subnets, route tables, etc.)
# ... (additional cleanup commands)
```

---

## 📚 References

- [CA-A2A Security Architecture](./a2a_security_architecture.md)
- [MCP Server Implementation Guide](./MCP_SERVER_IMPLEMENTATION_GUIDE.md)
- [Keycloak Integration Guide](./KEYCLOAK_INTEGRATION_GUIDE.md)
- [API Testing Guide](./API_TESTING_GUIDE.md)

---

## 📞 Support

For issues or questions:
- Check troubleshooting section above
- Review CloudWatch logs
- Check security group rules
- Verify IAM permissions

---

**Document Version:** 1.0  
**Last Updated:** January 25, 2026  
**Author:** Jaafar Benabderrazak

