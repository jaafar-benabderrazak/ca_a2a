# 🏗️ AWS Architecture - CA-A2A Document Processing Pipeline

**Version:** 1.0  
**Last Updated:** December 18, 2025  
**AWS Account:** 555043101106  
**Region:** eu-west-3 (Paris)

---

## 📐 Architecture Overview

### High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          Internet                                 │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             │ HTTPS/HTTP
                             ▼
┌────────────────────────────────────────────────────────────────────┐
│                    Application Load Balancer                        │
│                                                                     │
│  • Type: internet-facing                                           │
│  • Listener: Port 80 (HTTP)                                        │
│  • Health Check: /health every 30s                                 │
│  • Security Group: sg-05db73131090f365a                            │
└────────────────────────────┬───────────────────────────────────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
                ▼                         ▼
┌──────────────────────┐      ┌──────────────────────┐
│  Availability Zone 1 │      │  Availability Zone 2 │
│                      │      │                      │
│  Private Subnet      │      │  Private Subnet      │
│  10.0.10.0/24        │      │  10.0.20.0/24        │
└──────────────────────┘      └──────────────────────┘
         │                              │
         └──────────────┬───────────────┘
                        │
        ┌───────────────┴───────────────┐
        │                               │
        ▼                               ▼
┌────────────────┐              ┌────────────────┐
│  ECS Cluster   │              │  ECS Cluster   │
│  ca-a2a-cluster│              │  ca-a2a-cluster│
│                │              │                │
│  ┌──────────┐  │              │  ┌──────────┐  │
│  │Orchestr. │  │              │  │Orchestr. │  │
│  │  Task    │  │              │  │  Task    │  │
│  └──────────┘  │              │  └──────────┘  │
│  ┌──────────┐  │              │  ┌──────────┐  │
│  │Extractor │  │              │  │Extractor │  │
│  │  Task    │  │              │  │  Task    │  │
│  └──────────┘  │              │  └──────────┘  │
│  ┌──────────┐  │              │  ┌──────────┐  │
│  │Validator │  │              │  │Validator │  │
│  │  Task    │  │              │  │  Task    │  │
│  └──────────┘  │              │  └──────────┘  │
│  ┌──────────┐  │              │  ┌──────────┐  │
│  │Archivist │  │              │  │Archivist │  │
│  │  Task    │  │              │  │  Task    │  │
│  └──────────┘  │              │  └──────────┘  │
└────────┬───────┘              └────────┬───────┘
         │                               │
         └───────────────┬───────────────┘
                         │
          ┌──────────────┴──────────────┐
          │                             │
          ▼                             ▼
┌──────────────────┐           ┌──────────────────┐
│  Amazon S3       │           │  Amazon RDS      │
│                  │           │                  │
│  Bucket:         │           │  Engine: Postgres│
│  ca-a2a-docs-... │           │  Instance: t3.m  │
│                  │           │  Multi-AZ: No    │
│  Structure:      │           │  Storage: 20 GB  │
│  - incoming/     │           │  Database:       │
│  - processing/   │           │   documents_db   │
│  - processed/    │           │                  │
│  - failed/       │           │  Tables:         │
└──────────────────┘           │  - documents     │
                               │  - proc_logs     │
                               └──────────────────┘
```

---

## 🧩 Component Details

### 1. Network Layer

#### VPC Configuration
```yaml
VPC ID: vpc-086392a3eed899f72
CIDR Block: 10.0.0.0/16
DNS Hostnames: Enabled
DNS Resolution: Enabled
```

#### Subnets
| Name | Type | AZ | CIDR | Purpose |
|------|------|-------|------|---------|
| Private Subnet 1 | Private | eu-west-3a | 10.0.10.0/24 | ECS Tasks |
| Private Subnet 2 | Private | eu-west-3b | 10.0.20.0/24 | ECS Tasks |
| RDS Subnet 1 | Private | eu-west-3a | 10.0.30.0/24 | Database |
| RDS Subnet 2 | Private | eu-west-3b | 10.0.40.0/24 | Database |

#### Security Groups

**ALB Security Group (sg-05db73131090f365a)**
```yaml
Inbound Rules:
  - Port 80 (HTTP)
    Source: 0.0.0.0/0
    Purpose: Public web access
  - Port 443 (HTTPS)
    Source: 0.0.0.0/0
    Purpose: Secure web access

Outbound Rules:
  - All traffic
    Destination: 0.0.0.0/0
```

**ECS Security Group (sg-047a8f39f9cdcaf4c)**
```yaml
Inbound Rules:
  - Port 8001-8004
    Source: ALB Security Group
    Purpose: ALB to ECS tasks
  - Port 8001-8004
    Source: Self
    Purpose: Inter-agent communication

Outbound Rules:
  - Port 443 (HTTPS)
    Destination: 0.0.0.0/0
    Purpose: AWS API calls, ECR pulls
  - Port 5432 (PostgreSQL)
    Destination: RDS Security Group
    Purpose: Database access
```

**RDS Security Group (sg-0dfffbf7f98f77a4c)**
```yaml
Inbound Rules:
  - Port 5432 (PostgreSQL)
    Source: ECS Security Group
    Purpose: Allow ECS tasks to connect

Outbound Rules:
  - All traffic
    Destination: 0.0.0.0/0
```

#### VPC Endpoints
| Service | Type | Endpoint ID | Purpose |
|---------|------|-------------|---------|
| S3 | Gateway | vpce-xxx | S3 access without internet |
| ECR API | Interface | vpce-yyy | Pull Docker images |
| ECR DKR | Interface | vpce-zzz | Docker image layers |
| Secrets Manager | Interface | vpce-aaa | Retrieve secrets |
| CloudWatch Logs | Interface | vpce-bbb | Send logs |

---

### 2. Compute Layer (ECS)

#### ECS Cluster
```yaml
Name: ca-a2a-cluster
Launch Type: FARGATE
Services: 4
Tasks: 8 (2 per service)
```

#### Service Definitions

**Orchestrator Service**
```yaml
Name: orchestrator
Task Definition: ca-a2a-orchestrator:6
Desired Count: 2
Launch Type: FARGATE
CPU: 512 (0.5 vCPU)
Memory: 1024 MB (1 GB)
Port: 8001
Load Balancer: Attached to ALB
Health Check:
  Path: /health
  Interval: 30s
  Timeout: 5s
  Healthy Threshold: 2
  Unhealthy Threshold: 3
Environment Variables:
  - POSTGRES_HOST
  - POSTGRES_PORT
  - POSTGRES_DB
  - S3_BUCKET
  - AWS_REGION
Secrets:
  - POSTGRES_PASSWORD (from Secrets Manager)
```

**Extractor Service**
```yaml
Name: extractor
Task Definition: ca-a2a-extractor:latest
Desired Count: 2
CPU: 512
Memory: 1024 MB
Port: 8002
Load Balancer: None (internal)
```

**Validator Service**
```yaml
Name: validator
Task Definition: ca-a2a-validator:latest
Desired Count: 2
CPU: 512
Memory: 1024 MB
Port: 8003
Load Balancer: None (internal)
```

**Archivist Service**
```yaml
Name: archivist
Task Definition: ca-a2a-archivist:latest
Desired Count: 2
CPU: 512
Memory: 1024 MB
Port: 8004
Load Balancer: None (internal)
```

#### IAM Roles

**ECS Task Execution Role (ca-a2a-ecs-execution-role)**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "*"
    }
  ]
}
```

**ECS Task Role (ca-a2a-ecs-task-role)**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::ca-a2a-documents-555043101106/*",
        "arn:aws:s3:::ca-a2a-documents-555043101106"
      ]
    }
  ]
}
```

---

### 3. Storage Layer

#### Amazon S3
```yaml
Bucket Name: ca-a2a-documents-555043101106
Region: eu-west-3
Versioning: Disabled
Encryption: AES-256 (SSE-S3)
Public Access: Blocked

Folder Structure:
  /incoming/         # New documents
  /processing/       # Currently being processed
  /processed/        # Successfully processed
    /invoices/
    /contracts/
    /reports/
  /failed/           # Processing failed

Lifecycle Policies:
  - Move to Glacier after 90 days
  - Delete from Glacier after 365 days
```

#### Amazon RDS (PostgreSQL)
```yaml
Identifier: ca-a2a-postgres
Engine: postgres
Version: 15.7
Instance Class: db.t3.micro
  vCPU: 2
  RAM: 1 GB
Storage: 20 GB gp2
Multi-AZ: false
Backup Retention: 7 days
Automated Backups: Enabled
Encryption at Rest: Enabled
Encryption in Transit: Required (SSL)
Port: 5432
Endpoint: ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com

Database: documents_db
Tables:
  - documents (id, filename, s3_key, file_type, status, extracted_data, ...)
  - processing_logs (id, document_id, agent_name, operation, status, ...)

Indexes:
  - idx_documents_status
  - idx_documents_created_at
  - idx_processing_logs_document_id
  - idx_processing_logs_timestamp
```

---

### 4. Load Balancing

#### Application Load Balancer
```yaml
Name: ca-a2a-alb
Type: application
Scheme: internet-facing
IP Address Type: ipv4
DNS Name: ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com
VPC: vpc-086392a3eed899f72
Availability Zones:
  - eu-west-3a
  - eu-west-3b
Security Group: sg-05db73131090f365a

Listeners:
  - Protocol: HTTP
    Port: 80
    Default Action: Forward to ca-a2a-orch-tg

Target Groups:
  - Name: ca-a2a-orch-tg
    Protocol: HTTP
    Port: 8001
    Target Type: ip
    Health Check:
      Protocol: HTTP
      Path: /health
      Interval: 30s
      Timeout: 5s
      Healthy Threshold: 2
      Unhealthy Threshold: 3
    Targets: 2 (both healthy)
```

---

### 5. Monitoring & Logging

#### CloudWatch Log Groups
```yaml
/ecs/ca-a2a-orchestrator
  Retention: 7 days
  Size: ~10 MB/day
  
/ecs/ca-a2a-extractor
  Retention: 7 days
  Size: ~20 MB/day
  
/ecs/ca-a2a-validator
  Retention: 7 days
  Size: ~15 MB/day
  
/ecs/ca-a2a-archivist
  Retention: 7 days
  Size: ~10 MB/day
```

#### CloudWatch Metrics
- ECS CPU/Memory utilization
- ALB Request count, latency, HTTP codes
- RDS CPU, connections, storage
- S3 bucket size, request metrics

---

## 💰 Cost Breakdown

### Monthly Cost Estimate (eu-west-3)

| Service | Configuration | Monthly Cost |
|---------|---------------|--------------|
| **ECS Fargate** | 8 tasks × 0.5 vCPU × 1 GB | $40.00 |
| **RDS PostgreSQL** | db.t3.micro, 20 GB | $15.00 |
| **Application Load Balancer** | 1 ALB | $16.00 |
| **S3 Storage** | <1 GB | $0.50 |
| **Data Transfer** | ~5 GB/month | $0.45 |
| **CloudWatch Logs** | 1 GB/month | $0.50 |
| **VPC Endpoints** | 5 endpoints | $7.50 |
| **Secrets Manager** | 1 secret | $0.40 |
| **NAT Gateway** | 0 (using VPC endpoints) | $0.00 |
| **Total** | | **~$80.35/month** |

### Cost Optimization Options
1. Reduce tasks from 2→1 per service: Save ~$20/month
2. Use Fargate Spot: Save ~40% on compute
3. Move to RDS Serverless: Save ~$5/month
4. Implement S3 Intelligent-Tiering: Save on storage

---

## 🔒 Security Features

### Network Security
✅ Private subnets for all compute (no public IPs)  
✅ VPC endpoints for AWS service access  
✅ Security groups with principle of least privilege  
✅ Network ACLs for subnet-level control  

### Data Security
✅ SSL/TLS for all data in transit  
✅ RDS encryption at rest  
✅ S3 bucket encryption (SSE-S3)  
✅ Secrets Manager for password management  

### Access Control
✅ IAM roles with minimal permissions  
✅ Resource-based policies  
✅ No hard-coded credentials  
✅ SSO for human access  

### Monitoring
✅ CloudWatch Logs for all services  
✅ CloudTrail for API auditing  
✅ VPC Flow Logs for network monitoring  

### Application Security (A2A hardening)

- **External client authentication**: `X-API-Key`
- **Agent-to-agent authentication**: short-lived **JWT Bearer** (request-bound)
- **Authorization (RBAC)**: method allow-list by principal (`A2A_RBAC_POLICY_JSON`)
- **Replay protection**: JWT `jti` nonce cache
- **Rate limiting**: per-principal controls on `/message`
- **Payload size limits**: aiohttp `client_max_size`
- **Capability disclosure minimization**: `/card` and `/skills` can be RBAC-filtered

Related docs:
- `SECURITY.md`
- `DEMO_SECURITY_EVIDENCE.md`

---

## 📊 Scalability & High Availability

### Current Setup
- **Availability:** Multi-AZ deployment (2 AZs)
- **Redundancy:** 2 tasks per service
- **Auto-recovery:** ECS restarts failed tasks automatically
- **Load Distribution:** ALB distributes traffic across tasks

### Scaling Options

#### Horizontal Scaling (Add more tasks)
```bash
# Scale orchestrator to 4 tasks
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --desired-count 4 \
  --region eu-west-3
```

#### Vertical Scaling (Increase task resources)
```yaml
# Update task definition
CPU: 1024 (1 vCPU)
Memory: 2048 MB (2 GB)
```

#### Auto Scaling
```yaml
Target Tracking Scaling:
  Metric: ECSServiceAverageCPUUtilization
  Target Value: 70%
  Scale Out Cooldown: 300s
  Scale In Cooldown: 300s
  Min Capacity: 2
  Max Capacity: 10
```

---

## 🔄 Disaster Recovery

### Backup Strategy
- **RDS:** Automated daily snapshots, 7-day retention
- **S3:** Versioning disabled, lifecycle policies enabled
- **ECS:** Task definitions versioned in ECR

### Recovery Procedures

**RDS Failure:**
```bash
# Restore from latest snapshot
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier ca-a2a-postgres-restored \
  --db-snapshot-identifier <snapshot-id> \
  --region eu-west-3
```

**Service Failure:**
```bash
# Force new deployment
aws ecs update-service \
  --cluster ca-a2a-cluster \
  --service orchestrator \
  --force-new-deployment \
  --region eu-west-3
```

### RTO/RPO
- **Recovery Time Objective (RTO):** 15 minutes
- **Recovery Point Objective (RPO):** 24 hours

---

## 📞 Contact & Support

- **AWS Account:** 555043101106
- **Region:** eu-west-3 (Paris)
- **Project:** CA-A2A
- **Deployed By:** j.benabderrazak@reply.com
- **Last Updated:** December 18, 2025

---

## 📚 Related Documentation

- [End-to-End Demo Guide](./END_TO_END_DEMO.md)
- [Scenario Flows](./SCENARIO_FLOWS.md)
- [API Documentation](./API_TESTING_GUIDE.md)
- [Troubleshooting Guide](./TROUBLESHOOTING.md)

