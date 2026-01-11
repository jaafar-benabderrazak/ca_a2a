# CA-A2A System Architecture & Network Documentation

**Document Version:** 1.0 
**Last Updated:** December 18, 2025 
**Region:** eu-west-3 (Paris)

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Network Architecture](#network-architecture)
3. [Component Details](#component-details)
4. [Protocol Stack](#protocol-stack)
5. [Data Flow](#data-flow)
6. [Security Architecture](#security-architecture)

---

## 1. System Overview

The CA-A2A (Credit Agricole Agent-to-Agent) system is an intelligent document processing pipeline built on AWS using a multi-agent architecture with the A2A protocol.

### High-Level Architecture

```mermaid
graph TB
 subgraph Internet
 Client[Client/User]
 end
 
 subgraph AWS["AWS Cloud - eu-west-3"]
 subgraph VPC["VPC: vpc-086392a3eed899f72<br/>CIDR: 10.0.0.0/16"]
 subgraph Public["Public Subnets"]
 ALB["Application Load Balancer<br/>ca-a2a-alb<br/>DNS: ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"]
 IGW["Internet Gateway<br/>igw-052f22bed7f171258"]
 end
 
 subgraph Private["Private Subnets"]
 subgraph ECS["ECS Cluster: ca-a2a-cluster"]
 Orch["Orchestrator<br/>Port: 8001<br/>Tasks: 2"]
 Ext["Extractor<br/>Port: 8002<br/>Tasks: 2"]
 Val["Validator<br/>Port: 8003<br/>Tasks: 2"]
 Arch["Archivist<br/>Port: 8004<br/>Tasks: 2"]
 end
 
 RDS["RDS PostgreSQL<br/>ca-a2a-postgres<br/>Endpoint: ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com<br/>Port: 5432"]
 end
 
 VPCEndpoints["VPC Endpoints<br/>- Secrets Manager<br/>- ECR (API & DKR)<br/>- CloudWatch Logs<br/>- S3"]
 end
 
 S3["S3 Bucket<br/>ca-a2a-documents-555043101106"]
 Secrets["Secrets Manager<br/>ca-a2a/db-password"]
 ECR["ECR Repositories<br/>- ca-a2a/orchestrator<br/>- ca-a2a/extractor<br/>- ca-a2a/validator<br/>- ca-a2a/archivist"]
 CW["CloudWatch Logs<br/>/ecs/ca-a2a-*"]
 end
 
 Client -->|HTTPS/HTTP| ALB
 IGW -.->|Route| ALB
 ALB -->|Target Group| Orch
 Orch <-->|A2A Protocol| Ext
 Orch <-->|A2A Protocol| Val
 Orch <-->|A2A Protocol| Arch
 
 Orch <-->|MCP: PostgreSQL| RDS
 Ext <-->|MCP: PostgreSQL| RDS
 Val <-->|MCP: PostgreSQL| RDS
 Arch <-->|MCP: PostgreSQL| RDS
 
 Ext <-->|MCP: S3| S3
 Arch <-->|MCP: S3| S3
 
 ECS -.->|Private Link| VPCEndpoints
 VPCEndpoints -.-> S3
 VPCEndpoints -.-> Secrets
 VPCEndpoints -.-> ECR
 VPCEndpoints -.-> CW
```

---

## 2. Network Architecture

### 2.1 VPC Configuration

**VPC Details:**
- **VPC ID:** `vpc-086392a3eed899f72`
- **CIDR Block:** `10.0.0.0/16`
- **Region:** `eu-west-3` (Paris)
- **Availability Zones:** `eu-west-3a`, `eu-west-3b`

### 2.2 Subnet Layout

```mermaid
graph LR
 subgraph VPC["VPC: 10.0.0.0/16"]
 subgraph AZ1["eu-west-3a"]
 PubSub1["Public Subnet 1<br/>subnet-020c68e784c2c9354<br/>For ALB"]
 PrivSub1["Private Subnet 1<br/>subnet-07484aca0e473e3d0<br/>For ECS Tasks"]
 end
 
 subgraph AZ2["eu-west-3b"]
 PubSub2["Public Subnet 2<br/>subnet-0deca2d494c9ba33f<br/>For ALB"]
 PrivSub2["Private Subnet 2<br/>subnet-0aef6b4fcce7748a9<br/>For ECS Tasks"]
 end
 end
 
 IGW["Internet Gateway<br/>igw-052f22bed7f171258"]
 
 IGW -->|0.0.0.0/0| PubSub1
 IGW -->|0.0.0.0/0| PubSub2
```

### 2.3 Route Tables

**Main Route Table:** `rtb-0ec94e9c7c6ffbb24`

| Destination | Target | Purpose |
|-------------|--------|---------|
| `10.0.0.0/16` | `local` | VPC internal routing |
| `0.0.0.0/0` | `igw-052f22bed7f171258` | Internet access |

### 2.4 Security Groups

```mermaid
graph TB
 subgraph SG_ALB["ALB Security Group<br/>sg-05db73131090f365a"]
 direction TB
 ALB_IN_80["Inbound<br/>Port 80 (HTTP)<br/>0.0.0.0/0"]
 ALB_IN_443["Inbound<br/>Port 443 (HTTPS)<br/>0.0.0.0/0"]
 end
 
 subgraph SG_ECS["ECS Security Group<br/>sg-047a8f39f9cdcaf4c"]
 direction TB
 ECS_IN_8001["Inbound<br/>Port 8001<br/>From ALB SG"]
 ECS_IN_8002["Inbound<br/>Port 8002-8004<br/>Internal"]
 ECS_OUT_ALL["Outbound<br/>All traffic<br/>0.0.0.0/0"]
 end
 
 subgraph SG_RDS["RDS Security Group<br/>sg-0dfffbf7f98f77a4c"]
 direction TB
 RDS_IN_5432["Inbound<br/>Port 5432<br/>From ECS SG"]
 end
 
 SG_ALB -->|Port 8001| SG_ECS
 SG_ECS -->|Port 5432| SG_RDS
```

**Security Group Rules:**

| Security Group | Type | Protocol | Port | Source | Purpose |
|----------------|------|----------|------|--------|---------|
| `sg-05db73131090f365a` (ALB) | Inbound | TCP | 80 | `0.0.0.0/0` | HTTP from internet |
| `sg-05db73131090f365a` (ALB) | Inbound | TCP | 443 | `0.0.0.0/0` | HTTPS from internet |
| `sg-047a8f39f9cdcaf4c` (ECS) | Inbound | TCP | 8001 | ALB SG | Orchestrator from ALB |
| `sg-047a8f39f9cdcaf4c` (ECS) | Inbound | TCP | 8002-8004 | Self | Agent-to-agent |
| `sg-047a8f39f9cdcaf4c` (ECS) | Outbound | All | All | `0.0.0.0/0` | External access |
| `sg-0dfffbf7f98f77a4c` (RDS) | Inbound | TCP | 5432 | ECS SG | PostgreSQL from ECS |

---

## 3. Component Details

### 3.1 Application Load Balancer

**Configuration:**
- **Name:** `ca-a2a-alb`
- **ARN:** `arn:aws:elasticloadbalancing:eu-west-3:555043101106:loadbalancer/app/ca-a2a-alb/3c05d16b10706799`
- **DNS:** `ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com`
- **Scheme:** `internet-facing`
- **IP Type:** `ipv4`
- **IPs:** `13.37.61.78`, `13.38.253.92`

**Listener Configuration:**
- **Protocol:** HTTP
- **Port:** 80
- **Default Action:** Forward to target group

**Target Group:**
- **Name:** `ca-a2a-orch-tg`
- **ARN:** `arn:aws:elasticloadbalancing:eu-west-3:555043101106:targetgroup/ca-a2a-orch-tg/5bc795b288397779`
- **Protocol:** HTTP
- **Port:** 8001
- **Health Check Path:** `/health`
- **Health Check Interval:** 30 seconds
- **Healthy Threshold:** 2
- **Unhealthy Threshold:** 2
- **Timeout:** 5 seconds

**Current Targets:**
- `10.0.20.158:8001` - Healthy
- `10.0.10.75:8001` - Healthy

### 3.2 ECS Services

```mermaid
graph TB
 subgraph Cluster["ECS Cluster: ca-a2a-cluster"]
 subgraph Orchestrator["Orchestrator Service"]
 O1["Task 1<br/>IP: 10.0.20.158<br/>Port: 8001"]
 O2["Task 2<br/>IP: 10.0.10.75<br/>Port: 8001"]
 end
 
 subgraph Extractor["Extractor Service"]
 E1["Task 1<br/>Port: 8002"]
 E2["Task 2<br/>Port: 8002"]
 end
 
 subgraph Validator["Validator Service"]
 V1["Task 1<br/>Port: 8003"]
 V2["Task 2<br/>Port: 8003"]
 end
 
 subgraph Archivist["Archivist Service"]
 A1["Task 1<br/>Port: 8004"]
 A2["Task 2<br/>Port: 8004"]
 end
 end
 
 ALB["ALB"] -->|Health checks| O1
 ALB -->|Health checks| O2
 ALB -.->|Route traffic| O1
 ALB -.->|Route traffic| O2
```

**Service Details:**

| Service | Image | Port | Desired | Running | Task Definition |
|---------|-------|------|---------|---------|-----------------|
| orchestrator | `555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/orchestrator:latest` | 8001 | 2 | 2 | ca-a2a-orchestrator:6 |
| extractor | `555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/extractor:latest` | 8002 | 2 | 2 | ca-a2a-extractor:6 |
| validator | `555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/validator:latest` | 8003 | 2 | 2 | ca-a2a-validator:6 |
| archivist | `555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/archivist:latest` | 8004 | 2 | 2 | ca-a2a-archivist:6 |

**Task Configuration:**
- **Launch Type:** Fargate
- **Platform Version:** 1.4.0
- **CPU:** 256 (.25 vCPU)
- **Memory:** 512 MB
- **Network Mode:** `awsvpc`

### 3.3 RDS PostgreSQL

**Configuration:**
- **Identifier:** `ca-a2a-postgres`
- **Engine:** PostgreSQL 15.7
- **Instance Class:** `db.t3.micro`
- **Endpoint:** `ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com:5432`
- **Database:** `documents_db`
- **Multi-AZ:** No
- **Publicly Accessible:** No
- **Storage:** 20 GB (gp2)
- **Backup Retention:** 7 days
- **Encryption:** Enabled (at rest)
- **SSL/TLS:** Required

**Database Schema:**

```mermaid
erDiagram
 DOCUMENTS ||--o{ PROCESSING_LOGS : has
 
 DOCUMENTS {
 uuid id PK
 varchar filename
 varchar file_type
 varchar s3_key
 varchar status
 jsonb extracted_data
 jsonb validation_result
 varchar archived_s3_key
 timestamp created_at
 timestamp updated_at
 integer file_size
 }
 
 PROCESSING_LOGS {
 uuid id PK
 uuid document_id FK
 varchar agent_name
 varchar operation
 varchar status
 text message
 timestamp timestamp
 }
```

### 3.4 S3 Storage

**Bucket:** `ca-a2a-documents-555043101106`

**Folder Structure:**
```
ca-a2a-documents-555043101106/
├── incoming/ # Uploaded documents awaiting processing
├── processed/ # Successfully processed documents
├── archived/ # Long-term archived documents
└── failed/ # Failed processing attempts
```

**Bucket Policy:** Private (accessed via IAM roles)

---

## 4. Protocol Stack

### 4.1 Protocol Architecture

```mermaid
graph TB
 subgraph Client_Layer["Client Layer"]
 HTTP["HTTP/HTTPS<br/>REST API"]
 end
 
 subgraph Orchestrator_Layer["Orchestrator Layer"]
 A2A_Server["A2A Protocol Server<br/>JSON-RPC 2.0"]
 REST_Endpoints["REST Endpoints<br/>/health, /card, /status"]
 end
 
 subgraph Agent_Layer["Agent Layer"]
 A2A_Client["A2A Protocol Client<br/>JSON-RPC 2.0"]
 MCP["Model Context Protocol<br/>(MCP)"]
 end
 
 subgraph Resource_Layer["Resource Layer"]
 S3_API["S3 API<br/>boto3"]
 PG_API["PostgreSQL<br/>asyncpg"]
 end
 
 HTTP --> A2A_Server
 HTTP --> REST_Endpoints
 A2A_Server --> A2A_Client
 A2A_Client --> MCP
 MCP --> S3_API
 MCP --> PG_API
```

### 4.2 A2A Protocol (Agent-to-Agent)

**Based on:** JSON-RPC 2.0 Specification

**Endpoint:** `POST /message`

**Message Format:**

```json
{
 "jsonrpc": "2.0",
 "method": "method_name",
 "params": {
 "param1": "value1"
 },
 "id": 1
}
```

**Response Format:**

```json
{
 "jsonrpc": "2.0",
 "result": {
 "key": "value"
 },
 "id": 1,
 "_meta": {
 "correlation_id": "uuid"
 }
}
```

**Error Format:**

```json
{
 "jsonrpc": "2.0",
 "error": {
 "code": -32600,
 "message": "Error description",
 "data": {}
 },
 "id": 1
}
```

**Standard Error Codes:**
- `-32700`: Parse error
- `-32600`: Invalid request
- `-32601`: Method not found
- `-32602`: Invalid params
- `-32603`: Internal error

### 4.3 MCP (Model Context Protocol)

**Purpose:** Unified access to resources (S3, PostgreSQL)

**Features:**
- Connection pooling
- Retry logic with exponential backoff
- Circuit breaker pattern
- Timeout management
- SSL/TLS encryption

**S3 Resource Methods:**
- `get_object(key)` - Retrieve file from S3
- `put_object(key, data)` - Upload file to S3
- `list_objects(prefix, suffix)` - List files
- `delete_object(key)` - Delete file

**PostgreSQL Resource Methods:**
- `execute(query, *args)` - Execute INSERT/UPDATE/DELETE
- `fetch(query, *args)` - Fetch multiple rows
- `fetchrow(query, *args)` - Fetch single row
- `fetchval(query, *args)` - Fetch single value

---

## 5. Data Flow

### 5.1 Document Processing Pipeline

```mermaid
sequenceDiagram
 participant Client
 participant ALB
 participant Orchestrator
 participant Extractor
 participant Validator
 participant Archivist
 participant S3
 participant RDS
 
 Client->>S3: 1. Upload document to incoming/
 Client->>ALB: 2. POST /message<br/>{method: "process_document"}
 ALB->>Orchestrator: 3. Forward request<br/>Target: 10.0.20.158:8001
 
 Orchestrator->>RDS: 4. Create task record
 Orchestrator->>Client: 5. Return task_id
 
 par Async Processing
 Orchestrator->>Extractor: 6. A2A: extract_document
 Extractor->>S3: 7. Get document
 S3-->>Extractor: 8. Document content
 Extractor->>Extractor: 9. Extract data
 Extractor->>RDS: 10. Save extracted data
 Extractor-->>Orchestrator: 11. Extraction result
 
 Orchestrator->>Validator: 12. A2A: validate_document
 Validator->>Validator: 13. Validate data
 Validator->>RDS: 14. Save validation result
 Validator-->>Orchestrator: 15. Validation result
 
 Orchestrator->>Archivist: 16. A2A: archive_document
 Archivist->>S3: 17. Move to archived/
 Archivist->>RDS: 18. Update document status
 Archivist-->>Orchestrator: 19. Archiving result
 end
 
 Orchestrator->>RDS: 20. Update task status = completed
 
 Client->>ALB: 21. POST /message<br/>{method: "get_task_status"}
 ALB->>Orchestrator: 22. Forward request
 Orchestrator->>RDS: 23. Query task
 RDS-->>Orchestrator: 24. Task details
 Orchestrator-->>ALB: 25. Task status
 ALB-->>Client: 26. Complete status
```

### 5.2 Agent Discovery Flow

```mermaid
sequenceDiagram
 participant Client
 participant Orchestrator
 participant Extractor
 participant Validator
 participant Archivist
 
 Client->>Orchestrator: POST /message<br/>{method: "discover_agents"}
 
 par Discovery
 Orchestrator->>Extractor: GET /card
 Extractor-->>Orchestrator: Agent card + skills
 
 Orchestrator->>Validator: GET /card
 Validator-->>Orchestrator: Agent card + skills
 
 Orchestrator->>Archivist: GET /card
 Archivist-->>Orchestrator: Agent card + skills
 end
 
 Orchestrator->>Orchestrator: Build registry
 Orchestrator-->>Client: Discovery result<br/>{discovered_agents: 3, total_skills: 17}
```

### 5.3 Network Traffic Flow

```mermaid
graph LR
 subgraph Internet
 Client["Client<br/>Any IP"]
 end
 
 subgraph AWS_Public["AWS Public Zone"]
 IGW["Internet Gateway<br/>igw-052f22bed7f171258"]
 ALB["ALB<br/>13.37.61.78<br/>13.38.253.92"]
 end
 
 subgraph AWS_Private["AWS Private Zone"]
 Orch["Orchestrator<br/>10.0.20.158<br/>10.0.10.75"]
 Agents["Other Agents<br/>Private IPs"]
 RDS["RDS<br/>10.0.x.x"]
 end
 
 subgraph AWS_Services["AWS Services"]
 S3["S3<br/>VPC Endpoint"]
 Secrets["Secrets Manager<br/>VPC Endpoint"]
 CW["CloudWatch<br/>VPC Endpoint"]
 end
 
 Client -->|"1. HTTP/80"| IGW
 IGW -->|"2. Route"| ALB
 ALB -->|"3. HTTP/8001"| Orch
 Orch <-->|"4. HTTP/8002-8004"| Agents
 Orch <-->|"5. PostgreSQL/5432 + SSL"| RDS
 Orch <-->|"6. HTTPS via VPC Endpoint"| S3
 Orch <-->|"7. HTTPS via VPC Endpoint"| Secrets
 Agents <-->|"8. HTTPS via VPC Endpoint"| CW
```

---

## 6. Security Architecture

### 6.1 Security Layers

```mermaid
graph TB
 subgraph L1["Layer 1: Network Security"]
 VPC["VPC Isolation<br/>10.0.0.0/16"]
 SG["Security Groups<br/>Port-level filtering"]
 NACL["NACLs<br/>Subnet-level filtering"]
 end
 
 subgraph L2["Layer 2: Identity & Access"]
 IAM["IAM Roles<br/>Least privilege"]
 SSO["AWS SSO<br/>Federated access"]
 SecretsM["Secrets Manager<br/>Credential rotation"]
 end
 
 subgraph L3["Layer 3: Data Security"]
 TLS["TLS/SSL<br/>Data in transit"]
 Encrypt["Encryption at rest<br/>RDS, S3, EBS"]
 KMS["AWS KMS<br/>Key management"]
 end
 
 subgraph L4["Layer 4: Application Security"]
 Auth["Authentication<br/>Token validation"]
 Valid["Input validation<br/>JSON Schema"]
 RBAC["RBAC<br/>Agent permissions"]
 end
 
 L1 --> L2
 L2 --> L3
 L3 --> L4
```

### 6.5 Application security (A2A hardening)

Public entrypoint: **ALB → Orchestrator** (`POST /message`).

- **Authentication**
 - External client: `X-API-Key`
 - Agent-to-agent: **JWT Bearer** (short-lived, request-bound)
- **Authorization (RBAC)**: allow-list by principal (`A2A_RBAC_POLICY_JSON`)
- **Replay protection**: JWT `jti` nonce cache with TTL
- **Rate limiting**: per-principal sliding window (abuse resistance)
- **Payload size limits**: aiohttp `client_max_size` (DoS resistance)
- **Capability disclosure minimization**: `/card` and `/skills` can be **RBAC-filtered** (`A2A_CARD_VISIBILITY_MODE=rbac`)

Implementation reference:
- `a2a_security.py` (AuthN/AuthZ, replay, rate limiting)
- `base_agent.py` (enforcement on `/message`, RBAC-filtered `/card` + `/skills`)

Evidence:
- `DEMO_SECURITY_EVIDENCE.md` (captured outputs)
- `SECURITY.md` (security summary)

### 6.2 IAM Roles

**ECS Task Execution Role:** `ca-a2a-ecs-execution-role`
- Pull images from ECR
- Write logs to CloudWatch
- Read secrets from Secrets Manager

**ECS Task Role:** `ca-a2a-ecs-task-role`
- Access S3 bucket
- Connect to RDS (via security group)

### 6.3 Secrets Management

**Secrets stored in AWS Secrets Manager:**
- `ca-a2a/db-password` - RDS master password
- Retrieved at runtime via VPC endpoint
- Never hardcoded in code or environment variables

### 6.4 Encryption

**In Transit:**
- ALB to Internet: HTTP (HTTPS ready)
- ALB to ECS: HTTP (internal network)
- ECS to RDS: PostgreSQL with SSL/TLS (`ssl='require'`)
- ECS to S3: HTTPS via VPC endpoint
- ECS to Secrets Manager: HTTPS via VPC endpoint

**At Rest:**
- RDS: Encrypted with AWS KMS
- S3: Server-side encryption (SSE-S3)
- EBS volumes: Encrypted

---

## 7. Monitoring & Observability

### 7.1 CloudWatch Logs

**Log Groups:**
- `/ecs/ca-a2a-orchestrator` - Orchestrator logs
- `/ecs/ca-a2a-extractor` - Extractor logs
- `/ecs/ca-a2a-validator` - Validator logs
- `/ecs/ca-a2a-archivist` - Archivist logs

**Log Format:** JSON structured logging
**Retention:** 7 days (default)

### 7.2 Metrics

**ALB Metrics:**
- Target response time
- Healthy/unhealthy host count
- Request count
- HTTP 4xx/5xx errors

**ECS Metrics:**
- CPU utilization
- Memory utilization
- Task count
- Service deployment status

**RDS Metrics:**
- Database connections
- CPU utilization
- Free storage space
- Read/write IOPS

---

## 8. IP Address Reference

### External IPs
- **ALB:** `13.37.61.78`, `13.38.253.92`

### Internal IPs (Private)
- **Orchestrator Tasks:** `10.0.20.158`, `10.0.10.75`
- **Other agents:** Dynamic IPs in `10.0.0.0/16` range
- **RDS:** Private IP in VPC (accessed via DNS)

### DNS Names
- **ALB:** `ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com`
- **RDS:** `ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com`

---

## 9. Quick Reference

### API Endpoint
```
http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com
```

### Available Protocols
- **REST:** GET /health, /card, /status, /skills
- **A2A (JSON-RPC 2.0):** POST /message

### Network Ports
- **80** - ALB HTTP listener
- **8001** - Orchestrator service
- **8002** - Extractor service
- **8003** - Validator service
- **8004** - Archivist service
- **5432** - PostgreSQL RDS

---

**End of Architecture Documentation**

