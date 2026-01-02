# AWS Architecture - Mermaid Diagrams

**Project:** CA-A2A Multi-Agent Document Processing System  
**AWS Account:** 555043101106  
**Region:** eu-west-3 (Paris)  
**Generated:** January 2, 2026

---

## 1. High-Level System Architecture

```mermaid
graph TB
    subgraph Internet
        User[User/Client]
        S3Upload[S3 Upload]
    end
    
    subgraph "AWS Cloud - eu-west-3"
        ALB[Application Load Balancer<br/>ca-a2a-alb<br/>HTTP:80]
        
        subgraph "VPC: vpc-086392a3eed899f72 (10.0.0.0/16)"
            subgraph "AZ: eu-west-3a"
                subgraph "Private Subnet 1 (10.0.10.0/24)"
                    subgraph "ECS Cluster: ca-a2a-cluster"
                        Orch1[Orchestrator Task 1<br/>Port 8001<br/>512 CPU / 1GB RAM]
                        Ext1[Extractor Task 1<br/>Port 8002<br/>512 CPU / 1GB RAM]
                        Val1[Validator Task 1<br/>Port 8003<br/>512 CPU / 1GB RAM]
                        Arch1[Archivist Task 1<br/>Port 8004<br/>512 CPU / 1GB RAM]
                    end
                end
            end
            
            subgraph "AZ: eu-west-3b"
                subgraph "Private Subnet 2 (10.0.20.0/24)"
                    subgraph "ECS Cluster: ca-a2a-cluster"
                        Orch2[Orchestrator Task 2<br/>Port 8001]
                        Ext2[Extractor Task 2<br/>Port 8002]
                        Val2[Validator Task 2<br/>Port 8003]
                        Arch2[Archivist Task 2<br/>Port 8004]
                    end
                end
            end
            
            subgraph "Service Discovery"
                CloudMap[AWS Cloud Map<br/>Namespace: local<br/>extractor.local<br/>validator.local<br/>archivist.local]
            end
            
            subgraph "Event Processing"
                SQS[Amazon SQS<br/>ca-a2a-document-uploads]
                Lambda[AWS Lambda<br/>ca-a2a-s3-processor<br/>Python 3.11]
            end
            
            subgraph "Storage Layer"
                S3[Amazon S3<br/>ca-a2a-documents-555043101106<br/>AES-256 Encrypted]
                RDS[(Amazon RDS PostgreSQL 15.7<br/>ca-a2a-postgres<br/>db.t3.micro<br/>20 GB)]
            end
            
            subgraph "Security"
                Secrets[AWS Secrets Manager<br/>Credentials Storage]
            end
            
            subgraph "Monitoring"
                CW[CloudWatch<br/>Logs & Metrics]
                CT[CloudTrail<br/>API Auditing]
            end
        end
    end
    
    User -->|POST /upload| ALB
    S3Upload -->|aws s3 cp| S3
    ALB -->|HTTP:8001| Orch1
    ALB -->|HTTP:8001| Orch2
    
    Orch1 -.->|A2A Protocol| Ext1
    Orch1 -.->|A2A Protocol| Val1
    Orch1 -.->|A2A Protocol| Arch1
    Orch2 -.->|A2A Protocol| Ext2
    Orch2 -.->|A2A Protocol| Val2
    Orch2 -.->|A2A Protocol| Arch2
    
    Ext1 & Ext2 -.->|Service Discovery| CloudMap
    Val1 & Val2 -.->|Service Discovery| CloudMap
    Arch1 & Arch2 -.->|Service Discovery| CloudMap
    
    S3 -->|S3 Event Notification| SQS
    SQS -->|Trigger| Lambda
    Lambda -->|POST /a2a| Orch1
    Lambda -->|POST /a2a| Orch2
    
    Orch1 & Orch2 -->|Read/Write| S3
    Ext1 & Ext2 -->|Read| S3
    Arch1 & Arch2 -->|Write| S3
    
    Orch1 & Orch2 -->|SQL| RDS
    Arch1 & Arch2 -->|SQL| RDS
    
    Orch1 & Orch2 -.->|Get Secrets| Secrets
    Lambda -.->|Get Secrets| Secrets
    
    Orch1 & Orch2 -->|Logs| CW
    Ext1 & Ext2 -->|Logs| CW
    Val1 & Val2 -->|Logs| CW
    Arch1 & Arch2 -->|Logs| CW
    Lambda -->|Logs| CW
    
    style ALB fill:#FF9900
    style S3 fill:#569A31
    style RDS fill:#527FFF
    style SQS fill:#FF4F8B
    style Lambda fill:#FF9900
    style CW fill:#FF4F8B
    style Secrets fill:#DD344C
    style CloudMap fill:#FF9900
```

---

## 2. Document Processing Flow (Manual Upload)

```mermaid
sequenceDiagram
    participant User
    participant ALB as Application Load Balancer
    participant Orch as Orchestrator Service
    participant S3 as Amazon S3
    participant RDS as PostgreSQL
    participant Ext as Extractor Service
    participant Val as Validator Service
    participant Arch as Archivist Service
    participant CW as CloudWatch

    User->>ALB: POST /upload (invoice.pdf)
    ALB->>Orch: Forward request
    
    Orch->>S3: Upload to incoming/ folder
    S3-->>Orch: Upload confirmed
    
    Orch->>RDS: INSERT document record
    RDS-->>Orch: Document ID created
    
    Orch->>CW: Log: Processing started
    
    Note over Orch,Ext: Phase 1: Extraction
    Orch->>Ext: extract_document (A2A Protocol)
    Ext->>S3: Download file from incoming/
    S3-->>Ext: File contents
    Ext->>Ext: Extract text/data (PyPDF2, pdfplumber)
    Ext-->>Orch: extracted_data JSON
    
    Orch->>RDS: INSERT processing_log (extraction)
    Orch->>CW: Log: Extraction completed
    
    Note over Orch,Val: Phase 2: Validation
    Orch->>Val: validate_document (A2A Protocol)
    Val->>Val: Apply business rules
    Val->>Val: Check data integrity
    Val-->>Orch: validation_results
    
    Orch->>RDS: INSERT processing_log (validation)
    Orch->>CW: Log: Validation completed
    
    Note over Orch,Arch: Phase 3: Archival
    Orch->>Arch: archive_document (A2A Protocol)
    Arch->>S3: Move to processed/invoices/
    S3-->>Arch: Move confirmed
    Arch->>RDS: UPDATE document status='processed'
    Arch-->>Orch: archival_results
    
    Orch->>CW: Log: Processing completed
    Orch-->>ALB: Success response
    ALB-->>User: 200 OK with task_id
```

---

## 3. Automated S3 Event Processing Flow

```mermaid
sequenceDiagram
    participant User
    participant S3 as Amazon S3
    participant SQS as Amazon SQS
    participant Lambda as Lambda Function
    participant Orch as Orchestrator Service
    participant Pipeline as Processing Pipeline
    participant RDS as PostgreSQL

    User->>S3: aws s3 cp invoice.pdf s3://.../invoices/
    S3->>S3: Trigger: s3:ObjectCreated:*
    
    S3->>SQS: Send event notification
    Note over SQS: Message contains:<br/>bucket, key, timestamp
    
    SQS->>Lambda: Trigger (Event Source Mapping)
    Lambda->>Lambda: Parse S3 event
    Lambda->>Lambda: Extract bucket & key
    
    Lambda->>Orch: POST /a2a<br/>process_document
    Note over Lambda,Orch: JSON-RPC 2.0 request<br/>with JWT authentication
    
    Orch->>Pipeline: Start processing pipeline
    activate Pipeline
    Pipeline->>RDS: Create document record
    Pipeline->>Pipeline: Extract → Validate → Archive
    Pipeline->>RDS: Update status
    Pipeline-->>Orch: Processing results
    deactivate Pipeline
    
    Orch-->>Lambda: 200 OK with task_id
    Lambda->>SQS: Delete message
    Lambda->>Lambda: Log success
```

---

## 4. Network Architecture & Security Groups

```mermaid
graph TB
    subgraph "Internet Gateway"
        IGW[Internet Gateway]
    end
    
    subgraph "VPC: vpc-086392a3eed899f72"
        subgraph "Public Subnets"
            ALB[ALB<br/>sg-05db73131090f365a<br/>Inbound: 0.0.0.0/0:80,443<br/>Outbound: All]
        end
        
        subgraph "Private Subnets (10.0.10.0/24, 10.0.20.0/24)"
            ECS[ECS Tasks<br/>sg-047a8f39f9cdcaf4c<br/>Inbound: 8001-8004 from ALB+Self<br/>Outbound: 443,5432]
        end
        
        subgraph "RDS Subnets (10.0.30.0/24, 10.0.40.0/24)"
            RDS[(PostgreSQL<br/>sg-0dfffbf7f98f77a4c<br/>Inbound: 5432 from ECS<br/>Outbound: All)]
        end
        
        subgraph "VPC Endpoints"
            VPCE_S3[S3 Gateway Endpoint]
            VPCE_ECR[ECR Interface Endpoints]
            VPCE_SM[Secrets Manager Endpoint]
            VPCE_CW[CloudWatch Logs Endpoint]
        end
        
        subgraph "Route Tables"
            RT_Public[Public Route Table<br/>0.0.0.0/0 → IGW]
            RT_Private[Private Route Table<br/>S3 → VPCE<br/>AWS Services → Endpoints]
        end
    end
    
    subgraph "External AWS Services"
        S3_Svc[Amazon S3]
        ECR_Svc[Amazon ECR]
        SM_Svc[Secrets Manager]
        CW_Svc[CloudWatch]
    end
    
    IGW --> ALB
    ALB --> ECS
    ECS --> RDS
    
    ECS -.->|Private| VPCE_S3
    VPCE_S3 -.-> S3_Svc
    
    ECS -.->|Private| VPCE_ECR
    VPCE_ECR -.-> ECR_Svc
    
    ECS -.->|Private| VPCE_SM
    VPCE_SM -.-> SM_Svc
    
    ECS -.->|Private| VPCE_CW
    VPCE_CW -.-> CW_Svc
    
    ALB --> RT_Public
    ECS --> RT_Private
    
    style ALB fill:#FF9900
    style ECS fill:#FF9900
    style RDS fill:#527FFF
    style VPCE_S3 fill:#569A31
    style VPCE_ECR fill:#FF9900
    style VPCE_SM fill:#DD344C
    style VPCE_CW fill:#FF4F8B
```

---

## 5. A2A Protocol Communication Flow

```mermaid
sequenceDiagram
    participant Orch as Orchestrator
    participant JWT as JWT Token Service
    participant Ext as Extractor
    participant RBAC as RBAC Policy Engine
    participant Nonce as Nonce Cache

    Note over Orch: Client needs to call Extractor
    
    Orch->>JWT: Generate JWT token
    Note over JWT: Claims:<br/>iss: orchestrator<br/>sub: extractor<br/>jti: unique-nonce<br/>exp: 300s
    JWT-->>Orch: JWT token
    
    Orch->>Ext: POST /a2a<br/>Authorization: Bearer <token><br/>{"jsonrpc":"2.0","method":"extract_document"}
    
    Note over Ext: Security Validation
    Ext->>Ext: Verify JWT signature
    Ext->>Ext: Check expiration
    Ext->>Nonce: Check jti (replay protection)
    
    alt Nonce already used
        Nonce-->>Ext: Replay detected!
        Ext-->>Orch: 403 Forbidden
    else Nonce is new
        Nonce-->>Ext: OK
        Ext->>Nonce: Cache jti
        
        Ext->>RBAC: Check permissions<br/>Can orchestrator call extract_document?
        
        alt Permission denied
            RBAC-->>Ext: Access denied
            Ext-->>Orch: 403 Forbidden
        else Permission granted
            RBAC-->>Ext: Authorized
            
            Ext->>Ext: Execute method
            Ext->>Ext: Rate limit check
            Ext->>Ext: Payload size check
            
            Ext-->>Orch: 200 OK<br/>{"jsonrpc":"2.0","result":{...}}
        end
    end
```

---

## 6. ECS Service Deployment & Scaling

```mermaid
graph LR
    subgraph "Container Registry"
        ECR[Amazon ECR<br/>555043101106.dkr.ecr.eu-west-3]
        
        subgraph "Images"
            IMG_O[orchestrator:latest<br/>Python 3.11]
            IMG_E[extractor:latest<br/>Python 3.11]
            IMG_V[validator:latest<br/>Python 3.11]
            IMG_A[archivist:latest<br/>Python 3.11]
        end
    end
    
    subgraph "ECS Cluster: ca-a2a-cluster"
        subgraph "Task Definitions"
            TD_O[ca-a2a-orchestrator:6<br/>512 CPU / 1024 MB]
            TD_E[ca-a2a-extractor:latest<br/>512 CPU / 1024 MB]
            TD_V[ca-a2a-validator:latest<br/>512 CPU / 1024 MB]
            TD_A[ca-a2a-archivist:latest<br/>512 CPU / 1024 MB]
        end
        
        subgraph "Services (Fargate)"
            SVC_O[orchestrator<br/>Desired: 2<br/>Running: 2<br/>Status: ACTIVE]
            SVC_E[extractor<br/>Desired: 2<br/>Running: 2<br/>Status: ACTIVE]
            SVC_V[validator<br/>Desired: 2<br/>Running: 2<br/>Status: ACTIVE]
            SVC_A[archivist<br/>Desired: 2<br/>Running: 2<br/>Status: ACTIVE]
        end
        
        subgraph "Running Tasks"
            T_O1[Task: Orch-1<br/>IP: 10.0.10.x<br/>Health: HEALTHY]
            T_O2[Task: Orch-2<br/>IP: 10.0.20.x<br/>Health: HEALTHY]
            T_E1[Task: Ext-1<br/>IP: 10.0.10.x]
            T_E2[Task: Ext-2<br/>IP: 10.0.20.x]
            T_V1[Task: Val-1<br/>IP: 10.0.10.x]
            T_V2[Task: Val-2<br/>IP: 10.0.20.x]
            T_A1[Task: Arch-1<br/>IP: 10.0.10.x]
            T_A2[Task: Arch-2<br/>IP: 10.0.20.x]
        end
    end
    
    subgraph "Load Balancing"
        TG[Target Group<br/>ca-a2a-orch-tg<br/>Health: /health<br/>Interval: 30s]
        ALB_LB[Application Load Balancer]
    end
    
    IMG_O --> TD_O
    IMG_E --> TD_E
    IMG_V --> TD_V
    IMG_A --> TD_A
    
    TD_O --> SVC_O
    TD_E --> SVC_E
    TD_V --> SVC_V
    TD_A --> SVC_A
    
    SVC_O --> T_O1
    SVC_O --> T_O2
    SVC_E --> T_E1
    SVC_E --> T_E2
    SVC_V --> T_V1
    SVC_V --> T_V2
    SVC_A --> T_A1
    SVC_A --> T_A2
    
    T_O1 --> TG
    T_O2 --> TG
    TG --> ALB_LB
    
    style SVC_O fill:#00C853
    style SVC_E fill:#00C853
    style SVC_V fill:#00C853
    style SVC_A fill:#00C853
    style T_O1 fill:#00E676
    style T_O2 fill:#00E676
```

---

## 7. Data Storage Architecture

```mermaid
graph TB
    subgraph "Document Lifecycle"
        Upload[Document Upload]
        
        subgraph "S3 Bucket: ca-a2a-documents-555043101106"
            Incoming[📁 incoming/<br/>New uploads]
            Processing[📁 processing/<br/>Currently processing]
            Processed[📁 processed/<br/>✅ Successful]
            Failed[📁 failed/<br/>❌ Errors]
            
            subgraph "Processed Categories"
                Invoices[📄 processed/invoices/]
                Contracts[📄 processed/contracts/]
                Reports[📄 processed/reports/]
            end
        end
        
        subgraph "Lifecycle Policies"
            Glacier[❄️ Glacier<br/>After 90 days]
            Delete[🗑️ Delete<br/>After 365 days]
        end
        
        subgraph "PostgreSQL Database: documents_db"
            subgraph "Tables"
                Docs[(documents table<br/>────────────<br/>id: UUID<br/>filename: VARCHAR<br/>s3_key: VARCHAR<br/>file_type: VARCHAR<br/>status: VARCHAR<br/>extracted_data: JSONB<br/>metadata: JSONB<br/>created_at: TIMESTAMP<br/>updated_at: TIMESTAMP)]
                
                Logs[(processing_logs table<br/>────────────<br/>id: UUID<br/>document_id: UUID FK<br/>agent_name: VARCHAR<br/>operation: VARCHAR<br/>status: VARCHAR<br/>error_message: TEXT<br/>duration_ms: INTEGER<br/>timestamp: TIMESTAMP)]
            end
            
            subgraph "Indexes"
                IDX1[idx_documents_status]
                IDX2[idx_documents_created_at]
                IDX3[idx_processing_logs_document_id]
                IDX4[idx_processing_logs_timestamp]
            end
        end
    end
    
    Upload --> Incoming
    Incoming -->|Orchestrator starts| Processing
    Processing -->|Success| Processed
    Processing -->|Error| Failed
    Processed --> Invoices
    Processed --> Contracts
    Processed --> Reports
    
    Invoices --> Glacier
    Contracts --> Glacier
    Reports --> Glacier
    Glacier --> Delete
    
    Upload -.->|Metadata| Docs
    Processing -.->|Log each step| Logs
    Processed -.->|Final status| Docs
    Failed -.->|Error details| Docs
    
    Docs --> IDX1
    Docs --> IDX2
    Logs --> IDX3
    Logs --> IDX4
    
    style Incoming fill:#FFC107
    style Processing fill:#2196F3
    style Processed fill:#4CAF50
    style Failed fill:#F44336
    style Invoices fill:#81C784
    style Contracts fill:#81C784
    style Reports fill:#81C784
    style Glacier fill:#64B5F6
    style Delete fill:#E57373
```

---

## 8. Monitoring & Observability Stack

```mermaid
graph TB
    subgraph "Data Sources"
        Orch[Orchestrator Logs]
        Ext[Extractor Logs]
        Val[Validator Logs]
        Arch[Archivist Logs]
        Lambda[Lambda Logs]
        ALB_M[ALB Metrics]
        ECS_M[ECS Metrics]
        RDS_M[RDS Metrics]
        S3_M[S3 Metrics]
    end
    
    subgraph "CloudWatch"
        subgraph "Log Groups"
            LG1[/ecs/ca-a2a-orchestrator<br/>Retention: 7 days]
            LG2[/ecs/ca-a2a-extractor<br/>Retention: 7 days]
            LG3[/ecs/ca-a2a-validator<br/>Retention: 7 days]
            LG4[/ecs/ca-a2a-archivist<br/>Retention: 7 days]
            LG5[/aws/lambda/ca-a2a-s3-processor]
        end
        
        subgraph "Metrics"
            M1[ECS CPU/Memory Utilization]
            M2[ALB Request Count & Latency]
            M3[RDS Connections & Storage]
            M4[Lambda Invocations & Errors]
            M5[S3 Bucket Size & Requests]
        end
        
        subgraph "Alarms"
            A1[🔔 High CPU Alert<br/>Threshold: 80%]
            A2[🔔 High Error Rate<br/>Threshold: 10/5min]
            A3[🔔 RDS Connections<br/>Threshold: 80%]
            A4[🔔 Lambda Errors<br/>Threshold: 5%]
        end
        
        subgraph "Dashboards"
            D1[📊 Service Health Dashboard]
            D2[📊 Performance Dashboard]
            D3[📊 Cost Dashboard]
        end
    end
    
    subgraph "CloudTrail"
        CT[API Call Auditing<br/>Compliance Logging<br/>Security Analysis]
    end
    
    subgraph "VPC Flow Logs"
        VFL[Network Traffic Monitoring<br/>Security Analysis<br/>Troubleshooting]
    end
    
    subgraph "Container Insights"
        CI[ECS Container Metrics<br/>Task-level Performance<br/>Resource Utilization]
    end
    
    subgraph "Alerting"
        SNS[Amazon SNS<br/>Email/SMS Notifications]
    end
    
    Orch --> LG1
    Ext --> LG2
    Val --> LG3
    Arch --> LG4
    Lambda --> LG5
    
    ALB_M --> M2
    ECS_M --> M1
    RDS_M --> M3
    Lambda --> M4
    S3_M --> M5
    
    M1 --> A1
    M2 --> A2
    M3 --> A3
    M4 --> A4
    
    M1 & M2 & M3 & M4 & M5 --> D1
    M1 & M2 & M3 & M4 & M5 --> D2
    M1 & M2 & M3 & M4 & M5 --> D3
    
    ECS_M --> CI
    
    A1 & A2 & A3 & A4 --> SNS
    
    style A1 fill:#FF9800
    style A2 fill:#FF5722
    style A3 fill:#FF9800
    style A4 fill:#FF5722
    style D1 fill:#2196F3
    style D2 fill:#2196F3
    style D3 fill:#4CAF50
    style SNS fill:#FF4081
```

---

## 9. IAM Roles & Permissions

```mermaid
graph TB
    subgraph "IAM Roles"
        subgraph "ECS Task Execution Role"
            EXEC[ca-a2a-ecs-execution-role<br/>────────────<br/>Trust: ecs-tasks.amazonaws.com]
            
            EXEC_P1[📋 AmazonECSTaskExecutionRolePolicy<br/>• ECR: Pull images<br/>• Logs: Create/write streams]
            EXEC_P2[📋 Custom: Secrets Access<br/>• SecretsManager: GetSecretValue<br/>• KMS: Decrypt]
        end
        
        subgraph "ECS Task Role"
            TASK[ca-a2a-ecs-task-role<br/>────────────<br/>Trust: ecs-tasks.amazonaws.com]
            
            TASK_P1[📋 S3 Access Policy<br/>• s3:GetObject<br/>• s3:PutObject<br/>• s3:ListBucket<br/>Resource: ca-a2a-documents-*]
            TASK_P2[📋 RDS Access<br/>Via Security Groups<br/>Not IAM-based]
        end
        
        subgraph "Lambda Execution Role"
            LAMBDA_R[ca-a2a-lambda-s3-processor-role<br/>────────────<br/>Trust: lambda.amazonaws.com]
            
            LAMBDA_P1[📋 Lambda Basic Execution<br/>• Logs: CreateLogStream/PutLogEvents]
            LAMBDA_P2[📋 VPC Access<br/>• ec2:CreateNetworkInterface<br/>• ec2:DescribeNetworkInterfaces<br/>• ec2:DeleteNetworkInterface]
            LAMBDA_P3[📋 SQS Access<br/>• sqs:ReceiveMessage<br/>• sqs:DeleteMessage<br/>• sqs:GetQueueAttributes]
            LAMBDA_P4[📋 S3 Read Access<br/>• s3:GetObject<br/>Resource: ca-a2a-documents-*]
        end
    end
    
    subgraph "AWS Services"
        ECR[Amazon ECR<br/>Container Images]
        SM[Secrets Manager<br/>Credentials]
        CW[CloudWatch Logs]
        S3[Amazon S3<br/>Documents]
        SQS[Amazon SQS<br/>Events]
        VPC[VPC<br/>Network]
    end
    
    subgraph "ECS Tasks"
        T_ORCH[Orchestrator Tasks]
        T_EXT[Extractor Tasks]
        T_VAL[Validator Tasks]
        T_ARCH[Archivist Tasks]
    end
    
    subgraph "Lambda Functions"
        L_FUNC[ca-a2a-s3-processor]
    end
    
    EXEC --> EXEC_P1
    EXEC --> EXEC_P2
    TASK --> TASK_P1
    TASK --> TASK_P2
    LAMBDA_R --> LAMBDA_P1
    LAMBDA_R --> LAMBDA_P2
    LAMBDA_R --> LAMBDA_P3
    LAMBDA_R --> LAMBDA_P4
    
    EXEC_P1 -.->|Allow| ECR
    EXEC_P1 -.->|Allow| CW
    EXEC_P2 -.->|Allow| SM
    
    TASK_P1 -.->|Allow| S3
    
    LAMBDA_P1 -.->|Allow| CW
    LAMBDA_P2 -.->|Allow| VPC
    LAMBDA_P3 -.->|Allow| SQS
    LAMBDA_P4 -.->|Allow| S3
    
    T_ORCH -.->|Assumes| EXEC
    T_ORCH -.->|Assumes| TASK
    T_EXT -.->|Assumes| EXEC
    T_EXT -.->|Assumes| TASK
    T_VAL -.->|Assumes| EXEC
    T_VAL -.->|Assumes| TASK
    T_ARCH -.->|Assumes| EXEC
    T_ARCH -.->|Assumes| TASK
    
    L_FUNC -.->|Assumes| LAMBDA_R
    
    style EXEC fill:#DD344C
    style TASK fill:#DD344C
    style LAMBDA_R fill:#DD344C
    style EXEC_P1 fill:#FF9800
    style EXEC_P2 fill:#FF9800
    style TASK_P1 fill:#FF9800
    style LAMBDA_P1 fill:#FF9800
    style LAMBDA_P2 fill:#FF9800
    style LAMBDA_P3 fill:#FF9800
    style LAMBDA_P4 fill:#FF9800
```

---

## 10. Cost Analysis & Optimization

```mermaid
graph TB
    subgraph "Monthly AWS Costs - eu-west-3"
        subgraph "Compute Layer - $40.20"
            ECS[ECS Fargate<br/>8 tasks × 0.5 vCPU × 1GB<br/>24/7 running<br/>$40.00/month]
            Lambda[Lambda<br/>~10K invocations<br/>512MB × 60s avg<br/>$0.20/month]
        end
        
        subgraph "Storage Layer - $15.50"
            RDS[RDS PostgreSQL<br/>db.t3.micro<br/>20 GB gp2<br/>$15.00/month]
            S3[S3 Storage<br/><1 GB + requests<br/>$0.50/month]
        end
        
        subgraph "Networking Layer - $23.50"
            ALB[Application Load Balancer<br/>1 ALB + ~1M LCU-hours<br/>$16.00/month]
            VPCE[VPC Endpoints<br/>5 interface endpoints<br/>$7.50/month]
        end
        
        subgraph "Monitoring Layer - $0.60"
            CWL[CloudWatch Logs<br/>1 GB/month ingestion<br/>$0.50/month]
            SQS_C[SQS Queue<br/>~10K messages<br/>$0.10/month]
        end
        
        subgraph "Security Layer - $0.40"
            SM_C[Secrets Manager<br/>1 secret + requests<br/>$0.40/month]
        end
        
        subgraph "Data Transfer - $0.45"
            DT[Data Transfer Out<br/>~5 GB/month<br/>$0.45/month]
        end
        
        Total[💰 Total Monthly Cost<br/>$80.65/month<br/>≈ $968/year]
        
        ECS --> Total
        Lambda --> Total
        RDS --> Total
        S3 --> Total
        ALB --> Total
        VPCE --> Total
        CWL --> Total
        SQS_C --> Total
        SM_C --> Total
        DT --> Total
    end
    
    subgraph "Cost Optimization Options"
        OPT1[💡 Reduce to 1 task/service<br/>Save: $20/month<br/>New total: $60.65]
        
        OPT2[💡 Use Fargate Spot<br/>Save: 40% on compute<br/>New total: $64.65]
        
        OPT3[💡 RDS Reserved Instance<br/>1-year commitment<br/>Save: 40%<br/>New total: $74.65]
        
        OPT4[💡 S3 Intelligent-Tiering<br/>Auto-optimize storage<br/>Save: Variable]
        
        OPT5[💡 Reduce Log Retention<br/>7 days → 3 days<br/>Save: $0.25/month]
        
        OPT6[💡 Combine All Optimizations<br/>Best case scenario<br/>New total: ~$45/month<br/>Save: 44%]
    end
    
    subgraph "Scaling Cost Impact"
        SCALE1[📈 Double capacity<br/>16 tasks total<br/>Cost: ~$120/month]
        
        SCALE2[📈 10x capacity<br/>Auto-scaling to max<br/>Cost: ~$200/month]
        
        SCALE3[📈 Production-grade<br/>Multi-region + HA<br/>Cost: ~$300/month]
    end
    
    Total -.->|Consider| OPT1
    Total -.->|Consider| OPT2
    Total -.->|Consider| OPT3
    Total -.->|Consider| OPT4
    Total -.->|Consider| OPT5
    Total -.->|Best| OPT6
    
    Total -.->|Scale| SCALE1
    Total -.->|Scale| SCALE2
    Total -.->|Scale| SCALE3
    
    style Total fill:#4CAF50,color:#fff
    style ECS fill:#FF9900
    style RDS fill:#527FFF
    style ALB fill:#FF6B6B
    style OPT6 fill:#00E676
    style SCALE3 fill:#FF9800
```

---

## How to Use These Diagrams

### Viewing in GitHub/GitLab
These Mermaid diagrams will render automatically when viewing this file on GitHub or GitLab.

### Viewing in VS Code/Cursor
Install the "Markdown Preview Mermaid Support" extension to see rendered diagrams.

### Exporting to Images
Use [Mermaid Live Editor](https://mermaid.live) to export diagrams as PNG/SVG:
1. Copy the diagram code
2. Paste into mermaid.live
3. Click "Actions" → "Export as PNG/SVG"

### Embedding in Documentation
These diagrams can be embedded in any markdown documentation that supports Mermaid syntax.

---

## Related Documentation

- [AWS_ARCHITECTURE.md](./AWS_ARCHITECTURE.md) - Detailed specifications
- [AWS_ARCHITECTURE_DIAGRAM.md](./AWS_ARCHITECTURE_DIAGRAM.md) - ASCII diagrams
- [AWS_DEPLOYMENT.md](./AWS_DEPLOYMENT.md) - Deployment guide
- [SECURITY_GUIDE.md](./SECURITY_GUIDE.md) - Security details

---

**Generated:** January 2, 2026  
**Project:** CA-A2A Multi-Agent Document Processing System  
**Status:** ✅ All services operational

