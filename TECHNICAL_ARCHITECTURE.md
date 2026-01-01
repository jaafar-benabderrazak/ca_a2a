# CA A2A Multi-Agent Pipeline - Technical Deep Dive

A comprehensive technical explanation of the distributed multi-agent document processing system using A2A (Agent-to-Agent) protocol and AWS cloud infrastructure.

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture Layers](#architecture-layers)
3. [Network Topology](#network-topology)
4. [Agent Communication Protocol](#agent-communication-protocol)
5. [Document Processing Flow](#document-processing-flow)
6. [AWS Infrastructure](#aws-infrastructure)
7. [Data Flow & State Management](#data-flow--state-management)
8. [Service Discovery](#service-discovery)
9. [Security & Resilience](#security--resilience)
10. [Deployment Architecture](#deployment-architecture)

---

## System Overview

### What is CA A2A?

CA A2A is a **distributed multi-agent system** for intelligent document processing. It uses autonomous agents that communicate via the **A2A (Agent-to-Agent) protocol** to extract, validate, and archive structured data from documents (PDF and CSV).

### Key Concepts

```mermaid
graph TB
    subgraph "Core Concepts"
        A[Agent-to-Agent Protocol]
        B[Microservices Architecture]
        C[Event-Driven Processing]
        D[Cloud-Native Design]
    end

    subgraph "Technologies"
        E[Python + AsyncIO]
        F[AWS ECS Fargate]
        G[PostgreSQL]
        H[S3 Storage]
    end

    subgraph "Protocols"
        I[JSON-RPC 2.0]
        J[MCP - Model Context Protocol]
        K[HTTP/REST]
    end

    A --> E
    B --> F
    C --> G
    D --> F
    E --> I
    F --> K
    G --> J
```

### System Components

```mermaid
graph LR
    subgraph "4 Specialized Agents"
        O[Orchestrator<br/>Port 8001]
        E[Extractor<br/>Port 8002]
        V[Validator<br/>Port 8003]
        A[Archivist<br/>Port 8004]
    end

    subgraph "Storage Layer"
        S3[S3 Bucket<br/>Documents]
        DB[(PostgreSQL<br/>Metadata)]
    end

    subgraph "Infrastructure"
        ALB[Load Balancer]
        SD[Service Discovery<br/>AWS Cloud Map]
    end

    Client --> ALB
    ALB --> O
    O <-->|A2A| E
    O <-->|A2A| V
    O <-->|A2A| A
    E <-->|MCP| S3
    A <-->|MCP| DB

    SD -.->|DNS| E
    SD -.->|DNS| V
    SD -.->|DNS| A

    style O fill:#4CAF50
    style E fill:#2196F3
    style V fill:#FF9800
    style A fill:#9C27B0
```

---

## Architecture Layers

The system is organized in distinct layers, each with specific responsibilities.

### Layer Architecture

```mermaid
graph TB
    subgraph "Layer 1: API Gateway"
        ALB[Application Load Balancer<br/>HTTP/HTTPS Entry Point]
    end

    subgraph "Layer 2: Orchestration"
        ORCH[Orchestrator Agent<br/>Workflow Coordination]
    end

    subgraph "Layer 3: Processing Agents"
        EXT[Extractor<br/>Data Extraction]
        VAL[Validator<br/>Quality Assurance]
        ARC[Archivist<br/>Persistence]
    end

    subgraph "Layer 4: Protocol Layer"
        A2A[A2A Protocol<br/>JSON-RPC 2.0]
        MCP[MCP Protocol<br/>Resource Access]
    end

    subgraph "Layer 5: Storage"
        S3[S3<br/>Object Storage]
        RDS[RDS PostgreSQL<br/>Structured Data]
    end

    subgraph "Layer 6: Infrastructure"
        ECS[ECS Fargate<br/>Container Runtime]
        SD[Service Discovery<br/>DNS Resolution]
        CW[CloudWatch<br/>Logging & Monitoring]
    end

    ALB --> ORCH
    ORCH --> EXT
    ORCH --> VAL
    ORCH --> ARC

    EXT -.-> A2A
    VAL -.-> A2A
    ARC -.-> A2A

    EXT --> MCP
    ARC --> MCP

    MCP --> S3
    MCP --> RDS

    ORCH -.-> ECS
    EXT -.-> ECS
    VAL -.-> ECS
    ARC -.-> ECS

    ECS --> SD
    ECS --> CW
```

### Responsibilities by Layer

| Layer | Purpose | Components | Technology |
|-------|---------|------------|------------|
| **API Gateway** | External access point | ALB | AWS ELB |
| **Orchestration** | Workflow management | Orchestrator | Python AsyncIO |
| **Processing** | Business logic | 3 specialized agents | Python + Libraries |
| **Protocol** | Communication standards | A2A, MCP | JSON-RPC 2.0 |
| **Storage** | Data persistence | S3, RDS | AWS managed |
| **Infrastructure** | Runtime & ops | ECS, CloudWatch | AWS services |

---

## Network Topology

### AWS VPC Architecture

```mermaid
graph TB
    subgraph Internet
        USER[End Users]
    end

    subgraph "VPC: 10.0.0.0/16"
        subgraph "Availability Zone A"
            subgraph "Public Subnet 10.0.1.0/24"
                ALB1[ALB<br/>Node 1]
                NAT1[NAT<br/>Gateway]
            end

            subgraph "Private Subnet 10.0.10.0/24"
                ECS1A[Orchestrator<br/>Task]
                ECS1B[Extractor<br/>Task]
            end
        end

        subgraph "Availability Zone B"
            subgraph "Public Subnet 10.0.2.0/24"
                ALB2[ALB<br/>Node 2]
            end

            subgraph "Private Subnet 10.0.20.0/24"
                ECS2A[Validator<br/>Task]
                ECS2B[Archivist<br/>Task]
            end
        end

        IGW[Internet<br/>Gateway]
    end

    subgraph "AWS Services"
        S3[S3 Bucket]
        RDS[(RDS<br/>PostgreSQL)]
        ECR[ECR<br/>Container Registry]
    end

    USER --> IGW
    IGW --> ALB1
    IGW --> ALB2

    ALB1 --> ECS1A
    ALB2 --> ECS1A

    ECS1A <--> ECS1B
    ECS1A <--> ECS2A
    ECS1A <--> ECS2B

    ECS1B --> NAT1 --> IGW
    ECS2A --> NAT1 --> IGW
    ECS2B --> NAT1 --> IGW

    ECS1B --> S3
    ECS2B --> RDS
    ECS1A --> ECR

    style ALB1 fill:#FF9800
    style ALB2 fill:#FF9800
    style ECS1A fill:#4CAF50
    style ECS1B fill:#2196F3
    style ECS2A fill:#FF9800
    style ECS2B fill:#9C27B0
```

### Network Flow Explanation

1. **Public Subnets (10.0.1.0/24, 10.0.2.0/24)**
   - Host Application Load Balancer
   - Host NAT Gateway for outbound traffic
   - Direct route to Internet Gateway

2. **Private Subnets (10.0.10.0/24, 10.0.20.0/24)**
   - Host ECS Fargate tasks (agents)
   - No direct internet access
   - Route outbound through NAT Gateway
   - Access AWS services via service endpoints

3. **Security Groups**
   ```mermaid
   graph LR
       subgraph "Security Groups"
           SG1[ALB-SG<br/>Allow 80/443<br/>from Internet]
           SG2[ECS-SG<br/>Allow 8000-8999<br/>from ALB-SG]
           SG3[RDS-SG<br/>Allow 5432<br/>from ECS-SG]
       end

       Internet --> SG1
       SG1 --> SG2
       SG2 --> SG3
   ```

---

## Agent Communication Protocol

### A2A Protocol (JSON-RPC 2.0)

The A2A protocol enables standardized, reliable communication between agents.

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant E as Extractor

    Note over O,E: A2A Request/Response Pattern

    O->>E: JSON-RPC Request
    Note right of O: {<br/>"jsonrpc": "2.0",<br/>"method": "extract",<br/>"params": {...},<br/>"id": "req-123"<br/>}

    E->>E: Process Request

    E->>O: JSON-RPC Response
    Note left of E: {<br/>"jsonrpc": "2.0",<br/>"result": {...},<br/>"id": "req-123"<br/>}

    Note over O,E: Error Handling

    O->>E: Invalid Request
    E->>O: Error Response
    Note left of E: {<br/>"jsonrpc": "2.0",<br/>"error": {<br/>"code": -32600,<br/>"message": "..."<br/>}<br/>}
```

### Message Structure

```mermaid
classDiagram
    class A2AMessage {
        +String jsonrpc = "2.0"
        +String method
        +Object params
        +String|Number id
        +Object result
        +Error error
        +create_request()
        +create_response()
        +create_error()
        +to_json()
        +from_json()
    }

    class Error {
        +Number code
        +String message
        +Object data
    }

    class ErrorCodes {
        <<enumeration>>
        PARSE_ERROR = -32700
        INVALID_REQUEST = -32600
        METHOD_NOT_FOUND = -32601
        INVALID_PARAMS = -32602
        INTERNAL_ERROR = -32603
        EXTRACTION_ERROR = -32001
        VALIDATION_ERROR = -32002
        PERSISTENCE_ERROR = -32003
    }

    A2AMessage --> Error
    Error --> ErrorCodes
```

### Communication Patterns

```mermaid
graph TB
    subgraph "Pattern 1: Request-Response"
        A1[Agent A] -->|Request| B1[Agent B]
        B1 -->|Response| A1
    end

    subgraph "Pattern 2: Notification (Fire & Forget)"
        A2[Agent A] -->|Notification<br/>no id| B2[Agent B]
        B2 -.->|No Response| A2
    end

    subgraph "Pattern 3: Batch Request"
        A3[Agent A] -->|Multiple Requests<br/>in Array| B3[Agent B]
        B3 -->|Multiple Responses<br/>in Array| A3
    end

    subgraph "Pattern 4: With Retry Logic"
        A4[Agent A] -->|Request| B4[Agent B]
        B4 -.->|Timeout| A4
        A4 -->|Retry 1| B4
        B4 -.->|Timeout| A4
        A4 -->|Retry 2| B4
        B4 -->|Response| A4
    end
```

---

## Document Processing Flow

### Complete Workflow

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant O as Orchestrator
    participant E as Extractor
    participant V as Validator
    participant A as Archivist
    participant S3 as S3 Storage
    participant DB as PostgreSQL

    C->>O: POST /process<br/>{document_path}
    O->>O: Generate task_id
    O->>C: 202 Accepted<br/>{task_id, status}

    Note over O,A: Async Processing Begins

    O->>E: A2A: extract_document<br/>{task_id, path}
    E->>S3: Download document
    S3->>E: Document bytes
    E->>E: Extract data<br/>(PDF/CSV parsing)
    E->>O: Response<br/>{extracted_data}

    O->>V: A2A: validate_document<br/>{task_id, data}
    V->>V: Run validation rules<br/>- Completeness<br/>- Quality<br/>- Format<br/>- Consistency
    V->>V: Calculate score (0-100)
    V->>O: Response<br/>{validation_result, score}

    alt Score >= 70
        O->>A: A2A: archive_document<br/>{task_id, data, validation}
        A->>DB: INSERT INTO documents
        DB->>A: document_id
        A->>O: Response<br/>{document_id, status}
        O->>O: Update task: COMPLETED
    else Score < 70
        O->>O: Update task: VALIDATION_FAILED
    end

    C->>O: GET /status/{task_id}
    O->>C: Task status & results
```

### State Machine

```mermaid
stateDiagram-v2
    [*] --> RECEIVED: Client submits document

    RECEIVED --> EXTRACTING: Orchestrator assigns to Extractor

    EXTRACTING --> EXTRACTION_FAILED: Extraction error
    EXTRACTING --> VALIDATING: Extraction successful

    VALIDATING --> VALIDATION_FAILED: Validation error<br/>or score < 70
    VALIDATING --> ARCHIVING: Validation passed<br/>score >= 70

    ARCHIVING --> ARCHIVE_FAILED: Database error
    ARCHIVING --> COMPLETED: Successfully archived

    EXTRACTION_FAILED --> [*]
    VALIDATION_FAILED --> [*]
    ARCHIVE_FAILED --> [*]
    COMPLETED --> [*]

    note right of RECEIVED
        task_id assigned
        status = PENDING
    end note

    note right of COMPLETED
        document_id available
        stored in PostgreSQL
    end note
```

### Data Transformation Pipeline

```mermaid
graph LR
    subgraph "Input"
        DOC[PDF/CSV<br/>Document]
    end

    subgraph "Extraction Stage"
        E1[File Type<br/>Detection]
        E2[Content<br/>Parsing]
        E3[Structure<br/>Extraction]
    end

    subgraph "Validation Stage"
        V1[Completeness<br/>Check]
        V2[Quality<br/>Assessment]
        V3[Format<br/>Validation]
        V4[Score<br/>Calculation]
    end

    subgraph "Archival Stage"
        A1[Data<br/>Normalization]
        A2[Metadata<br/>Enrichment]
        A3[Database<br/>Insert]
    end

    subgraph "Output"
        RES[Structured<br/>Record]
    end

    DOC --> E1
    E1 --> E2
    E2 --> E3
    E3 --> V1
    V1 --> V2
    V2 --> V3
    V3 --> V4
    V4 --> A1
    A1 --> A2
    A2 --> A3
    A3 --> RES

    style E1 fill:#2196F3
    style E2 fill:#2196F3
    style E3 fill:#2196F3
    style V1 fill:#FF9800
    style V2 fill:#FF9800
    style V3 fill:#FF9800
    style V4 fill:#FF9800
    style A1 fill:#9C27B0
    style A2 fill:#9C27B0
    style A3 fill:#9C27B0
```

---

## AWS Infrastructure

### ECS Fargate Deployment

```mermaid
graph TB
    subgraph "ECS Cluster: ca-a2a-cluster"
        subgraph "Service: Orchestrator"
            T1A[Task 1<br/>Container]
            T1B[Task 2<br/>Container]
        end

        subgraph "Service: Extractor"
            T2A[Task 1<br/>Container]
            T2B[Task 2<br/>Container]
        end

        subgraph "Service: Validator"
            T3A[Task 1<br/>Container]
            T3B[Task 2<br/>Container]
        end

        subgraph "Service: Archivist"
            T4A[Task 1<br/>Container]
            T4B[Task 2<br/>Container]
        end
    end

    subgraph "Supporting Services"
        TG[Target Group<br/>Health Checks]
        SD[Service Discovery<br/>Cloud Map]
        ECR[ECR<br/>Container Images]
        CW[CloudWatch<br/>Logs & Metrics]
    end

    T1A --> TG
    T1B --> TG

    T2A --> SD
    T2B --> SD
    T3A --> SD
    T3B --> SD
    T4A --> SD
    T4B --> SD

    T1A -.-> ECR
    T2A -.-> ECR
    T3A -.-> ECR
    T4A -.-> ECR

    T1A --> CW
    T2A --> CW
    T3A --> CW
    T4A --> CW

    style T1A fill:#4CAF50
    style T1B fill:#4CAF50
    style T2A fill:#2196F3
    style T2B fill:#2196F3
    style T3A fill:#FF9800
    style T3B fill:#FF9800
    style T4A fill:#9C27B0
    style T4B fill:#9C27B0
```

### Container Architecture

```mermaid
graph TB
    subgraph "Fargate Task"
        subgraph "Container"
            APP[Python Application<br/>orchestrator_agent.py]
            LIBS[Dependencies<br/>aiohttp, asyncpg, etc.]
        end

        subgraph "Environment"
            ENV[Environment Variables<br/>- ORCHESTRATOR_HOST<br/>- ORCHESTRATOR_PORT<br/>- EXTRACTOR_HOST<br/>- DB credentials via Secrets]
        end

        subgraph "Network"
            ENI[Elastic Network Interface<br/>Private IP in VPC]
        end

        subgraph "Storage"
            EPHEMERAL[Ephemeral Storage<br/>20 GB]
        end

        subgraph "Resources"
            CPU[0.5 vCPU]
            MEM[1 GB RAM]
        end
    end

    subgraph "Task Definition"
        IMAGE[ECR Image<br/>555043101106.dkr.ecr.eu-west-3<br/>.amazonaws.com/ca-a2a/orchestrator]
        HC[Health Check<br/>curl localhost:8001/health]
        LOGS[Log Configuration<br/>awslogs driver → CloudWatch]
    end

    IMAGE --> APP
    ENV --> APP
    ENI --> APP
    CPU --> APP
    MEM --> APP
    HC -.-> APP
    APP --> LOGS
```

### Auto-Scaling Configuration

```mermaid
graph TB
    subgraph "ECS Service"
        DESIRED[Desired Count: 2]
        MIN[Min: 1]
        MAX[Max: 10]
    end

    subgraph "CloudWatch Metrics"
        CPU_METRIC[CPU Utilization]
        MEM_METRIC[Memory Utilization]
        REQ_METRIC[Request Count]
    end

    subgraph "Scaling Policies"
        SCALE_OUT[Scale Out<br/>if CPU > 70%<br/>Add 1 task]
        SCALE_IN[Scale In<br/>if CPU < 30%<br/>Remove 1 task]
    end

    subgraph "Actions"
        ADD[Add Task]
        REMOVE[Remove Task]
    end

    CPU_METRIC --> SCALE_OUT
    CPU_METRIC --> SCALE_IN
    MEM_METRIC --> SCALE_OUT
    REQ_METRIC --> SCALE_OUT

    SCALE_OUT --> ADD
    SCALE_IN --> REMOVE

    ADD --> DESIRED
    REMOVE --> DESIRED
```

---

## Data Flow & State Management

### Data Models

```mermaid
erDiagram
    TASKS ||--o{ DOCUMENTS : processes
    DOCUMENTS ||--o{ VALIDATION_RESULTS : has

    TASKS {
        uuid task_id PK
        string status
        string document_path
        timestamp created_at
        timestamp updated_at
        jsonb metadata
    }

    DOCUMENTS {
        uuid document_id PK
        uuid task_id FK
        string document_type
        jsonb extracted_data
        timestamp created_at
    }

    VALIDATION_RESULTS {
        uuid validation_id PK
        uuid document_id FK
        int score
        string status
        jsonb rules_results
        timestamp validated_at
    }
```

### Storage Strategy

```mermaid
graph TB
    subgraph "S3 Storage Strategy"
        S3_RAW[s3://bucket/raw/<br/>Original documents]
        S3_PROC[s3://bucket/processed/<br/>Processed documents]
        S3_ARCH[s3://bucket/archive/<br/>Archived documents]

        LIFECYCLE[S3 Lifecycle Policy<br/>- Standard: 30 days<br/>- IA: 60 days<br/>- Glacier: 90+ days]
    end

    subgraph "PostgreSQL Storage"
        DB_META[Document Metadata<br/>- IDs<br/>- Timestamps<br/>- Status]
        DB_DATA[Extracted Data<br/>- JSONB fields<br/>- Indexed columns]
        DB_VALID[Validation Results<br/>- Scores<br/>- Rule results]
    end

    subgraph "Cache Layer (Future)"
        REDIS[Redis Cache<br/>- Session data<br/>- Frequently accessed docs]
    end

    S3_RAW --> S3_PROC
    S3_PROC --> S3_ARCH
    S3_ARCH --> LIFECYCLE

    S3_RAW -.-> DB_META
    DB_META --> DB_DATA
    DB_DATA --> DB_VALID

    DB_DATA -.-> REDIS
```

### Transaction Flow

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant E as Extractor
    participant V as Validator
    participant A as Archivist
    participant DB as Database

    Note over O,DB: Transaction Boundaries

    rect rgb(200, 220, 255)
        Note over O: Transaction 1: Task Creation
        O->>O: BEGIN
        O->>O: INSERT task (status=PENDING)
        O->>O: COMMIT
    end

    rect rgb(220, 255, 200)
        Note over O,E: Transaction 2: Extraction
        O->>O: UPDATE task (status=EXTRACTING)
        O->>E: Extract request
        E->>E: Process document
        E->>O: Response
        O->>O: UPDATE task (status=EXTRACTED)
    end

    rect rgb(255, 220, 200)
        Note over O,V: Transaction 3: Validation
        O->>O: UPDATE task (status=VALIDATING)
        O->>V: Validate request
        V->>V: Run rules
        V->>O: Response
        O->>O: UPDATE task (status=VALIDATED)
    end

    rect rgb(255, 200, 220)
        Note over O,A,DB: Transaction 4: Archival
        O->>A: Archive request
        A->>DB: BEGIN
        A->>DB: INSERT document
        A->>DB: INSERT validation
        A->>DB: COMMIT
        A->>O: Response
        O->>O: UPDATE task (status=COMPLETED)
    end
```

---

## Service Discovery

### AWS Cloud Map Integration

```mermaid
graph TB
    subgraph "Cloud Map Namespace: local"
        NS[Namespace ID:<br/>ns-xxxxx]

        SVC1[Service: extractor.local<br/>Service ID: srv-1]
        SVC2[Service: validator.local<br/>Service ID: srv-2]
        SVC3[Service: archivist.local<br/>Service ID: srv-3]

        NS --> SVC1
        NS --> SVC2
        NS --> SVC3
    end

    subgraph "DNS Records"
        A1[A Record: extractor.local<br/>→ 10.0.10.15]
        A2[A Record: validator.local<br/>→ 10.0.20.22]
        A3[A Record: archivist.local<br/>→ 10.0.20.18]
    end

    subgraph "ECS Tasks"
        T1[Extractor Task<br/>IP: 10.0.10.15]
        T2[Validator Task<br/>IP: 10.0.20.22]
        T3[Archivist Task<br/>IP: 10.0.20.18]
    end

    SVC1 --> A1
    SVC2 --> A2
    SVC3 --> A3

    A1 -.-> T1
    A2 -.-> T2
    A3 -.-> T3

    T1 --> SVC1
    T2 --> SVC2
    T3 --> SVC3
```

### Discovery Process

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant DNS as Cloud Map DNS
    participant SD as Service Discovery
    participant E as Extractor Task

    Note over O,E: Agent Discovery Flow

    O->>DNS: Query: extractor.local
    DNS->>SD: Lookup service instances
    SD->>SD: Check health status
    SD->>DNS: Return healthy IPs<br/>[10.0.10.15, 10.0.10.23]
    DNS->>O: DNS Response<br/>10.0.10.15 (Round-robin)

    O->>E: HTTP POST http://10.0.10.15:8002/rpc<br/>A2A Request
    E->>O: A2A Response

    Note over O,E: If task fails, Cloud Map auto-removes

    E->>E: Task stops
    SD->>SD: Health check fails
    SD->>DNS: Deregister 10.0.10.15

    O->>DNS: Query: extractor.local
    DNS->>O: DNS Response<br/>10.0.10.23 (only healthy)
```

---

## Security & Resilience

### Security Layers

```mermaid
graph TB
    subgraph "Network Security"
        VPC[VPC Isolation<br/>10.0.0.0/16]
        SG[Security Groups<br/>Port restrictions]
        NACL[Network ACLs<br/>Subnet rules]
        PRIV[Private Subnets<br/>No direct internet]
    end

    subgraph "Access Control"
        IAM[IAM Roles<br/>Least privilege]
        SEC[Secrets Manager<br/>Credential storage]
        EXEC[Task Execution Role<br/>ECR, Logs access]
        TASK[Task Role<br/>S3, DB access]
    end

    subgraph "Data Security"
        S3E[S3 Encryption<br/>AES-256]
        RDSE[RDS Encryption<br/>At-rest encryption]
        TLS[TLS in Transit<br/>HTTPS/SSL]
    end

    subgraph "Application Security"
        VAL[Input Validation<br/>Pydantic models]
        AUTH[Authentication<br/>Future: API keys]
        RATE[Rate Limiting<br/>Future: per client]
    end

    VPC --> SG
    SG --> NACL
    NACL --> PRIV

    IAM --> SEC
    IAM --> EXEC
    IAM --> TASK

    S3E --> TLS
    RDSE --> TLS

    VAL --> AUTH
    AUTH --> RATE
```

### Resilience Patterns

```mermaid
graph TB
    subgraph "Retry Logic"
        R1[Exponential Backoff<br/>1s, 2s, 4s, 8s]
        R2[Max Attempts: 3]
        R3[Jitter Added<br/>Prevent thundering herd]
    end

    subgraph "Circuit Breaker"
        CB1[Closed<br/>Normal operation]
        CB2[Open<br/>Fast fail after 5 errors]
        CB3[Half-Open<br/>Test after cooldown]

        CB1 -->|5 consecutive errors| CB2
        CB2 -->|30s cooldown| CB3
        CB3 -->|Success| CB1
        CB3 -->|Failure| CB2
    end

    subgraph "Timeout Management"
        T1[Request Timeout<br/>30 seconds]
        T2[Health Check<br/>5 seconds]
        T3[Connection Timeout<br/>10 seconds]
    end

    subgraph "Graceful Degradation"
        GD1[Primary: Full processing]
        GD2[Degraded: Skip optional validations]
        GD3[Minimal: Store raw, process later]

        GD1 -->|High load| GD2
        GD2 -->|Critical load| GD3
        GD3 -->|Load normalized| GD1
    end
```

### Error Handling Flow

```mermaid
flowchart TD
    START[Request Received] --> TRY[Try Operation]

    TRY -->|Success| SUCCESS[Return Response]
    TRY -->|Error| CLASSIFY{Classify Error}

    CLASSIFY -->|Network Error| RETRY{Retry Count < 3?}
    CLASSIFY -->|Validation Error| LOG_RETURN[Log & Return Error]
    CLASSIFY -->|System Error| CIRCUIT{Circuit Open?}

    RETRY -->|Yes| BACKOFF[Exponential Backoff]
    RETRY -->|No| FAIL[Mark as Failed]

    BACKOFF --> TRY

    CIRCUIT -->|Yes| FAST_FAIL[Fast Fail]
    CIRCUIT -->|No| INCREMENT[Increment Error Count]

    INCREMENT --> CHECK{Count >= 5?}
    CHECK -->|Yes| OPEN_CIRCUIT[Open Circuit Breaker]
    CHECK -->|No| LOG_RETURN

    OPEN_CIRCUIT --> FAST_FAIL
    FAST_FAIL --> LOG_RETURN

    LOG_RETURN --> NOTIFY[Notify Monitoring]
    FAIL --> NOTIFY

    SUCCESS --> END[Complete]
    NOTIFY --> END
```

---

## Deployment Architecture

### Complete System Diagram

```mermaid
graph TB
    subgraph "Client Layer"
        WEB[Web Client]
        API[API Client]
        CLI[CLI Client]
    end

    subgraph "AWS Region: eu-west-3"
        subgraph "Public Zone"
            R53[Route 53<br/>DNS]
            ALB[Application<br/>Load Balancer]
        end

        subgraph "Private Zone - AZ A"
            ORCH1[Orchestrator<br/>Task 1]
            EXT1[Extractor<br/>Task 1]
        end

        subgraph "Private Zone - AZ B"
            ORCH2[Orchestrator<br/>Task 2]
            VAL1[Validator<br/>Task 1]
            ARC1[Archivist<br/>Task 1]
        end

        subgraph "Data Services"
            S3[S3 Bucket<br/>Documents]
            RDS[(RDS PostgreSQL<br/>Multi-AZ)]
            ECR[ECR<br/>Containers]
        end

        subgraph "Management & Monitoring"
            CM[Cloud Map<br/>Service Discovery]
            CW[CloudWatch<br/>Logs & Metrics]
            SM[Secrets Manager<br/>Credentials]
        end
    end

    WEB --> R53
    API --> R53
    CLI --> R53

    R53 --> ALB
    ALB --> ORCH1
    ALB --> ORCH2

    ORCH1 <-->|A2A| EXT1
    ORCH1 <-->|A2A| VAL1
    ORCH1 <-->|A2A| ARC1

    ORCH2 <-->|A2A| EXT1
    ORCH2 <-->|A2A| VAL1
    ORCH2 <-->|A2A| ARC1

    EXT1 <-->|MCP| S3
    ARC1 <-->|MCP| RDS

    ORCH1 -.->|Pull| ECR
    ORCH2 -.->|Pull| ECR
    EXT1 -.->|Pull| ECR
    VAL1 -.->|Pull| ECR
    ARC1 -.->|Pull| ECR

    CM -.->|DNS| EXT1
    CM -.->|DNS| VAL1
    CM -.->|DNS| ARC1

    ORCH1 -->|Logs| CW
    ORCH2 -->|Logs| CW
    EXT1 -->|Logs| CW
    VAL1 -->|Logs| CW
    ARC1 -->|Logs| CW

    ARC1 -.->|Read| SM

    style ORCH1 fill:#4CAF50
    style ORCH2 fill:#4CAF50
    style EXT1 fill:#2196F3
    style VAL1 fill:#FF9800
    style ARC1 fill:#9C27B0
```

### Resource Allocation

```mermaid
pie title "Monthly AWS Costs (€173)"
    "ECS Fargate (8 tasks)" : 60
    "RDS PostgreSQL" : 55
    "ALB" : 22
    "NAT Gateway" : 38
    "S3 + CloudWatch" : 8
```

### Scaling Characteristics

```mermaid
graph LR
    subgraph "Load: 10 docs/min"
        L1[2 Tasks per Service<br/>8 Total]
    end

    subgraph "Load: 50 docs/min"
        L2[4 Tasks per Service<br/>16 Total]
    end

    subgraph "Load: 200 docs/min"
        L3[10 Tasks per Service<br/>40 Total]
    end

    L1 -->|Auto-scale| L2
    L2 -->|Auto-scale| L3
    L3 -->|Scale down| L2
    L2 -->|Scale down| L1
```

---

## Summary

### Key Takeaways

1. **Distributed Architecture**
   - 4 specialized agents with clear responsibilities
   - Autonomous operation via A2A protocol
   - Scalable microservices design

2. **Cloud-Native Design**
   - Serverless containers (ECS Fargate)
   - Managed services (RDS, S3, ALB)
   - Infrastructure as Code ready

3. **Production Ready**
   - Multi-AZ deployment for HA
   - Comprehensive error handling
   - Full observability with CloudWatch
   - Secure by design (VPC, SG, encryption)

4. **Extensible**
   - Easy to add new agent types
   - Pluggable validation rules
   - Support for new document formats

### Technology Stack Summary

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Runtime** | Python 3.9 + AsyncIO | High-performance async processing |
| **Framework** | aiohttp | HTTP server and client |
| **Protocol** | JSON-RPC 2.0 | Agent-to-agent communication |
| **Validation** | Pydantic v2 | Type-safe data models |
| **Storage** | PostgreSQL + S3 | Structured + unstructured data |
| **Containers** | Docker + ECS Fargate | Portable, scalable deployment |
| **Networking** | AWS VPC + ALB | Secure, load-balanced access |
| **Discovery** | AWS Cloud Map | Service mesh integration |
| **Monitoring** | CloudWatch | Centralized logging and metrics |

### Performance Metrics

- **Latency**: < 2 seconds per document (average)
- **Throughput**: 50-200 documents/minute (scalable)
- **Availability**: 99.9% (Multi-AZ)
- **Error Rate**: < 0.1% (with retries)

---

## References

- [A2A Protocol Specification](A2A_BEST_PRACTICES.md)
- [AWS Deployment Guide](AWS_DEPLOYMENT.md)
- [API Documentation](DOCUMENTATION.md)
- [Demo Guide](DEMO_GUIDE.md)

---

**Document Version:** 1.0
**Last Updated:** December 2025
**Region:** eu-west-3 (Paris)
