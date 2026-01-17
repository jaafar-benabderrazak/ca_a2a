# 1. System Architecture

[← Back to Index](README.md)

---


### 1.1 Production Deployment

```mermaid
graph TB
    subgraph Internet
        User[External User]
    end
    
    subgraph AWS["AWS Cloud - eu-west-3"]
        subgraph VPC["VPC: 10.0.0.0/16"]
            subgraph Public["Public Subnets"]
                ALB[Application Load Balancer<br/>HTTPS/HTTP]
                NAT[NAT Gateway]
            end
            
            subgraph Private["Private Subnets - ECS Cluster"]
                direction TB
                Orch[Orchestrator<br/>:8001]
                Ext[Extractor<br/>:8002]
                Val[Validator<br/>:8003]
                Arch[Archivist<br/>:8004]
                KC[Keycloak<br/>:8080]
                MCP[MCP Server<br/>:8000<br/>Resource Gateway]
            end
            
            subgraph Data["Data Layer"]
                RDS[RDS Aurora PostgreSQL<br/>documents DB]
                KC_RDS[RDS PostgreSQL<br/>keycloak DB]
            end
        end
        
        subgraph Services["AWS Services"]
            SM[Secrets Manager]
            CW[CloudWatch Logs]
            S3[S3 Bucket]
            ECR[ECR Repositories]
        end
    end
    
    User -->|1. HTTPS| ALB
    ALB -->|2. HTTP| Orch
    Orch -->|A2A Protocol| Ext
    Orch -->|A2A Protocol| Val
    Orch -->|A2A Protocol| Arch
    
    Orch -.->|Auth| KC
    Ext -.->|Auth| KC
    Val -.->|Auth| KC
    Arch -.->|Auth| KC
    
    KC -->|JDBC| KC_RDS
    
    Orch -->|HTTP API| MCP
    Ext -->|HTTP API| MCP
    Val -->|HTTP API| MCP
    Arch -->|HTTP API| MCP
    
    MCP -->|asyncpg<br/>Connection Pool| RDS
    MCP -.->|aioboto3| S3
    Arch -.->|boto3| S3
    
    Private -.->|VPC Endpoints| SM
    Private -.->|VPC Endpoints| CW
    Private -.->|NAT Gateway| Internet
```

### 1.2 Component Overview

| Component | Type | Port | Purpose | Instances |
|-----------|------|------|---------|-----------|
| **Orchestrator** | ECS Fargate | 8001 | Request coordination, workflow | 2 |
| **Extractor** | ECS Fargate | 8002 | Document text extraction | 2 |
| **Validator** | ECS Fargate | 8003 | Content validation | 2 |
| **Archivist** | ECS Fargate | 8004 | Document archival, retrieval | 2 |
| **Keycloak** | ECS Fargate | 8080 | Identity Provider (OAuth2/OIDC) | 1 |
| **ALB** | AWS Service | 80/443 | Load balancing, TLS termination | Multi-AZ |
| **RDS Aurora** | Managed DB | 5432 | Document metadata, audit logs | Multi-AZ |
| **RDS Postgres** | Managed DB | 5432 | Keycloak data (users, roles) | Multi-AZ |

---


---

[Next: Security Layers (Defense-in-Depth) →](02-SECURITY_LAYERS.md)
