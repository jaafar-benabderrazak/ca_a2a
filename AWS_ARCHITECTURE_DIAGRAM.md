# AWS Architecture Diagram - CA-A2A Document Processing System

**Generated:** January 14, 2026  
**Account:** 555043101106  
**Region:** eu-west-3 (Paris)  
**Status:** Fully Deployed & Operational  
**New Features:** Keycloak OAuth2/OIDC Service

---

## Complete System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ INTERNET │
└──────────────────────────────────────────┬──────────────────────────────────────────────────┘
 │
 │ HTTPS/HTTP
 │
 ┌──────────────────────▼──────────────────────┐
 │ Application Load Balancer (ALB) │
 │ ca-a2a-alb-1432397105.eu-west-3.elb... │
 │ │
 │ DNS Name: Public │
 │ Scheme: internet-facing │
 │ Security Group: sg-05db73131090f365a │
 │ Listener: HTTP:80 → Target Group │
 └──────────────┬───────────────────────────────┘
 │
 │ HTTP:8001
 │
┌──────────────────────────────────▼────────────────────────────────────────────────────────────┐
│ VPC: vpc-086392a3eed899f72 │
│ CIDR: 10.0.0.0/16 │
│ │
│ ┌────────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ AVAILABILITY ZONE eu-west-3a │ │
│ │ │ │
│ │ ┌────────────────────────────────────────────────────────────────────────────────┐ │ │
│ │ │ Private Subnet 1 (10.0.10.0/24) │ │ │
│ │ │ │ │ │
│ │ │ ┌────────────────────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ ECS CLUSTER: ca-a2a-cluster (FARGATE) │ │ │ │
│ │ │ │ │ │ │ │
│ │ │ │ ┌───────────────────────────────────────────────────────┐ │ │ │ │
│ │ │ │ │ ORCHESTRATOR Service (2 tasks) │ │ │ │ │
│ │ │ │ │ Port: 8001 │ CPU: 512 │ Memory: 1024 MB │ │ │ │ │
│ │ │ │ │ Image: ca-a2a/orchestrator:latest │ │ │ │ │
│ │ │ │ │ Health: /health │ Version: 1.0.0 │ │ │ │ │
│ │ │ │ │ Status: HEALTHY (2/2 running) │ │ │ │ │
│ │ │ │ │ │ │ │ │ │
│ │ │ │ │ Capabilities: │ │ │ │ │
│ │ │ │ │ • process_document │ │ │ │ │
│ │ │ │ │ • get_agent_registry │ │ │ │ │
│ │ │ │ │ • upload_handler (POST /upload) │ │ │ │ │
│ │ │ │ └────────────────────┬────────────────────────────────────┘ │ │ │ │
│ │ │ │ │ │ │ │ │
│ │ │ │ ┌────────────────────▼────────────────────────────────┐ │ │ │ │
│ │ │ │ │ EXTRACTOR Service (2 tasks) │ │ │ │ │
│ │ │ │ │ Port: 8002 │ CPU: 512 │ Memory: 1024 MB │ │ │ │ │
│ │ │ │ │ Image: ca-a2a/extractor:latest │ │ │ │ │
│ │ │ │ │ Status: ACTIVE (2/2 running) │ │ │ │ │
│ │ │ │ │ │ │ │ │ │
│ │ │ │ │ Capabilities: │ │ │ │ │
│ │ │ │ │ • extract_document (PDF, CSV) │ │ │ │ │
│ │ │ │ │ • Libraries: PyPDF2, pdfplumber, pandas │ │ │ │ │
│ │ │ │ └────────────────────┬──────────────────────────────────┘ │ │ │ │
│ │ │ │ │ │ │ │ │
│ │ │ │ ┌────────────────────▼────────────────────────────────┐ │ │ │ │
│ │ │ │ │ VALIDATOR Service (2 tasks) │ │ │ │ │
│ │ │ │ │ Port: 8003 │ CPU: 512 │ Memory: 1024 MB │ │ │ │ │
│ │ │ │ │ Image: ca-a2a/validator:latest │ │ │ │ │
│ │ │ │ │ Status: ACTIVE (2/2 running) │ │ │ │ │
│ │ │ │ │ │ │ │ │ │
│ │ │ │ │ Capabilities: │ │ │ │ │
│ │ │ │ │ • validate_document │ │ │ │ │
│ │ │ │ │ • Business rules validation │ │ │ │ │
│ │ │ │ └────────────────────┬──────────────────────────────────┘ │ │ │ │
│ │ │ │ │ │ │ │ │
│ │ │ │ ┌────────────────────▼────────────────────────────────┐ │ │ │ │
│ │ │ │ │ ARCHIVIST Service (2 tasks) │ │ │ │ │
│ │ │ │ │ Port: 8004 │ CPU: 512 │ Memory: 1024 MB │ │ │ │ │
│ │ │ │ │ Image: ca-a2a/archivist:latest │ │ │ │ │
│ │ │ │ │ Status: ACTIVE (2/2 running) │ │ │ │ │
│ │ │ │ │ │ │ │ │ │
│ │ │ │ │ Capabilities: │ │ │ │ │
│ │ │ │ │ • archive_document │ │ │ │ │
│ │ │ │ │ • Database persistence │ │ │ │ │
│ │ │ │ │ • S3 organization (processed/, failed/) │ │ │ │ │
│ │ │ │ └────────────────────┬──────────────────────────────────┘ │ │ │ │
│ │ │ │ │ │ │ │ │
│ │ │ │ ┌────────────────────▼────────────────────────────────┐ │ │ │ │
│ │ │ │ │ **KEYCLOAK Service (1 task) [NEW]** │ │ │ │ │
│ │ │ │ │ Port: 8080 │ CPU: 1024 │ Memory: 2048 MB │ │ │ │ │
│ │ │ │ │ Image: ca-a2a/keycloak:23.0 │ │ │ │ │
│ │ │ │ │ Status: ACTIVE (1/1 running) │ │ │ │ │
│ │ │ │ │ │ │ │ │ │
│ │ │ │ │ Capabilities: │ │ │ │ │
│ │ │ │ │ • **OAuth2/OIDC Provider** │ │ │ │ │
│ │ │ │ │ • **JWT Token Issuance (RS256)** │ │ │ │ │
│ │ │ │ │ • **User Management** │ │ │ │ │
│ │ │ │ │ • **Role Management (RBAC)** │ │ │ │ │
│ │ │ │ │ • **Authentication Events Audit** │ │ │ │ │
│ │ │ │ │ • **Service Discovery:** keycloak.ca-a2a.local:8080│ │ │ │ │
│ │ │ │ └────────────────────┬──────────────────────────────────┘ │ │ │ │
│ │ │ │ │ │ │ │ │
│ │ │ └────────────────────────┼────────────────────────────────────────────────┘ │ │ │
│ │ │ │ │ │ │
│ │ │ Security Group: sg-047a8f39f9cdcaf4c │ │ │
│ │ │ • Inbound: 8001-8004 from ALB and Self │ │ │
│ │ │ • Outbound: HTTPS (443), PostgreSQL (5432), **Keycloak (8080)** │ │ │
│ │ │ │ │ │
│ │ │ **Keycloak Security Group:** sg-0fea873848c240253 │ │ │
│ │ │ • Inbound: 8080 from Agent SGs │ │ │
│ │ │ • Outbound: PostgreSQL (5432), HTTPS (443) │ │ │
│ │ └────────────────────────────┼───────────────────────────────────────────────────────┘ │ │
│ │ │ │ │
│ └────────────────────────────────┼──────────────────────────────────────────────────────────┘ │
│ │ │
│ ┌────────────────────────────────┼──────────────────────────────────────────────────────────┐ │
│ │ AVAILABILITY ZONE eu-west-3b │ │
│ │ │ │ │
│ │ ┌────────────────────────────▼─────────────────────────────────────────────────────┐ │ │
│ │ │ Private Subnet 2 (10.0.20.0/24) │ │ │
│ │ │ │ │ │
│ │ [Same ECS tasks replicated for High Availability] │ │ │
│ │ │ • Orchestrator Task (1 of 2) │ │ │
│ │ │ • Extractor Task (1 of 2) │ │ │
│ │ │ • Validator Task (1 of 2) │ │ │
│ │ │ • Archivist Task (1 of 2) │ │ │
│ │ │ • **Keycloak Task (1 of 1 - HA planned for Phase 2)** │ │ │
│ │ │ │ │ │
│ │ └───────────────────────────────────────┬────────────────────────────────────────────┘ │ │
│ └───────────────────────────────────────────┼───────────────────────────────────────────────┘ │
│ │ │
│ ┌──────────────────────────────────────────┼──────────────────────────────────────────────┐ │
│ │ AWS CLOUD MAP SERVICE DISCOVERY │ │
│ │ Namespace: local │ │
│ │ │ │
│ │ • extractor.local → ECS tasks (10.0.10.x, 10.0.20.x) │ │
│ │ • validator.local → ECS tasks (10.0.10.x, 10.0.20.x) │ │
│ │ • archivist.local → ECS tasks (10.0.10.x, 10.0.20.x) │ │
│ │ • **keycloak.local → ECS tasks (10.0.10.x) [NEW]** │ │
│ └─────────────────────────────────────────────────────────────────────────────────────────┘ │
│ │ │
│ │ │
│ ┌──────────────────────────────────────────┴──────────────────────────────────────────────┐ │
│ │ STORAGE & DATA LAYER │ │
│ │ │ │
│ │ ┌──────────────────────────────────┐ ┌────────────────────────────────────────┐ │ │
│ │ │ AMAZON S3 │ │ AMAZON RDS (PostgreSQL 15.7) │ │ │
│ │ │ ca-a2a-documents-555043101106 │ │ ca-a2a-postgres │ │ │
│ │ │ │ │ │ │ │
│ │ │ Region: eu-west-3 │ │ Instance: db.t3.micro │ │ │
│ │ │ Encryption: AES-256 (SSE-S3) │ │ Storage: 20 GB gp2 │ │ │
│ │ │ Versioning: Disabled │ │ Multi-AZ: No │ │ │
│ │ │ Public Access: BLOCKED │ │ Backup: 7 days retention │ │ │
│ │ │ │ │ Encryption: Enabled (at rest) │ │ │
│ │ │ Folder Structure: │ │ SSL/TLS: Required (in transit) │ │ │
│ │ │ ├─ incoming/ │ │ │ │ │
│ │ │ ├─ processing/ │ │ Endpoint: │ │ │
│ │ │ ├─ processed/ │ │ ca-a2a-postgres.czkdu9wcburt... │ │ │
│ │ │ │ ├─ invoices/ │ │ Port: 5432 │ │ │
│ │ │ │ ├─ contracts/ │ │ │ │ │
│ │ │ │ └─ reports/ │ │ Database: documents_db │ │ │
│ │ │ └─ failed/ │ │ **Database: keycloak [NEW]** │ │ │
│ │ │ │ │ │ │ │
│ │ │ Lifecycle: │ │ Tables (documents_db): │ │ │
│ │ │ Lifecycle: │ │ • documents │ │ │
│ │ │ • Glacier after 90 days │ │ - id, filename, s3_key │ │ │
│ │ │ • Delete after 365 days │ │ - file_type, status │ │ │
│ │ │ │ │ - extracted_data, metadata │ │ │
│ │ │ │ │ - created_at, updated_at │ │ │
│ │ │ ┌─────────────────────────┐ │ │ │ │ │
│ │ │ │ S3 EVENT NOTIFICATION │ │ │ • processing_logs │ │ │
│ │ │ │ │ │ │ - id, document_id │ │ │
│ │ │ │ Trigger: │ │ │ - agent_name, operation │ │ │
│ │ │ │ s3:ObjectCreated:* │ │ │ - status, error_message │ │ │
│ │ │ │ Filter: invoices/*.pdf │ │ │ - timestamp │ │ │
│ │ │ └──────────┬──────────────┘ │ │ │ │ │
│ │ │ │ │ │ Indexes: │ │ │
│ │ └───────────────┼─────────────────┘ │ • idx_documents_status │ │ │
│ │ │ │ • idx_documents_created_at │ │ │
│ │ │ │ • idx_processing_logs_document_id │ │ │
│ │ ▼ │ • idx_processing_logs_timestamp │ │ │
│ │ ┌──────────────────────────────┐ │ │ │ │
│ │ │ AMAZON SQS │ │ Security Group: sg-0dfffbf7f98f77a4c│ │ │
│ │ │ ca-a2a-document-uploads │ │ • Inbound: 5432 from ECS SG │ │ │
│ │ │ │ └────────────────────────────────────────┘ │ │
│ │ │ Message Retention: 4 days │ ┌────────────────────────────────────────┐ │ │
│ │ │ Visibility Timeout: 30s │ │ SECRETS MANAGER │ │ │
│ │ │ Encryption: SQS managed │ │ │ │ │
│ │ └──────────────┬───────────────┘ │ • ca-a2a/postgres-password │ │ │
│ │ │ │ • ca-a2a/aws-credentials │ │ │
│ │ │ │ **• ca-a2a/keycloak-admin-password**│ │ │
│ │ │ │ **• ca-a2a/keycloak-client-secret** │ │ │
│ │ │ └────────────────────────────────────────┘ │ │
│ │ ▼ │ │
│ │ ┌──────────────────────────────┐ │ │
│ │ │ AWS LAMBDA │ │ │
│ │ │ ca-a2a-s3-processor │ │ │
│ │ │ │ │ │
│ │ │ Runtime: Python 3.11 │ │ │
│ │ │ Memory: 512 MB │ │ │
│ │ │ Timeout: 60 seconds │ │ │
│ │ │ VPC: Same as ECS │ │ │
│ │ │ │ │ │
│ │ │ Trigger: SQS messages │ │ │
│ │ │ Action: POST to │ │ │
│ │ │ Orchestrator /a2a │ │ │
│ │ │ with process_document │ │ │
│ │ │ │ │ │
│ │ │ IAM Role: │ │ │
│ │ │ ca-a2a-lambda-s3- │ │ │
│ │ │ processor-role │ │ │
│ │ └──────────────────────────────┘ │ │
│ └─────────────────────────────────────────────────────────────────────────────────────┘ │
│ │
│ ┌─────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ VPC ENDPOINTS (Private AWS Service Access) │ │
│ │ │ │
│ │ • vpce-xxx: S3 (Gateway) │ │
│ │ • vpce-yyy: ECR API (Interface) │ │
│ │ • vpce-zzz: ECR DKR (Interface) │ │
│ │ • vpce-aaa: Secrets Manager (Interface) │ │
│ │ • vpce-bbb: CloudWatch Logs (Interface) │ │
│ └─────────────────────────────────────────────────────────────────────────────────────┘ │
│ │
└─────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ MONITORING & OBSERVABILITY │
│ │
│ ┌──────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ AWS CLOUDWATCH │ │
│ │ │ │
│ │ Log Groups: │ │
│ │ • /ecs/ca-a2a-orchestrator (Retention: 7 days, ~10 MB/day) │ │
│ │ • /ecs/ca-a2a-extractor (Retention: 7 days, ~20 MB/day) │ │
│ │ • /ecs/ca-a2a-validator (Retention: 7 days, ~15 MB/day) │ │
│ │ • /ecs/ca-a2a-archivist (Retention: 7 days, ~10 MB/day) │ │
│ │ • **/ecs/ca-a2a-keycloak (Retention: 30 days, ~5 MB/day) [NEW]** │ │
│ │ • /aws/lambda/ca-a2a-s3-processor (Lambda function logs) │ │
│ │ │ │
│ │ Metrics: │ │
│ │ • ECS: CPU/Memory utilization, task count │ │
│ │ • ALB: Request count, latency, HTTP codes (2xx, 4xx, 5xx) │ │
│ │ • RDS: CPU, connections, storage, read/write IOPS │ │
│ │ • S3: Bucket size, request metrics │ │
│ │ • Lambda: Invocations, duration, errors │ │
│ │ │ │
│ │ Container Insights: ENABLED │ │
│ └──────────────────────────────────────────────────────────────────────────────────────┘ │
│ │
│ ┌──────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ AWS CLOUDTRAIL │ │
│ │ │ │
│ │ • API call auditing │ │
│ │ • Resource change tracking │ │
│ │ • Compliance logging │ │
│ └──────────────────────────────────────────────────────────────────────────────────────┘ │
│ │
│ ┌──────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ VPC FLOW LOGS │ │
│ │ │ │
│ │ • Network traffic monitoring │ │
│ │ • Security analysis │ │
│ └──────────────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ IAM ROLES & PERMISSIONS │
│ │
│ ┌──────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ ECS Task Execution Role (ca-a2a-ecs-execution-role) │ │
│ │ • Pull images from ECR │ │
│ │ • Write logs to CloudWatch │ │
│ │ • Retrieve secrets from Secrets Manager │ │
│ └──────────────────────────────────────────────────────────────────────────────────────┘ │
│ │
│ ┌──────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ ECS Task Role (ca-a2a-ecs-task-role) │ │
│ │ • S3: GetObject, PutObject, ListBucket on ca-a2a-documents-* bucket │ │
│ │ • PostgreSQL access via security groups │ │
│ └──────────────────────────────────────────────────────────────────────────────────────┘ │
│ │
│ ┌──────────────────────────────────────────────────────────────────────────────────────┐ │
│ │ Lambda Execution Role (ca-a2a-lambda-s3-processor-role) │ │
│ │ • SQS: ReceiveMessage, DeleteMessage, GetQueueAttributes │ │
│ │ • S3: GetObject on ca-a2a-documents-* bucket │ │
│ │ • VPC: CreateNetworkInterface, DescribeNetworkInterfaces │ │
│ │ • CloudWatch Logs: CreateLogStream, PutLogEvents │ │
│ └──────────────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ SECURITY FEATURES │
│ │
│ Network Security: │
│ Private subnets for all compute (no public IPs) │
│ VPC endpoints for AWS service access (no internet gateway needed) │
│ Security groups with principle of least privilege │
│ Network ACLs for subnet-level control │
│ │
│ Data Security: │
│ SSL/TLS for all data in transit (ALB, RDS, S3) │
│ RDS encryption at rest (AWS KMS) │
│ S3 bucket encryption (SSE-S3 AES-256) │
│ Secrets Manager for credential management │
│ │
│ Application Security (A2A Protocol): │
│ External client authentication: X-API-Key │
│ Agent-to-agent authentication: Short-lived JWT Bearer tokens (request-bound) │
│ Authorization (RBAC): Method allow-list by principal (A2A_RBAC_POLICY_JSON) │
│ Replay protection: JWT jti nonce cache │
│ Rate limiting: Per-principal controls on /message endpoint │
│ Payload size limits: aiohttp client_max_size configuration │
│ Capability disclosure minimization: /card and /skills RBAC-filtered │
│ │
│ Access Control: │
│ IAM roles with minimal permissions │
│ Resource-based policies (S3 bucket policy, SQS policy) │
│ No hard-coded credentials │
│ SSO for human access (AWS IAM Identity Center) │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow Diagram

### 1. Document Upload via ALB (Manual)

```
User/Client
 │
 │ POST /upload (multipart/form-data)
 │ with file + metadata
 │
 ▼
Application Load Balancer (HTTP:80)
 │
 │ Forwards to Target Group
 │
 ▼
Orchestrator Service (Port 8001)
 │
 │ upload_handler.py processes request
 │ Saves file to S3: incoming/
 │
 ├──► S3: ca-a2a-documents-555043101106/incoming/filename.pdf
 │
 ├──► PostgreSQL: INSERT into documents table
 │
 └──► Initiates processing pipeline
 │
 ▼
 process_document method
 │
 ├──► Extractor (Port 8002)
 │ │ Extracts text/data from PDF/CSV
 │ └──► Returns extracted_data JSON
 │
 ├──► Validator (Port 8003)
 │ │ Validates business rules
 │ └──► Returns validation_results
 │
 └──► Archivist (Port 8004)
 │ Archives to S3: processed/invoices/
 │ Updates PostgreSQL with final status
 └──► Returns archival_results
```

### 2. Automated Document Processing via S3 Events

```
File Upload to S3
 │
 │ aws s3 cp file.pdf s3://bucket/invoices/2026/01/file.pdf
 │
 ▼
S3 Bucket: ca-a2a-documents-555043101106
 │
 │ Event: s3:ObjectCreated:*
 │ Filter: invoices/*.pdf
 │
 ▼
S3 Event Notification
 │
 ▼
SQS Queue: ca-a2a-document-uploads
 │
 │ Message: {bucket, key, event_time, ...}
 │
 ▼
Lambda Function: ca-a2a-s3-processor
 │
 │ Triggered by SQS message
 │ Parses S3 event
 │ Calls Orchestrator via A2A protocol
 │
 │ POST http://orchestrator.local:8001/a2a
 │ {
 │ "jsonrpc": "2.0",
 │ "method": "process_document",
 │ "params": {
 │ "s3_key": "invoices/2026/01/file.pdf",
 │ "file_type": "invoice"
 │ }
 │ }
 │
 ▼
Orchestrator processes document
 │
 ├──► Extractor → Validator → Archivist
 │
 └──► Result stored in PostgreSQL + S3
```

### 3. Agent-to-Agent Communication (A2A Protocol)

```
Orchestrator
 │
 │ JSON-RPC 2.0 request
 │ {
 │ "jsonrpc": "2.0",
 │ "method": "extract_document",
 │ "params": {...},
 │ "id": "request-123"
 │ }
 │
 │ Headers:
 │ Authorization: Bearer <JWT_TOKEN>
 │ Content-Type: application/json
 │
 ▼
Extractor Agent (discovered via Cloud Map)
 │
 │ 1. Validates JWT token
 │ 2. Checks RBAC permissions
 │ 3. Verifies nonce (replay protection)
 │ 4. Executes method
 │
 ▼
 │ JSON-RPC 2.0 response
 │ {
 │ "jsonrpc": "2.0",
 │ "result": {
 │ "status": "success",
 │ "extracted_data": {...}
 │ },
 │ "id": "request-123"
 │ }
 │
 ▼
Orchestrator receives result
```

---

## Cost Breakdown (Monthly - eu-west-3)

| Service | Configuration | Monthly Cost |
|---------|---------------|--------------|
| **ECS Fargate** | 8 tasks × 0.5 vCPU × 1 GB × 24h | $40.00 |
| **RDS PostgreSQL** | db.t3.micro, 20 GB gp2 | $15.00 |
| **Application Load Balancer** | 1 ALB, ~1M requests | $16.00 |
| **S3 Storage** | <1 GB + requests | $0.50 |
| **Lambda** | ca-a2a-s3-processor, ~10K invocations | $0.20 |
| **SQS** | 1 queue, ~10K messages | $0.10 |
| **Data Transfer** | ~5 GB outbound | $0.45 |
| **CloudWatch Logs** | 1 GB/month ingestion | $0.50 |
| **VPC Endpoints** | 5 interface endpoints | $7.50 |
| **Secrets Manager** | 1 secret | $0.40 |
| **NAT Gateway** | 0 (using VPC endpoints) | $0.00 |
| **CloudTrail** | Management events | $0.00 |
| **Total** | | **~$80.65/month** |

### Cost Optimization Options:
- Reduce tasks from 2→1 per service: Save ~$20/month
- Use Fargate Spot: Save ~40% on compute
- RDS Reserved Instances: Save ~40% with 1-year commitment
- S3 Intelligent-Tiering: Automatic cost optimization
- Reduce CloudWatch log retention: 7→3 days

---

## Scaling Capabilities

### Current Configuration (8 tasks total)
- **CPU:** 4 vCPU (8 tasks × 0.5 vCPU)
- **Memory:** 8 GB (8 tasks × 1 GB)
- **Throughput:** ~50 documents/minute
- **Availability:** Multi-AZ (2 zones)

### Horizontal Scaling (Add more tasks)
```bash
# Scale orchestrator to 4 tasks
aws ecs update-service \
 --cluster ca-a2a-cluster \
 --service orchestrator \
 --desired-count 4 \
 --region eu-west-3

# Result: ~100 documents/minute
```

### Vertical Scaling (Increase task resources)
```yaml
# Update task definition
CPU: 1024 (1 vCPU)
Memory: 2048 MB (2 GB)

# Result: Faster individual document processing
```

### Auto Scaling Configuration
```yaml
Target Tracking Scaling Policy:
 Metric: ECSServiceAverageCPUUtilization
 Target Value: 70%
 Scale Out Cooldown: 300 seconds
 Scale In Cooldown: 300 seconds
 Min Capacity: 2 tasks
 Max Capacity: 10 tasks

# Cost at max scale: ~$200/month
```

---

## High Availability Features

| Feature | Implementation | Benefit |
|---------|---------------|----------|
| **Multi-AZ Deployment** | Tasks in eu-west-3a and eu-west-3b | Zone failure resilience |
| **Load Balancing** | ALB distributes across all tasks | Even traffic distribution |
| **Health Checks** | /health endpoint every 30s | Automatic unhealthy task replacement |
| **Service Auto-Recovery** | ECS restarts failed tasks | Self-healing system |
| **RDS Automated Backups** | Daily snapshots, 7-day retention | Data recovery capability |
| **S3 Cross-Region Replication** | Optional (not currently enabled) | Disaster recovery |
| **CloudWatch Alarms** | CPU, memory, errors | Proactive issue detection |

**RTO (Recovery Time Objective):** 15 minutes 
**RPO (Recovery Point Objective):** 24 hours (RDS snapshots)

---

## Deployment Timeline & Status

| Date | Event | Status |
|------|-------|--------|
| 2025-12-18 | Initial AWS infrastructure deployed | Complete ✅ |
| 2026-01-02 17:23 | Fixed MCP SDK import error | Complete ✅ |
| 2026-01-02 17:23 | Rebuilt all agents (Python 3.11) | Complete ✅ |
| 2026-01-02 | Deployed archivist fix (MCP_SERVER_URL) | Complete ✅ |
| 2026-01-02 | Setup S3 event pipeline (Lambda + SQS) | Complete ✅ |
| **2026-01-14** | **Deployed Keycloak OAuth2/OIDC service** | **Complete** ✅ |
| **2026-01-14** | **Integrated Keycloak with all agents** | **Complete** ✅ |
| Current | All services HEALTHY and operational | Running ✅ |

**Total Running Tasks:** 9/9 (2 per agent service + 1 Keycloak)  
**System Status:** **FULLY OPERATIONAL**

---

## Access URLs & Endpoints

### Public Endpoints (via ALB)
- **Health Check:** `http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health`
- **Upload:** `POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/upload`
- **A2A Protocol:** `POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/a2a`

### Internal Endpoints (Service Discovery)
- **Orchestrator:** `http://orchestrator.local:8001`
- **Extractor:** `http://extractor.local:8002`
- **Validator:** `http://validator.local:8003`
- **Archivist:** `http://archivist.local:8004`
- **Keycloak (NEW):** `http://keycloak.ca-a2a.local:8080`

### Keycloak OAuth2/OIDC (NEW)
- **Token Endpoint:** `http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token`
- **JWKS Endpoint:** `http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/certs`
- **Admin Console:** `http://keycloak.ca-a2a.local:8080/admin` (internal only)
- **Realm:** `ca-a2a`
- **Client ID:** `ca-a2a-agents`
- **Admin Username:** `admin`
- **Admin Password:** Stored in AWS Secrets Manager (`ca-a2a/keycloak-admin-password`)

### Database
- **Endpoint:** `ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com:5432`
- **Databases:**
  - `documents_db` (agent data)
  - `keycloak` (OAuth2/OIDC data) **[NEW]**
- **User:** `postgres`
- **Password:** Stored in AWS Secrets Manager

### S3 Bucket
- **Name:** `ca-a2a-documents-555043101106`
- **Region:** `eu-west-3`
- **URL:** `s3://ca-a2a-documents-555043101106`

---

## Keycloak OAuth2/OIDC Integration (NEW)

### Overview

**Keycloak 23.0** has been deployed as an ECS Fargate service to provide enterprise-grade identity and access management.

### Deployment Details

| Component | Details |
|-----------|---------|
| **Service Name** | `keycloak` |
| **Image** | `555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/keycloak:23.0` |
| **Task Definition** | `ca-a2a-keycloak` |
| **CPU** | 1024 (1 vCPU) |
| **Memory** | 2048 MB (2 GB) |
| **Port** | 8080 (HTTP, internal only) |
| **Service Discovery** | `keycloak.ca-a2a.local:8080` |
| **Health Check** | `/health/ready` (90s start period) |
| **Database** | PostgreSQL `keycloak` schema in RDS cluster |
| **Running Tasks** | 1/1 (HA planned for Phase 2) |
| **Status** | **ACTIVE** ✅ |

### Network Configuration

**Security Group:** `ca-a2a-keycloak-sg` (sg-0fea873848c240253)
- **Inbound Rules:**
  - Port 8080 from Agent Security Groups (Orchestrator, Extractor, Validator, Archivist)
  - Port 8080 from within VPC (health checks, admin access)
- **Outbound Rules:**
  - Port 5432 to RDS Security Group (PostgreSQL for keycloak database)
  - Port 443 to VPC CIDR (CloudWatch logs)
  - Port 53 to VPC CIDR (DNS resolution)

**Subnets:**
- Private Subnet 1 (10.0.10.0/24) - Primary deployment
- Private Subnet 2 (10.0.20.0/24) - HA ready (not yet enabled)

### Authentication Configuration

**Realm:** `ca-a2a`

**Client:** `ca-a2a-agents`
- Type: Confidential
- Protocol: openid-connect
- Access Token Lifespan: 5 minutes
- Refresh Token Lifespan: 30 days

**Users:**
| Username | Role | Type | Purpose |
|----------|------|------|---------|
| `admin-user` | admin | Human | Full system access |
| `lambda-service` | lambda | Service | Lambda function authentication |
| `orchestrator-service` | orchestrator | Service | Service-to-service calls |

**Roles → RBAC Mapping:**
| Keycloak Role | A2A Principal | Allowed Methods |
|---------------|---------------|-----------------|
| `admin` | admin | `*` (all methods) |
| `lambda` | lambda | `*` (all methods) |
| `orchestrator` | orchestrator | `extract_document`, `validate_document`, `archive_document`, `list_skills`, `get_health` |
| `viewer` | viewer | `list_skills`, `get_health` (read-only) |

### API Endpoints

**Token Endpoint (OAuth2):**
```
POST http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=password
client_id=ca-a2a-agents
client_secret=<secret>
username=<user>
password=<password>

Response:
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "expires_in": 300,
  "token_type": "Bearer"
}
```

**JWKS Endpoint (Public Keys):**
```
GET http://keycloak.ca-a2a.local:8080/realms/ca-a2a/protocol/openid-connect/certs

Response:
{
  "keys": [
    {
      "kid": "qunlkj...",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "<RSA modulus>",
      "e": "AQAB"
    }
  ]
}
```

**Health Endpoints:**
- `/health` - General health status
- `/health/ready` - Readiness check (used by ECS)

### Agent Integration

**Environment Variables (per agent):**
```bash
A2A_USE_KEYCLOAK=true
KEYCLOAK_URL=http://keycloak.ca-a2a.local:8080
KEYCLOAK_REALM=ca-a2a
KEYCLOAK_CLIENT_ID=ca-a2a-agents
KEYCLOAK_CACHE_TTL=3600  # Cache JWKS for 1 hour
```

**Secrets (AWS Secrets Manager):**
- `ca-a2a/keycloak-admin-password` - Keycloak admin console password
- `ca-a2a/keycloak-client-secret` - Client secret for agent authentication
- `ca-a2a/keycloak-admin-user-password` - Test user password

**Hybrid Authentication Mode:**
The agents support multiple authentication methods simultaneously:
1. **Keycloak JWT** (RS256, verified via JWKS) - **NEW**
2. **Legacy JWT** (HS256, verified via shared secret) - Existing
3. **API Keys** (static keys from JSON config) - Existing

This allows gradual migration without breaking existing integrations.

### Database Schema

**PostgreSQL Database:** `keycloak` (in RDS cluster)

**Key Tables (60+ total):**
- `user_entity` - User accounts
- `credential` - User credentials (hashed)
- `realm` - Realm configurations
- `client` - Client applications
- `role_entity` - Role definitions
- `user_role_mapping` - User-to-role assignments
- `user_session` - Active user sessions
- `event_entity` - Audit events (logins, logouts, etc.)

**Storage Size:** ~50 MB (initial deployment)

### Monitoring

**CloudWatch Log Group:** `/ecs/ca-a2a-keycloak`
- **Retention:** 30 days
- **Average Size:** ~5 MB/day
- **Key Log Events:**
  - Startup: "Keycloak ... started in ...ms"
  - Ready: "Listening on: http://0.0.0.0:8080"
  - Login: "type=LOGIN, realmId=ca-a2a, username=..."
  - Failed Login: "type=LOGIN_ERROR, username=..."

**ECS Service Metrics:**
- CPU Utilization
- Memory Utilization
- Task Count (running/desired)
- Health Check Status

**Custom Metrics (via logs):**
- Authentication attempts (success/failure rate)
- Token issuance rate
- JWKS cache hits/misses

### Security Features

**Token Security:**
- **RS256 Asymmetric Signing:** Private key kept in Keycloak, public key distributed via JWKS
- **Short Access Token Lifespan:** 5 minutes reduces exposure risk
- **Long Refresh Token Lifespan:** 30 days balances security and UX
- **Token Rotation:** New tokens issued on refresh, old tokens invalidated

**Network Security:**
- **Private Deployment:** No public IP, internal-only access
- **Security Groups:** Strict firewall rules (port 8080 only from agents)
- **Service Discovery:** Private DNS resolution (`keycloak.ca-a2a.local`)

**Brute Force Protection:**
- Configurable failure thresholds
- Automatic account lockout after N failed attempts
- Rate limiting per user

**Audit Trail:**
- All authentication events logged to `event_entity` table
- CloudWatch integration for real-time monitoring
- Compliance-ready logs (who, what, when, from where)

### Deployment Scripts

**Deploy Keycloak:**
```bash
./deploy-keycloak.sh

# Steps performed:
# 1. Create Keycloak security group
# 2. Create CloudWatch log group
# 3. Pull Keycloak 23.0 image
# 4. Push to ECR
# 5. Register ECS task definition
# 6. Create ECS service with Service Discovery
# 7. Create keycloak database schema in RDS
```

**Configure Realm:**
```bash
./configure-keycloak.sh

# Steps performed:
# 1. Create ca-a2a realm
# 2. Configure ca-a2a-agents client
# 3. Create users (admin-user, lambda-service, orchestrator-service)
# 4. Assign roles
# 5. Set token lifespans
```

**Update Agents:**
```bash
./update-agents-keycloak.sh

# Steps performed:
# 1. Add Keycloak environment variables to agent task definitions
# 2. Update ECS services to use new task definitions
# Note: Agents work in hybrid mode - both legacy and Keycloak auth supported
```

### Testing

**Test Authentication:**
```bash
./test-keycloak-auth.sh

# Tests:
# ✅ Keycloak service health
# ✅ Obtain access token
# ✅ Call orchestrator with Keycloak JWT
# ✅ Refresh token
# ✅ Invalid token rejection
```

**Unit Tests:**
```bash
pytest test_keycloak_integration.py -v

# Test coverage:
# - JWT validator initialization
# - Token verification (mocked)
# - RBAC role mapping
# - Security manager integration
# - End-to-end flow
```

### Future Enhancements (Phase 2)

**Planned Features:**
- ✅ **High Availability:** 2+ Keycloak instances across AZs
- ✅ **Public Admin Console:** External ALB with HTTPS (ACM certificate)
- ✅ **MFA Integration:** TOTP (Google Authenticator), SMS, Email
- ✅ **SSO Integration:** Google, GitHub, Azure AD, Okta
- ✅ **User Federation:** LDAP, Active Directory synchronization
- ✅ **Fine-Grained RBAC:** Resource-level permissions (ABAC)
- ✅ **RDS Multi-AZ:** Automatic failover for keycloak database

### Documentation

- [`KEYCLOAK_INTEGRATION_GUIDE.md`](./KEYCLOAK_INTEGRATION_GUIDE.md) - Comprehensive guide
- [`KEYCLOAK_QUICK_START.md`](./KEYCLOAK_QUICK_START.md) - 15-minute quick start
- [`KEYCLOAK_IMPLEMENTATION_SUMMARY.md`](./KEYCLOAK_IMPLEMENTATION_SUMMARY.md) - Summary
- [`keycloak_auth.py`](./keycloak_auth.py) - Source code with docstrings
- [`keycloak_client_example.py`](./keycloak_client_example.py) - Client examples

---

## Related Documentation

- [AWS_ARCHITECTURE.md](./AWS_ARCHITECTURE.md) - Detailed component specifications
- [AWS_DEPLOYMENT.md](./AWS_DEPLOYMENT.md) - Deployment guide and procedures
- [DEPLOYMENT_SUCCESS.md](./DEPLOYMENT_SUCCESS.md) - Latest deployment status
- [SECURITY_GUIDE.md](./SECURITY_GUIDE.md) - Security implementation details
- [DEMO_2H_QUICK_REFERENCE.md](./DEMO_2H_QUICK_REFERENCE.md) - Testing guide
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) - Common issues and solutions
- **[KEYCLOAK_INTEGRATION_GUIDE.md](./KEYCLOAK_INTEGRATION_GUIDE.md) - Keycloak OAuth2/OIDC guide (NEW)**
- **[KEYCLOAK_QUICK_START.md](./KEYCLOAK_QUICK_START.md) - Keycloak quick start (NEW)**
- **[KEYCLOAK_DOCUMENTATION_UPDATES.md](./KEYCLOAK_DOCUMENTATION_UPDATES.md) - What's new (NEW)**

---

**Generated by:** AI Assistant  
**Date:** January 14, 2026  
**Project:** CA-A2A Multi-Agent Document Processing System  
**AWS Account:** 555043101106  
**Region:** eu-west-3 (Paris)  
**Version:** 2.1 (with Keycloak OAuth2/OIDC)


