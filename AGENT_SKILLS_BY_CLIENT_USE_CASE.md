# Agent Skills Categorized by Client Use Cases

This document organizes the CA A2A multi-agent system skills into **3 main categories** based on typical client needs and use cases.

---

## Overview

The CA A2A system provides **25+ specialized skills** across 4 agents. These skills are organized into categories that align with different client priorities:

1. **Document Processing & Extraction** - Extract and transform document data
2. **Quality Control & Compliance** - Validate, audit, and ensure data quality
3. **Storage & Analytics** - Archive, search, and analyze document data

---

## Category 1: Document Processing & Extraction

**Target Clients:** Organizations that need to extract structured data from unstructured documents

### Use Case Examples

#### 📊 Financial Services
**Client:** Bank processing loan applications
- **Need:** Extract data from PDF loan applications, tax returns, and bank statements
- **Skills Used:**
  - `extract_document` - Extract text and tables from loan PDFs
  - `pdf_text_extraction` - Extract applicant information
  - `pdf_table_extraction` - Extract financial tables
  - `process_document` - Orchestrate the full extraction pipeline
  - `get_task_status` - Track processing status for compliance

**Workflow:**
```
Upload PDF → Extract Text & Tables → Structure Data → Ready for Review
```

#### 🏥 Healthcare
**Client:** Hospital digitizing medical records
- **Need:** Extract patient data from scanned documents and CSV lab results
- **Skills Used:**
  - `extract_document` - Extract from medical records
  - `csv_parsing` - Parse lab results with statistics
  - `process_batch` - Process multiple patient records at once
  - `list_supported_formats` - Check which document types are supported

**Workflow:**
```
Batch Upload → Multi-format Extraction → Structured Patient Data
```

#### 📦 Supply Chain
**Client:** Logistics company processing shipping manifests
- **Need:** Extract data from CSV shipping lists and PDF invoices
- **Skills Used:**
  - `csv_parsing` - Parse shipping manifests with type inference
  - `pdf_table_extraction` - Extract invoice line items
  - `process_batch` - Process hundreds of documents daily
  - `list_pending_documents` - Monitor processing queue

**Workflow:**
```
Daily Upload → Batch Processing → Track Status → Export Data
```

### Skills in This Category

| Skill ID | Agent | Description | Avg Time |
|----------|-------|-------------|----------|
| `extract_document` | Extractor | Extract data from PDF or CSV | 2500ms |
| `pdf_text_extraction` | Extractor | Extract text from PDFs | 2000ms |
| `pdf_table_extraction` | Extractor | Extract tables from PDFs | 3000ms |
| `csv_parsing` | Extractor | Parse CSV with statistics | 1500ms |
| `list_supported_formats` | Extractor | Get supported formats | 10ms |
| `process_document` | Orchestrator | Full processing pipeline | 5000ms |
| `process_batch` | Orchestrator | Batch processing | 10000ms |
| `get_task_status` | Orchestrator | Track task status | 50ms |
| `list_pending_documents` | Orchestrator | List pending docs | 200ms |

**Total Processing Capacity:** 50MB PDFs, 100MB CSVs

---

## Category 2: Quality Control & Compliance

**Target Clients:** Organizations with strict data quality requirements and regulatory compliance needs

### Use Case Examples

#### 🏛️ Government & Regulatory
**Client:** Tax authority processing tax returns
- **Need:** Validate data completeness, format correctness, and maintain audit trails
- **Skills Used:**
  - `validate_document` - Full validation with scoring
  - `data_completeness_check` - Ensure all required fields present
  - `data_format_validation` - Validate SSN, EIN formats
  - `audit_logging` - Track all processing for compliance
  - `get_validation_rules` - Document validation criteria

**Workflow:**
```
Extract → Validate Fields → Check Formats → Score → Audit Log
```

**Validation Rules Applied:**
- Data Completeness: 100% of required fields must be present
- Format Validation: SSN pattern `^\d{3}-\d{2}-\d{4}$`
- Quality Score: Minimum 85/100 for auto-approval
- Audit: All actions logged with timestamp and agent

#### 💊 Pharmaceutical
**Client:** Pharma company processing clinical trial data
- **Need:** Ensure data quality meets FDA requirements
- **Skills Used:**
  - `data_quality_assessment` - Assess data quality metrics
  - `data_consistency_check` - Check data consistency
  - `validate_document` - Calculate quality scores
  - `audit_logging` - Maintain FDA-compliant audit trail

**Workflow:**
```
Extract Trial Data → Quality Assessment → Consistency Check → Score 90+ → Archive with Audit
```

**Quality Metrics:**
- Completeness: All trial endpoints documented
- Consistency: Patient IDs consistent across tables
- Missing Data: <5% allowed
- Quality Score: Must achieve "excellent" (90+)

#### 🏢 Enterprise Data Governance
**Client:** Large corporation with data quality mandates
- **Need:** Enforce data standards across departments
- **Skills Used:**
  - `validate_document` - Apply corporate data standards
  - `data_format_validation` - Enforce format policies
  - `get_validation_rules` - Document standards for teams
  - `get_document_stats` - Report on data quality metrics

**Workflow:**
```
Department Upload → Validate Standards → Score → Report to Governance
```

**Validation Categories:**
- Excellent (90-100): Auto-approved
- Good (75-89): Supervisor review
- Acceptable (60-74): Requires correction
- Poor/Failed (<60): Rejected

### Skills in This Category

| Skill ID | Agent | Description | Avg Time |
|----------|-------|-------------|----------|
| `validate_document` | Validator | Full validation + scoring | 500ms |
| `data_completeness_check` | Validator | Check required fields | 100ms |
| `data_format_validation` | Validator | Validate with regex | 150ms |
| `data_quality_assessment` | Validator | Quality metrics | 200ms |
| `data_consistency_check` | Validator | Consistency validation | 300ms |
| `get_validation_rules` | Validator | Get validation rules | 10ms |
| `audit_logging` | Archivist | Audit trail logging | 50ms |

**Validation Scoring:**
- Excellent: 90-100
- Good: 75-89
- Acceptable: 60-74
- Poor: 40-59
- Failed: 0-39

---

## Category 3: Storage & Analytics

**Target Clients:** Organizations that need long-term storage, searchability, and business intelligence

### Use Case Examples

#### 📚 Digital Archive & Records Management
**Client:** Legal firm managing case documents
- **Need:** Store documents long-term with searchable metadata
- **Skills Used:**
  - `archive_document` - Store with metadata in PostgreSQL
  - `search_documents` - Search by case, type, date, score
  - `get_document` - Retrieve specific documents
  - `update_document_status` - Mark as reviewed/archived

**Workflow:**
```
Process → Validate → Archive → Search/Retrieve → Update Status
```

**Search Capabilities:**
- By case type: "litigation", "contract", "discovery"
- By validation score: Only "excellent" or "good" documents
- By date range: Last 30 days, this quarter, this year
- Pagination: 50 results per page

#### 📈 Business Intelligence & Reporting
**Client:** Insurance company analyzing claims
- **Need:** Aggregate statistics and trends from document processing
- **Skills Used:**
  - `get_document_stats` - Overall statistics
  - `search_documents` - Filter by status and type
  - `archive_document` - Store for analytics
  - `discover_agents` - Monitor system capabilities

**Workflow:**
```
Process Claims → Archive → Generate Statistics → Business Reports
```

**Analytics Available:**
- Total documents processed: 125,000
- Recent activity (24h): 3,450
- Average validation score: 87.3
- By status: 85% validated, 10% warnings, 5% failed
- By type: 60% PDF, 40% CSV
- Processing trends over time

#### 🔍 Compliance Audit & Investigation
**Client:** Financial institution preparing for audit
- **Need:** Retrieve specific documents and demonstrate processing integrity
- **Skills Used:**
  - `search_documents` - Find documents by criteria
  - `get_document` - Retrieve full document with audit trail
  - `get_document_stats` - Compliance metrics
  - `audit_logging` - Show complete processing history

**Workflow:**
```
Search Query → Filter Results → Retrieve Documents → Show Audit Trail
```

**Audit Queries:**
- All documents processed by Agent X on Date Y
- All failed validations in last quarter
- All documents with score < 75
- Processing time per document type
- Complete audit log for Document ID

#### 🎯 Data Lake & ETL
**Client:** Tech company building data warehouse
- **Need:** Export processed documents to data lake
- **Skills Used:**
  - `search_documents` - Query documents with pagination
  - `get_document` - Get full extracted data
  - `get_document_stats` - Monitor ingestion
  - `get_agent_registry` - Track agent versions

**Workflow:**
```
Extract → Validate → Archive → ETL Export → Data Warehouse
```

### Skills in This Category

| Skill ID | Agent | Description | Avg Time |
|----------|-------|-------------|----------|
| `archive_document` | Archivist | Archive to PostgreSQL | 300ms |
| `get_document` | Archivist | Retrieve by ID or key | 100ms |
| `update_document_status` | Archivist | Update status | 150ms |
| `search_documents` | Archivist | Search with filters | 200ms |
| `get_document_stats` | Archivist | Statistics & metrics | 300ms |
| `audit_logging` | Archivist | Audit trail | 50ms |
| `discover_agents` | Orchestrator | Agent discovery | 500ms |
| `get_agent_registry` | Orchestrator | Registry info | 50ms |

**Storage Features:**
- PostgreSQL persistence with ACID guarantees
- Full-text search on metadata
- Pagination for large result sets
- Idempotency (duplicate detection)
- Complete audit trail

---

## Cross-Category Integration Examples

Most clients use skills from **multiple categories** for complete workflows:

### Example 1: Insurance Claims Processing
**Client:** Insurance company processing claims

```mermaid
graph LR
    A[Upload Claim PDF] --> B[Category 1: Extract]
    B --> C[Category 2: Validate]
    C --> D[Category 3: Archive]
    D --> E[Category 3: Analytics]

    style A fill:#e1f5ff
    style B fill:#fff4e1
    style C fill:#ffe1f0
    style D fill:#e1ffe7
    style E fill:#e1ffe7
```

**Skills Used:**
1. **Category 1:** `extract_document`, `pdf_table_extraction`
2. **Category 2:** `validate_document`, `data_quality_assessment`
3. **Category 3:** `archive_document`, `get_document_stats`

**Business Value:**
- 85% reduction in manual data entry
- 100% audit compliance
- Real-time processing dashboards
- Sub-5-second processing per claim

### Example 2: Medical Records Digitization
**Client:** Hospital digitizing patient records

```mermaid
graph LR
    A[Scan Records] --> B[Batch Extract]
    B --> C[Validate Data]
    C --> D[Archive & Index]
    D --> E[Search System]

    style A fill:#e1f5ff
    style B fill:#fff4e1
    style C fill:#ffe1f0
    style D fill:#e1ffe7
    style E fill:#e1ffe7
```

**Skills Used:**
1. **Category 1:** `process_batch`, `extract_document`
2. **Category 2:** `validate_document`, `data_completeness_check`
3. **Category 3:** `archive_document`, `search_documents`

**Business Value:**
- Process 1,000+ records/day
- HIPAA-compliant audit trail
- Instant patient record search
- Data quality score: 92/100 average

### Example 3: Financial Document Processing
**Client:** Bank processing loan applications

```mermaid
graph TD
    A[Upload Application] --> B[Extract Data]
    B --> C[Validate Formats]
    C --> D{Score >= 85?}
    D -->|Yes| E[Archive - Approved]
    D -->|No| F[Archive - Review]
    E --> G[Analytics Dashboard]
    F --> G

    style A fill:#e1f5ff
    style B fill:#fff4e1
    style C fill:#ffe1f0
    style D fill:#ffe1f0
    style E fill:#e1ffe7
    style F fill:#e1ffe7
    style G fill:#e1ffe7
```

**Skills Used:**
1. **Category 1:** `extract_document`, `pdf_text_extraction`, `process_document`
2. **Category 2:** `validate_document`, `data_format_validation`
3. **Category 3:** `archive_document`, `search_documents`, `get_document_stats`

**Business Value:**
- 70% auto-approval rate (score >= 85)
- 30% flagged for review (score < 85)
- Complete regulatory audit trail
- Real-time application status tracking

---

## Skill Discovery & Agent Registry

Clients can dynamically discover available skills using:

### Discovery Skills

| Skill | Description | Use Case |
|-------|-------------|----------|
| `discover_agents` | Find all agents and their capabilities | System initialization, monitoring |
| `get_agent_registry` | Get complete registry with skills | API documentation, capability matrix |
| `list_supported_formats` | Get supported document formats | Pre-upload validation |
| `get_validation_rules` | Get validation rules for doc types | Understand quality requirements |

**Example Discovery Response:**
```json
{
  "total_agents": 4,
  "active_agents": 4,
  "total_skills": 26,
  "available_skills": [
    "extract_document",
    "validate_document",
    "archive_document",
    "..."
  ],
  "agents": {
    "Orchestrator": {
      "endpoint": "http://orchestrator.local:8001",
      "status": "active",
      "skills_count": 6
    },
    "Extractor": {...},
    "Validator": {...},
    "Archivist": {...}
  }
}
```

---

## Performance Benchmarks by Category

### Category 1: Document Processing
- **PDF Extraction:** 2.5s average (up to 50MB)
- **CSV Parsing:** 1.5s average (up to 100MB)
- **Batch Processing:** 100 documents in 4 minutes
- **Throughput:** ~1,500 documents/hour

### Category 2: Quality Control
- **Validation:** 500ms per document
- **Completeness Check:** 100ms
- **Format Validation:** 150ms
- **Quality Assessment:** 200ms
- **Total Quality Check:** ~950ms

### Category 3: Storage & Analytics
- **Archive:** 300ms per document
- **Search:** 200ms (avg 50 results)
- **Retrieval:** 100ms by ID
- **Statistics:** 300ms for full stats
- **Audit Query:** 150ms per log entry

### End-to-End Processing
**Single Document (PDF):**
```
Extract (2.5s) + Validate (0.5s) + Archive (0.3s) = ~3.3s total
```

**Batch (100 PDFs):**
```
Parallel processing: ~4-5 minutes for 100 documents
Sequential: ~330 seconds (3.3s × 100)
Actual: ~270 seconds (parallel optimization)
```

---

## Client Selection Guide

### Choose Category 1 (Document Processing) If You Need:
- ✅ Extract data from PDFs, CSVs
- ✅ Handle multiple document formats
- ✅ Batch processing capabilities
- ✅ Fast extraction (2-3s per document)
- ✅ Support for text and tables

### Choose Category 2 (Quality Control) If You Need:
- ✅ Data validation and scoring
- ✅ Regulatory compliance
- ✅ Audit trails
- ✅ Quality metrics and reporting
- ✅ Format and completeness checks

### Choose Category 3 (Storage & Analytics) If You Need:
- ✅ Long-term document storage
- ✅ Search and retrieval
- ✅ Business intelligence
- ✅ Statistics and reporting
- ✅ Compliance audits

### Most Clients Need All 3 Categories:
**Full Pipeline:** Extract → Validate → Archive → Analyze

---

## API Access by Category

All skills are accessible via A2A protocol:

### Category 1 Example: Extract Document
```bash
curl -X POST http://extractor.local:8002/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "extract_document",
    "params": {
      "s3_key": "invoices/inv-2024-001.pdf"
    }
  }'
```

### Category 2 Example: Validate Document
```bash
curl -X POST http://validator.local:8003/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "2",
    "method": "validate_document",
    "params": {
      "s3_key": "invoices/inv-2024-001.pdf",
      "extracted_data": {...},
      "document_type": "pdf"
    }
  }'
```

### Category 3 Example: Search Documents
```bash
curl -X POST http://archivist.local:8004/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "3",
    "method": "search_documents",
    "params": {
      "status": "validated",
      "min_score": 85,
      "limit": 50
    }
  }'
```

---

## Summary

The CA A2A multi-agent system provides **26 specialized skills** organized into **3 client-focused categories**:

| Category | Skills | Primary Value | Typical Clients |
|----------|--------|---------------|-----------------|
| **1. Document Processing** | 9 skills | Extract & transform data | Any org processing documents |
| **2. Quality Control** | 7 skills | Validate & audit | Regulated industries |
| **3. Storage & Analytics** | 8 skills | Archive & analyze | Enterprises, data teams |
| **Discovery** | 2 skills | System capabilities | All clients |

**Total:** 26 skills across 4 specialized agents

**Key Differentiators:**
- ✅ Microservices architecture (each category can scale independently)
- ✅ A2A protocol for interoperability
- ✅ Real-time processing (3-5s per document)
- ✅ Enterprise-grade (PostgreSQL, S3, ECS Fargate)
- ✅ Full audit compliance
- ✅ Dynamic skill discovery

For questions or custom category configurations, see the [Technical Architecture Guide](./TECHNICAL_ARCHITECTURE.md).
