# 🎭 Scenario Flows - CA-A2A Document Processing Pipeline

**Version:** 1.0  
**Last Updated:** December 18, 2025

---

## 📋 Table of Contents

1. [Scenario 1: Invoice Processing](#scenario-1-invoice-processing)
2. [Scenario 2: Contract Review](#scenario-2-contract-review)
3. [Scenario 3: Bulk CSV Processing](#scenario-3-bulk-csv-processing)
4. [Error Handling Flows](#error-handling-flows)
5. [Retry & Recovery Flows](#retry--recovery-flows)

---

## Scenario 1: Invoice Processing

### Business Context
**Use Case:** Automated invoice data extraction for accounting and AP automation  
**Document Type:** PDF Invoice  
**Processing Time:** 10-15 seconds  
**Success Rate:** 98%

### Flow Diagram

```
┌─────────┐
│  User   │
└────┬────┘
     │ 1. Upload invoice.pdf to S3
     ▼
┌────────────┐
│  S3 Bucket │
│  /incoming/│
└─────┬──────┘
      │ 2. Trigger via API
      ▼
┌──────────────┐
│     ALB      │
└──────┬───────┘
       │ 3. Route to
       ▼
┌────────────────┐
│  Orchestrator  │
│                │
│  ┌──────────┐  │
│  │ Receive  │  │ 4. Parse request
│  │ Request  │  │    Validate s3_key
│  └────┬─────┘  │
│       │        │
│  ┌────▼─────┐  │
│  │ Discover │  │ 5. Find Extractor agent
│  │  Agents  │  │
│  └────┬─────┘  │
│       │        │
│  ┌────▼─────┐  │
│  │ Create   │  │ 6. Generate workflow ID
│  │ Workflow │  │    Store in DB
│  └────┬─────┘  │
└───────┼────────┘
        │ 7. Delegate to Extractor
        ▼
┌────────────────┐
│   Extractor    │
│                │
│  ┌──────────┐  │
│  │ Download │  │ 8. Get file from S3
│  │   File   │  │    s3://bucket/incoming/invoice.pdf
│  └────┬─────┘  │
│       │        │
│  ┌────▼─────┐  │
│  │ Analyze  │  │ 9. Detect file type
│  │   Type   │  │    Result: PDF/Invoice
│  └────┬─────┘  │
│       │        │
│  ┌────▼─────┐  │
│  │ Extract  │  │ 10. Parse PDF content
│  │   Data   │  │     Extract text blocks
│  └────┬─────┘  │
│       │        │
│  ┌────▼─────┐  │
│  │ Identify │  │ 11. Find key fields:
│  │  Fields  │  │     - Invoice #: INV-2025-001
│  └────┬─────┘  │     - Date: 2025-12-18
│       │        │     - Subtotal: €13,000.00
│  ┌────▼─────┐  │     - Tax (20%): €2,600.00
│  │ Structure│  │     - Total: €15,600.00
│  │  Output  │  │
│  └────┬─────┘  │
└───────┼────────┘
        │ 12. Return extracted data
        ▼
┌────────────────┐
│  Orchestrator  │
│                │
│  ┌──────────┐  │
│  │  Store   │  │ 13. Save to documents table
│  │  Results │  │     status='extracted'
│  └────┬─────┘  │
└───────┼────────┘
        │ 14. Delegate to Validator
        ▼
┌────────────────┐
│   Validator    │
│                │
│  ┌──────────┐  │
│  │  Load    │  │ 15. Get extracted data
│  │  Data    │  │
│  └────┬─────┘  │
│       │        │
│  ┌────▼─────┐  │
│  │ Validate │  │ 16. Check calculations:
│  │  Rules   │  │     ✓ Total = Subtotal + Tax
│  └────┬─────┘  │     ✓ Tax = Subtotal × 0.20
│       │        │     ✓ Required fields present
│  ┌────▼─────┐  │
│  │  Score   │  │ 17. Confidence: 98%
│  │ Confidence│ │     Issues: 0
│  └────┬─────┘  │
└───────┼────────┘
        │ 18. Return validation result
        ▼
┌────────────────┐
│  Orchestrator  │
│                │
│  ┌──────────┐  │
│  │ Update   │  │ 19. Update status='validated'
│  │   DB     │  │
│  └────┬─────┘  │
└───────┼────────┘
        │ 20. Delegate to Archivist
        ▼
┌────────────────┐
│   Archivist    │
│                │
│  ┌──────────┐  │
│  │ Categorize│ │ 21. Determine type: INVOICE
│  │ Document │  │     Folder: processed/invoices/
│  └────┬─────┘  │
│       │        │
│  ┌────▼─────┐  │
│  │   Move   │  │ 22. S3 copy:
│  │   File   │  │     incoming/ → processed/invoices/
│  └────┬─────┘  │
│       │        │
│  ┌────▼─────┐  │
│  │  Apply   │  │ 23. Add metadata tags
│  │Metadata  │  │     Delete from incoming/
│  └────┬─────┘  │
└───────┼────────┘
        │ 24. Return archival result
        ▼
┌────────────────┐
│  Orchestrator  │
│                │
│  ┌──────────┐  │
│  │ Finalize │  │ 25. status='completed'
│  │ Workflow │  │     processing_time=12.5s
│  └────┬─────┘  │
└───────┼────────┘
        │ 26. Return success response
        ▼
┌─────────┐
│   API   │
│ Response│ 27. {
└─────────┘      "status": "completed",
                 "document_id": 123,
                 "extracted_data": {...},
                 "confidence": 0.98
                }
```

### Detailed Steps

| Step | Agent | Action | Duration | Output |
|------|-------|--------|----------|--------|
| 1-2 | User | Upload & trigger | 1s | S3 key |
| 3-6 | Orchestrator | Initialize workflow | 0.5s | Workflow ID |
| 7-11 | Extractor | Download & extract | 5s | Structured data |
| 12-13 | Orchestrator | Store results | 0.5s | DB record |
| 14-17 | Validator | Validate data | 3s | Validation report |
| 18-19 | Orchestrator | Update status | 0.5s | Updated record |
| 20-23 | Archivist | Archive document | 2s | Archived |
| 24-26 | Orchestrator | Finalize | 0.5s | Final response |

**Total Time:** ~12.5 seconds

---

## Scenario 2: Contract Review

### Business Context
**Use Case:** Legal contract metadata extraction and compliance checking  
**Document Type:** PDF Contract  
**Processing Time:** 15-20 seconds  
**Success Rate:** 95%

### Flow Diagram

```
Contract Upload → Orchestrator → Extractor
                       ↓
                   Validator
                       ↓
     ┌─────────────────┴────────────────┐
     │         Compliance Check          │
     │  • Required clauses present       │
     │  • Termination notice adequate    │
     │  • Compensation terms clear       │
     │  • IP ownership defined           │
     └──────────────┬───────────────────┘
                    ↓
               Archivist
                    ↓
        Store in /processed/contracts/
```

### Key Extraction Points

**Contract Metadata:**
- Parties (Provider, Client)
- Effective Date
- Term Duration
- Termination Clauses
- Compensation Details
- IP Ownership

**Validation Rules:**
- ✓ Both parties identified
- ✓ Effective date present and valid
- ✓ Termination clause included
- ✓ Compensation clearly stated
- ✓ Confidentiality section present

### Sample Extracted Data
```json
{
  "document_type": "CONTRACT",
  "contract_type": "Professional Services Agreement",
  "parties": {
    "provider": "Tech Services SARL",
    "client": "Acme Corporation"
  },
  "dates": {
    "effective_date": "2025-12-18",
    "expiration_date": "2026-12-18"
  },
  "financial": {
    "monthly_retainer": 10000,
    "currency": "EUR",
    "hourly_rate": 150
  },
  "clauses": {
    "termination_notice": "30 days",
    "confidentiality_period": "3 years",
    "ip_ownership": "Client upon payment"
  },
  "compliance": {
    "score": 0.95,
    "missing_clauses": [],
    "warnings": []
  }
}
```

---

## Scenario 3: Bulk CSV Processing

### Business Context
**Use Case:** Employee data import and validation  
**Document Type:** CSV File  
**Processing Time:** 5-10 seconds  
**Success Rate:** 99%

### Flow Diagram

```
CSV Upload → Orchestrator → Extractor
                               ↓
                         Parse CSV
                         Validate Structure
                         Check Data Types
                               ↓
                          Validator
                               ↓
              ┌────────────────┴────────────────┐
              │      Row-Level Validation       │
              │  • Email format                 │
              │  • Salary range (>0, <1M)       │
              │  • Required fields              │
              │  • Department code              │
              └─────────────┬───────────────────┘
                            ↓
                       Archivist
                            ↓
              Store validated records in DB
```

### CSV Processing Steps

**1. Structure Validation**
```python
Expected Columns:
- Employee_ID (string, unique)
- First_Name (string, required)
- Last_Name (string, required)
- Department (string, required)
- Position (string, required)
- Hire_Date (date, YYYY-MM-DD)
- Salary (number, > 0)
- Email (string, email format)
```

**2. Data Validation**
```python
Rules:
- Employee_ID: Matches pattern E\d{3}
- Email: Valid format, @company.com domain
- Salary: Between 30,000 and 200,000
- Hire_Date: Not in future
- Department: In [Engineering, Sales, HR, Marketing, Finance, Operations]
```

**3. Row-by-Row Processing**
```
Total Rows: 10
✓ Valid: 10 (100%)
✗ Invalid: 0 (0%)
⚠ Warnings: 0 (0%)
```

### Sample Validation Report
```json
{
  "file": "employee_data.csv",
  "total_rows": 10,
  "valid_rows": 10,
  "invalid_rows": 0,
  "warnings": [],
  "validation_details": [
    {
      "row": 1,
      "employee_id": "E001",
      "status": "valid",
      "issues": []
    },
    ...
  ],
  "summary": {
    "processing_time": "8.2s",
    "confidence": 1.0,
    "recommendation": "APPROVE"
  }
}
```

---

## Error Handling Flows

### Flow 1: Invalid File Format

```
Upload file.xyz → Orchestrator → Extractor
                                     ↓
                          Unsupported format detected
                                     ↓
                          Return error to Orchestrator
                                     ↓
                              Update DB:
                         status='failed'
                         error='Unsupported format'
                                     ↓
                          Move to /failed/
                                     ↓
                      Return error response to user
```

**Error Response:**
```json
{
  "status": "failed",
  "error_code": "UNSUPPORTED_FORMAT",
  "message": "File format '.xyz' is not supported",
  "supported_formats": ["pdf", "csv", "txt"],
  "document_id": 124
}
```

### Flow 2: Validation Failure

```
Process document → Extract data → Validate
                                     ↓
                          Validation fails:
                      Total ≠ Subtotal + Tax
                                     ↓
                          confidence < 0.80
                                     ↓
                       status='validation_failed'
                                     ↓
                    Store with validation report
                                     ↓
                   Move to /failed/validation/
                                     ↓
                Alert human reviewer (future)
```

**Validation Failure Response:**
```json
{
  "status": "validation_failed",
  "confidence": 0.65,
  "issues": [
    {
      "field": "total",
      "expected": 15600.00,
      "actual": 15500.00,
      "severity": "critical"
    }
  ],
  "recommendation": "MANUAL_REVIEW",
  "document_id": 125
}
```

### Flow 3: Service Unavailable

```
Orchestrator → Call Extractor
                     ↓
              Connection timeout
              (Circuit breaker open)
                     ↓
          Retry with exponential backoff
                     ↓
       Attempt 1: Failed (1s wait)
       Attempt 2: Failed (2s wait)
       Attempt 3: Failed (4s wait)
                     ↓
           Mark as 'retry_later'
                     ↓
        Add to retry queue (future)
                     ↓
      Return temporary failure response
```

---

## Retry & Recovery Flows

### Automatic Retry Strategy

**Retry Configuration:**
```python
max_retries = 3
base_delay = 1.0  # seconds
max_delay = 10.0  # seconds
exponential_factor = 2.0

Retry Schedule:
- Attempt 1: Immediate
- Attempt 2: After 1s
- Attempt 3: After 2s
- Attempt 4: After 4s
```

### Circuit Breaker Pattern

**States:**
```
CLOSED (Normal) → OPEN (Failing) → HALF_OPEN (Testing) → CLOSED
                     ↓                     ↓
              After 60s timeout    If success → CLOSED
                                  If fail → OPEN
```

**Configuration:**
```python
failure_threshold = 5  # Open after 5 failures
success_threshold = 2  # Close after 2 successes
timeout = 60  # seconds in OPEN state
```

### Recovery Workflow

```
1. Detect failure (agent unavailable)
   ↓
2. Open circuit breaker
   ↓
3. Store document state in DB
   status='pending_retry'
   ↓
4. Wait for recovery timeout (60s)
   ↓
5. Attempt half-open (test call)
   ↓
   ├─ Success → Close circuit, resume processing
   │
   └─ Failure → Reopen circuit, wait another 60s
```

---

## Monitoring & Observability

### Key Metrics to Track

**Processing Metrics:**
- Documents processed per hour
- Average processing time
- Success rate by document type
- Validation confidence distribution

**System Metrics:**
- API response time (p50, p95, p99)
- Agent availability
- Circuit breaker state
- Retry queue depth

**Business Metrics:**
- Document types distribution
- Processing cost per document
- Manual review rate
- SLA compliance

---

## 📞 Support

- **AWS Account:** 555043101106
- **Region:** eu-west-3
- **Project:** CA-A2A
- **Contact:** j.benabderrazak@reply.com

---

## 📚 Related Documentation

- [End-to-End Demo Guide](./END_TO_END_DEMO.md)
- [AWS Architecture](./AWS_ARCHITECTURE.md)
- [API Testing Guide](./API_TESTING_GUIDE.md)

