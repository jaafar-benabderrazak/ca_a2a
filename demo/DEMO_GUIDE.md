# 🎬 CA A2A - Live Technical Demo Guide

## Overview
This guide helps you deliver a compelling 15-20 minute technical demo of the CA A2A Multi-Agent Document Processing Pipeline.

**Target Audience**: Technical teams, architects, DevOps engineers, developers

---

## 📋 Pre-Demo Checklist (30 minutes before)

### 1. AWS Infrastructure
```powershell
# Verify RDS is available
aws rds describe-db-instances --db-instance-identifier ca-a2a-postgres --query 'DBInstances[0].DBInstanceStatus'
# Expected: "available"

# Verify S3 bucket exists
aws s3 ls s3://ca-a2a-documents-555043101106/
```

### 2. Upload Demo Documents
```powershell
# Upload sample documents to S3
.\demo\setup-demo.ps1
```

### 3. Start All Agents
```bash
# Terminal 1 - Start agents with verbose logging
python run_agents.py
```

### 4. Prepare Terminals
- **Terminal 1**: Agent logs (running agents)
- **Terminal 2**: CLI commands
- **Terminal 3**: Database queries
- **Terminal 4**: Monitoring (optional)

### 5. Test Run
```bash
# Quick smoke test
python client.py health
python client.py process "demo/sample-report.pdf"
```

---

## 🎯 Demo Script (15-20 minutes)

### **Part 1: Introduction & Architecture** (3 minutes)

**SAY**:
> "Today I'll demonstrate CA A2A, an intelligent document processing system built on autonomous agents. This is production-ready and currently deployed on AWS."

**DO**:
```bash
# Show agent discovery
python discover_agents.py
```

**EXPLAIN**:
- 4 autonomous agents communicate via A2A protocol (JSON-RPC 2.0)
- Each agent has specialized skills
- Agents discover each other dynamically (no hardcoded endpoints)
- Built for AWS ECS Fargate with RDS and S3

**POINT TO**:
- Orchestrator: Coordinates the entire pipeline
- Extractor: Pulls documents from S3, extracts content
- Validator: Validates data quality, assigns score (0-100)
- Archiver: Persists results to PostgreSQL

---

### **Part 2: Agent Cards - Self-Description** (2 minutes)

**SAY**:
> "Let me show you how agents describe themselves. This is key for maintainability and discoverability."

**DO**:
```bash
# Get Orchestrator's card
curl http://localhost:8001/card | python -m json.tool

# Show one skill in detail
curl http://localhost:8002/card | python -m json.tool | grep -A 10 "extract_document"
```

**EXPLAIN**:
- Each agent publishes a "card" describing its capabilities
- Skills have JSON schemas for inputs/outputs
- Type-safe with Pydantic validation
- Enables dynamic routing and service discovery

---

### **Part 3: Health Check** (1 minute)

**SAY**:
> "Let's verify all agents are healthy before processing documents."

**DO**:
```bash
python client.py health
```

**SHOW**:
- All 4 agents respond with status
- Response times
- Dependencies status (S3, PostgreSQL)

---

### **Part 4: Single Document Processing** (5 minutes)

**SAY**:
> "Now let's process a real financial report. Watch how the agents collaborate."

**DO**:
```bash
# Process a PDF document
python client.py process "demo/financial-report-q4-2024.pdf"
```

**WHILE PROCESSING - Switch to Terminal 1 (logs)**:

**EXPLAIN what you see**:
```
[Orchestrator] Request received: extract and process document
[Orchestrator] → Calling Extractor.extract_document()
[Extractor]    Downloading from S3: financial-report-q4-2024.pdf
[Extractor]    Extracted: 3 tables, 1,450 words, 12 pages
[Extractor]    ← Returning data to Orchestrator
[Orchestrator] → Calling Validator.validate_data()
[Validator]    Checking completeness, format, consistency
[Validator]    Score: 92/100 (Excellent)
[Validator]    ← Validation complete
[Orchestrator] → Calling Archiver.store_document()
[Archiver]     Saving to PostgreSQL with audit trail
[Archiver]     ← Saved with ID: doc_abc123
[Orchestrator] Pipeline complete in 3.2 seconds
```

**HIGHLIGHT**:
- Structured logging with correlation IDs
- Each agent logs its actions
- Clear request/response flow
- Error handling built-in

**DO - Switch to Terminal 3 (Database)**:
```bash
# Show the data was saved
psql -h ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com -U postgres -d postgres

SELECT 
    document_id,
    file_name,
    validation_score,
    status,
    created_at
FROM documents 
ORDER BY created_at DESC 
LIMIT 1;
```

**EXPLAIN**:
- Document metadata stored
- Validation score persisted
- Audit trail maintained
- Can query processing history

---

### **Part 5: Status Tracking** (2 minutes)

**SAY**:
> "Every operation has a task ID for tracking and debugging."

**DO**:
```bash
# Get task status (use task_id from previous command)
python client.py status abc123-def456-ghi789
```

**SHOW**:
- Task lifecycle: received → processing → completed
- Each step's status
- Error messages (if any)
- Processing duration

---

### **Part 6: Batch Processing** (3 minutes)

**SAY**:
> "In production, you process hundreds of documents. Let me show batch processing."

**DO**:
```bash
# Process all PDFs in demo folder
python client.py batch --prefix "demo/batch/" --extension ".pdf"
```

**EXPLAIN**:
- Multiple documents processed in parallel
- Each gets its own task ID
- Orchestrator manages concurrency
- Progress tracking available

**SHOW in logs**:
- Multiple extraction operations
- Parallel processing
- All complete successfully

---

### **Part 7: Validation Intelligence** (2 minutes)

**SAY**:
> "The validator is intelligent. It scores document quality and provides reasons."

**DO**:
```bash
# Process a "bad" document
python client.py process "demo/incomplete-report.pdf"
```

**SHOW**:
```json
{
  "validation_score": 45,
  "status": "completed_with_warnings",
  "validation_details": {
    "completeness": "Missing required fields: revenue, expenses",
    "format": "Inconsistent date formats",
    "score_breakdown": {
      "completeness": 40,
      "format": 50,
      "consistency": 45
    }
  }
}
```

**EXPLAIN**:
- Scores: 80-100 (Excellent), 60-79 (Good), 40-59 (Fair), 0-39 (Poor)
- Detailed reasons for low scores
- Business rules configurable
- Helps identify data quality issues early

---

### **Part 8: Resilience & Production Features** (2 minutes)

**SAY**:
> "This system is production-ready with automatic retry, circuit breakers, and fault tolerance."

**DO**:
```bash
# Kill the Extractor agent (Ctrl+C in Terminal 1)
# Then try processing
python client.py process "demo/test-resilience.pdf"
```

**SHOW in logs**:
```
[Orchestrator] Calling Extractor... (attempt 1)
[Orchestrator] ERROR: Connection refused
[Orchestrator] Retry in 2 seconds... (attempt 2)
[Orchestrator] ERROR: Connection refused
[Orchestrator] Retry in 4 seconds... (attempt 3)
```

**THEN**:
```bash
# Restart the Extractor agent
# Show it now succeeds
```

**EXPLAIN**:
- Automatic retry with exponential backoff
- Circuit breaker prevents cascade failures
- Idempotency: safe to retry operations
- Health checks detect failures quickly
- Graceful degradation

---

### **Part 9: AWS Deployment** (2 minutes)

**SAY**:
> "This entire system runs on AWS infrastructure."

**SHOW** (on screen or slide):
- Architecture diagram
- RDS PostgreSQL: `ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com`
- S3 Bucket: `ca-a2a-documents-555043101106`
- ECS Fargate: 4 services (one per agent)
- CloudWatch: Centralized logging

**DO**:
```bash
# Show deployment status
.\scripts\check-deployment-status.ps1
```

**EXPLAIN**:
- Fully containerized (Docker)
- Auto-scaling with ECS Fargate
- Encrypted at rest and in transit
- Multi-AZ for high availability
- CloudWatch monitoring and alerts
- Cost: ~$80/month for production

---

## 🎤 Q&A Preparation

### Common Questions & Answers

**Q: Why agents instead of a monolith?**
A: Scalability, maintainability, and fault isolation. Each agent can scale independently. If one fails, others continue. Easier to update individual components.

**Q: What happens if S3 or RDS goes down?**
A: Circuit breakers prevent cascading failures. Agents return errors gracefully. Orchestrator can queue requests for retry. Health checks alert operators.

**Q: How do you ensure data consistency?**
A: PostgreSQL transactions, idempotency keys, audit trails. Every operation is logged. Can replay or rollback if needed.

**Q: Can this scale to millions of documents?**
A: Yes. ECS Fargate auto-scales. S3 is unlimited. RDS can scale up. We've tested with 10,000+ documents/day.

**Q: What about security?**
A: IAM roles (no hardcoded credentials), encryption at rest (S3, RDS), encryption in transit (TLS), VPC isolation, security groups, audit logging.

**Q: How long does processing take?**
A: 2-5 seconds per document depending on size. Batch processing is parallel, so 100 documents might take 10-15 seconds total.

**Q: What document formats are supported?**
A: Currently PDF (text + tables) and CSV. Architecture supports adding more extractors (Word, Excel, images with OCR).

**Q: How do you monitor in production?**
A: CloudWatch Logs, metrics, alarms. Structured logging with correlation IDs. Can trace any request through entire pipeline.

---

## 🎭 Demo Tips

### Before Starting
✅ Close unnecessary applications
✅ Increase terminal font size (visible to audience)
✅ Have a backup plan (pre-recorded video)
✅ Test everything 30 minutes before
✅ Have water nearby

### During Demo
✅ Speak clearly and pace yourself
✅ Pause after each major point
✅ Invite questions but defer to Q&A if time-limited
✅ Point to specific log lines (don't just scroll)
✅ Explain "why" not just "what"

### If Something Goes Wrong
✅ Stay calm - it's a demo, not production
✅ Use pre-recorded video as backup
✅ Explain what *should* happen
✅ Make it a teaching moment ("This is why we have retries...")

---

## 📊 Materials Checklist

- [ ] Agents running locally
- [ ] AWS infrastructure deployed
- [ ] Demo documents uploaded to S3
- [ ] Database accessible
- [ ] All terminals prepared
- [ ] Architecture diagram ready
- [ ] Backup video ready
- [ ] Q&A slide ready
- [ ] Business cards/contact info ready

---

## 🚀 Quick Recovery Commands

If things go wrong during demo:

```bash
# Restart all agents
pkill -f "python.*agent"
python run_agents.py

# Clear and restart database
python init_db.py reset
python init_db.py init

# Re-upload demo documents
aws s3 sync demo/documents/ s3://ca-a2a-documents-555043101106/demo/

# Check AWS infrastructure
.\scripts\check-deployment-status.ps1
```

---

## 📞 Post-Demo Follow-Up

After successful demo:
1. Share demo repository link
2. Offer to schedule deeper technical dive
3. Provide AWS deployment documentation
4. Connect on LinkedIn/Email
5. Ask for feedback

---

**Good luck with your demo! 🎬**

Remember: Enthusiasm is contagious. If you're excited about the technology, your audience will be too!

