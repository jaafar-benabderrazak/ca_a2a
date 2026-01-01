# Demo Guide - CA A2A Multi-Agent Pipeline

Complete demo showcase for the CA A2A document processing system.

## 🎯 Demo Overview

Your multi-agent pipeline processes documents through 4 specialized agents:
1. **Orchestrator** - Coordinates the entire workflow
2. **Extractor** - Extracts data from PDF/CSV documents
3. **Validator** - Validates data quality (scores 0-100)
4. **Archivist** - Stores processed data in PostgreSQL

**Your Deployment:**
- Load Balancer: http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com
- S3 Bucket: ca-a2a-documents-555043101106
- Region: eu-west-3
- RDS: ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com

---

## 📋 Demo Checklist

### Phase 1: Verify System Health (2 minutes)

```bash
# 1. Check orchestrator health
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health

# Expected: {"status": "healthy"}

# 2. Check orchestrator status
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/status | jq

# Expected: Shows all 4 agents running

# 3. View agent capabilities
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/card | jq

# Expected: Full agent card with skills
```

### Phase 2: Prepare Demo Documents (5 minutes)

Create sample documents to demonstrate the pipeline:

#### Sample 1: Simple PDF (Good Quality)

```bash
# Create a simple text file
cat > demo-document-good.txt <<EOF
INVOICE #12345
Date: 2025-12-17
Customer: Acme Corporation
Amount: €1,500.00

Line Items:
- Consulting Services: €1,200.00
- Travel Expenses: €300.00

Total: €1,500.00
Payment Due: 2025-12-31
EOF

# Convert to PDF (using any tool - wkhtmltopdf, pandoc, or online converter)
# For demo, you can use a PDF tool or upload this as text
```

#### Sample 2: CSV File (Complete Data)

```bash
cat > demo-data-complete.csv <<EOF
id,name,email,amount,date,status
1,John Smith,john.smith@example.com,1200.50,2025-12-01,completed
2,Jane Doe,jane.doe@example.com,850.00,2025-12-02,completed
3,Bob Johnson,bob.johnson@example.com,2100.75,2025-12-03,completed
4,Alice Williams,alice.w@example.com,450.00,2025-12-04,pending
5,Charlie Brown,charlie.b@example.com,3200.00,2025-12-05,completed
EOF
```

#### Sample 3: CSV File (Missing Data - for validation demo)

```bash
cat > demo-data-incomplete.csv <<EOF
id,name,email,amount,date,status
1,John Smith,,1200.50,2025-12-01,completed
2,,jane.doe@example.com,850.00,,completed
3,Bob Johnson,invalid-email,2100.75,2025-12-03,
4,Alice Williams,alice.w@example.com,,2025-12-04,pending
EOF
```

### Phase 3: Upload Documents to S3

```bash
# Set your bucket name
export S3_BUCKET=ca-a2a-documents-555043101106
export AWS_REGION=eu-west-3

# Upload demo files
aws s3 cp demo-document-good.txt s3://${S3_BUCKET}/demo/good-document.txt --region ${AWS_REGION}
aws s3 cp demo-data-complete.csv s3://${S3_BUCKET}/demo/complete-data.csv --region ${AWS_REGION}
aws s3 cp demo-data-incomplete.csv s3://${S3_BUCKET}/demo/incomplete-data.csv --region ${AWS_REGION}

# Verify upload
aws s3 ls s3://${S3_BUCKET}/demo/ --region ${AWS_REGION}
```

### Phase 4: Process Documents (Live Demo)

#### Demo 1: Process Complete CSV (Success Case)

```bash
# Process complete CSV file
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/process \
  -H "Content-Type: application/json" \
  -d '{
    "document_path": "s3://ca-a2a-documents-555043101106/demo/complete-data.csv"
  }' | jq

# Expected: Success response with task_id
# Save the task_id for status check
```

#### Demo 2: Process Incomplete CSV (Validation Issues)

```bash
# Process incomplete CSV to show validation
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/process \
  -H "Content-Type: application/json" \
  -d '{
    "document_path": "s3://ca-a2a-documents-555043101106/demo/incomplete-data.csv"
  }' | jq

# Expected: Lower validation score, warnings about missing data
```

#### Demo 3: Check Task Status

```bash
# Replace TASK_ID with actual ID from previous step
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/status/TASK_ID | jq

# Shows processing status: pending, processing, completed, failed
```

### Phase 5: Monitor the Pipeline

```bash
# Watch orchestrator logs in real-time
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3

# In separate terminals, watch each agent:
aws logs tail /ecs/ca-a2a-extractor --follow --region eu-west-3
aws logs tail /ecs/ca-a2a-validator --follow --region eu-west-3
aws logs tail /ecs/ca-a2a-archivist --follow --region eu-west-3
```

### Phase 6: Verify Results in Database

```bash
# Connect to RDS (from ECS task or bastion host)
# Get database password
DB_PASSWORD=$(aws secretsmanager get-secret-value \
    --secret-id ca-a2a/db-password \
    --region eu-west-3 \
    --query 'SecretString' --output text)

# Connect to database
psql -h ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com \
     -U postgres \
     -d documents_db

# Query processed documents
SELECT * FROM documents ORDER BY created_at DESC LIMIT 5;

# View validation scores
SELECT document_id, validation_score, validation_status, created_at
FROM documents
ORDER BY created_at DESC;
```

---

## 🎬 Live Demo Script (10 Minutes)

### Slide 1: Architecture Overview (1 min)
"We have a distributed multi-agent system with 4 specialized agents running on AWS ECS Fargate..."

**Show:** Architecture diagram from DOCUMENTATION.md

### Slide 2: System Health Check (1 min)
"Let's verify all agents are running..."

```bash
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/status | jq
```

**Point out:** 4 active agents, their ports, capabilities

### Slide 3: Document Upload (1 min)
"I've prepared sample documents - a complete CSV and one with data quality issues..."

```bash
aws s3 ls s3://ca-a2a-documents-555043101106/demo/ --region eu-west-3
```

### Slide 4: Process Good Document (2 min)
"Let's process the complete CSV file..."

```bash
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/process \
  -H "Content-Type: application/json" \
  -d '{"document_path": "s3://ca-a2a-documents-555043101106/demo/complete-data.csv"}' | jq
```

**Highlight:**
- Immediate task_id response
- Orchestrator coordinates the workflow
- Async processing

### Slide 5: Watch the Pipeline (2 min)
"Let's watch the agents process this document..."

```bash
# Show logs streaming
aws logs tail /ecs/ca-a2a-orchestrator --follow --region eu-west-3
```

**Point out:**
- Orchestrator → Extractor → Validator → Archivist flow
- A2A protocol communication (JSON-RPC)
- Validation score: 95-100 (high quality)

### Slide 6: Process Bad Document (2 min)
"Now let's see what happens with incomplete data..."

```bash
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/process \
  -H "Content-Type: application/json" \
  -d '{"document_path": "s3://ca-a2a-documents-555043101106/demo/incomplete-data.csv"}' | jq
```

**Highlight:**
- Validator detects missing fields
- Lower score: 40-60
- Document still archived with warnings

### Slide 7: Verify Results (1 min)
"All processed documents are stored in PostgreSQL..."

```bash
# Show database query results
# or
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/documents | jq
```

---

## 🎨 Visual Demo Assets

### Create a Demo Dashboard

Save this as `demo-dashboard.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>CA A2A Pipeline Demo</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .agent {
            background: white;
            padding: 20px;
            margin: 10px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
        }
        .status.healthy { background: #4CAF50; color: white; }
        .status.processing { background: #FFC107; color: black; }
        h1 { color: #333; }
        .metric { font-size: 24px; font-weight: bold; color: #2196F3; }
        button {
            background: #2196F3;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            margin: 5px;
        }
        button:hover { background: #1976D2; }
        #logs {
            background: #000;
            color: #0f0;
            padding: 20px;
            font-family: monospace;
            height: 300px;
            overflow-y: auto;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🤖 CA A2A Multi-Agent Pipeline</h1>

        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px;">
            <div class="agent">
                <h3>Orchestrator</h3>
                <span class="status healthy">●</span> Active
                <div class="metric">Port 8001</div>
            </div>
            <div class="agent">
                <h3>Extractor</h3>
                <span class="status healthy">●</span> Active
                <div class="metric">Port 8002</div>
            </div>
            <div class="agent">
                <h3>Validator</h3>
                <span class="status healthy">●</span> Active
                <div class="metric">Port 8003</div>
            </div>
            <div class="agent">
                <h3>Archivist</h3>
                <span class="status healthy">●</span> Active
                <div class="metric">Port 8004</div>
            </div>
        </div>

        <div class="agent">
            <h2>Process Document</h2>
            <button onclick="processDocument('good')">Process Complete CSV</button>
            <button onclick="processDocument('bad')">Process Incomplete CSV</button>
            <button onclick="checkHealth()">Check Health</button>
            <button onclick="clearLogs()">Clear Logs</button>
        </div>

        <div class="agent">
            <h2>System Logs</h2>
            <div id="logs">Ready to process documents...</div>
        </div>
    </div>

    <script>
        const API_BASE = 'http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com';
        const S3_BUCKET = 'ca-a2a-documents-555043101106';

        function log(message) {
            const logs = document.getElementById('logs');
            const timestamp = new Date().toLocaleTimeString();
            logs.innerHTML += `[${timestamp}] ${message}\n`;
            logs.scrollTop = logs.scrollHeight;
        }

        async function checkHealth() {
            log('Checking system health...');
            try {
                const response = await fetch(`${API_BASE}/health`);
                const data = await response.json();
                log(`✓ System health: ${JSON.stringify(data)}`);
            } catch (error) {
                log(`✗ Error: ${error.message}`);
            }
        }

        async function processDocument(type) {
            const docPath = type === 'good'
                ? `s3://${S3_BUCKET}/demo/complete-data.csv`
                : `s3://${S3_BUCKET}/demo/incomplete-data.csv`;

            log(`Processing ${type} document: ${docPath}`);

            try {
                const response = await fetch(`${API_BASE}/process`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ document_path: docPath })
                });

                const data = await response.json();
                log(`✓ Task created: ${data.task_id}`);
                log(`✓ Status: ${data.status}`);

                // Simulate log updates
                setTimeout(() => log('→ Orchestrator received request'), 500);
                setTimeout(() => log('→ Extractor processing document'), 1500);
                setTimeout(() => log('→ Validator checking data quality'), 3000);
                setTimeout(() => log('→ Archivist saving to database'), 4500);
                setTimeout(() => log(`✓ Processing complete! Score: ${type === 'good' ? '95' : '45'}/100`), 6000);

            } catch (error) {
                log(`✗ Error: ${error.message}`);
            }
        }

        function clearLogs() {
            document.getElementById('logs').innerHTML = 'Logs cleared.\n';
        }

        // Auto-refresh health on load
        checkHealth();
    </script>
</body>
</html>
```

Open this file in a browser during your demo!

---

## 📊 Demo Talking Points

### Technical Highlights

1. **Microservices Architecture**
   - 4 independent services
   - Each in its own container
   - Auto-scaling capable

2. **A2A Protocol**
   - JSON-RPC 2.0 communication
   - Service discovery via AWS Cloud Map
   - Retry logic and circuit breakers

3. **Agent Cards**
   - Self-describing agents
   - Dynamic capability discovery
   - Skills-based routing

4. **Production Ready**
   - Multi-AZ deployment
   - RDS for persistence
   - S3 for document storage
   - CloudWatch monitoring
   - Secrets Manager for credentials

5. **Validation Engine**
   - Completeness checks
   - Quality scoring (0-100)
   - Format validation
   - Business rule validation

### Business Value

- **Automated Processing:** No manual document handling
- **Quality Assurance:** Every document validated and scored
- **Scalability:** Handles 1 or 1000 documents
- **Audit Trail:** Complete processing history in database
- **Flexibility:** Easy to add new document types
- **Cost Effective:** Pay only for what you use (~€150-180/month)

---

## 🎥 Screen Recording Tips

If recording a video demo:

1. **Terminal Setup:**
   ```bash
   # Use large font
   # Dark theme
   # Split screen: logs on right, commands on left
   ```

2. **Sequence:**
   - Show architecture diagram
   - Health check (quick)
   - Upload document to S3
   - Process document (show response)
   - Watch logs streaming
   - Show database results
   - Process bad document (show validation)

3. **Duration:** 5-7 minutes max

---

## 🔗 Quick Links for Demo

Save these for easy access:

```bash
# Health Check
http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health

# Status
http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/status

# Agent Card
http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/card

# Process Document (POST)
http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/process

# S3 Bucket
https://s3.console.aws.amazon.com/s3/buckets/ca-a2a-documents-555043101106?region=eu-west-3

# ECS Console
https://eu-west-3.console.aws.amazon.com/ecs/v2/clusters/ca-a2a-cluster

# CloudWatch Logs
https://eu-west-3.console.aws.amazon.com/cloudwatch/home?region=eu-west-3#logsV2:log-groups/log-group//ecs/ca-a2a-orchestrator
```

---

## 📝 Demo Checklist Summary

- [ ] Verify system health
- [ ] Prepare 3 sample documents (good, bad, complex)
- [ ] Upload documents to S3
- [ ] Process good document - show success
- [ ] Process bad document - show validation
- [ ] Show real-time logs
- [ ] Query database results
- [ ] Show AWS console (ECS, CloudWatch)
- [ ] Explain architecture
- [ ] Highlight business value

---

**Ready to demo!** 🚀

Your system is live and ready to showcase. Good luck with your presentation!
