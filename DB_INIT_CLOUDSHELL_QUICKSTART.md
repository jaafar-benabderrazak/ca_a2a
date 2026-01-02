# Quick Fix: Initialize Database via CloudShell

## ⚡ Fastest Solution (2 minutes)

The repository already includes `init_db_cloudshell.py` which works perfectly from AWS CloudShell!

---

## 🚀 Steps

### 1. Open AWS CloudShell
- Go to: https://console.aws.amazon.com
- Log in with your AWS SSO
- Switch to **eu-west-3** region (top-right dropdown)
- Click the **CloudShell** icon (looks like `>_` in the top navigation bar)

### 2. Run These Commands

```bash
# Clone the repository
git clone https://github.com/jaafar-benabderrazak/ca_a2a.git
cd ca_a2a

# Install required Python packages
pip3 install asyncpg boto3

# Run the initialization script
python3 init_db_cloudshell.py
```

### 3. Verify Success

You should see output like:

```
Getting database password from Secrets Manager...
Connecting to RDS: ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com
Connected!
Creating documents table...
✓ Documents table created
Creating processing_logs table...
✓ Processing_logs table created
Creating indexes...
✓ Indexes created
✓ Found 2 tables:
  - documents: 0 rows
  - processing_logs: 0 rows
✓ Database schema initialized successfully!
```

---

## ✅ Done!

Your database schema is now initialized and ready for production use.

### Update Documentation

In `ETAT_DU_PROJET.md`, change:

```markdown
| Database | `documents_db` | ⚠️ **Existe mais schéma à initialiser** |
```

To:

```markdown
| Database | `documents_db` | ✅ **Schéma initialisé le YYYY-MM-DD** |
```

---

## 🔍 Troubleshooting

### Issue: "Unable to connect to RDS"

**Cause:** CloudShell might not have network access to the private RDS instance.

**Solution:** The RDS is in a private subnet. CloudShell should be able to reach it through AWS's internal networking, but if not:
1. Check RDS security group allows inbound from CloudShell
2. Use ECS Exec method instead (see below)

### Alternative: ECS Exec Method

If CloudShell doesn't work, use a running ECS container:

```bash
# Get a running task ARN
TASK_ARN=$(aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service-name ca-a2a-orchestrator \
  --region eu-west-3 \
  --query 'taskArns[0]' \
  --output text)

# Connect to the task
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task $TASK_ARN \
  --container orchestrator \
  --interactive \
  --command "/bin/sh" \
  --region eu-west-3

# Inside the container:
python3 -c "
import asyncio
from mcp_protocol import PostgreSQLResource

async def init():
    db = PostgreSQLResource()
    await db.connect()
    await db.initialize_schema()
    print('Schema initialized!')
    await db.disconnect()

asyncio.run(init())
"
```

---

## 📝 What Gets Created

### Tables

1. **documents** - Main document storage
   - Columns: id, s3_key, document_type, file_name, file_size, status, validation_score, metadata (JSONB), extracted_data (JSONB), validation_details (JSONB), timestamps
   
2. **processing_logs** - Audit trail
   - Columns: id, document_id (FK), agent_name, action, status, details (JSONB), timestamp

### Indexes (6 total)

- `idx_documents_s3_key` - S3 key lookup
- `idx_documents_status` - Filter by status
- `idx_documents_type` - Filter by type
- `idx_documents_date` - Time-based queries
- `idx_logs_document_id` - Logs per document
- `idx_logs_agent` - Logs per agent

---

## 🎯 Summary

**Time:** ~2 minutes  
**Cost:** Free (CloudShell is free for first 1GB of storage)  
**Result:** Fully initialized database schema ready for production

This is the **simplest and fastest** method to initialize your database schema!

---

**Date:** January 1, 2026  
**Author:** Jaafar Benabderrazak

