# How to Inspect RDS PostgreSQL Data

The database appears empty because we haven't verified if data was actually written. Let me show you multiple ways to check.

---

## 🔍 Method 1: Use the API to Check Database (EASIEST)

Since the orchestrator is already connected to the database, use the API to query it:

```bash
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# List pending documents (queries the database)
curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {"limit": 100},
    "id": 1
  }' | jq '.result'
```

**If this returns `count: 0`**, the database is truly empty (no documents have been fully processed yet).

---

## 🔍 Method 2: Use ECS Exec to Connect from Inside Container (RECOMMENDED)

Connect directly to the orchestrator container which has database access:

### Step 1: Get Task ARN
```bash
export AWS_REGION=eu-west-3

TASK_ARN=$(aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service-name orchestrator \
  --region $AWS_REGION \
  --query 'taskArns[0]' \
  --output text)

echo "Task ARN: $TASK_ARN"
```

### Step 2: Connect with ECS Exec
```bash
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task $TASK_ARN \
  --container orchestrator \
  --interactive \
  --command "/bin/sh" \
  --region $AWS_REGION
```

### Step 3: Inside the Container, Run Python
```python
# Once inside the container, run Python
python3 << 'EOF'
import asyncio
import asyncpg
import os
from dotenv import load_dotenv

async def check_db():
    # Load environment variables
    load_dotenv()
    
    # Connect to database
    conn = await asyncpg.connect(
        host=os.getenv('POSTGRES_HOST'),
        port=int(os.getenv('POSTGRES_PORT', 5432)),
        user=os.getenv('POSTGRES_USER'),
        password=os.getenv('POSTGRES_PASSWORD'),
        database=os.getenv('POSTGRES_DB', 'documents_db'),
        ssl='require'
    )
    
    # Check if tables exist
    tables = await conn.fetch("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public'
    """)
    
    print("\n=== Tables in Database ===")
    for table in tables:
        print(f"  - {table['table_name']}")
    
    # Count documents
    doc_count = await conn.fetchval("SELECT COUNT(*) FROM documents")
    print(f"\n=== Document Count ===")
    print(f"Total documents: {doc_count}")
    
    # Show recent documents
    if doc_count > 0:
        docs = await conn.fetch("""
            SELECT id, filename, file_type, status, created_at 
            FROM documents 
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        
        print("\n=== Recent Documents ===")
        for doc in docs:
            print(f"  {doc['filename']} - {doc['status']} - {doc['created_at']}")
    else:
        print("No documents found in database")
    
    # Count processing logs
    log_count = await conn.fetchval("SELECT COUNT(*) FROM processing_logs")
    print(f"\n=== Processing Logs ===")
    print(f"Total logs: {log_count}")
    
    await conn.close()

asyncio.run(check_db())
EOF
```

---

## 🔍 Method 3: Install psql in CloudShell and Connect

### Step 1: Install PostgreSQL Client in CloudShell
```bash
# For Amazon Linux 2023
sudo dnf install -y postgresql15
```

### Step 2: Get Database Password
```bash
export AWS_REGION=eu-west-3

# Get the password from Secrets Manager
DB_PASSWORD=$(aws secretsmanager get-secret-value \
  --secret-id ca-a2a/db-password \
  --region $AWS_REGION \
  --query 'SecretString' \
  --output text)

echo "Password retrieved"
```

### Step 3: Update RDS Security Group

**IMPORTANT:** Your RDS is in a private subnet and CloudShell can't reach it by default. You need to:

#### Option A: Use ECS Exec (Method 2) instead ✅ RECOMMENDED

#### Option B: Temporarily allow CloudShell IP (NOT RECOMMENDED for production)
```bash
# Get CloudShell IP
MY_IP=$(curl -s https://checkip.amazonaws.com)

# Add temporary rule to RDS security group
aws ec2 authorize-security-group-ingress \
  --group-id sg-0dfffbf7f98f77a4c \
  --protocol tcp \
  --port 5432 \
  --cidr $MY_IP/32 \
  --region $AWS_REGION

# Connect
psql "postgresql://postgres:$DB_PASSWORD@ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com:5432/documents_db?sslmode=require"

# When done, remove the rule
aws ec2 revoke-security-group-ingress \
  --group-id sg-0dfffbf7f98f77a4c \
  --protocol tcp \
  --port 5432 \
  --cidr $MY_IP/32 \
  --region $AWS_REGION
```

---

## 🔍 Method 4: Create a Python Script to Query via API

Create a script that uses the MCP context (if you're running locally with proper AWS credentials):

```python
# save as check_db.py
import asyncio
import asyncpg
import os

async def main():
    conn = await asyncpg.connect(
        host='ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com',
        port=5432,
        user='postgres',
        password='YOUR_PASSWORD_HERE',  # Get from Secrets Manager
        database='documents_db',
        ssl='require'
    )
    
    # Check tables
    tables = await conn.fetch("""
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'public'
    """)
    print("Tables:", [t['table_name'] for t in tables])
    
    # Count documents
    count = await conn.fetchval("SELECT COUNT(*) FROM documents")
    print(f"Documents: {count}")
    
    # Show documents
    if count > 0:
        docs = await conn.fetch("SELECT * FROM documents LIMIT 5")
        for doc in docs:
            print(doc)
    
    await conn.close()

asyncio.run(main())
```

---

## 💡 Why the Database Might Be Empty

The database could be empty because:

1. **No documents have been fully processed yet**
   - Documents are only written to DB after extraction completes
   - Check if processing tasks actually completed

2. **Tasks are failing before writing to DB**
   - Check orchestrator logs for errors
   - Check if extraction/validation/archiving agents are working

3. **Database connection issue**
   - Tasks might not be able to connect to RDS
   - Check security group allows ECS tasks to reach RDS

---

## 🧪 Test: Process a Document and Verify

Let's process a document and immediately check if it appears in the database:

```bash
export AWS_REGION=eu-west-3
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# 1. Upload test document
echo "Test document $(date)" > /tmp/db-test.txt
aws s3 cp /tmp/db-test.txt s3://ca-a2a-documents-555043101106/incoming/db-test.txt --region $AWS_REGION

# 2. Process it
RESULT=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {"s3_key": "incoming/db-test.txt"},
    "id": 1
  }')

echo "$RESULT" | jq '.'
TASK_ID=$(echo "$RESULT" | jq -r '.result.task_id')
echo "Task ID: $TASK_ID"

# 3. Wait 40 seconds
echo "Waiting 40 seconds for processing..."
sleep 40

# 4. Check task status
curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"method\": \"get_task_status\",
    \"params\": {\"task_id\": \"$TASK_ID\"},
    \"id\": 2
  }" | jq '.result | {task_id, status, current_stage}'

# 5. Query database via API
echo ""
echo "=== Checking Database ==="
curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {"limit": 10},
    "id": 3
  }' | jq '.result'
```

---

## 🔍 Check Orchestrator Logs for Database Writes

```bash
# Check if database operations are happening
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "database OR postgres OR documents_db" \
  --start-time $(($(date +%s) - 600))000 \
  --region eu-west-3 \
  --query 'events[*].message' \
  --output text | tail -20
```

---

## 📊 Quick Database Status Check

Run this complete check:

```bash
export AWS_REGION=eu-west-3
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

echo "=== Database Status Check ==="
echo ""

# 1. Check via API (easiest)
echo "1. Documents in database:"
RESULT=$(curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {"limit": 100},
    "id": 1
  }')

DOC_COUNT=$(echo "$RESULT" | jq -r '.result.count // 0')
echo "   Total documents: $DOC_COUNT"

if [ "$DOC_COUNT" -gt "0" ]; then
    echo ""
    echo "   Documents found:"
    echo "$RESULT" | jq -r '.result.documents[] | "   - \(.s3_key) (\(.status))"'
else
    echo "   Database is empty or no documents have been processed yet"
fi

# 2. Check recent processing
echo ""
echo "2. Recent task processing:"
curl -s $ALB_URL/status | jq '{
  active_tasks,
  completed_tasks,
  failed_tasks,
  total_tasks
}'

# 3. Check S3 for processed files
echo ""
echo "3. S3 processed files:"
PROCESSED=$(aws s3 ls s3://ca-a2a-documents-555043101106/processed/ --region $AWS_REGION | wc -l)
echo "   Processed folder: $PROCESSED files"

# 4. Check logs for database operations
echo ""
echo "4. Recent database operations (last 5 minutes):"
aws logs filter-log-events \
  --log-group-name /ecs/ca-a2a-orchestrator \
  --filter-pattern "\"Database\" OR \"documents\" OR \"INSERT\"" \
  --start-time $(($(date +%s) - 300))000 \
  --region $AWS_REGION \
  --query 'length(events)' \
  --output text | xargs -I {} echo "   {} database-related log entries"
```

---

## ✅ Recommended Approach

**Use Method 1 (API Query) first** - it's the easiest and tells you if data exists:

```bash
curl -s -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {"limit": 100},
    "id": 1
  }' | jq '.result.count'
```

If this returns `0`, the database is empty because:
- No documents have been successfully processed yet
- Or the processing pipeline has issues

**Then use Method 2 (ECS Exec)** if you need direct database access for troubleshooting.

---

## 🐛 Troubleshooting Empty Database

If the database is empty after processing documents:

1. **Check if tasks completed:**
   ```bash
   curl -s http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/status | jq '{completed_tasks, failed_tasks}'
   ```

2. **Check orchestrator logs for errors:**
   ```bash
   aws logs tail /ecs/ca-a2a-orchestrator --since 10m --region eu-west-3 | grep -i "error\|fail"
   ```

3. **Check if agents are responding:**
   ```bash
   curl -s -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc": "2.0", "method": "discover_agents", "params": {}, "id": 1}' \
     | jq '.result.discovered_agents'
   ```

4. **Verify RDS security group allows ECS tasks:**
   ```bash
   aws ec2 describe-security-groups \
     --group-ids sg-0dfffbf7f98f77a4c \
     --region eu-west-3 \
     --query 'SecurityGroups[0].IpPermissions[?ToPort==`5432`]'
   ```

---

**Start with the API query method - it's the simplest way to check if data exists!** 🎯

