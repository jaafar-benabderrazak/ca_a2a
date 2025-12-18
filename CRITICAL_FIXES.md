# Critical Fixes for CA-A2A System

## 🐛 Issues Found

### Issue 1: `_meta` Parameter Error ✅ FIXED
**Error:** `__init__() got an unexpected keyword argument '_meta'`

**Root Cause:** The `base_agent.py` adds `_meta` field to responses for tracking, but when the orchestrator parses responses from other agents, it tries to pass this field to `A2AMessage.__init__()` which doesn't accept it.

**Fix Applied:** Modified `base_agent.py` line 286-289 to filter out `_meta` before creating `A2AMessage` object.

---

### Issue 2: Database Schema Not Initialized ⚠️ NEEDS FIX
**Error:** `relation "documents" does not exist`

**Root Cause:** The database tables haven't been created yet. The `mcp_protocol.py` was supposed to initialize the schema automatically, but it's not working.

**Fix Required:** Force database schema initialization

---

## 🔧 Fix Script for CloudShell

Run this script to apply both fixes:

```bash
#!/bin/bash
# Fix CA-A2A Critical Issues
export AWS_REGION=eu-west-3

echo "========================================="
echo "  APPLYING CRITICAL FIXES"
echo "========================================="
echo ""

# Fix 1: Code fix already applied - need to rebuild and redeploy

echo "=== Fix 1: Rebuild Orchestrator with Code Fix ==="
echo "The code fix has been applied locally."
echo "You need to rebuild the Docker image and push to ECR."
echo ""
echo "From your local machine (NOT CloudShell):"
echo "  cd ca_a2a"
echo "  docker build -t orchestrator -f Dockerfile.orchestrator ."
echo "  docker tag orchestrator:latest 555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/orchestrator:latest"
echo "  aws ecr get-login-password --region eu-west-3 | docker login --username AWS --password-stdin 555043101106.dkr.ecr.eu-west-3.amazonaws.com"
echo "  docker push 555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/orchestrator:latest"
echo "  aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --force-new-deployment --region eu-west-3"
echo ""

# Fix 2: Initialize database schema via ECS Exec

echo "=== Fix 2: Initialize Database Schema ==="
echo "Connecting to orchestrator container to initialize database..."

TASK_ARN=$(aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service-name orchestrator \
  --region $AWS_REGION \
  --query 'taskArns[0]' \
  --output text)

echo "Task ARN: $TASK_ARN"
echo ""

# Create init script
cat > /tmp/init_db_schema.py << 'PYTHON_SCRIPT'
import asyncio
import asyncpg
import os

async def init_schema():
    print("Connecting to database...")
    
    # Get connection details from environment
    host = os.getenv('POSTGRES_HOST')
    port = int(os.getenv('POSTGRES_PORT', 5432))
    user = os.getenv('POSTGRES_USER')
    password = os.getenv('POSTGRES_PASSWORD')
    database = os.getenv('POSTGRES_DB', 'documents_db')
    
    print(f"Connecting to {host}:{port}/{database}")
    
    conn = await asyncpg.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        ssl='require'
    )
    
    print("Connected! Creating tables...")
    
    # Create documents table
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            filename VARCHAR(255) NOT NULL,
            file_type VARCHAR(50) NOT NULL,
            s3_key VARCHAR(512) NOT NULL,
            status VARCHAR(50) NOT NULL,
            extracted_data JSONB,
            validation_result JSONB,
            archived_s3_key VARCHAR(512),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            file_size INTEGER
        )
    """)
    print("✓ Created documents table")
    
    # Create processing_logs table
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS processing_logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            document_id UUID REFERENCES documents(id),
            agent_name VARCHAR(100) NOT NULL,
            operation VARCHAR(100) NOT NULL,
            status VARCHAR(50) NOT NULL,
            message TEXT,
            timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("✓ Created processing_logs table")
    
    # Create indexes
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_created_at ON documents(created_at)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_processing_logs_document_id ON processing_logs(document_id)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_processing_logs_timestamp ON processing_logs(timestamp)")
    print("✓ Created indexes")
    
    # Verify
    table_count = await conn.fetchval("""
        SELECT COUNT(*) FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name IN ('documents', 'processing_logs')
    """)
    
    print(f"\nVerification: Found {table_count} tables (expected 2)")
    
    await conn.close()
    print("\n✓ Database schema initialized successfully!")

if __name__ == '__main__':
    asyncio.run(init_schema())
PYTHON_SCRIPT

echo "Uploading init script to S3..."
aws s3 cp /tmp/init_db_schema.py s3://ca-a2a-documents-555043101106/scripts/init_db_schema.py --region $AWS_REGION

echo ""
echo "Running initialization in container..."
echo ""
echo "Manual steps (ECS Exec not available in script):"
echo "1. Connect to container:"
echo "   aws ecs execute-command --cluster ca-a2a-cluster --task $TASK_ARN --container orchestrator --interactive --command \"/bin/sh\" --region $AWS_REGION"
echo ""
echo "2. Inside container, run:"
echo "   python3 << 'EOF'"
echo "   # Paste the content of /tmp/init_db_schema.py here"
echo "   EOF"
echo ""

echo "========================================="
echo "  FIX INSTRUCTIONS COMPLETE"
echo "========================================="
```

---

## 🚀 Quick Fix Steps

### Step 1: Fix Code Locally (On Your Windows Machine)

The code fix has been applied to `base_agent.py`. Now rebuild and redeploy:

```powershell
# On your local Windows machine
cd "C:\Users\j.benabderrazak\OneDrive - Reply\Bureau\work\CA\A2A\ca_a2a"

# Build orchestrator
docker build -t orchestrator -f Dockerfile.orchestrator .

# Tag for ECR
docker tag orchestrator:latest 555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/orchestrator:latest

# Login to ECR
aws ecr get-login-password --region eu-west-3 --profile reply-sso | docker login --username AWS --password-stdin 555043101106.dkr.ecr.eu-west-3.amazonaws.com

# Push
docker push 555043101106.dkr.ecr.eu-west-3.amazonaws.com/ca-a2a/orchestrator:latest

# Force redeploy
aws ecs update-service --cluster ca-a2a-cluster --service orchestrator --force-new-deployment --region eu-west-3 --profile reply-sso
```

### Step 2: Initialize Database (In CloudShell)

```bash
export AWS_REGION=eu-west-3

# Get orchestrator task
TASK_ARN=$(aws ecs list-tasks \
  --cluster ca-a2a-cluster \
  --service-name orchestrator \
  --region $AWS_REGION \
  --query 'taskArns[0]' \
  --output text)

# Connect with ECS Exec
aws ecs execute-command \
  --cluster ca-a2a-cluster \
  --task $TASK_ARN \
  --container orchestrator \
  --interactive \
  --command "/bin/sh" \
  --region $AWS_REGION
```

Once inside the container:

```python
python3 << 'EOF'
import asyncio
import asyncpg
import os

async def init():
    conn = await asyncpg.connect(
        host=os.getenv('POSTGRES_HOST'),
        port=int(os.getenv('POSTGRES_PORT', 5432)),
        user=os.getenv('POSTGRES_USER'),
        password=os.getenv('POSTGRES_PASSWORD'),
        database=os.getenv('POSTGRES_DB', 'documents_db'),
        ssl='require'
    )
    
    print("Creating tables...")
    
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            filename VARCHAR(255) NOT NULL,
            file_type VARCHAR(50) NOT NULL,
            s3_key VARCHAR(512) NOT NULL,
            status VARCHAR(50) NOT NULL,
            extracted_data JSONB,
            validation_result JSONB,
            archived_s3_key VARCHAR(512),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            file_size INTEGER
        )
    """)
    
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS processing_logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            document_id UUID REFERENCES documents(id),
            agent_name VARCHAR(100) NOT NULL,
            operation VARCHAR(100) NOT NULL,
            status VARCHAR(50) NOT NULL,
            message TEXT,
            timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_created_at ON documents(created_at)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_processing_logs_document_id ON processing_logs(document_id)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_processing_logs_timestamp ON processing_logs(timestamp)")
    
    count = await conn.fetchval("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('documents', 'processing_logs')")
    print(f"✓ Created {count} tables")
    
    await conn.close()

asyncio.run(init())
EOF
```

### Step 3: Test Again

```bash
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Upload test file
echo "Test after fix $(date)" > /tmp/test-fixed.txt
aws s3 cp /tmp/test-fixed.txt s3://ca-a2a-documents-555043101106/incoming/test-fixed.txt --region eu-west-3

# Process
curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {"s3_key": "incoming/test-fixed.txt"},
    "id": 1
  }' | jq '.result'

# Wait and check
sleep 40

# Check database
curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {"limit": 10},
    "id": 2
  }' | jq '.result'
```

---

## 📋 Summary

### Fixed
- ✅ **Code fix applied:** Filter out `_meta` field in `base_agent.py`
- ⏳ **Needs rebuild:** Orchestrator Docker image needs to be rebuilt and pushed

### To Fix
- ⚠️ **Database schema:** Run initialization script in container
- ⏳ **Testing:** Retest after both fixes applied

---

**Priority:** Fix database schema first (can be done in CloudShell), then rebuild orchestrator image when convenient.

