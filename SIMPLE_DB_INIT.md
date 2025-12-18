# 🎯 SIMPLE DATABASE INITIALIZATION GUIDE

## ⚡ **Quick Solution: Use CloudShell**

Since the RDS database is in a private subnet, the easiest way to initialize it is from AWS CloudShell (which has VPC access).

---

## 📝 **Steps**

### 1. Upload the Script to CloudShell

In AWS CloudShell, run:

```bash
# Create the init script
cat > init_db.py << 'EOF'
import asyncio
import asyncpg
import boto3

DB_HOST = "ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com"
DB_PORT = 5432
DB_USER = "postgres"
DB_NAME = "documents_db"
REGION = "eu-west-3"
SECRET_ID = "ca-a2a/db-password"

def get_db_password():
    client = boto3.client('secretsmanager', region_name=REGION)
    response = client.get_secret_value(SecretId=SECRET_ID)
    return response['SecretString']

async def initialize_schema():
    print("Getting database password...")
    password = get_db_password()
    
    print(f"Connecting to {DB_HOST}:{DB_PORT}/{DB_NAME}...")
    conn = await asyncpg.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=password,
        database=DB_NAME,
        ssl='require'
    )
    
    print("Connected! Creating schema...")
    
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id SERIAL PRIMARY KEY,
            s3_key VARCHAR(500) UNIQUE NOT NULL,
            document_type VARCHAR(50) NOT NULL,
            file_name VARCHAR(255) NOT NULL,
            file_size INTEGER,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processing_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(50) DEFAULT 'pending',
            validation_score FLOAT,
            metadata JSONB,
            extracted_data JSONB,
            validation_details JSONB,
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("✓ Created documents table")
    
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS processing_logs (
            id SERIAL PRIMARY KEY,
            document_id INTEGER REFERENCES documents(id),
            agent_name VARCHAR(50) NOT NULL,
            action VARCHAR(100) NOT NULL,
            status VARCHAR(50) NOT NULL,
            details JSONB,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    print("✓ Created processing_logs table")
    
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_s3_key ON documents(s3_key)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_date ON documents(processing_date)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_document_id ON processing_logs(document_id)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_agent ON processing_logs(agent_name)")
    print("✓ Created indexes")
    
    tables = await conn.fetch("""
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name IN ('documents', 'processing_logs')
        ORDER BY table_name
    """)
    
    print(f"\n✓ Verification: Found {len(tables)} tables:")
    for table in tables:
        row_count = await conn.fetchval(f"SELECT COUNT(*) FROM {table['table_name']}")
        print(f"  - {table['table_name']}: {row_count} rows")
    
    await conn.close()
    print("\n✓ Database schema initialized successfully!")

if __name__ == '__main__':
    asyncio.run(initialize_schema())
EOF
```

### 2. Install Dependencies

```bash
pip3 install asyncpg --user
```

### 3. Run the Script

```bash
python3 init_db.py
```

**Expected Output:**
```
Getting database password...
Connecting to ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com:5432/documents_db...
Connected! Creating schema...
✓ Created documents table
✓ Created processing_logs table
✓ Created indexes

✓ Verification: Found 2 tables:
  - documents: 0 rows
  - processing_logs: 0 rows

✓ Database schema initialized successfully!
```

---

## 4. Test the API

After initialization, test that the API works:

```bash
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Should now return empty array instead of null
curl -s -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {"limit": 5},
    "id": 1
  }' | jq '.'
```

**Expected:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "count": 0,
    "documents": []
  },
  "id": 1
}
```

---

## 🎯 **Why This Works**

- ✅ CloudShell runs inside AWS network
- ✅ Has access to private subnets
- ✅ Can reach RDS directly
- ✅ Has boto3 pre-installed for Secrets Manager
- ✅ No complex Lambda deployment needed

---

## 🚨 **If You Get an Error**

### "Could not connect to server"
Your CloudShell might not have network access to the RDS subnet. Check that:
1. RDS security group (`sg-0dfffbf7f98f77a4c`) allows inbound from ECS security group (`sg-047a8f39f9cdcaf4c`)
2. Or temporarily allow all inbound on port 5432

### "asyncpg.exceptions.InvalidPasswordError"
The password doesn't match. Verify:
```bash
aws secretsmanager get-secret-value --secret-id ca-a2a/db-password --region eu-west-3 --query 'SecretString' --output text
```

### "database does not exist"
Create it first:
```bash
# Connect to postgres database and create documents_db
# (This should have been done during deployment)
```

---

## ✅ **After Success**

Once the schema is initialized, you can:
1. Test document processing end-to-end
2. Upload files to S3
3. Call the orchestrator API
4. See results in the database

---

**Total Time: ~2 minutes** ⚡

