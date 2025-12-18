#!/bin/bash
# Initialize Database Schema from Local Machine
# Run this from your Windows machine where you have RDS access

export AWS_REGION=eu-west-3
export AWS_PROFILE=reply-sso

echo "========================================="
echo "  DATABASE SCHEMA INITIALIZATION"
echo "========================================="
echo ""

echo "Step 1: Getting database password..."
DB_PASSWORD=$(aws secretsmanager get-secret-value \
  --secret-id ca-a2a/db-password \
  --region $AWS_REGION \
  --profile $AWS_PROFILE \
  --query 'SecretString' \
  --output text)

if [ -z "$DB_PASSWORD" ]; then
  echo "❌ Failed to get database password"
  exit 1
fi

echo "✓ Password retrieved"
echo ""

echo "Step 2: Getting your IP address..."
MY_IP=$(curl -s https://checkip.amazonaws.com)
echo "Your IP: $MY_IP"
echo ""

echo "Step 3: Temporarily allowing your IP in RDS security group..."
aws ec2 authorize-security-group-ingress \
  --group-id sg-0dfffbf7f98f77a4c \
  --protocol tcp \
  --port 5432 \
  --cidr "$MY_IP/32" \
  --region $AWS_REGION \
  --profile $AWS_PROFILE 2>/dev/null

if [ $? -eq 0 ]; then
  echo "✓ IP whitelisted"
else
  echo "⚠ IP might already be whitelisted or command failed (continuing anyway...)"
fi

echo ""
echo "Step 4: Initializing database schema..."
echo ""

# Create Python script to init schema
cat > /tmp/init_schema.py << 'PYTHON_SCRIPT'
import asyncio
import asyncpg
import sys

DB_HOST = "ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com"
DB_PORT = 5432
DB_USER = "postgres"
DB_NAME = "documents_db"

async def initialize_schema(password):
    try:
        print(f"Connecting to {DB_HOST}:{DB_PORT}/{DB_NAME}...")
        
        conn = await asyncpg.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=password,
            database=DB_NAME,
            ssl='require'
        )
        
        print("✓ Connected!")
        print("")
        print("Creating tables...")
        
        # Create documents table
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
        
        # Create processing_logs table
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
        
        # Create indexes
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_s3_key ON documents(s3_key)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_documents_date ON documents(processing_date)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_document_id ON processing_logs(document_id)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_agent ON processing_logs(agent_name)")
        print("✓ Created indexes")
        
        # Verify
        tables = await conn.fetch("""
            SELECT table_name FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('documents', 'processing_logs')
            ORDER BY table_name
        """)
        
        print("")
        print(f"✓ Verification: Found {len(tables)} tables")
        for table in tables:
            row_count = await conn.fetchval(f"SELECT COUNT(*) FROM {table['table_name']}")
            print(f"  - {table['table_name']}: {row_count} rows")
        
        await conn.close()
        print("")
        print("✓ Database schema initialized successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python init_schema.py <password>")
        sys.exit(1)
    
    success = asyncio.run(initialize_schema(sys.argv[1]))
    sys.exit(0 if success else 1)
PYTHON_SCRIPT

# Run the init script
python /tmp/init_schema.py "$DB_PASSWORD"
INIT_RESULT=$?

echo ""
echo "Step 5: Removing temporary security group rule..."
aws ec2 revoke-security-group-ingress \
  --group-id sg-0dfffbf7f98f77a4c \
  --protocol tcp \
  --port 5432 \
  --cidr "$MY_IP/32" \
  --region $AWS_REGION \
  --profile $AWS_PROFILE 2>/dev/null

echo "✓ Temporary rule removed"
echo ""

if [ $INIT_RESULT -eq 0 ]; then
  echo "========================================="
  echo "  ✓ INITIALIZATION COMPLETE!"
  echo "========================================="
  echo ""
  echo "You can now test the API:"
  echo "  curl -s -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message \\"
  echo "    -H 'Content-Type: application/json' \\"
  echo "    -d '{\"jsonrpc\": \"2.0\", \"method\": \"list_pending_documents\", \"params\": {\"limit\": 5}, \"id\": 1}' | jq '.'"
else
  echo "========================================="
  echo "  ❌ INITIALIZATION FAILED"
  echo "========================================="
  exit 1
fi

