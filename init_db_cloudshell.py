# Simple CloudShell Script to Initialize Database
# Upload this file to CloudShell and run: python3 init_db_cloudshell.py

import asyncio
import asyncpg
import boto3
import json

# Configuration
DB_HOST = "ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com"
DB_PORT = 5432
DB_USER = "postgres"
DB_NAME = "documents_db"
REGION = "eu-west-3"
SECRET_ID = "ca-a2a/db-password"

def get_db_password():
    """Get database password from Secrets Manager"""
    client = boto3.client('secretsmanager', region_name=REGION)
    response = client.get_secret_value(SecretId=SECRET_ID)
    return response['SecretString']

async def initialize_schema():
    """Initialize database schema"""
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
    
    print(f"\n✓ Verification: Found {len(tables)} tables:")
    for table in tables:
        row_count = await conn.fetchval(f"SELECT COUNT(*) FROM {table['table_name']}")
        print(f"  - {table['table_name']}: {row_count} rows")
    
    await conn.close()
    print("\n✓ Database schema initialized successfully!")

if __name__ == '__main__':
    asyncio.run(initialize_schema())

