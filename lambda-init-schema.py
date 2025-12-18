# Lambda Function to Initialize Database Schema
# Deploy this as a one-time Lambda function in the same VPC as RDS

import json
import asyncio
import asyncpg
import boto3
import os

# Get secret from Secrets Manager
def get_db_password():
    client = boto3.client('secretsmanager', region_name='eu-west-3')
    response = client.get_secret_value(SecretId='ca-a2a/db-password')
    return response['SecretString']

async def initialize_schema():
    password = get_db_password()
    
    print("Connecting to database...")
    conn = await asyncpg.connect(
        host='ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com',
        port=5432,
        user='postgres',
        password=password,
        database='documents_db',
        ssl='require'
    )
    
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
    
    print(f"✓ Verified: Found {len(tables)} tables")
    
    await conn.close()
    return {"status": "success", "tables": len(tables)}

def lambda_handler(event, context):
    try:
        result = asyncio.get_event_loop().run_until_complete(initialize_schema())
        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }
    except Exception as e:
        print(f"Error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({"error": str(e)})
        }

