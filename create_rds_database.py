"""
Quick script to create documents_db database on RDS
"""
import asyncio
import asyncpg
import os
from dotenv import load_dotenv

async def create_database():
    load_dotenv()
    
    HOST = os.getenv('POSTGRES_HOST', 'ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com')
    PORT = int(os.getenv('POSTGRES_PORT', 5432))
    USER = os.getenv('POSTGRES_USER', 'postgres')
    PASSWORD = os.getenv('POSTGRES_PASSWORD', 'benabderrazak')
    DB_NAME = 'documents_db'
    
    print(f"Connecting to postgres@{HOST}:{PORT}")
    
    # Connect to default 'postgres' database to create new database
    conn = await asyncpg.connect(
        host=HOST,
        port=PORT,
        user=USER,
        password=PASSWORD,
        database='postgres',
        ssl='require'
    )
    
    try:
        # Check if database exists
        exists = await conn.fetchval(
            "SELECT 1 FROM pg_database WHERE datname = $1", DB_NAME
        )
        
        if exists:
            print(f"Database '{DB_NAME}' already exists")
        else:
            # Create database
            await conn.execute(f'CREATE DATABASE {DB_NAME}')
            print(f"[OK] Created database '{DB_NAME}'")
        
    finally:
        await conn.close()
    
    print(f"\nNow initializing schema in '{DB_NAME}'...")
    
    # Connect to the new database and create schema
    conn = await asyncpg.connect(
        host=HOST,
        port=PORT,
        user=USER,
        password=PASSWORD,
        database=DB_NAME,
        ssl='require'
    )
    
    try:
        # Create tables
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                s3_key VARCHAR(512) NOT NULL UNIQUE,
                file_type VARCHAR(50),
                file_size BIGINT,
                status VARCHAR(50) DEFAULT 'pending',
                extracted_data JSONB,
                validation_results JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                error_message TEXT
            );
        ''')
        
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS processing_logs (
                id SERIAL PRIMARY KEY,
                document_id INTEGER REFERENCES documents(id),
                agent_name VARCHAR(100),
                operation VARCHAR(100),
                status VARCHAR(50),
                details JSONB,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        ''')
        
        # Create indexes
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_documents_created_at ON documents(created_at);')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_processing_logs_document_id ON processing_logs(document_id);')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_processing_logs_timestamp ON processing_logs(timestamp);')
        
        print("[OK] Schema initialized successfully")
        
    finally:
        await conn.close()

if __name__ == '__main__':
    asyncio.run(create_database())

