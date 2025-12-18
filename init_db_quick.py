"""Quick script to create documents_db database via ECS Exec"""
import asyncio
import asyncpg
import os

async def create_db():
    # RDS connection details (from ECS task env vars)
    HOST = os.getenv('POSTGRES_HOST')
    PORT = int(os.getenv('POSTGRES_PORT', 5432))
    USER = os.getenv('POSTGRES_USER')
    PASSWORD = os.getenv('POSTGRES_PASSWORD')
    
    print(f"Connecting to {HOST}...")
    
    # Connect to postgres database
    conn = await asyncpg.connect(
        host=HOST, port=PORT, user=USER, password=PASSWORD,
        database='postgres', ssl='require'
    )
    
    try:
        # Check if DB exists
        exists = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname='documents_db'")
        if not exists:
            await conn.execute('CREATE DATABASE documents_db')
            print("Created documents_db")
        else:
            print("documents_db already exists")
    finally:
        await conn.close()
    
    # Connect to documents_db and create schema
    conn = await asyncpg.connect(
        host=HOST, port=PORT, user=USER, password=PASSWORD,
        database='documents_db', ssl='require'
    )
    
    try:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS documents (
                id SERIAL PRIMARY KEY, filename VARCHAR(255) NOT NULL,
                s3_key VARCHAR(512) NOT NULL UNIQUE, file_type VARCHAR(50),
                file_size BIGINT, status VARCHAR(50) DEFAULT 'pending',
                extracted_data JSONB, validation_results JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, error_message TEXT
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS processing_logs (
                id SERIAL PRIMARY KEY, document_id INTEGER REFERENCES documents(id),
                agent_name VARCHAR(100), operation VARCHAR(100), status VARCHAR(50),
                details JSONB, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status)')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_documents_created_at ON documents(created_at)')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_processing_logs_document_id ON processing_logs(document_id)')
        await conn.execute('CREATE INDEX IF NOT EXISTS idx_processing_logs_timestamp ON processing_logs(timestamp)')
        print("Schema created successfully!")
    finally:
        await conn.close()

asyncio.run(create_db())

