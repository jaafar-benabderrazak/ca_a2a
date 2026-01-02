import json
import boto3
import psycopg2
from psycopg2.extras import RealDictCursor

def get_db_password():
    """Get database password from Secrets Manager"""
    client = boto3.client('secretsmanager', region_name='eu-west-3')
    response = client.get_secret_value(SecretId='ca-a2a/db-password')
    return response['SecretString']

def lambda_handler(event, context):
    """Initialize database schema"""
    results = []
    
    try:
        results.append("Getting database password from Secrets Manager...")
        password = get_db_password()
        
        results.append(f"Connecting to RDS: ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com")
        conn = psycopg2.connect(
            host='ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com',
            port=5432,
            user='postgres',
            password=password,
            database='documents_db',
            sslmode='require',
            connect_timeout=10
        )
        
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        results.append("Connected successfully!")
        
        # Create documents table
        results.append("Creating documents table...")
        cursor.execute("""
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
        conn.commit()
        results.append("âœ“ Documents table created")
        
        # Create processing_logs table
        results.append("Creating processing_logs table...")
        cursor.execute("""
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
        conn.commit()
        results.append("âœ“ Processing_logs table created")
        
        # Create indexes
        results.append("Creating indexes...")
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_documents_s3_key ON documents(s3_key)",
            "CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status)",
            "CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type)",
            "CREATE INDEX IF NOT EXISTS idx_documents_date ON documents(processing_date)",
            "CREATE INDEX IF NOT EXISTS idx_logs_document_id ON processing_logs(document_id)",
            "CREATE INDEX IF NOT EXISTS idx_logs_agent ON processing_logs(agent_name)"
        ]
        
        for idx_sql in indexes:
            cursor.execute(idx_sql)
        conn.commit()
        results.append("âœ“ Indexes created")
        
        # Verify tables
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('documents', 'processing_logs')
            ORDER BY table_name
        """)
        tables = cursor.fetchall()
        
        results.append(f"âœ“ Verification: Found {len(tables)} tables:")
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) as count FROM {table['table_name']}")
            count = cursor.fetchone()['count']
            results.append(f"  - {table['table_name']}: {count} rows")
        
        cursor.close()
        conn.close()
        
        results.append("âœ“ Database schema initialized successfully!")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Database schema initialized successfully',
                'details': results
            })
        }
        
    except Exception as e:
        error_msg = f"Error: {str(e)}"
        results.append(error_msg)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Failed to initialize database schema',
                'error': str(e),
                'details': results
            })
        }
