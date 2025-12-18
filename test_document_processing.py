"""
Test script to trigger document processing
Simulates uploading documents and triggering the orchestrator
"""
import asyncio
import aiohttp
import json
from datetime import datetime

# Since we can't access the orchestrator directly (it's not exposed via ALB yet),
# we'll check the database to see if documents were registered

async def check_s3_documents():
    """List documents in S3 bucket"""
    import aioboto3
    import os
    
    bucket_name = "ca-a2a-documents-555043101106"
    
    session = aioboto3.Session()
    async with session.client('s3', region_name='eu-west-3') as s3:
        try:
            response = await s3.list_objects_v2(
                Bucket=bucket_name,
                Prefix='incoming/'
            )
            
            if 'Contents' in response:
                print(f"\n[OK] Found {len(response['Contents'])} documents in S3:")
                for obj in response['Contents']:
                    print(f"  - {obj['Key']} ({obj['Size']} bytes, {obj['LastModified']})")
                return response['Contents']
            else:
                print("[INFO] No documents found in S3")
                return []
        except Exception as e:
            print(f"[ERROR] Failed to list S3 objects: {e}")
            return []

async def check_database():
    """Check database for processed documents"""
    import asyncpg
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    
    HOST = os.getenv('POSTGRES_HOST', 'ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com')
    PORT = int(os.getenv('POSTGRES_PORT', 5432))
    USER = os.getenv('POSTGRES_USER', 'postgres')
    PASSWORD = os.getenv('POSTGRES_PASSWORD', 'benabderrazak')
    DB = 'documents_db'
    
    try:
        conn = await asyncpg.connect(
            host=HOST, port=PORT, user=USER, password=PASSWORD,
            database=DB, ssl='require'
        )
        
        # Check documents table
        doc_count = await conn.fetchval("SELECT COUNT(*) FROM documents")
        print(f"\n[DB] Documents table: {doc_count} records")
        
        if doc_count > 0:
            docs = await conn.fetch("""
                SELECT id, filename, s3_key, file_type, status, created_at 
                FROM documents 
                ORDER BY created_at DESC 
                LIMIT 10
            """)
            print("\nRecent documents:")
            for doc in docs:
                print(f"  [{doc['status']}] {doc['filename']} ({doc['file_type']}) - {doc['s3_key']}")
        
        # Check processing logs
        log_count = await conn.fetchval("SELECT COUNT(*) FROM processing_logs")
        print(f"\n[DB] Processing logs table: {log_count} records")
        
        if log_count > 0:
            logs = await conn.fetch("""
                SELECT agent_name, operation, status, timestamp 
                FROM processing_logs 
                ORDER BY timestamp DESC 
                LIMIT 10
            """)
            print("\nRecent processing logs:")
            for log in logs:
                print(f"  [{log['status']}] {log['agent_name']}: {log['operation']} @ {log['timestamp']}")
        
        await conn.close()
        return doc_count, log_count
        
    except Exception as e:
        print(f"[ERROR] Database check failed: {e}")
        return 0, 0

async def main():
    print("=" * 60)
    print("DOCUMENT PROCESSING TEST")
    print("=" * 60)
    
    print("\n[1/2] Checking S3 bucket for uploaded documents...")
    s3_docs = await check_s3_documents()
    
    print("\n[2/2] Checking database for processing results...")
    doc_count, log_count = await check_database()
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"S3 Documents:      {len(s3_docs)}")
    print(f"DB Documents:      {doc_count}")
    print(f"Processing Logs:   {log_count}")
    
    if doc_count == 0:
        print("\n[NOTE] No documents in database yet.")
        print("The current architecture requires manual triggering of the orchestrator.")
        print("To fully automate, you would need to:")
        print("  1. Configure S3 Event Notifications to trigger Lambda/SQS")
        print("  2. Or implement a polling mechanism in the orchestrator")
        print("  3. Or expose orchestrator API and call it after S3 upload")

if __name__ == "__main__":
    asyncio.run(main())

