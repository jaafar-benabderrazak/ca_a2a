import asyncio
import sys
sys.path.insert(0, '/app')

from mcp_protocol import PostgreSQLResource

async def initialize_database():
    print("Starting database schema initialization...")
    print("=" * 50)
    
    db = PostgreSQLResource()
    
    try:
        print("\n[1/4] Connecting to PostgreSQL database...")
        await db.connect()
        print("✓ Connected successfully!")
        
        print("\n[2/4] Creating database schema...")
        await db.initialize_schema()
        print("✓ Schema initialized!")
        
        print("\n[3/4] Verifying tables...")
        tables = await db.fetch_all("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name
        """)
        
        print(f"✓ Found {len(tables)} table(s):")
        for table in tables:
            print(f"  - {table['table_name']}")
        
        print("\n[4/4] Getting table counts...")
        doc_count = await db.fetch_value("SELECT COUNT(*) FROM documents")
        log_count = await db.fetch_value("SELECT COUNT(*) FROM processing_logs")
        
        print(f"  - documents: {doc_count} rows")
        print(f"  - processing_logs: {log_count} rows")
        
        print("\n" + "=" * 50)
        print("✓ DATABASE SCHEMA INITIALIZED SUCCESSFULLY!")
        print("=" * 50)
        
    except Exception as e:
        print(f"\n✗ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        await db.disconnect()

if __name__ == "__main__":
    asyncio.run(initialize_database())

