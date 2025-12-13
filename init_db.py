"""
Database initialization script
Creates the PostgreSQL schema and initial data
"""
import asyncio
import sys
from mcp_protocol import PostgreSQLResource
from config import POSTGRES_CONFIG


async def init_database():
    """Initialize database schema"""
    print("Initializing database schema...")
    
    db = PostgreSQLResource()
    
    try:
        await db.connect()
        print(f"Connected to database: {POSTGRES_CONFIG['database']}")
        
        # Initialize schema
        await db.initialize_schema()
        print("✓ Schema initialized successfully")
        
        # Verify tables
        tables = await db.fetch_all("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
        """)
        
        print(f"\nCreated tables:")
        for table in tables:
            print(f"  - {table['table_name']}")
        
        # Get counts
        doc_count = await db.fetch_value("SELECT COUNT(*) FROM documents")
        log_count = await db.fetch_value("SELECT COUNT(*) FROM processing_logs")
        
        print(f"\nCurrent data:")
        print(f"  - Documents: {doc_count}")
        print(f"  - Processing logs: {log_count}")
        
        print("\n✓ Database initialization completed successfully")
        
    except Exception as e:
        print(f"\n✗ Error initializing database: {str(e)}")
        sys.exit(1)
    finally:
        await db.disconnect()


async def reset_database():
    """Drop and recreate all tables"""
    print("WARNING: This will delete all data!")
    response = input("Are you sure you want to reset the database? (yes/no): ")
    
    if response.lower() != 'yes':
        print("Aborted.")
        return
    
    db = PostgreSQLResource()
    
    try:
        await db.connect()
        print("Connected to database")
        
        # Drop tables
        print("Dropping existing tables...")
        await db.execute("DROP TABLE IF EXISTS processing_logs CASCADE")
        await db.execute("DROP TABLE IF EXISTS documents CASCADE")
        print("✓ Tables dropped")
        
        # Recreate schema
        print("Creating schema...")
        await db.initialize_schema()
        print("✓ Schema created")
        
        print("\n✓ Database reset completed successfully")
        
    except Exception as e:
        print(f"\n✗ Error resetting database: {str(e)}")
        sys.exit(1)
    finally:
        await db.disconnect()


async def check_database():
    """Check database connection and status"""
    print("Checking database connection...")
    
    db = PostgreSQLResource()
    
    try:
        await db.connect()
        print("✓ Database connection successful")
        
        # Check PostgreSQL version
        version = await db.fetch_value("SELECT version()")
        print(f"\nPostgreSQL version:")
        print(f"  {version.split(',')[0]}")
        
        # Check tables
        tables = await db.fetch_all("""
            SELECT 
                table_name,
                (SELECT COUNT(*) FROM information_schema.columns WHERE table_name = t.table_name) as column_count
            FROM information_schema.tables t
            WHERE table_schema = 'public'
        """)
        
        print(f"\nTables:")
        if tables:
            for table in tables:
                print(f"  - {table['table_name']} ({table['column_count']} columns)")
        else:
            print("  No tables found. Run 'python init_db.py init' to create schema.")
        
        # Check indexes
        indexes = await db.fetch_all("""
            SELECT indexname, tablename
            FROM pg_indexes
            WHERE schemaname = 'public'
            ORDER BY tablename, indexname
        """)
        
        print(f"\nIndexes:")
        if indexes:
            for idx in indexes:
                print(f"  - {idx['indexname']} on {idx['tablename']}")
        else:
            print("  No indexes found.")
        
        print("\n✓ Database check completed")
        
    except Exception as e:
        print(f"\n✗ Error checking database: {str(e)}")
        sys.exit(1)
    finally:
        await db.disconnect()


async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Database initialization utility')
    parser.add_argument('action', choices=['init', 'reset', 'check'], 
                       help='Action to perform: init (create schema), reset (drop and recreate), check (verify connection)')
    
    args = parser.parse_args()
    
    if args.action == 'init':
        await init_database()
    elif args.action == 'reset':
        await reset_database()
    elif args.action == 'check':
        await check_database()


if __name__ == '__main__':
    asyncio.run(main())

