#!/usr/bin/env python3
"""
Database migration runner for CA-A2A v5.1
Executes SQL migration scripts against PostgreSQL RDS
"""

import asyncio
import os
import sys
import json

# Try asyncpg first, fall back to psycopg2 if not available
try:
    import asyncpg
    USE_ASYNCPG = True
except ImportError:
    try:
        import psycopg2
        USE_ASYNCPG = False
    except ImportError:
        print("ERROR: Neither asyncpg nor psycopg2 is installed")
        print("Install one with: pip install asyncpg  OR  pip install psycopg2-binary")
        sys.exit(1)


async def run_migration_asyncpg(host: str, port: int, database: str, user: str, password: str, sql_file: str):
    """Run migration using asyncpg"""
    print(f"[INFO] Connecting to {host}:{port}/{database} as {user} (asyncpg)")
    
    try:
        conn = await asyncpg.connect(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password,
            timeout=30
        )
        
        print(f"[INFO] Connected successfully")
        
        # Read SQL file
        with open(sql_file, 'r') as f:
            sql = f.read()
        
        print(f"[INFO] Executing migration from {sql_file}...")
        
        # Execute SQL
        await conn.execute(sql)
        
        print("[SUCCESS] Migration executed successfully")
        
        # Verify table exists
        result = await conn.fetchrow("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'revoked_tokens'
            ) as exists
        """)
        
        if result['exists']:
            # Get row count
            count = await conn.fetchval("SELECT COUNT(*) FROM revoked_tokens")
            print(f"[SUCCESS] Table 'revoked_tokens' exists with {count} rows")
        else:
            print("[ERROR] Table 'revoked_tokens' was not created")
            return False
        
        await conn.close()
        return True
        
    except Exception as e:
        print(f"[ERROR] Migration failed: {e}")
        return False


def run_migration_psycopg2(host: str, port: int, database: str, user: str, password: str, sql_file: str):
    """Run migration using psycopg2"""
    print(f"[INFO] Connecting to {host}:{port}/{database} as {user} (psycopg2)")
    
    try:
        import psycopg2
        
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password,
            connect_timeout=30
        )
        
        print(f"[INFO] Connected successfully")
        
        cursor = conn.cursor()
        
        # Read SQL file
        with open(sql_file, 'r') as f:
            sql = f.read()
        
        print(f"[INFO] Executing migration from {sql_file}...")
        
        # Execute SQL
        cursor.execute(sql)
        conn.commit()
        
        print("[SUCCESS] Migration executed successfully")
        
        # Verify table exists
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'revoked_tokens'
            )
        """)
        
        exists = cursor.fetchone()[0]
        
        if exists:
            # Get row count
            cursor.execute("SELECT COUNT(*) FROM revoked_tokens")
            count = cursor.fetchone()[0]
            print(f"[SUCCESS] Table 'revoked_tokens' exists with {count} rows")
        else:
            print("[ERROR] Table 'revoked_tokens' was not created")
            cursor.close()
            conn.close()
            return False
        
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"[ERROR] Migration failed: {e}")
        return False


async def main():
    """Main migration runner"""
    
    # Configuration from environment or defaults
    DB_HOST = os.getenv('DB_HOST', 'documents-db.cluster-czkdu9wcburt.eu-west-3.rds.amazonaws.com')
    DB_PORT = int(os.getenv('DB_PORT', '5432'))
    DB_NAME = os.getenv('DB_NAME', 'documents')
    DB_USER = os.getenv('DB_USER', 'postgres')
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    
    if not DB_PASSWORD:
        print("[ERROR] DB_PASSWORD environment variable is required")
        print("Usage: $env:DB_PASSWORD='yourpassword'; python run_migration_python.py")
        sys.exit(1)
    
    # SQL migration file
    sql_file = os.path.join(os.path.dirname(__file__), '001_create_revoked_tokens_table.sql')
    
    if not os.path.exists(sql_file):
        print(f"[ERROR] Migration file not found: {sql_file}")
        sys.exit(1)
    
    print("=" * 60)
    print("CA-A2A DATABASE MIGRATION v5.1")
    print("=" * 60)
    print(f"Host:     {DB_HOST}")
    print(f"Port:     {DB_PORT}")
    print(f"Database: {DB_NAME}")
    print(f"User:     {DB_USER}")
    print(f"Library:  {'asyncpg' if USE_ASYNCPG else 'psycopg2'}")
    print("=" * 60)
    
    if USE_ASYNCPG:
        success = await run_migration_asyncpg(DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, sql_file)
    else:
        success = run_migration_psycopg2(DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, sql_file)
    
    if success:
        print("\n✅ Migration completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Migration failed")
        sys.exit(1)


if __name__ == '__main__':
    if USE_ASYNCPG:
        asyncio.run(main())
    else:
        asyncio.run(main())  # Still works with sync function

