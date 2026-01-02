#!/bin/bash
cd /app
python3 << 'PYTHON_EOF'
import asyncio
import sys
from mcp_protocol import PostgreSQLResource

async def init():
    print("Initializing database schema...")
    db = PostgreSQLResource()
    await db.connect()
    print("[OK] Connected to database")
    await db.initialize_schema()
    print("[OK] Schema initialized")
    tables = await db.fetch_all("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name")
    print(f"[OK] Found {len(tables)} tables: {[t['table_name'] for t in tables]}")
    doc_count = await db.fetch_value("SELECT COUNT(*) FROM documents")
    log_count = await db.fetch_value("SELECT COUNT(*) FROM processing_logs")
    print(f"[OK] documents: {doc_count} rows")
    print(f"[OK] processing_logs: {log_count} rows")
    await db.disconnect()
    print("[SUCCESS] Database schema initialized!")

asyncio.run(init())
PYTHON_EOF