import asyncio
import os

import asyncpg
from dotenv import load_dotenv


def load_config():
    load_dotenv()
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = int(os.getenv("POSTGRES_PORT", 5432))
    user = os.getenv("POSTGRES_USER", "postgres")
    password = os.getenv("POSTGRES_PASSWORD", "postgres")
    db = os.getenv("POSTGRES_DB") or os.getenv("POSTGRES_DATABASE") or "documents_db"
    return host, port, user, password, db


async def main():
    host, port, user, password, db = load_config()
    print(f"Connecting to postgres://{user}@{host}:{port}/{db}\n")

    conn = await asyncpg.connect(host=host, port=port, user=user, password=password, database=db)
    try:
        tables = await conn.fetch(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            ORDER BY table_name
            """
        )
        print("Tables:")
        for t in tables:
            print(f"  - {t['table_name']}")
        print()

        async def show_table(name: str, cols: str, order_by: str = "1", limit: int = 5):
            print(f"Top {limit} rows from {name}:")
            try:
                rows = await conn.fetch(f"SELECT {cols} FROM {name} ORDER BY {order_by} DESC LIMIT {limit}")
            except Exception as e:
                print(f"  (error: {e})\n")
                return
            if not rows:
                print("  (no rows)\n")
                return
            for r in rows:
                print("  ", dict(r))
            print()

        # Counts
        for name in ["documents", "processing_logs"]:
            try:
                count = await conn.fetchval(f"SELECT COUNT(*) FROM {name}")
                print(f"Count {name}: {count}")
            except Exception as e:
                print(f"Count {name}: error ({e})")
        print()

        await show_table(
            "documents",
            cols="id, file_name, status, validation_score, created_at, s3_key",
            order_by="created_at",
            limit=5,
        )
        await show_table(
            "processing_logs",
            cols="id, document_id, agent_name, action, status, timestamp",
            order_by="timestamp",
            limit=5,
        )
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())

