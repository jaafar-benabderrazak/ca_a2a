"""
AWS MCP Server - HTTP Version for ECS Deployment
Provides HTTP API wrapper around MCP server for distributed agent access
"""
import asyncio
import json
import logging
from typing import Dict, Any
from datetime import datetime

from aiohttp import web
import aioboto3
import asyncpg
from botocore.exceptions import ClientError

from config import AWS_CONFIG, POSTGRES_CONFIG
from utils import retry_with_backoff, CircuitBreaker

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mcp-server-http")


class MCPServerHTTP:
    """HTTP wrapper for MCP server operations"""
    
    def __init__(self):
        self.s3_session: aioboto3.Session = None
        self.pg_pool: asyncpg.Pool = None
        
        # Circuit breakers
        self.s3_circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=ClientError
        )
        self.pg_circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=asyncpg.PostgresError
        )
        
        logger.info("MCP HTTP Server initialized")
    
    async def initialize(self):
        """Initialize AWS and DB connections"""
        # Initialize S3
        self.s3_session = aioboto3.Session(
            region_name=AWS_CONFIG['region']
        )
        logger.info(f"S3 session initialized for region {AWS_CONFIG['region']}")
        
        # Initialize PostgreSQL pool
        self.pg_pool = await asyncpg.create_pool(
            host=POSTGRES_CONFIG['host'],
            port=POSTGRES_CONFIG['port'],
            user=POSTGRES_CONFIG['user'],
            password=POSTGRES_CONFIG['password'],
            database=POSTGRES_CONFIG['database'],
            min_size=2,
            max_size=10,
            command_timeout=60
        )
        logger.info(f"PostgreSQL pool created: {POSTGRES_CONFIG['database']}")
    
    async def cleanup(self):
        """Cleanup connections"""
        if self.pg_pool:
            await self.pg_pool.close()
            logger.info("PostgreSQL pool closed")
    
    # ========== S3 Operations ==========
    
    async def s3_list_objects(self, prefix: str = "", limit: int = 100) -> Dict[str, Any]:
        """List objects in S3 bucket"""
        async def _list():
            async with self.s3_session.client('s3') as s3:
                response = await s3.list_objects_v2(
                    Bucket=AWS_CONFIG['s3_bucket'],
                    Prefix=prefix,
                    MaxKeys=limit
                )
                
                objects = []
                for obj in response.get('Contents', []):
                    objects.append({
                        'key': obj['Key'],
                        'size': obj['Size'],
                        'last_modified': obj['LastModified'].isoformat(),
                        'etag': obj['ETag']
                    })
                
                return {
                    'bucket': AWS_CONFIG['s3_bucket'],
                    'objects': objects,
                    'count': len(objects),
                    'success': True
                }
        
        return await retry_with_backoff(
            lambda: self.s3_circuit_breaker.call_async(_list),
            max_retries=3,
            exceptions=(ClientError,)
        )
    
    async def s3_get_object(self, key: str) -> Dict[str, Any]:
        """Get object from S3"""
        async def _get():
            async with self.s3_session.client('s3') as s3:
                response = await s3.get_object(
                    Bucket=AWS_CONFIG['s3_bucket'],
                    Key=key
                )
                
                body = await response['Body'].read()
                
                return {
                    'key': key,
                    'content': body.decode('utf-8', errors='ignore'),
                    'content_type': response['ContentType'],
                    'size': response['ContentLength'],
                    'success': True
                }
        
        return await retry_with_backoff(
            lambda: self.s3_circuit_breaker.call_async(_get),
            max_retries=3,
            exceptions=(ClientError,)
        )
    
    async def s3_put_object(self, key: str, body: bytes, content_type: str = "application/octet-stream") -> Dict[str, Any]:
        """Put object to S3"""
        async def _put():
            async with self.s3_session.client('s3') as s3:
                await s3.put_object(
                    Bucket=AWS_CONFIG['s3_bucket'],
                    Key=key,
                    Body=body,
                    ContentType=content_type
                )
                
                return {
                    'key': key,
                    'bucket': AWS_CONFIG['s3_bucket'],
                    'size': len(body),
                    'success': True
                }
        
        return await retry_with_backoff(
            lambda: self.s3_circuit_breaker.call_async(_put),
            max_retries=3,
            exceptions=(ClientError,)
        )
    
    # ========== PostgreSQL Operations ==========
    
    async def postgres_query(self, query: str, params: list = None) -> Dict[str, Any]:
        """Execute SELECT query"""
        async def _query():
            async with self.pg_pool.acquire() as conn:
                rows = await conn.fetch(query, *(params or []))
                
                return {
                    'rows': [dict(row) for row in rows],
                    'count': len(rows),
                    'success': True
                }
        
        return await retry_with_backoff(
            lambda: self.pg_circuit_breaker.call_async(_query),
            max_retries=3,
            exceptions=(asyncpg.PostgresError,)
        )
    
    async def postgres_execute(self, query: str, params: list = None) -> Dict[str, Any]:
        """Execute INSERT/UPDATE/DELETE query"""
        async def _execute():
            async with self.pg_pool.acquire() as conn:
                result = await conn.execute(query, *(params or []))
                return {
                    'result': result,
                    'success': True
                }
        
        return await retry_with_backoff(
            lambda: self.pg_circuit_breaker.call_async(_execute),
            max_retries=3,
            exceptions=(asyncpg.PostgresError,)
        )
    
    async def postgres_init_schema(self) -> Dict[str, Any]:
        """Initialize database schema"""
        schema_sql = """
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
        );
        
        CREATE INDEX IF NOT EXISTS idx_documents_s3_key ON documents(s3_key);
        CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);
        CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type);
        CREATE INDEX IF NOT EXISTS idx_documents_date ON documents(processing_date);
        
        CREATE TABLE IF NOT EXISTS processing_logs (
            id SERIAL PRIMARY KEY,
            document_id INTEGER REFERENCES documents(id),
            agent_name VARCHAR(50) NOT NULL,
            action VARCHAR(100) NOT NULL,
            status VARCHAR(50) NOT NULL,
            details JSONB,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_logs_document_id ON processing_logs(document_id);
        CREATE INDEX IF NOT EXISTS idx_logs_agent ON processing_logs(agent_name);
        """
        
        async def _execute():
            async with self.pg_pool.acquire() as conn:
                await conn.execute(schema_sql)
                return {
                    'message': 'Schema initialized successfully',
                    'tables': ['documents', 'processing_logs'],
                    'success': True
                }
        
        return await retry_with_backoff(
            lambda: self.pg_circuit_breaker.call_async(_execute),
            max_retries=3,
            exceptions=(asyncpg.PostgresError,)
        )
    
    # ========== HTTP Handlers ==========
    
    async def handle_call_tool(self, request: web.Request) -> web.Response:
        """Handle tool call requests"""
        try:
            data = await request.json()
            tool_name = data.get('tool')
            arguments = data.get('arguments', {})
            
            logger.info(f"Tool call: {tool_name}")
            
            # Route to appropriate method
            if tool_name == "s3_list_objects":
                result = await self.s3_list_objects(**arguments)
            elif tool_name == "s3_get_object":
                result = await self.s3_get_object(**arguments)
            elif tool_name == "s3_put_object":
                result = await self.s3_put_object(**arguments)
            elif tool_name == "postgres_query":
                result = await self.postgres_query(**arguments)
            elif tool_name == "postgres_execute":
                result = await self.postgres_execute(**arguments)
            elif tool_name == "postgres_init_schema":
                result = await self.postgres_init_schema()
            else:
                return web.json_response({
                    'error': f'Unknown tool: {tool_name}',
                    'success': False
                }, status=400)
            
            return web.json_response(result)
        
        except Exception as e:
            logger.error(f"Tool execution error: {str(e)}")
            return web.json_response({
                'error': str(e),
                'success': False
            }, status=500)
    
    async def handle_health(self, request: web.Request) -> web.Response:
        """Health check endpoint"""
        try:
            # Check PostgreSQL
            async with self.pg_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            
            # Check S3 (simple list operation)
            async with self.s3_session.client('s3') as s3:
                await s3.head_bucket(Bucket=AWS_CONFIG['s3_bucket'])
            
            return web.json_response({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'services': {
                    'postgresql': 'ok',
                    's3': 'ok'
                }
            })
        
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return web.json_response({
                'status': 'unhealthy',
                'error': str(e)
            }, status=503)


async def create_app() -> web.Application:
    """Create and configure the web application"""
    server = MCPServerHTTP()
    await server.initialize()
    
    app = web.Application()
    
    # Routes
    app.router.add_post('/call_tool', server.handle_call_tool)
    app.router.add_get('/health', server.handle_health)
    
    # Cleanup on shutdown
    async def cleanup(app):
        await server.cleanup()
    
    app.on_cleanup.append(cleanup)
    
    return app


def main():
    """Main entry point"""
    port = 8000
    logger.info(f"Starting MCP HTTP Server on port {port}")
    
    app = asyncio.run(create_app())
    web.run_app(app, host='0.0.0.0', port=port)


if __name__ == '__main__':
    main()

