"""
AWS-Specific MCP Server
Implements Model Context Protocol for S3 and PostgreSQL resources
Provides standardized resource access for AI agents

MCP Specification: https://spec.modelcontextprotocol.io/
"""
import asyncio
import json
import logging
import sys
from typing import Any, Dict, List, Optional, Sequence
from datetime import datetime

# MCP SDK imports
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    ResourceTemplate,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)

# AWS and Database imports
import aioboto3
import asyncpg
from botocore.exceptions import ClientError

# Local imports
from config import AWS_CONFIG, POSTGRES_CONFIG
from utils import retry_with_backoff, CircuitBreaker

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mcp-server")


class AWSMCPServer:
    """
    AWS-Specific MCP Server providing S3 and PostgreSQL resources
    """
    
    def __init__(self):
        self.server = Server("ca-a2a-aws-resources")
        self.s3_session: Optional[aioboto3.Session] = None
        self.pg_pool: Optional[asyncpg.Pool] = None
        
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
        
        # Register handlers
        self._register_handlers()
        
        logger.info("AWS MCP Server initialized")
    
    def _register_handlers(self):
        """Register MCP protocol handlers"""
        
        # List resources handler
        @self.server.list_resources()
        async def list_resources() -> List[Resource]:
            """List all available MCP resources"""
            resources = []
            
            # S3 bucket resource
            resources.append(Resource(
                uri=f"s3://{AWS_CONFIG['s3_bucket']}/",
                name=f"S3 Bucket: {AWS_CONFIG['s3_bucket']}",
                description="AWS S3 bucket for document storage",
                mimeType="application/x-directory"
            ))
            
            # PostgreSQL database resource
            resources.append(Resource(
                uri=f"postgres://{POSTGRES_CONFIG['host']}/{POSTGRES_CONFIG['database']}",
                name=f"PostgreSQL: {POSTGRES_CONFIG['database']}",
                description="Document processing database with documents and processing_logs tables",
                mimeType="application/x-postgresql"
            ))
            
            logger.info(f"Listed {len(resources)} resources")
            return resources
        
        # List resource templates handler
        @self.server.list_resource_templates()
        async def list_resource_templates() -> List[ResourceTemplate]:
            """List resource URI templates for dynamic resources"""
            templates = []
            
            # S3 object template
            templates.append(ResourceTemplate(
                uriTemplate=f"s3://{AWS_CONFIG['s3_bucket']}/{{path}}",
                name="S3 Object",
                description="Access individual S3 objects by path",
                mimeType="application/octet-stream"
            ))
            
            # PostgreSQL table template
            templates.append(ResourceTemplate(
                uriTemplate=f"postgres://{POSTGRES_CONFIG['host']}/{POSTGRES_CONFIG['database']}/{{table}}",
                name="PostgreSQL Table",
                description="Access PostgreSQL tables",
                mimeType="application/json"
            ))
            
            logger.info(f"Listed {len(templates)} resource templates")
            return templates
        
        # Read resource handler
        @self.server.read_resource()
        async def read_resource(uri: str) -> str:
            """Read content from a resource URI"""
            logger.info(f"Reading resource: {uri}")
            
            if uri.startswith("s3://"):
                return await self._read_s3_resource(uri)
            elif uri.startswith("postgres://"):
                return await self._read_postgres_resource(uri)
            else:
                raise ValueError(f"Unsupported URI scheme: {uri}")
        
        # List tools handler
        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            """List all available MCP tools"""
            tools = [
                Tool(
                    name="s3_list_objects",
                    description="List objects in S3 bucket with optional prefix filter",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "prefix": {
                                "type": "string",
                                "description": "Prefix to filter objects (e.g., 'incoming/', 'processed/')"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of objects to return",
                                "default": 100
                            }
                        }
                    }
                ),
                Tool(
                    name="s3_get_object",
                    description="Download an object from S3",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "key": {
                                "type": "string",
                                "description": "S3 object key"
                            }
                        },
                        "required": ["key"]
                    }
                ),
                Tool(
                    name="s3_put_object",
                    description="Upload an object to S3",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "key": {
                                "type": "string",
                                "description": "S3 object key"
                            },
                            "content": {
                                "type": "string",
                                "description": "Object content (base64 encoded for binary)"
                            },
                            "metadata": {
                                "type": "object",
                                "description": "Optional metadata"
                            }
                        },
                        "required": ["key", "content"]
                    }
                ),
                Tool(
                    name="postgres_query",
                    description="Execute a SELECT query on PostgreSQL",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "SQL SELECT query"
                            },
                            "params": {
                                "type": "array",
                                "description": "Query parameters",
                                "items": {"type": "string"}
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="postgres_execute",
                    description="Execute an INSERT/UPDATE/DELETE query on PostgreSQL",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "SQL query"
                            },
                            "params": {
                                "type": "array",
                                "description": "Query parameters",
                                "items": {"type": "string"}
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool(
                    name="document_store",
                    description="Store a document with extracted data in PostgreSQL",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "s3_key": {"type": "string"},
                            "document_type": {"type": "string"},
                            "file_name": {"type": "string"},
                            "status": {"type": "string"},
                            "extracted_data": {"type": "object"},
                            "validation_score": {"type": "number"}
                        },
                        "required": ["s3_key", "document_type", "file_name"]
                    }
                ),
                Tool(
                    name="document_list",
                    description="List documents from PostgreSQL with optional filters",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "status": {
                                "type": "string",
                                "description": "Filter by status (pending, processing, completed, failed)"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of documents",
                                "default": 10
                            }
                        }
                    }
                )
            ]
            
            logger.info(f"Listed {len(tools)} tools")
            return tools
        
        # Call tool handler
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
            """Execute a tool and return results"""
            logger.info(f"Calling tool: {name} with args: {arguments}")
            
            try:
                if name == "s3_list_objects":
                    result = await self._tool_s3_list_objects(**arguments)
                elif name == "s3_get_object":
                    result = await self._tool_s3_get_object(**arguments)
                elif name == "s3_put_object":
                    result = await self._tool_s3_put_object(**arguments)
                elif name == "postgres_query":
                    result = await self._tool_postgres_query(**arguments)
                elif name == "postgres_execute":
                    result = await self._tool_postgres_execute(**arguments)
                elif name == "document_store":
                    result = await self._tool_document_store(**arguments)
                elif name == "document_list":
                    result = await self._tool_document_list(**arguments)
                else:
                    raise ValueError(f"Unknown tool: {name}")
                
                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2, default=str)
                )]
            
            except Exception as e:
                logger.error(f"Tool execution error: {str(e)}")
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "error": str(e),
                        "tool": name,
                        "arguments": arguments
                    }, indent=2)
                )]
    
    # ========== Resource Readers ==========
    
    async def _read_s3_resource(self, uri: str) -> str:
        """Read S3 resource content"""
        # Parse URI: s3://bucket/key
        parts = uri[5:].split('/', 1)
        bucket = parts[0]
        key = parts[1] if len(parts) > 1 else ""
        
        if not key:
            # List bucket contents
            objects = await self._tool_s3_list_objects(prefix="", limit=100)
            return json.dumps(objects, indent=2, default=str)
        else:
            # Get object content
            result = await self._tool_s3_get_object(key=key)
            return json.dumps(result, indent=2, default=str)
    
    async def _read_postgres_resource(self, uri: str) -> str:
        """Read PostgreSQL resource content"""
        # Parse URI: postgres://host/database/table
        parts = uri.split('/')
        table = parts[-1] if len(parts) > 4 else None
        
        if table:
            # Query table
            query = f"SELECT * FROM {table} LIMIT 100"
            result = await self._tool_postgres_query(query=query)
            return json.dumps(result, indent=2, default=str)
        else:
            # List tables
            query = """
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
                ORDER BY table_name
            """
            result = await self._tool_postgres_query(query=query)
            return json.dumps(result, indent=2, default=str)
    
    # ========== S3 Tools ==========
    
    async def _tool_s3_list_objects(self, prefix: str = "", limit: int = 100) -> Dict[str, Any]:
        """List objects in S3 bucket"""
        async def _list():
            objects = []
            async with self.s3_session.client('s3') as s3_client:
                paginator = s3_client.get_paginator('list_objects_v2')
                async for page in paginator.paginate(
                    Bucket=AWS_CONFIG['s3_bucket'],
                    Prefix=prefix,
                    MaxKeys=limit
                ):
                    if 'Contents' in page:
                        for obj in page['Contents']:
                            objects.append({
                                'key': obj['Key'],
                                'size': obj['Size'],
                                'last_modified': obj['LastModified'].isoformat(),
                                'etag': obj['ETag']
                            })
                            if len(objects) >= limit:
                                break
                    if len(objects) >= limit:
                        break
            
            return {
                'bucket': AWS_CONFIG['s3_bucket'],
                'prefix': prefix,
                'count': len(objects),
                'objects': objects
            }
        
        return await retry_with_backoff(
            lambda: self.s3_circuit_breaker.call(_list),
            max_retries=3,
            exceptions=(ClientError,)
        )
    
    async def _tool_s3_get_object(self, key: str) -> Dict[str, Any]:
        """Get object from S3"""
        async def _get():
            async with self.s3_session.client('s3') as s3_client:
                response = await s3_client.get_object(
                    Bucket=AWS_CONFIG['s3_bucket'],
                    Key=key
                )
                content = await response['Body'].read()
                
                # Try to decode as text, otherwise base64
                try:
                    content_text = content.decode('utf-8')
                    content_repr = content_text
                    is_binary = False
                except UnicodeDecodeError:
                    import base64
                    content_repr = base64.b64encode(content).decode('ascii')
                    is_binary = True
                
                return {
                    'key': key,
                    'size': len(content),
                    'content_type': response.get('ContentType'),
                    'is_binary': is_binary,
                    'content': content_repr,
                    'metadata': response.get('Metadata', {})
                }
        
        return await retry_with_backoff(
            lambda: self.s3_circuit_breaker.call(_get),
            max_retries=3,
            exceptions=(ClientError,)
        )
    
    async def _tool_s3_put_object(self, key: str, content: str, metadata: Dict[str, str] = None) -> Dict[str, Any]:
        """Put object to S3"""
        # Try to decode from base64 if binary
        try:
            import base64
            content_bytes = base64.b64decode(content)
        except:
            content_bytes = content.encode('utf-8')
        
        async with self.s3_session.client('s3') as s3_client:
            params = {
                'Bucket': AWS_CONFIG['s3_bucket'],
                'Key': key,
                'Body': content_bytes
            }
            if metadata:
                params['Metadata'] = metadata
            
            response = await s3_client.put_object(**params)
            
            return {
                'key': key,
                'size': len(content_bytes),
                'etag': response['ETag'],
                'version_id': response.get('VersionId')
            }
    
    # ========== PostgreSQL Tools ==========
    
    async def _tool_postgres_query(self, query: str, params: List[Any] = None) -> Dict[str, Any]:
        """Execute SELECT query"""
        async def _query():
            async with self.pg_pool.acquire() as conn:
                rows = await conn.fetch(query, *(params or []))
                return {
                    'query': query,
                    'row_count': len(rows),
                    'rows': [dict(row) for row in rows]
                }
        
        return await retry_with_backoff(
            lambda: self.pg_circuit_breaker.call_async(_query),
            max_retries=3,
            exceptions=(asyncpg.PostgresError,)
        )
    
    async def _tool_postgres_execute(self, query: str, params: List[Any] = None) -> Dict[str, Any]:
        """Execute INSERT/UPDATE/DELETE query"""
        async def _execute():
            async with self.pg_pool.acquire() as conn:
                result = await conn.execute(query, *(params or []))
                return {
                    'query': query,
                    'result': result,
                    'success': True
                }
        
        return await retry_with_backoff(
            lambda: self.pg_circuit_breaker.call_async(_execute),
            max_retries=3,
            exceptions=(asyncpg.PostgresError,)
        )
    
    # ========== High-Level Tools ==========
    
    async def _tool_document_store(
        self,
        s3_key: str,
        document_type: str,
        file_name: str,
        status: str = "pending",
        extracted_data: Dict = None,
        validation_score: float = None
    ) -> Dict[str, Any]:
        """Store document in database"""
        query = """
            INSERT INTO documents (
                s3_key, document_type, file_name, status,
                extracted_data, validation_score, processing_date
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
        """
        
        async with self.pg_pool.acquire() as conn:
            doc_id = await conn.fetchval(
                query,
                s3_key,
                document_type,
                file_name,
                status,
                json.dumps(extracted_data) if extracted_data else None,
                validation_score,
                datetime.utcnow()
            )
            
            return {
                'document_id': doc_id,
                's3_key': s3_key,
                'status': status,
                'success': True
            }
    
    async def _tool_document_list(
        self,
        status: str = None,
        limit: int = 10
    ) -> Dict[str, Any]:
        """List documents from database"""
        if status:
            query = """
                SELECT id, s3_key, document_type, file_name, status,
                       validation_score, processing_date
                FROM documents
                WHERE status = $1
                ORDER BY processing_date DESC
                LIMIT $2
            """
            params = [status, limit]
        else:
            query = """
                SELECT id, s3_key, document_type, file_name, status,
                       validation_score, processing_date
                FROM documents
                ORDER BY processing_date DESC
                LIMIT $1
            """
            params = [limit]
        
        async with self.pg_pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
            
            return {
                'count': len(rows),
                'documents': [dict(row) for row in rows]
            }
    
    # ========== Connection Management ==========
    
    async def connect(self):
        """Connect to AWS S3 and PostgreSQL"""
        logger.info("Connecting to resources...")
        
        # Connect to S3
        self.s3_session = aioboto3.Session(
            aws_access_key_id=AWS_CONFIG.get('access_key_id'),
            aws_secret_access_key=AWS_CONFIG.get('secret_access_key'),
            region_name=AWS_CONFIG['region']
        )
        logger.info("Connected to S3")
        
        # Connect to PostgreSQL
        self.pg_pool = await asyncpg.create_pool(
            host=POSTGRES_CONFIG['host'],
            port=POSTGRES_CONFIG['port'],
            database=POSTGRES_CONFIG['database'],
            user=POSTGRES_CONFIG['user'],
            password=POSTGRES_CONFIG['password'],
            min_size=2,
            max_size=10,
            ssl='require'
        )
        logger.info("Connected to PostgreSQL")
        
        logger.info("MCP Server ready")
    
    async def disconnect(self):
        """Disconnect from resources"""
        if self.pg_pool:
            await self.pg_pool.close()
            logger.info("Disconnected from PostgreSQL")
        
        self.s3_session = None
        logger.info("Disconnected from S3")


async def main():
    """Main entry point for MCP server"""
    logger.info("Starting AWS MCP Server...")
    
    # Create server instance
    mcp_server = AWSMCPServer()
    
    # Connect to resources
    await mcp_server.connect()
    
    try:
        # Run stdio server
        async with stdio_server() as (read_stream, write_stream):
            logger.info("MCP Server running on stdio")
            await mcp_server.server.run(
                read_stream,
                write_stream,
                mcp_server.server.create_initialization_options()
            )
    finally:
        await mcp_server.disconnect()
        logger.info("AWS MCP Server stopped")


if __name__ == "__main__":
    asyncio.run(main())

