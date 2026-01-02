"""
MCP Client HTTP - For distributed agent access to MCP server
"""
import aiohttp
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class MCPClientHTTP:
    """HTTP client for MCP server"""
    
    def __init__(self, server_url: str = "http://localhost:8000"):
        self.server_url = server_url.rstrip('/')
        self.session: Optional[aiohttp.ClientSession] = None
        self.logger = logging.getLogger(f"{__name__}.MCPClientHTTP")
    
    async def connect(self):
        """Initialize HTTP session"""
        if not self.session:
            self.session = aiohttp.ClientSession()
            self.logger.info(f"Connected to MCP server at {self.server_url}")
    
    async def disconnect(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None
            self.logger.info("Disconnected from MCP server")
    
    async def call_tool(self, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool on the MCP server"""
        if not self.session:
            await self.connect()
        
        try:
            async with self.session.post(
                f"{self.server_url}/call_tool",
                json={'tool': tool, 'arguments': arguments},
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                if response.status != 200:
                    error_data = await response.json()
                    raise Exception(f"MCP tool call failed: {error_data.get('error', 'Unknown error')}")
                
                return await response.json()
        
        except aiohttp.ClientError as e:
            self.logger.error(f"MCP client error: {str(e)}")
            raise Exception(f"Failed to call MCP tool {tool}: {str(e)}")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check MCP server health"""
        if not self.session:
            await self.connect()
        
        try:
            async with self.session.get(
                f"{self.server_url}/health",
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                return await response.json()
        
        except aiohttp.ClientError as e:
            self.logger.error(f"Health check failed: {str(e)}")
            return {'status': 'unreachable', 'error': str(e)}


class MCPS3ClientHTTP:
    """S3 resource client for MCP HTTP"""
    
    def __init__(self, mcp: MCPClientHTTP):
        self.mcp = mcp
    
    async def list_objects(self, prefix: str = "", suffix: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """List objects in S3 bucket"""
        result = await self.mcp.call_tool("s3_list_objects", {
            "prefix": prefix,
            "limit": limit
        })
        
        objects = result.get('objects', [])
        
        # Filter by suffix if provided
        if suffix:
            objects = [obj for obj in objects if obj['key'].endswith(suffix)]
        
        return objects
    
    async def get_object(self, key: str) -> bytes:
        """Download object from S3"""
        result = await self.mcp.call_tool("s3_get_object", {"key": key})
        content = result.get('content', '')
        return content.encode('utf-8') if isinstance(content, str) else content
    
    async def put_object(
        self,
        key: str,
        body: bytes = None,
        content: str = None,
        content_type: str = "application/octet-stream",
        metadata: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Upload object to S3
        
        Args:
            key: S3 object key
            body: Raw bytes content (if provided, takes precedence)
            content: Base64-encoded string content (alternative to body)
            content_type: MIME type
            metadata: Optional metadata dict
        
        Returns:
            Upload result dict
        """
        import base64
        
        # Handle different input formats
        if body is not None:
            # Convert bytes to base64
            body_b64 = base64.b64encode(body).decode('utf-8')
        elif content is not None:
            # Use provided base64 string
            body_b64 = content
        else:
            raise ValueError("Either 'body' or 'content' must be provided")
        
        tool_args = {
            "key": key,
            "body": body_b64,
            "content_type": content_type
        }
        
        if metadata:
            tool_args["metadata"] = metadata
        
        result = await self.mcp.call_tool("s3_put_object", tool_args)
        
        return result


class MCPPostgreSQLClientHTTP:
    """PostgreSQL resource client for MCP HTTP"""
    
    def __init__(self, mcp: MCPClientHTTP):
        self.mcp = mcp
    
    async def execute(self, query: str, *args) -> str:
        """Execute a query (INSERT, UPDATE, DELETE)"""
        result = await self.mcp.call_tool("postgres_execute", {
            "query": query,
            "params": list(args) if args else []
        })
        return result.get('result', 'OK')
    
    async def fetch_one(self, query: str, *args) -> Optional[Dict[str, Any]]:
        """Fetch a single row"""
        result = await self.mcp.call_tool("postgres_query", {
            "query": query,
            "params": list(args) if args else []
        })
        
        rows = result.get('rows', [])
        return rows[0] if rows else None
    
    async def fetch_all(self, query: str, *args) -> List[Dict[str, Any]]:
        """Fetch multiple rows"""
        result = await self.mcp.call_tool("postgres_query", {
            "query": query,
            "params": list(args) if args else []
        })
        
        return result.get('rows', [])
    
    async def fetch_value(self, query: str, *args) -> Any:
        """Fetch a single value"""
        row = await self.fetch_one(query, *args)
        if row:
            return next(iter(row.values()))
        return None
    
    async def execute_many(self, query: str, args_list: List[tuple]) -> None:
        """Execute query with multiple parameter sets"""
        for args in args_list:
            await self.execute(query, *args)
    
    async def initialize_schema(self) -> None:
        """Initialize database schema"""
        result = await self.mcp.call_tool("postgres_init_schema", {})
        self.mcp.logger.info(f"Schema initialization: {result.get('message', 'OK')}")


class MCPContextHTTP:
    """
    Context manager for MCP HTTP client
    Drop-in replacement for MCPContext using HTTP transport
    """
    
    def __init__(self, server_url: str = "http://mcp-server:8000"):
        self.client = MCPClientHTTP(server_url)
        self.s3: Optional[MCPS3ClientHTTP] = None
        self.postgres: Optional[MCPPostgreSQLClientHTTP] = None
        self.logger = logging.getLogger(f"{__name__}.MCPContextHTTP")
    
    async def __aenter__(self):
        """Connect to MCP server"""
        await self.client.connect()
        
        # Create resource clients
        self.s3 = MCPS3ClientHTTP(self.client)
        self.postgres = MCPPostgreSQLClientHTTP(self.client)
        
        self.logger.info("MCP HTTP context initialized")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Disconnect from MCP server"""
        await self.client.disconnect()
        self.logger.info("MCP HTTP context closed")
        return False

