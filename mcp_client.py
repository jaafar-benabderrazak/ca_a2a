"""
MCP Client Wrapper for CA A2A Agents
Provides a simplified interface for agents to interact with MCP server
"""
import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager

from mcp.client import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

logger = logging.getLogger(__name__)


class MCPClient:
    """
    MCP Client wrapper providing simplified access to AWS resources
    Compatible with existing mcp_protocol.py interface for easy migration
    """
    
    def __init__(self, server_script_path: str = "mcp_server.py"):
        self.server_script_path = server_script_path
        self.session: Optional[ClientSession] = None
        self._client_context = None
        self.logger = logging.getLogger(f"{__name__}.MCPClient")
    
    async def connect(self):
        """Connect to MCP server"""
        try:
            server_params = StdioServerParameters(
                command="python",
                args=[self.server_script_path],
                env=None  # Use system environment
            )
            
            # Create client context
            self._client_context = stdio_client(server_params)
            read_stream, write_stream = await self._client_context.__aenter__()
            
            # Initialize session
            self.session = ClientSession(read_stream, write_stream)
            await self.session.__aenter__()
            
            # Initialize the connection
            await self.session.initialize()
            
            self.logger.info("Connected to MCP server")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to MCP server: {str(e)}")
            raise
    
    async def disconnect(self):
        """Disconnect from MCP server"""
        try:
            if self.session:
                await self.session.__aexit__(None, None, None)
            
            if self._client_context:
                await self._client_context.__aexit__(None, None, None)
            
            self.logger.info("Disconnected from MCP server")
        
        except Exception as e:
            self.logger.error(f"Error disconnecting from MCP server: {str(e)}")
    
    async def list_resources(self) -> List[Dict[str, Any]]:
        """List all available resources"""
        if not self.session:
            raise RuntimeError("Not connected to MCP server")
        
        result = await self.session.list_resources()
        return [
            {
                'uri': r.uri,
                'name': r.name,
                'description': r.description,
                'mimeType': r.mimeType
            }
            for r in result.resources
        ]
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List all available tools"""
        if not self.session:
            raise RuntimeError("Not connected to MCP server")
        
        result = await self.session.list_tools()
        return [
            {
                'name': t.name,
                'description': t.description,
                'inputSchema': t.inputSchema
            }
            for t in result.tools
        ]
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool and return the result"""
        if not self.session:
            raise RuntimeError("Not connected to MCP server")
        
        result = await self.session.call_tool(name, arguments)
        
        # Extract text content from result
        if result.content and len(result.content) > 0:
            content_item = result.content[0]
            if hasattr(content_item, 'text'):
                return json.loads(content_item.text)
        
        return None
    
    async def read_resource(self, uri: str) -> str:
        """Read resource content"""
        if not self.session:
            raise RuntimeError("Not connected to MCP server")
        
        result = await self.session.read_resource(uri)
        
        # Extract text content
        if result.contents and len(result.contents) > 0:
            return result.contents[0].text
        
        return ""


class MCPS3Client:
    """
    S3 client interface using MCP
    Compatible with existing S3Resource interface
    """
    
    def __init__(self, mcp_client: MCPClient):
        self.mcp = mcp_client
        self.logger = logging.getLogger(f"{__name__}.MCPS3Client")
    
    async def list_objects(self, prefix: str = "", limit: int = 100) -> List[Dict[str, Any]]:
        """List objects in S3 bucket"""
        result = await self.mcp.call_tool("s3_list_objects", {
            "prefix": prefix,
            "limit": limit
        })
        return result.get('objects', [])
    
    async def get_object(self, key: str) -> bytes:
        """Download object from S3"""
        result = await self.mcp.call_tool("s3_get_object", {"key": key})
        
        content = result.get('content', '')
        is_binary = result.get('is_binary', False)
        
        if is_binary:
            import base64
            return base64.b64decode(content)
        else:
            return content.encode('utf-8')
    
    async def get_object_metadata(self, key: str) -> Dict[str, Any]:
        """Get object metadata"""
        result = await self.mcp.call_tool("s3_get_object", {"key": key})
        return {
            'content_type': result.get('content_type'),
            'content_length': result.get('size'),
            'etag': result.get('etag'),
            'metadata': result.get('metadata', {})
        }
    
    async def put_object(self, key: str, data: bytes, metadata: Dict[str, str] = None) -> Dict[str, Any]:
        """Upload object to S3"""
        import base64
        
        # Encode to base64 for transport
        content_b64 = base64.b64encode(data).decode('ascii')
        
        result = await self.mcp.call_tool("s3_put_object", {
            "key": key,
            "content": content_b64,
            "metadata": metadata or {}
        })
        
        return {
            'etag': result.get('etag'),
            'version_id': result.get('version_id')
        }


class MCPPostgreSQLClient:
    """
    PostgreSQL client interface using MCP
    Compatible with existing PostgreSQLResource interface
    """
    
    def __init__(self, mcp_client: MCPClient):
        self.mcp = mcp_client
        self.logger = logging.getLogger(f"{__name__}.MCPPostgreSQLClient")
    
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
            # Return first value from the row
            return next(iter(row.values()))
        return None
    
    async def execute_many(self, query: str, args_list: List[tuple]) -> None:
        """Execute query with multiple parameter sets"""
        for args in args_list:
            await self.execute(query, *args)
    
    # High-level document operations
    
    async def store_document(
        self,
        s3_key: str,
        document_type: str,
        file_name: str,
        status: str = "pending",
        extracted_data: Dict = None,
        validation_score: float = None
    ) -> int:
        """Store document in database"""
        result = await self.mcp.call_tool("document_store", {
            "s3_key": s3_key,
            "document_type": document_type,
            "file_name": file_name,
            "status": status,
            "extracted_data": extracted_data,
            "validation_score": validation_score
        })
        
        return result.get('document_id')
    
    async def list_documents(
        self,
        status: str = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """List documents from database"""
        params = {"limit": limit}
        if status:
            params["status"] = status
        
        result = await self.mcp.call_tool("document_list", params)
        return result.get('documents', [])


class MCPContext:
    """
    Context manager for MCP client
    Drop-in replacement for existing MCPContext from mcp_protocol.py
    """
    
    def __init__(self, server_script_path: str = "mcp_server.py"):
        self.client = MCPClient(server_script_path)
        self.s3: Optional[MCPS3Client] = None
        self.postgres: Optional[MCPPostgreSQLClient] = None
        self.logger = logging.getLogger(f"{__name__}.MCPContext")
    
    async def __aenter__(self):
        """Connect to MCP server"""
        await self.client.connect()
        
        # Create resource clients
        self.s3 = MCPS3Client(self.client)
        self.postgres = MCPPostgreSQLClient(self.client)
        
        self.logger.info("MCP context initialized")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Disconnect from MCP server"""
        await self.client.disconnect()
        self.logger.info("MCP context closed")


# Convenience function for quick access
@asynccontextmanager
async def create_mcp_context(server_script_path: str = "mcp_server.py"):
    """
    Create an MCP context as an async context manager
    
    Usage:
        async with create_mcp_context() as mcp:
            objects = await mcp.s3.list_objects()
            docs = await mcp.postgres.list_documents()
    """
    context = MCPContext(server_script_path)
    async with context as ctx:
        yield ctx


# Example usage
async def example_usage():
    """Example of using MCP client"""
    
    # Method 1: Using context manager
    async with create_mcp_context() as mcp:
        # List S3 objects
        objects = await mcp.s3.list_objects(prefix="incoming/", limit=10)
        print(f"Found {len(objects)} objects")
        
        # List documents
        documents = await mcp.postgres.list_documents(status="pending", limit=5)
        print(f"Found {len(documents)} pending documents")
    
    # Method 2: Manual connection management
    client = MCPClient()
    await client.connect()
    
    try:
        # List resources
        resources = await client.list_resources()
        print(f"Available resources: {resources}")
        
        # List tools
        tools = await client.list_tools()
        print(f"Available tools: {[t['name'] for t in tools]}")
        
        # Call a tool directly
        result = await client.call_tool("s3_list_objects", {"prefix": "", "limit": 5})
        print(f"S3 objects: {result}")
        
    finally:
        await client.disconnect()


if __name__ == "__main__":
    # Run example
    asyncio.run(example_usage())

