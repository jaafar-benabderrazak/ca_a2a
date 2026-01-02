"""
MCP Context Auto - Automatically selects stdio or HTTP based on environment
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def get_mcp_context():
    """
    Factory function that returns appropriate MCP context based on environment
    
    - Local/Docker: Uses MCPContext (stdio)
    - AWS ECS: Uses MCPContextHTTP (HTTP)
    """
    mcp_server_url = os.getenv('MCP_SERVER_URL')
    
    if mcp_server_url:
        # HTTP mode (AWS ECS / distributed deployment)
        from mcp_client_http import MCPContextHTTP
        logger.info(f"Using MCP HTTP client: {mcp_server_url}")
        return MCPContextHTTP(server_url=mcp_server_url)
    else:
        # Stdio mode (local/docker-compose)
        from mcp_client import MCPContext
        logger.info("Using MCP stdio client")
        return MCPContext()


# Convenience alias
MCPContext = get_mcp_context

__all__ = ['get_mcp_context', 'MCPContext']

