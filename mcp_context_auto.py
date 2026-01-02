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
    
    - HTTP Mode (if MCP_SERVER_URL set): Uses MCPContextHTTP
    - stdio Mode (fallback): Uses MCPContext with embedded server
    - No MCP (fallback): Returns None (agent can function without MCP)
    """
    mcp_server_url = os.getenv('MCP_SERVER_URL')
    
    if mcp_server_url:
        # HTTP mode (AWS ECS / distributed deployment)
        try:
            from mcp_client_http import MCPContextHTTP
            logger.info(f"Using MCP HTTP client: {mcp_server_url}")
            return MCPContextHTTP(server_url=mcp_server_url)
        except ImportError as e:
            logger.warning(f"MCP HTTP client not available: {e}. Trying stdio mode...")
    
    # Try stdio mode (embedded MCP server)
    try:
        from mcp_client import MCPContext
        logger.info("Using MCP stdio client with embedded server")
        return MCPContext()
    except ImportError as e:
        logger.warning(f"MCP stdio client not available: {e}")
    except RuntimeError as e:
        # MCP SDK not available in container - this is OK for agents that don't need MCP
        logger.warning(f"MCP not available: {e}")
        logger.info("Agent will run without MCP (direct boto3/asyncpg access)")
        return None
    
    # No MCP available - return None (agents should handle this gracefully)
    logger.warning("No MCP client available. Agent will use direct AWS SDK access.")
    return None


# Convenience alias
MCPContext = get_mcp_context

__all__ = ['get_mcp_context', 'MCPContext']

