"""
MCP Context Auto - Automatically selects the appropriate MCP implementation
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def get_mcp_context():
    """
    Factory function that returns appropriate MCP context based on environment
    
    - Default: Uses MCPContext from mcp_protocol.py (native Python, works everywhere)
    - HTTP mode (if MCP_SERVER_URL set): Uses MCPContextHTTP for distributed deployments
    
    The native MCPContext provides both S3 and PostgreSQL resources directly
    without requiring an external MCP server process.
    """
    mcp_server_url = os.getenv('MCP_SERVER_URL')
    
    if mcp_server_url:
        # HTTP mode (distributed deployment with separate MCP server)
        try:
        from mcp_client_http import MCPContextHTTP
        logger.info(f"Using MCP HTTP client: {mcp_server_url}")
        return MCPContextHTTP(server_url=mcp_server_url)
        except ImportError as e:
            logger.warning(f"MCPContextHTTP not available: {e}. Falling back to native implementation.")
    
    # Default: Native Python implementation (works in all environments)
    from mcp_protocol import MCPContext
    logger.info("Using native MCP implementation (S3 + PostgreSQL)")
    return MCPContext()


# Convenience alias
MCPContext = get_mcp_context

__all__ = ['get_mcp_context', 'MCPContext']

