#!/usr/bin/env python3
"""
MCP Server Deployment and Management Script
Provides commands to start, stop, test, and monitor the MCP server
"""
import asyncio
import subprocess
import sys
import signal
import os
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from mcp_client import MCPClient


class MCPServerManager:
    """Manage MCP server lifecycle"""
    
    def __init__(self):
        self.server_process = None
        self.server_script = "mcp_server.py"
    
    def start_server(self, background=True):
        """Start MCP server"""
        print("🚀 Starting MCP server...")
        
        if background:
            # Start in background
            log_file = open('mcp_server.log', 'w')
            self.server_process = subprocess.Popen(
                [sys.executable, self.server_script],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE
            )
            print(f"✓ MCP server started (PID: {self.server_process.pid})")
            print(f"  Logs: mcp_server.log")
            
            # Wait a moment for server to initialize
            time.sleep(2)
            
        else:
            # Start in foreground
            print("  Running in foreground (Ctrl+C to stop)...")
            subprocess.run([sys.executable, self.server_script])
    
    def stop_server(self):
        """Stop MCP server"""
        if self.server_process:
            print("🛑 Stopping MCP server...")
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=5)
                print("✓ MCP server stopped")
            except subprocess.TimeoutExpired:
                print("⚠️  Server didn't stop gracefully, killing...")
                self.server_process.kill()
                self.server_process.wait()
                print("✓ MCP server killed")
            
            self.server_process = None
        else:
            print("⚠️  No MCP server process found")
    
    async def test_connection(self):
        """Test MCP server connection"""
        print("🔍 Testing MCP server connection...")
        
        try:
            client = MCPClient(self.server_script)
            await client.connect()
            
            print("✓ Connected to MCP server")
            
            # List resources
            resources = await client.list_resources()
            print(f"\n📦 Resources ({len(resources)}):")
            for r in resources:
                print(f"  • {r['name']}")
                print(f"    URI: {r['uri']}")
                print(f"    {r['description']}")
            
            # List tools
            tools = await client.list_tools()
            print(f"\n🔧 Tools ({len(tools)}):")
            for t in tools:
                print(f"  • {t['name']}: {t['description']}")
            
            # Test S3 listing
            print(f"\n🪣 Testing S3 (list objects)...")
            result = await client.call_tool("s3_list_objects", {"prefix": "", "limit": 5})
            print(f"  ✓ Found {result['count']} objects")
            
            # Test PostgreSQL query
            print(f"\n🗄️  Testing PostgreSQL (list documents)...")
            result = await client.call_tool("document_list", {"limit": 5})
            print(f"  ✓ Found {result['count']} documents")
            
            await client.disconnect()
            print("\n✓ All tests passed!")
            
        except Exception as e:
            print(f"\n❌ Error: {str(e)}")
            sys.exit(1)
    
    def show_status(self):
        """Show MCP server status"""
        print("📊 MCP Server Status")
        print("=" * 50)
        
        # Check if server script exists
        if os.path.exists(self.server_script):
            print(f"✓ Server script: {self.server_script}")
        else:
            print(f"❌ Server script not found: {self.server_script}")
        
        # Check if log file exists
        if os.path.exists('mcp_server.log'):
            print(f"✓ Log file: mcp_server.log")
            # Show last 10 lines
            print("\nLast 10 log lines:")
            with open('mcp_server.log', 'r') as f:
                lines = f.readlines()
                for line in lines[-10:]:
                    print(f"  {line.rstrip()}")
        else:
            print(f"  No log file found")
        
        # Check process
        if self.server_process and self.server_process.poll() is None:
            print(f"\n✓ Server running (PID: {self.server_process.pid})")
        else:
            print(f"\n⚠️  Server not running (or not started by this script)")
    
    def show_help(self):
        """Show help message"""
        print("""
MCP Server Manager
==================

Commands:
  start         Start MCP server in background
  start-fg      Start MCP server in foreground
  stop          Stop MCP server
  restart       Restart MCP server
  test          Test MCP server connection
  status        Show MCP server status
  help          Show this help message

Examples:
  python mcp_deploy.py start        # Start server
  python mcp_deploy.py test         # Test connection
  python mcp_deploy.py status       # Check status
  python mcp_deploy.py stop         # Stop server

Environment:
  Set these environment variables or update config.py:
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_REGION
    POSTGRES_PASSWORD
""")


async def main():
    """Main entry point"""
    manager = MCPServerManager()
    
    # Parse command
    if len(sys.argv) < 2:
        manager.show_help()
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == "start":
        manager.start_server(background=True)
    
    elif command == "start-fg":
        manager.start_server(background=False)
    
    elif command == "stop":
        manager.stop_server()
    
    elif command == "restart":
        manager.stop_server()
        time.sleep(1)
        manager.start_server(background=True)
    
    elif command == "test":
        await manager.test_connection()
    
    elif command == "status":
        manager.show_status()
    
    elif command == "help":
        manager.show_help()
    
    else:
        print(f"Unknown command: {command}")
        manager.show_help()
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)

