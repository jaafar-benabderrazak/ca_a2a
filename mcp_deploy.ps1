# MCP Server Deployment Script for Windows
# PowerShell version of mcp_deploy.py

param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateSet("start", "start-fg", "stop", "restart", "test", "status", "help")]
    [string]$Command
)

$ErrorActionPreference = "Continue"
$MCPServerScript = "mcp_server.py"
$MCPLogFile = "mcp_server.log"
$MCPPidFile = "mcp_server.pid"

function Start-MCPServer {
    param([bool]$Background = $true)
    
    Write-Host "`n🚀 Starting MCP server..." -ForegroundColor Cyan
    
    if ($Background) {
        # Start in background
        $process = Start-Process -FilePath "python" `
            -ArgumentList $MCPServerScript `
            -RedirectStandardOutput $MCPLogFile `
            -RedirectStandardError $MCPLogFile `
            -PassThru `
            -WindowStyle Hidden
        
        # Save PID
        $process.Id | Out-File $MCPPidFile
        
        Write-Host "✓ MCP server started (PID: $($process.Id))" -ForegroundColor Green
        Write-Host "  Logs: $MCPLogFile" -ForegroundColor DarkGray
        
        # Wait for initialization
        Start-Sleep -Seconds 2
    }
    else {
        # Start in foreground
        Write-Host "  Running in foreground (Ctrl+C to stop)..." -ForegroundColor DarkGray
        python $MCPServerScript
    }
}

function Stop-MCPServer {
    Write-Host "`n🛑 Stopping MCP server..." -ForegroundColor Cyan
    
    if (Test-Path $MCPPidFile) {
        $pid = Get-Content $MCPPidFile
        
        try {
            $process = Get-Process -Id $pid -ErrorAction Stop
            Stop-Process -Id $pid -Force
            Write-Host "✓ MCP server stopped (PID: $pid)" -ForegroundColor Green
        }
        catch {
            Write-Host "⚠️  Process not found (PID: $pid)" -ForegroundColor Yellow
        }
        
        Remove-Item $MCPPidFile -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "⚠️  No PID file found. Searching for python processes..." -ForegroundColor Yellow
        
        $pythonProcesses = Get-Process -Name python -ErrorAction SilentlyContinue
        foreach ($proc in $pythonProcesses) {
            $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
            if ($cmdLine -like "*$MCPServerScript*") {
                Stop-Process -Id $proc.Id -Force
                Write-Host "✓ Stopped MCP server (PID: $($proc.Id))" -ForegroundColor Green
            }
        }
    }
}

function Test-MCPServer {
    Write-Host "`n🔍 Testing MCP server connection..." -ForegroundColor Cyan
    
    # Use Python to test
    python -c @"
import asyncio
import sys
sys.path.insert(0, '.')
from mcp_client import MCPClient

async def test():
    try:
        client = MCPClient('$MCPServerScript')
        await client.connect()
        print('✓ Connected to MCP server')
        
        resources = await client.list_resources()
        print(f'\n📦 Resources ({len(resources)}):')
        for r in resources:
            print(f'  • {r[\"name\"]}')
            print(f'    URI: {r[\"uri\"]}')
        
        tools = await client.list_tools()
        print(f'\n🔧 Tools ({len(tools)}):')
        for t in tools:
            print(f'  • {t[\"name\"]}: {t[\"description\"]}')
        
        result = await client.call_tool('s3_list_objects', {'prefix': '', 'limit': 5})
        print(f'\n🪣 S3: Found {result[\"count\"]} objects')
        
        result = await client.call_tool('document_list', {'limit': 5})
        print(f'🗄️  PostgreSQL: Found {result[\"count\"]} documents')
        
        await client.disconnect()
        print('\n✓ All tests passed!')
    except Exception as e:
        print(f'\n❌ Error: {str(e)}')
        sys.exit(1)

asyncio.run(test())
"@
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n✓ MCP server test completed successfully" -ForegroundColor Green
    }
    else {
        Write-Host "`n❌ MCP server test failed" -ForegroundColor Red
    }
}

function Show-MCPStatus {
    Write-Host "`n📊 MCP Server Status" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor DarkGray
    
    # Check server script
    if (Test-Path $MCPServerScript) {
        Write-Host "✓ Server script: $MCPServerScript" -ForegroundColor Green
    }
    else {
        Write-Host "❌ Server script not found: $MCPServerScript" -ForegroundColor Red
    }
    
    # Check config
    if (Test-Path "config.py") {
        Write-Host "✓ Configuration: config.py" -ForegroundColor Green
    }
    else {
        Write-Host "⚠️  Configuration not found: config.py" -ForegroundColor Yellow
    }
    
    # Check MCP client
    if (Test-Path "mcp_client.py") {
        Write-Host "✓ MCP client: mcp_client.py" -ForegroundColor Green
    }
    
    # Check log file
    if (Test-Path $MCPLogFile) {
        Write-Host "✓ Log file: $MCPLogFile" -ForegroundColor Green
        
        Write-Host "`nLast 10 log lines:" -ForegroundColor Yellow
        Get-Content $MCPLogFile -Tail 10 | ForEach-Object {
            Write-Host "  $_" -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "  No log file found" -ForegroundColor DarkGray
    }
    
    # Check process
    Write-Host ""
    if (Test-Path $MCPPidFile) {
        $pid = Get-Content $MCPPidFile
        $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
        
        if ($process) {
            Write-Host "✓ Server running (PID: $pid)" -ForegroundColor Green
            Write-Host "  CPU: $($process.CPU)s" -ForegroundColor DarkGray
            Write-Host "  Memory: $([math]::Round($process.WorkingSet64 / 1MB, 2)) MB" -ForegroundColor DarkGray
            Write-Host "  Started: $($process.StartTime)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "⚠️  PID file exists but process not found" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "⚠️  Server not running (no PID file)" -ForegroundColor Yellow
    }
}

function Show-MCPHelp {
    Write-Host @"

╔════════════════════════════════════════════════════════════════╗
║                    MCP Server Manager                           ║
║                   (Windows PowerShell)                          ║
╚════════════════════════════════════════════════════════════════╝

Commands:
  start         Start MCP server in background
  start-fg      Start MCP server in foreground
  stop          Stop MCP server
  restart       Restart MCP server
  test          Test MCP server connection
  status        Show MCP server status
  help          Show this help message

Examples:
  .\mcp_deploy.ps1 start        # Start server
  .\mcp_deploy.ps1 test         # Test connection
  .\mcp_deploy.ps1 status       # Check status
  .\mcp_deploy.ps1 stop         # Stop server

Environment:
  Set these in config.py or environment variables:
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_REGION (default: eu-west-3)
    POSTGRES_PASSWORD

Files:
  mcp_server.py      - MCP server implementation
  mcp_client.py      - MCP client wrapper for agents
  mcp-config.json    - MCP server configuration
  mcp_deploy.ps1     - This script (Windows)
  mcp_deploy.py      - Python version (cross-platform)

"@ -ForegroundColor White
}

# Main execution
switch ($Command) {
    "start" {
        Start-MCPServer -Background $true
    }
    "start-fg" {
        Start-MCPServer -Background $false
    }
    "stop" {
        Stop-MCPServer
    }
    "restart" {
        Stop-MCPServer
        Start-Sleep -Seconds 1
        Start-MCPServer -Background $true
    }
    "test" {
        Test-MCPServer
    }
    "status" {
        Show-MCPStatus
    }
    "help" {
        Show-MCPHelp
    }
}

Write-Host ""

