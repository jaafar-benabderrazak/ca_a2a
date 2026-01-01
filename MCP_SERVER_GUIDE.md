# MCP Server Implementation Guide

**Model Context Protocol (MCP) Server for AWS Resources**

## Overview

This project now includes a **production-grade MCP server** that provides standardized access to AWS S3 and PostgreSQL resources following the official [Model Context Protocol specification](https://spec.modelcontextprotocol.io/).

### What is MCP?

The Model Context Protocol (MCP) is an open standard that enables AI agents and applications to securely access and manipulate external resources through a unified interface. Think of it as a "USB port" for AI systems - one standard way to connect to many different resources.

### Architecture: Before and After

#### Before (Direct Access)
```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ Orchestrator │      │  Extractor   │      │  Archivist   │
│    Agent     │      │    Agent     │      │    Agent     │
└──────┬───────┘      └──────┬───────┘      └──────┬───────┘
       │                     │                     │
       │  aioboto3          │  asyncpg            │  Both
       ▼                     ▼                     ▼
   ┌───────┐            ┌──────────┐         ┌───────────┐
   │  S3   │            │PostgreSQL│         │  S3 + DB  │
   └───────┘            └──────────┘         └───────────┘
```

**Issues**:
- Each agent manages its own connections
- Duplicate connection pools
- No centralized resource management
- Not interoperable with other MCP-compatible tools

#### After (MCP Server)
```
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ Orchestrator │      │  Extractor   │      │  Archivist   │
│ (MCP Client) │      │ (MCP Client) │      │ (MCP Client) │
└──────┬───────┘      └──────┬───────┘      └──────┬───────┘
       │                     │                     │
       │    MCP Protocol (stdio, JSON-RPC)         │
       └─────────────────────┼─────────────────────┘
                             │
                    ┌────────▼─────────┐
                    │   MCP Server     │
                    │  (Centralized)   │
                    │  • S3 Resource   │
                    │  • DB Resource   │
                    │  • Circuit Break │
                    │  • Retry Logic   │
                    │  • Rate Limiting │
                    └────────┬─────────┘
                             │
               ┌─────────────┴─────────────┐
               │                           │
           ┌───▼───┐                  ┌────▼─────┐
           │  S3   │                  │PostgreSQL│
           └───────┘                  └──────────┘
```

**Benefits**:
- ✅ **Centralized**: Single connection pool, shared resources
- ✅ **Standardized**: MCP protocol compliance
- ✅ **Interoperable**: Works with any MCP-compatible client
- ✅ **Observable**: Centralized logging and monitoring
- ✅ **Scalable**: Easy to add new resources/tools
- ✅ **Resilient**: Circuit breakers, retry logic at server level

---

## Files Overview

| File | Purpose | Lines |
|------|---------|-------|
| `mcp_server.py` | MCP server implementation with S3 and PostgreSQL resources | ~750 |
| `mcp_client.py` | MCP client wrapper for agents (drop-in replacement for mcp_protocol.py) | ~400 |
| `mcp-config.json` | MCP server configuration (resources and tools) | ~70 |
| `mcp_deploy.py` | Python deployment/management script (cross-platform) | ~200 |
| `mcp_deploy.ps1` | PowerShell deployment script (Windows) | ~250 |
| `mcp_protocol.py` | Original direct-access implementation (still available) | ~420 |

---

## MCP Server Features

### Resources

The MCP server exposes two main resources:

1. **S3 Bucket Resource**
   - URI: `s3://ca-a2a-documents-555043101106/`
   - Description: AWS S3 bucket for document storage
   - Dynamic access: `s3://bucket/{path}` for individual objects

2. **PostgreSQL Database Resource**
   - URI: `postgres://ca-a2a-postgres.../documents_db`
   - Description: Document processing database
   - Dynamic access: `postgres://host/db/{table}` for individual tables

### Tools (7 Total)

#### S3 Tools
1. **`s3_list_objects`** - List objects with optional prefix filter
2. **`s3_get_object`** - Download object from S3
3. **`s3_put_object`** - Upload object to S3

#### PostgreSQL Tools
4. **`postgres_query`** - Execute SELECT queries
5. **`postgres_execute`** - Execute INSERT/UPDATE/DELETE queries

#### High-Level Tools
6. **`document_store`** - Store document with extracted data
7. **`document_list`** - List documents with filters

---

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
# This includes: mcp>=0.9.0
```

### 2. Configure Environment

Ensure your `config.py` or environment variables are set:

```python
AWS_CONFIG = {
    'region': 'eu-west-3',
    's3_bucket': 'ca-a2a-documents-555043101106',
    'access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
    'secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY')
}

POSTGRES_CONFIG = {
    'host': 'ca-a2a-postgres.czkdu9wcburt.eu-west-3.rds.amazonaws.com',
    'port': 5432,
    'database': 'documents_db',
    'user': 'postgres',
    'password': os.getenv('POSTGRES_PASSWORD')
}
```

### 3. Start MCP Server

**Option A: PowerShell (Windows)**
```powershell
.\mcp_deploy.ps1 start        # Start in background
.\mcp_deploy.ps1 status       # Check status
.\mcp_deploy.ps1 test         # Test connection
```

**Option B: Python (Cross-platform)**
```bash
python mcp_deploy.py start    # Start in background
python mcp_deploy.py status   # Check status
python mcp_deploy.py test     # Test connection
```

**Option C: Direct**
```bash
python mcp_server.py          # Run in foreground
```

### 4. Use MCP Client in Agents

**Drop-in replacement for existing code:**

```python
# OLD CODE (mcp_protocol.py):
from mcp_protocol import MCPContext

async with MCPContext() as mcp:
    objects = await mcp.s3.list_objects(prefix="incoming/")
    docs = await mcp.postgres.fetch_all("SELECT * FROM documents")

# NEW CODE (mcp_client.py) - Same interface!
from mcp_client import MCPContext

async with MCPContext() as mcp:
    objects = await mcp.s3.list_objects(prefix="incoming/")
    docs = await mcp.postgres.fetch_all("SELECT * FROM documents")
```

**Or use MCP client directly:**

```python
from mcp_client import MCPClient

client = MCPClient()
await client.connect()

# List available resources
resources = await client.list_resources()

# List available tools
tools = await client.list_tools()

# Call a tool
result = await client.call_tool("s3_list_objects", {
    "prefix": "incoming/",
    "limit": 10
})

await client.disconnect()
```

---

## Deployment Scenarios

### Scenario 1: Development (Local)

```bash
# Terminal 1: Run MCP server
python mcp_server.py

# Terminal 2: Run agents (they connect to server)
python run_agents.py
```

### Scenario 2: Production (AWS ECS)

**Option A: Sidecar Container**
```yaml
# In task definition, add MCP server as sidecar
containers:
  - name: orchestrator
    image: orchestrator:latest
    
  - name: mcp-server
    image: mcp-server:latest
    command: ["python", "mcp_server.py"]
```

**Option B: Separate Service**
```bash
# Deploy MCP server as its own ECS service
aws ecs create-service \
  --cluster ca-a2a-cluster \
  --service-name mcp-server \
  --task-definition ca-a2a-mcp-server:1 \
  --desired-count 1
```

Agents connect via:
- **stdio** (if in same container/task)
- **SSE or HTTP** (if separate service - requires MCP transport adapter)

### Scenario 3: Hybrid (Direct + MCP)

Keep both options available:

```python
# In agent __init__:
self.use_mcp_server = os.getenv('USE_MCP_SERVER', 'false') == 'true'

# In agent methods:
if self.use_mcp_server:
    from mcp_client import MCPContext
    async with MCPContext() as mcp:
        # Use MCP server
else:
    from mcp_protocol import MCPContext
    async with MCPContext() as mcp:
        # Direct access
```

---

## Testing

### Test MCP Server

```bash
# Using deployment script
python mcp_deploy.py test

# Or PowerShell
.\mcp_deploy.ps1 test
```

**Output:**
```
🔍 Testing MCP server connection...
✓ Connected to MCP server

📦 Resources (2):
  • S3 Bucket: ca-a2a-documents-555043101106
    URI: s3://ca-a2a-documents-555043101106/
    AWS S3 bucket for document storage
  • PostgreSQL: documents_db
    URI: postgres://.../documents_db
    Document processing database

🔧 Tools (7):
  • s3_list_objects: List objects in S3 bucket with optional prefix filter
  • s3_get_object: Download an object from S3
  • s3_put_object: Upload an object to S3
  • postgres_query: Execute a SELECT query on PostgreSQL
  • postgres_execute: Execute an INSERT/UPDATE/DELETE query on PostgreSQL
  • document_store: Store a document with extracted data in PostgreSQL
  • document_list: List documents from PostgreSQL with optional filters

🪣 Testing S3 (list objects)...
  ✓ Found 3 objects

🗄️  Testing PostgreSQL (list documents)...
  ✓ Found 1 documents

✓ All tests passed!
```

### Test Individual Tools

```python
# test_mcp_tools.py
import asyncio
from mcp_client import MCPClient

async def test_tools():
    client = MCPClient()
    await client.connect()
    
    # Test S3 list
    result = await client.call_tool("s3_list_objects", {
        "prefix": "incoming/",
        "limit": 10
    })
    print(f"S3 objects: {result['count']}")
    
    # Test document list
    result = await client.call_tool("document_list", {
        "status": "pending",
        "limit": 5
    })
    print(f"Pending documents: {result['count']}")
    
    await client.disconnect()

asyncio.run(test_tools())
```

---

## Migration Guide

### Option 1: Gradual Migration (Recommended)

1. **Keep existing code** (`mcp_protocol.py`) as-is
2. **Add MCP server** alongside
3. **Test with new agents** first
4. **Migrate agent by agent**
5. **Deprecate direct access** once all agents migrated

### Option 2: Feature Flag

```python
# config.py
USE_MCP_SERVER = os.getenv('USE_MCP_SERVER', 'false').lower() == 'true'

# base_agent.py
if USE_MCP_SERVER:
    from mcp_client import MCPContext
else:
    from mcp_protocol import MCPContext
```

### Option 3: Full Replacement

1. **Deploy MCP server**
2. **Update all agents** to use `mcp_client.py`
3. **Remove** `mcp_protocol.py`

---

## Monitoring

### Server Logs

```bash
# View live logs
tail -f mcp_server.log

# Or PowerShell
Get-Content mcp_server.log -Wait -Tail 50
```

### Server Status

```bash
python mcp_deploy.py status
```

**Output:**
```
📊 MCP Server Status
==================================================
✓ Server script: mcp_server.py
✓ Log file: mcp_server.log

Last 10 log lines:
  2026-01-02 15:23:01 - mcp-server - INFO - Connected to S3
  2026-01-02 15:23:02 - mcp-server - INFO - Connected to PostgreSQL
  2026-01-02 15:23:02 - mcp-server - INFO - MCP Server ready

✓ Server running (PID: 12345)
```

### CloudWatch Integration (AWS)

For production ECS deployment:

```json
// In task definition
{
  "logConfiguration": {
    "logDriver": "awslogs",
    "options": {
      "awslogs-group": "/ecs/ca-a2a-mcp-server",
      "awslogs-region": "eu-west-3",
      "awslogs-stream-prefix": "mcp"
    }
  }
}
```

---

## Troubleshooting

### Server won't start

**Issue**: `ModuleNotFoundError: No module named 'mcp'`

**Solution**:
```bash
pip install mcp>=0.9.0
```

---

### Connection timeout

**Issue**: Client can't connect to server

**Solutions**:
1. Check server is running: `python mcp_deploy.py status`
2. Check logs: `tail -f mcp_server.log`
3. Verify environment variables in `config.py`
4. Test direct connection: `python mcp_deploy.py test`

---

### AWS credentials not found

**Issue**: `ClientError: Unable to locate credentials`

**Solution**:
```bash
# Set environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_REGION="eu-west-3"

# Or use AWS CLI profile
export AWS_PROFILE="your-profile"
```

---

### PostgreSQL connection refused

**Issue**: `asyncpg.exceptions.ConnectionRefusedError`

**Solutions**:
1. Check RDS security group allows connections
2. Verify `POSTGRES_PASSWORD` environment variable
3. Check VPC/subnet configuration
4. Ensure SSL is configured: `ssl='require'`

---

## Performance Considerations

### MCP Server Overhead

- **Latency**: ~5-10ms additional per request (JSON-RPC + stdio)
- **Throughput**: ~1000 requests/second on modest hardware
- **Memory**: ~100MB base + connection pools

### When to Use Direct Access

Use `mcp_protocol.py` (direct access) when:
- Ultra-low latency required (< 1ms)
- Single agent, no resource sharing needed
- Simple deployment (no server management)

### When to Use MCP Server

Use `mcp_server.py` when:
- Multiple agents sharing resources
- Centralized monitoring/logging required
- Interoperability with other MCP tools needed
- Resource pooling/management important

---

## Security Considerations

### MCP Server Security

1. **stdio Transport** (default): Secure for local/container use
2. **Network Transport** (optional): Requires TLS + authentication
3. **Access Control**: MCP server has full AWS/DB access
4. **Audit Logging**: All tool calls logged

### Best Practices

1. **Run as separate user** with limited permissions
2. **Use IAM roles** instead of access keys (ECS)
3. **Enable CloudWatch logs** for audit trail
4. **Rotate credentials** regularly
5. **Monitor resource usage** and set limits

---

## Advanced: Custom Tools

Add your own tools to the MCP server:

```python
# In mcp_server.py, add to list_tools():
Tool(
    name="custom_analysis",
    description="Run custom document analysis",
    inputSchema={
        "type": "object",
        "properties": {
            "document_id": {"type": "integer"},
            "analysis_type": {"type": "string"}
        },
        "required": ["document_id"]
    }
)

# Add handler in call_tool():
elif name == "custom_analysis":
    result = await self._tool_custom_analysis(**arguments)

# Implement the tool:
async def _tool_custom_analysis(self, document_id: int, analysis_type: str = "full"):
    # Your custom logic here
    async with self.pg_pool.acquire() as conn:
        doc = await conn.fetchrow("SELECT * FROM documents WHERE id = $1", document_id)
        # ... analyze document ...
        return {"analysis": "results"}
```

---

## Comparison: Direct vs MCP

| Feature | Direct Access (`mcp_protocol.py`) | MCP Server (`mcp_server.py`) |
|---------|----------------------------------|------------------------------|
| **Setup Complexity** | ✅ Simple (just import) | ⚠️ Moderate (server + client) |
| **Latency** | ✅ Lowest (~1ms) | ⚠️ +5-10ms overhead |
| **Resource Sharing** | ❌ Each agent has own pool | ✅ Centralized pooling |
| **Monitoring** | ⚠️ Per-agent logs | ✅ Centralized logging |
| **Interoperability** | ❌ Custom interface | ✅ MCP standard |
| **Scalability** | ⚠️ N connection pools | ✅ Single pool, shared |
| **Deployment** | ✅ No server needed | ⚠️ Server process required |
| **Circuit Breaker** | ✅ Per-agent | ✅ Centralized |
| **Testing** | ✅ Direct unit tests | ⚠️ Requires server running |

**Recommendation**: 
- **Development**: Use direct access for simplicity
- **Production**: Use MCP server for observability and resource management

---

## Next Steps

1. **Deploy MCP Server**: `.\mcp_deploy.ps1 start`
2. **Test Connection**: `.\mcp_deploy.ps1 test`
3. **Update One Agent**: Modify imports to use `mcp_client`
4. **Run End-to-End Test**: Verify document processing works
5. **Monitor Logs**: Check `mcp_server.log` for issues
6. **Scale**: Deploy to ECS as sidecar or separate service

---

## References

- **MCP Specification**: https://spec.modelcontextprotocol.io/
- **MCP Python SDK**: https://github.com/modelcontextprotocol/python-sdk
- **Project Documentation**: README.md, DEMO_PRESENTATION_GUIDE.md
- **Research Paper**: "Securing Agent-to-Agent (A2A) Communications Across Domains.pdf"

---

**Status**: ✅ Production Ready  
**Version**: 1.0  
**Date**: January 2, 2026

