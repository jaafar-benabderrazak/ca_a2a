# Agent Cards Quick Reference

## Quick Commands

### Query Agent Cards
```bash
# Get full agent card
curl http://localhost:8002/card | jq

# Get just skills
curl http://localhost:8003/skills | jq

# Get agent status
curl http://localhost:8004/status | jq

# Check health
curl http://localhost:8001/health
```

### Orchestrator Discovery
```bash
# Trigger discovery
curl -X POST http://localhost:8001/message -H "Content-Type: application/json" -d '{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "discover_agents",
  "params": {}
}'

# Get registry
curl -X POST http://localhost:8001/message -H "Content-Type: application/json" -d '{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "get_agent_registry",
  "params": {}
}'
```

### Run Discovery Demo
```bash
python discover_agents.py
```

---

## Agent Endpoints Reference

### All Agents
- `GET /health` - Health check
- `GET /status` - Status and metrics
- `GET /card` - Complete agent card
- `GET /skills` - List of skills
- `POST /message` - A2A communication

### Agent URLs (Default)
- Orchestrator: `http://localhost:8001`
- Extractor: `http://localhost:8002`
- Validator: `http://localhost:8003`
- Archivist: `http://localhost:8004`

---

## Agent Skills Reference

### Extractor (8002)
1. `extract_document` - Main extraction
2. `pdf_text_extraction` - PDF text
3. `pdf_table_extraction` - PDF tables
4. `csv_parsing` - CSV with stats
5. `list_supported_formats` - Format info

### Validator (8003)
1. `validate_document` - Main validation
2. `data_completeness_check` - Completeness
3. `data_format_validation` - Format check
4. `data_quality_assessment` - Quality
5. `data_consistency_check` - Consistency
6. `get_validation_rules` - Rules info

### Archivist (8004)
1. `archive_document` - Archive
2. `get_document` - Retrieve
3. `update_document_status` - Update
4. `search_documents` - Search
5. `get_document_stats` - Statistics
6. `audit_logging` - Audit trail

### Orchestrator (8001)
1. `process_document` - Process single
2. `process_batch` - Process batch
3. `get_task_status` - Task status
4. `list_pending_documents` - List pending
5. `discover_agents` - Discover
6. `get_agent_registry` - Registry

---

## Python API Examples

### Query Agent Card
```python
import aiohttp
import asyncio

async def get_agent_card(url):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{url}/card") as response:
            return await response.json()

# Usage
card = asyncio.run(get_agent_card("http://localhost:8002"))
print(f"Agent: {card['name']}")
print(f"Skills: {len(card['skills'])}")
```

### Use Orchestrator Registry
```python
async def get_registry():
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "http://localhost:8001/message",
            json={
                "jsonrpc": "2.0",
                "id": "1",
                "method": "get_agent_registry",
                "params": {}
            }
        ) as response:
            result = await response.json()
            return result['result']

registry = asyncio.run(get_registry())
print(f"Active agents: {registry['active_agents']}")
print(f"Total skills: {registry['total_skills']}")
```

### Find Agent by Skill
```python
from agent_card import AgentRegistry

registry = AgentRegistry()
# ... register agents ...

# Find agents with specific skill
endpoints = registry.get_endpoints_for_skill("extract_document")
print(f"Extract skill available at: {endpoints}")
```

---

## Agent Card Structure

```python
{
    "agent_id": str,           # Unique ID
    "name": str,               # Agent name
    "version": str,            # Semantic version
    "description": str,        # What it does
    "status": str,             # "active" | "inactive"
    "endpoint": str,           # HTTP URL
    "skills": [                # Array of skills
        {
            "skill_id": str,
            "name": str,
            "description": str,
            "method": str,     # A2A method
            "input_schema": dict,
            "output_schema": dict,
            "tags": [str],
            "avg_processing_time_ms": int,
            "max_input_size_mb": int
        }
    ],
    "resources": {
        "memory_mb": int,
        "cpu_cores": float,
        "storage_required": bool,
        "network_required": bool
    },
    "dependencies": {
        "services": [str],     # e.g., ["s3", "postgres"]
        "libraries": [str]     # e.g., ["PyPDF2", "pandas"]
    },
    "endpoints": {
        "health_check": "/health",
        "metrics": "/status",
        "card": "/card",
        "skills": "/skills"
    },
    "last_updated": str        # ISO timestamp
}
```

---

## AWS Integration

### Service Discovery
```bash
# Agents auto-register in AWS Cloud Map
# DNS: extractor.local, validator.local, etc.

# Orchestrator discovers via /card endpoint
# No manual configuration needed!
```

### Health Checks
```bash
# ALB target groups use /health
# Unhealthy agents automatically deregistered
```

### Auto-Scaling
```yaml
# Scale based on agent metrics
Target: ECSServiceAverageCPUUtilization > 70%
Min: 2 tasks
Max: 10 tasks
```

---

## Common Tasks

### Add New Skill to Agent
```python
# In your agent class
def _define_skills(self):
    return [
        AgentSkill(
            skill_id='my_new_skill',
            name='My New Skill',
            description='What it does',
            method='handle_method_name',
            tags=['category'],
            avg_processing_time_ms=1000
        ),
        # ... other skills
    ]
```

### Create New Agent with Card
```python
from base_agent import BaseAgent
from agent_card import AgentSkill

class MyAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            'MyAgent',
            'localhost',
            8005,
            version='1.0.0',
            description='My agent description'
        )
    
    def _define_skills(self):
        return [
            AgentSkill(
                skill_id='my_skill',
                name='My Skill',
                description='Description',
                method='my_method',
                tags=['tag1']
            )
        ]
    
    def _register_handlers(self):
        self.protocol.register_handler('my_method', self.handle_my_method)
    
    async def initialize(self):
        pass
    
    async def cleanup(self):
        pass
    
    async def handle_my_method(self, params):
        return {"result": "success"}
```

---

## Troubleshooting

### Agent Not Discovered
```bash
# Check agent is running
curl http://localhost:8002/health

# Check orchestrator logs
grep "discovery" agents.log

# Manually trigger discovery
curl -X POST http://localhost:8001/message -d '{
  "jsonrpc": "2.0",
  "method": "discover_agents",
  "params": {}
}'
```

### Card Endpoint 500 Error
```bash
# Check if _define_skills() is implemented
# Check agent logs for initialization errors
tail -f agents.log | grep ERROR
```

### Registry Empty
```bash
# Check if agents are accessible
curl http://localhost:8002/card
curl http://localhost:8003/card
curl http://localhost:8004/card

# Check orchestrator initialization
curl http://localhost:8001/status | jq '.discovered_agents'
```

---

## Documentation Links

- Full Implementation: `AGENT_CARDS_IMPLEMENTATION.md`
- AWS Deployment: `AWS_DEPLOYMENT.md`
- Architecture: `ARCHITECTURE.md`
- Main README: `README.md`

---

**Quick Tip**: Run `python discover_agents.py` for a comprehensive demo of the agent card system!
