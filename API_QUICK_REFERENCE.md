# CA-A2A API Quick Reference

## 🚀 **IMPORTANT: Use `/message` endpoint for A2A Protocol**

The orchestrator uses **A2A Protocol (JSON-RPC 2.0)** for all method calls.

**Base URL:** `http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com`

---

## 📡 **Endpoints**

### REST Endpoints (GET)
- `GET /health` - Health check
- `GET /card` - Agent card with capabilities
- `GET /status` - Detailed agent status
- `GET /skills` - List of available skills

### A2A Protocol Endpoint (POST)
- `POST /message` - **All A2A method calls go here**

---

## 🔧 **A2A Protocol Format**

All A2A calls use JSON-RPC 2.0 format:

```json
{
  "jsonrpc": "2.0",
  "method": "method_name",
  "params": { /* method parameters */ },
  "id": 1
}
```

**Success Response:**
```json
{
  "jsonrpc": "2.0",
  "result": { /* method result */ },
  "id": 1
}
```

**Error Response:**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32600,
    "message": "Error description"
  },
  "id": 1
}
```

---

## 📚 **Available Methods**

### 1. Process Single Document

**Method:** `process_document`

**Request:**
```bash
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {
      "s3_key": "incoming/document.txt",
      "priority": "normal"
    },
    "id": 1
  }'
```

**Parameters:**
- `s3_key` (required): S3 key of document to process
- `priority` (optional): `"low"`, `"normal"`, or `"high"` (default: `"normal"`)

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "task_id": "uuid-here",
    "s3_key": "incoming/document.txt",
    "status": "processing",
    "message": "Document processing started"
  },
  "id": 1
}
```

---

### 2. Process Batch of Documents

**Method:** `process_batch`

**Request:**
```bash
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_batch",
    "params": {
      "prefix": "incoming/",
      "file_extension": ".txt"
    },
    "id": 2
  }'
```

**Parameters:**
- `prefix` (optional): S3 prefix filter
- `file_extension` (optional): File extension filter

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "batch_id": "uuid-here",
    "total_documents": 5,
    "task_ids": ["task-1", "task-2", ...],
    "status": "processing",
    "message": "Batch processing started for 5 documents"
  },
  "id": 2
}
```

---

### 3. Get Task Status

**Method:** `get_task_status`

**Request:**
```bash
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "get_task_status",
    "params": {
      "task_id": "your-task-id-here"
    },
    "id": 3
  }'
```

**Parameters:**
- `task_id` (required): Task ID to query

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "task_id": "uuid",
    "s3_key": "incoming/document.txt",
    "status": "completed",
    "current_stage": "completed",
    "started_at": "2025-12-18T20:00:00",
    "completed_at": "2025-12-18T20:01:30",
    "stages": {
      "extraction": {"status": "completed", ...},
      "validation": {"status": "completed", ...},
      "archiving": {"status": "completed", ...}
    }
  },
  "id": 3
}
```

---

### 4. List Pending Documents

**Method:** `list_pending_documents`

**Request:**
```bash
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "list_pending_documents",
    "params": {
      "limit": 10
    },
    "id": 4
  }'
```

**Parameters:**
- `limit` (optional): Maximum number of documents to return (default: 50)

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "count": 3,
    "documents": [
      {
        "id": "uuid",
        "s3_key": "incoming/doc1.txt",
        "status": "processing",
        "processing_date": "2025-12-18T20:00:00"
      },
      ...
    ]
  },
  "id": 4
}
```

---

### 5. Discover Agents

**Method:** `discover_agents`

**Request:**
```bash
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "discover_agents",
    "params": {},
    "id": 5
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "discovered_agents": 3,
    "total_skills": 12,
    "agents": [
      {
        "name": "Extractor",
        "endpoint": "http://...",
        "status": "active",
        "skills_count": 4
      },
      ...
    ],
    "discovery_timestamp": "2025-12-18T20:00:00"
  },
  "id": 5
}
```

---

### 6. Get Agent Registry

**Method:** `get_agent_registry`

**Request:**
```bash
curl -X POST http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "get_agent_registry",
    "params": {},
    "id": 6
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "total_agents": 4,
    "active_agents": 4,
    "total_skills": 15,
    "available_skills": ["process_document", "extract_document", ...],
    "agents": {
      "Orchestrator": {
        "endpoint": "http://...",
        "skills": [...],
        "status": "active"
      },
      ...
    }
  },
  "id": 6
}
```

---

## 🧪 **Quick Testing**

### 1. Health Check
```bash
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/health | jq '.'
```

### 2. Get Agent Card
```bash
curl http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com/card | jq '.'
```

### 3. Process a Document
```bash
# Set variables
export ALB_URL="http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com"

# Upload test file
echo "Test content" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://ca-a2a-documents-555043101106/incoming/test.txt

# Process it
curl -X POST $ALB_URL/message \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "process_document",
    "params": {"s3_key": "incoming/test.txt"},
    "id": 1
  }' | jq '.'
```

---

## ⚠️ **Common Mistakes**

### ❌ **WRONG** - Posting to root
```bash
curl -X POST http://ca-a2a-alb.../  # 404 Not Found
```

### ✅ **CORRECT** - Post to /message
```bash
curl -X POST http://ca-a2a-alb.../message  # Works!
```

### ❌ **WRONG** - Missing jsonrpc field
```json
{
  "method": "process_document",
  "params": {...}
}
```

### ✅ **CORRECT** - Full JSON-RPC 2.0 format
```json
{
  "jsonrpc": "2.0",
  "method": "process_document",
  "params": {...},
  "id": 1
}
```

---

## 📖 **More Information**

- **Architecture**: See `AWS_ARCHITECTURE.md`
- **Scenarios**: See `SCENARIO_FLOWS.md`
- **Testing**: See `CLOUDSHELL_TESTING.md`
- **End-to-End Demo**: See `END_TO_END_DEMO.md`

---

## 🎯 **Status Codes**

- `200` - Success
- `204` - No Content (for notifications)
- `400` - Bad Request (invalid JSON-RPC)
- `404` - Not Found (wrong endpoint)
- `500` - Internal Server Error

---

**Last Updated:** December 18, 2025  
**ALB URL:** `http://ca-a2a-alb-1432397105.eu-west-3.elb.amazonaws.com`  
**Region:** `eu-west-3`

