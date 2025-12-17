# Dynamic Skill Filtering Guide

This guide explains how to dynamically filter available agent skills based on user categories for role-based access control (RBAC).

---

## Overview

The skill filtering system allows you to:

✅ **Control access** to agent capabilities based on user roles
✅ **Define custom user categories** (Viewer, Standard User, Power User, Analyst, Auditor, Admin)
✅ **Filter skills dynamically** per request based on authentication
✅ **Support API clients** with custom skill grants
✅ **Integrate with JWT** or API key authentication
✅ **Maintain audit trails** of who used which skills

---

## User Categories

### Built-in Categories

| Category | Access Level | Use Case | Allowed Skills |
|----------|-------------|----------|----------------|
| **Viewer** | Read-only | View documents and stats | 6 skills (get, search, stats) |
| **Standard User** | Process documents | Regular document processing | 9 skills (extract, process) |
| **Power User** | Process + Validate | Full processing pipeline | 15 skills (extract, validate, archive) |
| **Analyst** | Analytics focused | Business intelligence | 8 skills (search, stats, analytics) |
| **Auditor** | Audit & compliance | Compliance review | 10 skills (validate, search, audit) |
| **Admin** | Full access | System administration | All 26 skills |
| **API Client** | Custom scope | Programmatic access | Custom skill list |

---

## Quick Start

### 1. Basic Usage

```python
from skill_filter import SkillFilter, UserContext, UserCategory

# Create filter
skill_filter = SkillFilter()

# Define user
user = UserContext(
    user_id='user123',
    category=UserCategory.POWER_USER
)

# Check if user can use a skill
can_extract = skill_filter.can_use_skill('extract_document', user)
print(f"Can extract: {can_extract}")  # True

can_batch = skill_filter.can_use_skill('process_batch', user)
print(f"Can batch process: {can_batch}")  # False (denied for power users)
```

### 2. Filter Agent Card

```python
from agent_card import AgentCard

# Get agent card (from your agent)
agent_card = orchestrator_agent.agent_card

# Filter for specific user
filtered_card = skill_filter.filter_agent_card(agent_card, user)

print(f"Total skills: {len(agent_card.skills)}")
print(f"User has access to: {len(filtered_card.skills)} skills")
```

### 3. Integrate with Your Agent

```python
from base_agent import BaseAgent
from skill_filter_integration import FilteredAgentMixin

# Update your agent class
class OrchestratorAgent(FilteredAgentMixin, BaseAgent):
    def __init__(self):
        super().__init__(
            'Orchestrator',
            config['host'],
            config['port'],
            require_auth=True  # Enable authentication
        )
        # ... rest of initialization
```

### 4. Handle Filtered Requests

```python
# In your HTTP handler
async def handle_a2a_request(request):
    # Extract user context from headers
    user_context = agent.extract_user_context(dict(request.headers))

    # Parse A2A message
    message = A2AMessage(**await request.json())

    # Handle with permission checking
    response = await agent.handle_filtered_message(message, user_context)

    return web.json_response(response.to_dict())
```

---

## Authentication Methods

### Method 1: JWT Token (Recommended for Production)

**Request:**
```bash
curl -X POST http://orchestrator.local:8001/a2a \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "process_document",
    "params": {"s3_key": "doc.pdf"}
  }'
```

**JWT Payload:**
```json
{
  "user_id": "user123",
  "category": "power_user",
  "custom_allowed_skills": ["special_skill"],
  "custom_denied_skills": ["dangerous_skill"],
  "exp": 1735689600
}
```

**Generate JWT:**
```python
import jwt
from datetime import datetime, timedelta

payload = {
    'user_id': 'user123',
    'category': 'power_user',
    'exp': datetime.utcnow() + timedelta(hours=24)
}

token = jwt.encode(payload, 'your-secret-key', algorithm='HS256')
```

### Method 2: API Key (For API Clients)

**Request:**
```bash
curl -X POST http://orchestrator.local:8001/a2a \
  -H "X-API-Key: test-key-premium" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "process_batch",
    "params": {"prefix": "invoices/"}
  }'
```

**API Client Configuration:**
```python
api_clients = {
    'test-key-premium': {
        'client_id': 'client_002',
        'allowed_skills': [
            'extract_document',
            'process_document',
            'process_batch',
            'validate_document',
            'archive_document'
        ],
        'metadata': {'tier': 'premium', 'rate_limit': 1000}
    }
}
```

### Method 3: Simple Headers (Development Only)

**Request:**
```bash
curl -X POST http://orchestrator.local:8001/a2a \
  -H "X-User-ID: user123" \
  -H "X-User-Category: power_user" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "extract_document",
    "params": {"s3_key": "doc.pdf"}
  }'
```

---

## Permission Configuration

### Example 1: Financial Services

```python
from skill_filter import UserContext, UserCategory

# Loan Officer - Can process individual applications
loan_officer = UserContext(
    user_id='loan_officer_001',
    category=UserCategory.STANDARD_USER,
    custom_allowed_skills={'search_documents', 'get_document_stats'}
)

# Compliance Officer - Can audit and review
compliance_officer = UserContext(
    user_id='compliance_001',
    category=UserCategory.AUDITOR,
    custom_allowed_skills={'update_document_status'}
)

# Data Analyst - Analytics only
analyst = UserContext(
    user_id='analyst_001',
    category=UserCategory.ANALYST
)
```

### Example 2: Healthcare

```python
# Data Entry Clerk - Limited processing
data_entry = UserContext(
    user_id='clerk_001',
    category=UserCategory.STANDARD_USER,
    custom_denied_skills={'process_batch'}  # No batch processing
)

# Records Manager - Full processing + admin
records_manager = UserContext(
    user_id='manager_001',
    category=UserCategory.POWER_USER,
    custom_allowed_skills={'update_document_status'}
)

# HIPAA Auditor - Audit trail access only
hipaa_auditor = UserContext(
    user_id='auditor_001',
    category=UserCategory.AUDITOR,
    metadata={'certification': 'HIPAA', 'clearance': 'PHI'}
)
```

### Example 3: Custom API Clients

```python
from skill_filter import create_api_client_context

# Analytics API - Read-only analytics
analytics_api = create_api_client_context(
    client_id='analytics_team',
    allowed_skills=[
        'get_document',
        'search_documents',
        'get_document_stats',
        'get_task_status',
        'list_pending_documents'
    ],
    metadata={'department': 'analytics', 'tier': 'premium'}
)

# Processing API - Document processing only
processing_api = create_api_client_context(
    client_id='processing_service',
    allowed_skills=[
        'extract_document',
        'process_document',
        'validate_document',
        'archive_document'
    ],
    metadata={'service': 'batch_processor', 'tier': 'enterprise'}
)

# Integration API - Limited scope
integration_api = create_api_client_context(
    client_id='partner_integration',
    allowed_skills=[
        'process_document',
        'get_task_status',
        'get_document'
    ],
    metadata={'partner': 'acme_corp', 'tier': 'partner'}
)
```

---

## Skill Categories

Skills are organized into categories for easier permission management:

### Category 1: Document Processing (9 skills)
- `extract_document`
- `pdf_text_extraction`
- `pdf_table_extraction`
- `csv_parsing`
- `list_supported_formats`
- `process_document`
- `process_batch`
- `get_task_status`
- `list_pending_documents`

### Category 2: Quality Control (7 skills)
- `validate_document`
- `data_completeness_check`
- `data_format_validation`
- `data_quality_assessment`
- `data_consistency_check`
- `get_validation_rules`
- `audit_logging`

### Category 3: Storage & Analytics (8 skills)
- `archive_document`
- `get_document`
- `update_document_status`
- `search_documents`
- `get_document_stats`

### Discovery (2 skills)
- `discover_agents`
- `get_agent_registry`

---

## Permission Matrix

| User Category | Doc Processing | Quality Control | Storage & Analytics | Discovery |
|---------------|----------------|-----------------|---------------------|-----------|
| **Viewer** | ❌ | ❌ | Read-only | ✅ |
| **Standard User** | ✅ (no batch) | ❌ | Read-only | ✅ |
| **Power User** | ✅ | ✅ | Limited write | ✅ |
| **Analyst** | Read status | ❌ | ✅ (no update) | ✅ |
| **Auditor** | ❌ | ✅ | Read-only | ✅ |
| **Admin** | ✅ | ✅ | ✅ | ✅ |
| **API Client** | Custom | Custom | Custom | Custom |

---

## API Endpoints

### 1. Get Filtered Agent Card

Returns agent card with only skills the user can access.

```bash
GET /card
Headers:
  Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "name": "Orchestrator",
  "version": "1.0.0",
  "skills": [
    {
      "skill_id": "process_document",
      "name": "Process Document",
      "description": "...",
      "method": "process_document"
    }
  ],
  "filtered_for": {
    "user_id": "user123",
    "category": "power_user",
    "skills_count": 15
  }
}
```

### 2. Get User Permissions

Returns detailed permission information for authenticated user.

```bash
GET /permissions
Headers:
  Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "user_id": "user123",
  "category": "power_user",
  "allowed_skills": [
    "extract_document",
    "process_document",
    "validate_document",
    "..."
  ],
  "skill_count": 15,
  "skill_count_by_category": {
    "document_processing": 7,
    "quality_control": 6,
    "storage_analytics": 2
  },
  "permissions": {
    "user_category": "power_user",
    "description": "Full document processing and validation capabilities",
    "allowed_skill_categories": ["document_processing", "quality_control"],
    "explicitly_allowed_skills": ["get_document", "search_documents"],
    "denied_skills": ["update_document_status"]
  }
}
```

### 3. A2A Endpoint with Filtering

Standard A2A endpoint with permission checking.

```bash
POST /a2a
Headers:
  Authorization: Bearer <jwt_token>
  Content-Type: application/json

Body:
{
  "jsonrpc": "2.0",
  "id": "1",
  "method": "extract_document",
  "params": {"s3_key": "doc.pdf"}
}
```

**Success Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "result": {
    "s3_key": "doc.pdf",
    "document_type": "pdf",
    "extracted_data": {...}
  }
}
```

**Access Denied Response:**
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "error": {
    "code": -32601,
    "message": "Access denied: User category 'viewer' cannot use skill 'extract_document'"
  }
}
```

---

## Configuration Files

### 1. Environment Variables

```bash
# .env
REQUIRE_AUTH=true
JWT_SECRET=your-secret-key-here
DEFAULT_USER_CATEGORY=viewer
ALLOW_ANONYMOUS=false
```

### 2. User Configuration (YAML)

```yaml
# users.yaml
users:
  - user_id: user123
    category: power_user
    custom_allowed_skills:
      - special_feature
    metadata:
      department: finance
      clearance_level: 3

  - user_id: user456
    category: analyst
    custom_denied_skills:
      - sensitive_data_access
    metadata:
      department: marketing

api_clients:
  - client_id: analytics_service
    api_key: key_analytics_001
    category: api_client
    allowed_skills:
      - get_document
      - search_documents
      - get_document_stats
    rate_limit: 1000
    metadata:
      tier: premium
      department: analytics
```

### 3. Database Schema

```sql
-- users table
CREATE TABLE users (
    user_id VARCHAR(255) PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    custom_allowed_skills JSONB DEFAULT '[]',
    custom_denied_skills JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- api_clients table
CREATE TABLE api_clients (
    client_id VARCHAR(255) PRIMARY KEY,
    api_key VARCHAR(255) UNIQUE NOT NULL,
    category VARCHAR(50) DEFAULT 'api_client',
    allowed_skills JSONB NOT NULL,
    rate_limit INTEGER DEFAULT 100,
    metadata JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- access_logs table (audit trail)
CREATE TABLE access_logs (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    user_category VARCHAR(50) NOT NULL,
    skill_id VARCHAR(255) NOT NULL,
    access_granted BOOLEAN NOT NULL,
    ip_address INET,
    user_agent TEXT,
    request_params JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_access_logs_user_id ON access_logs(user_id);
CREATE INDEX idx_access_logs_skill_id ON access_logs(skill_id);
CREATE INDEX idx_access_logs_created_at ON access_logs(created_at);
```

---

## Testing

### Unit Tests

```python
import pytest
from skill_filter import SkillFilter, UserContext, UserCategory
from agent_card import AgentSkill

def test_viewer_cannot_extract():
    skill_filter = SkillFilter()
    viewer = UserContext(user_id='test', category=UserCategory.VIEWER)

    assert not skill_filter.can_use_skill('extract_document', viewer)
    assert skill_filter.can_use_skill('get_document', viewer)

def test_power_user_can_process():
    skill_filter = SkillFilter()
    power_user = UserContext(user_id='test', category=UserCategory.POWER_USER)

    assert skill_filter.can_use_skill('extract_document', power_user)
    assert skill_filter.can_use_skill('validate_document', power_user)
    assert not skill_filter.can_use_skill('update_document_status', power_user)

def test_custom_permissions():
    skill_filter = SkillFilter()
    user = UserContext(
        user_id='test',
        category=UserCategory.VIEWER,
        custom_allowed_skills={'extract_document'}
    )

    # Viewer normally can't extract, but custom permission allows it
    assert skill_filter.can_use_skill('extract_document', user)

def test_admin_access():
    skill_filter = SkillFilter()
    admin = UserContext(user_id='admin', category=UserCategory.ADMIN)

    # Admin can use all skills
    assert skill_filter.can_use_skill('extract_document', admin)
    assert skill_filter.can_use_skill('update_document_status', admin)
    assert skill_filter.can_use_skill('any_skill', admin)
```

### Integration Tests

```bash
# Test viewer access
curl -X POST http://localhost:8001/a2a \
  -H "X-User-Category: viewer" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"extract_document","params":{"s3_key":"doc.pdf"}}'

# Expected: Access denied

# Test power user access
curl -X POST http://localhost:8001/a2a \
  -H "X-User-Category: power_user" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"extract_document","params":{"s3_key":"doc.pdf"}}'

# Expected: Success
```

---

## Best Practices

### 1. **Use JWT for Production**
- Don't use simple headers in production
- Always verify JWT signatures
- Set appropriate expiration times
- Use HTTPS only

### 2. **Principle of Least Privilege**
- Grant minimum required permissions
- Use deny lists for sensitive operations
- Review permissions regularly

### 3. **Audit Everything**
- Log all access attempts (granted and denied)
- Include user context in all logs
- Monitor for suspicious patterns

### 4. **Rate Limiting**
- Implement per-user rate limits
- Different limits for different categories
- Stricter limits for sensitive operations

### 5. **Custom Permissions**
- Use custom_allowed_skills sparingly
- Document why custom permissions were granted
- Review custom permissions quarterly

---

## Migration Guide

### Step 1: Add FilteredAgentMixin to Your Agents

```python
# Before
class OrchestratorAgent(BaseAgent):
    def __init__(self):
        super().__init__('Orchestrator', host, port)

# After
from skill_filter_integration import FilteredAgentMixin

class OrchestratorAgent(FilteredAgentMixin, BaseAgent):
    def __init__(self):
        super().__init__('Orchestrator', host, port, require_auth=True)
```

### Step 2: Update HTTP Handlers

```python
# Before
async def a2a_handler(request):
    message = A2AMessage(**await request.json())
    response = await agent.protocol.handle_message(message)
    return web.json_response(response.to_dict())

# After
async def a2a_handler(request):
    user_context = agent.extract_user_context(dict(request.headers))
    message = A2AMessage(**await request.json())
    response = await agent.handle_filtered_message(message, user_context)
    return web.json_response(response.to_dict())
```

### Step 3: Add Middleware

```python
from skill_filter_integration import skill_filter_middleware

app = web.Application(middlewares=[skill_filter_middleware])
app['agent'] = agent
```

### Step 4: Update Documentation

- Document required headers for API clients
- Provide JWT token generation examples
- List available user categories

---

## Troubleshooting

### Issue: "Authentication required" error

**Solution:**
- Ensure `Authorization` header is present
- Check JWT token format: `Bearer <token>`
- Verify token is not expired

### Issue: "Access denied" for valid user

**Solution:**
- Check user category permissions
- Verify skill_id matches exactly
- Check for denied_skills overrides
- Review custom permissions

### Issue: Admin user denied access

**Solution:**
- Ensure category is exactly `"admin"` (lowercase)
- Check for custom_denied_skills
- Verify FilteredAgentMixin is properly initialized

---

## Security Considerations

⚠️ **Critical Security Points:**

1. **Always verify JWT signatures in production**
2. **Use HTTPS only - never HTTP**
3. **Store API keys securely (database, not code)**
4. **Rotate API keys regularly**
5. **Log all access attempts**
6. **Implement rate limiting**
7. **Use strong JWT secret keys**
8. **Set appropriate token expiration**
9. **Validate all user input**
10. **Regular security audits**

---

## Summary

The skill filtering system provides:

✅ **6 built-in user categories** + custom API clients
✅ **26 skills organized into 3 categories**
✅ **Multiple authentication methods** (JWT, API key, headers)
✅ **Fine-grained permission control**
✅ **Easy integration with existing agents**
✅ **Complete audit trail**
✅ **Production-ready security**

For questions or support, see:
- [AGENT_SKILLS_BY_CLIENT_USE_CASE.md](./AGENT_SKILLS_BY_CLIENT_USE_CASE.md) - Skill categories
- [TECHNICAL_ARCHITECTURE.md](./TECHNICAL_ARCHITECTURE.md) - System architecture
- [skill_filter.py](./skill_filter.py) - Core implementation
- [skill_filter_integration.py](./skill_filter_integration.py) - Integration examples
