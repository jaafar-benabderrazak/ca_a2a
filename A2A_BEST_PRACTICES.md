# A2A Best Practices Implementation Guide

## Overview

This document describes the A2A (Agent-to-Agent) best practices implemented in the CA A2A document processing pipeline, based on official A2A protocol guidelines and production patterns.

## Best Practices Implemented

### 1. **JSON Schema Validation** ✅

All agent skills define input and output schemas using JSON Schema format.

**Location**: `agent_card.py` (AgentSkill class)

**Example**:
```python
AgentSkill(
    skill_id='extract_document',
    name='Document Extraction',
    input_schema={
        'type': 'object',
        'required': ['s3_key'],
        'properties': {
            's3_key': {'type': 'string'}
        }
    },
    output_schema={
        'type': 'object',
        'properties': {
            'extracted_data': {'type': 'object'},
            'document_type': {'type': 'string'}
        }
    }
)
```

**Benefits**:
- Type safety without code generation
- Clear contracts between agents
- Automatic validation at request time
- Self-documenting APIs

---

### 2. **Retry Logic with Exponential Backoff** ✅

All external calls (S3, PostgreSQL) use retry logic with exponential backoff.

**Location**: `utils.py` (`retry_with_backoff`)

**Implementation**:
```python
async def retry_with_backoff(
    func: Callable,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0
):
    # Retries: 1s, 2s, 4s...
```

**Applied to**:
- S3 operations (list, get, put)
- PostgreSQL queries (execute, fetch)
- Inter-agent communication

**Benefits**:
- Resilience to transient failures
- Prevents cascading failures
- Respects service recovery time

---

### 3. **Circuit Breaker Pattern** ✅

Prevents cascading failures by failing fast when services are degraded.

**Location**: `utils.py` (`CircuitBreaker`)

**States**:
- **Closed**: Normal operation
- **Open**: Service unavailable, fail fast
- **Half-Open**: Testing if service recovered

**Configuration**:
```python
CircuitBreaker(
    failure_threshold=5,      # Open after 5 failures
    recovery_timeout=60,      # Try recovery after 60s
    expected_exception=ClientError
)
```

**Applied to**:
- S3Resource operations
- PostgreSQLResource operations

**Benefits**:
- Fast failure detection
- Prevents resource exhaustion
- Automatic recovery testing

---

### 4. **Idempotency Support** ✅

Write operations are idempotent—safe to retry without duplicates.

**Location**: `utils.py` (`IdempotencyStore`, `generate_idempotency_key`)

**Implementation**:
```python
idempotency_key = generate_idempotency_key(
    'archive_document',
    {'s3_key': document_key}
)

# Check cache
cached = idempotency_store.get(idempotency_key)
if cached:
    return cached

# Process and cache result
result = await process()
idempotency_store.set(idempotency_key, result)
```

**Applied to**:
- Archivist: `archive_document` operation
- Prevents duplicate document entries
- Safe retries from orchestrator

**Benefits**:
- Safe retries
- Consistent results
- No duplicate side effects

---

### 5. **Structured Logging with Correlation IDs** ✅

All requests tracked with correlation IDs across agents.

**Location**: `utils.py` (`StructuredLogger`), `base_agent.py` (`handle_http_message`)

**Implementation**:
```python
correlation_id = request.headers.get('X-Correlation-ID', generate_correlation_id())

structured_logger.log_request(
    method='extract_document',
    params=params,
    correlation_id=correlation_id
)
```

**Log Format**:
```json
{
  "timestamp": "2025-12-13T...",
  "agent": "Extractor",
  "method": "extract_document",
  "correlation_id": "2025-12-13-a1b2c3d4",
  "duration_ms": 2500,
  "success": true
}
```

**Benefits**:
- End-to-end request tracing
- Easy debugging across agents
- Performance analytics per skill
- Audit trail

---

### 6. **Timeout Protection** ✅

All operations have timeouts to prevent hanging.

**Location**: `utils.py` (`timeout_decorator`), `mcp_protocol.py`

**Examples**:
```python
@timeout_decorator(30.0)  # 30s timeout
async def get_object(key: str):
    # S3 download operation

@timeout_decorator(10.0)  # 10s timeout
async def execute(query: str):
    # PostgreSQL query
```

**Benefits**:
- No hanging operations
- Predictable latency
- Resource protection

---

### 7. **Enhanced Health Checks** ✅

Health endpoints check agent AND dependency health.

**Location**: `base_agent.py` (`health_check`, `_check_dependencies`)

**Response Format**:
```json
{
  "status": "healthy|degraded|unhealthy",
  "agent": "Extractor",
  "version": "1.0.0",
  "uptime_seconds": 3600,
  "dependencies": {
    "s3": {
      "healthy": true,
      "bucket": "my-bucket"
    }
  }
}
```

**HTTP Status**:
- 200: Healthy
- 503: Degraded or Unhealthy

**Benefits**:
- ALB target group health checks
- Dependency monitoring
- Graceful degradation

---

### 8. **Performance Monitoring** ✅

Per-skill performance metrics tracked automatically.

**Location**: `utils.py` (`PerformanceMonitor`), `base_agent.py`

**Metrics Tracked**:
- Total requests per skill
- Success/failure counts
- Min/max/avg duration
- Success rate

**Example**:
```json
{
  "extract_document": {
    "total_requests": 1000,
    "successful_requests": 980,
    "failed_requests": 20,
    "avg_duration_ms": 2500,
    "success_rate": 0.98
  }
}
```

**Benefits**:
- Performance analytics
- SLA monitoring
- Capacity planning
- Optimization targets

---

## How to Use These Best Practices

### For New Agent Skills

When adding a new skill to an agent:

1. **Define schemas**:
```python
AgentSkill(
    skill_id='my_new_skill',
    input_schema={...},
    output_schema={...}
)
```

2. **Use structured logging**:
```python
self.structured_logger.log_request(method, params, correlation_id)
```

3. **Wrap external calls with retry**:
```python
result = await retry_with_backoff(
    lambda: my_external_call(),
    max_retries=3
)
```

4. **Add timeouts**:
```python
@timeout_decorator(30.0)
async def my_operation():
    ...
```

5. **Implement idempotency for writes**:
```python
key = generate_idempotency_key(operation, params)
cached = self.idempotency_store.get(key)
if cached:
    return cached
```

---

### For New Agents

When creating a new agent:

1. **Inherit from BaseAgent**
2. **Implement required methods**:
   - `_register_handlers()`
   - `_define_skills()`
   - `_check_dependencies()`
3. **Use MCP for resources** (S3, PostgreSQL)
4. **Follow naming conventions**

**Template**:
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
            description='What it does'
        )
    
    def _define_skills(self):
        return [
            AgentSkill(
                skill_id='my_skill',
                name='My Skill',
                description='...',
                method='my_method',
                input_schema={...},
                output_schema={...},
                tags=['category']
            )
        ]
    
    def _register_handlers(self):
        self.protocol.register_handler('my_method', self.handle_my_method)
    
    async def _check_dependencies(self):
        # Return health of dependencies
        return {'service': {'healthy': True}}
    
    async def initialize(self):
        # Setup resources
        pass
    
    async def cleanup(self):
        # Teardown resources
        pass
    
    async def handle_my_method(self, params):
        # Implement skill logic
        return {'result': 'success'}
```

---

## Testing Best Practices

### 1. Test Idempotency
```python
# Call twice with same params
result1 = await agent.handle_archive_document(params)
result2 = await agent.handle_archive_document(params)
assert result1 == result2
```

### 2. Test Circuit Breaker
```python
# Trigger failures
for _ in range(6):  # More than threshold
    try:
        await resource.operation()
    except:
        pass

# Next call should fail fast
with pytest.raises(Exception, match="Circuit breaker is OPEN"):
    await resource.operation()
```

### 3. Test Correlation IDs
```python
response = await client.post(
    '/message',
    headers={'X-Correlation-ID': 'test-123'},
    json=request
)
assert response.json()['_meta']['correlation_id'] == 'test-123'
```

### 4. Test Health Checks
```python
response = await client.get('/health')
assert response.status in [200, 503]
assert 'dependencies' in response.json()
```

---

## Monitoring & Observability

### CloudWatch Metrics to Collect

1. **Per-skill latency**:
   - `GET /status` returns performance metrics
   - Export to CloudWatch via custom metrics

2. **Circuit breaker state**:
   - Track open/closed transitions
   - Alert on prolonged open state

3. **Idempotency cache hits**:
   - Track cache hit rate
   - Monitor for cache effectiveness

4. **Correlation ID traces**:
   - CloudWatch Logs Insights queries
   - X-Ray distributed tracing

### Example CloudWatch Query
```sql
fields @timestamp, correlation_id, method, duration_ms, success
| filter agent = "Extractor"
| stats avg(duration_ms), count(*) by method
```

---

## Production Checklist

- [x] All skills have input/output schemas
- [x] Retry logic with exponential backoff
- [x] Circuit breakers on external calls
- [x] Timeouts on all async operations
- [x] Idempotency for write operations
- [x] Structured logging with correlation IDs
- [x] Health checks include dependencies
- [x] Performance monitoring per skill
- [ ] OpenTelemetry integration (future)
- [ ] Distributed tracing spans (future)
- [ ] Rate limiting (future)
- [ ] Authentication/authorization (future)

---

## References

- **A2A Protocol Official**: https://a2a-protocol.org/
- **A2A Python Samples**: https://github.com/a2aproject/a2a-samples/
- **JSON Schema**: https://json-schema.org/
- **Circuit Breaker Pattern**: Martin Fowler's blog
- **12-Factor App**: https://12factor.net/

---

**Version**: 1.0.0  
**Last Updated**: December 2025  
**Status**: Production Ready
