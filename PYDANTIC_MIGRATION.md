# Pydantic Validation Migration Guide

## Overview

The system now supports **Pydantic v2** for request/response validation, providing better type safety, automatic validation, and improved error messages.

## ✨ What Changed

### 1. **Added Pydantic Support**
- ✅ Pydantic 2.5+ added to requirements
- ✅ All agent request/response models defined in `pydantic_models.py`
- ✅ Agent Cards now support both JSON Schema and Pydantic models
- ✅ Validation automatically uses Pydantic when available

### 2. **Backward Compatibility**
- ✅ JSON Schema validation still works
- ✅ Agent Cards can use either approach
- ✅ No breaking changes to existing code

---

## 📦 New File: `pydantic_models.py`

Contains type-safe models for all agent operations:

```python
from pydantic_models import (
    # Orchestrator
    ProcessDocumentRequest,
    ProcessDocumentResponse,
    GetTaskStatusRequest,
    GetTaskStatusResponse,
    
    # Extractor
    ExtractDocumentRequest,
    ExtractDocumentResponse,
    
    # Validator
    ValidateDocumentRequest,
    ValidateDocumentResponse,
    
    # Archivist
    ArchiveDocumentRequest,
    ArchiveDocumentResponse,
    SearchDocumentsRequest,
    SearchDocumentsResponse,
    
    # Health & Status
    HealthCheckResponse,
    StatusResponse
)
```

---

## 🚀 How to Use Pydantic Models

### Method 1: Define Skills with Pydantic (Recommended)

```python
from agent_card import AgentSkill
from pydantic_models import ExtractDocumentRequest, ExtractDocumentResponse

# Create skill with Pydantic models
skill = AgentSkill.from_pydantic(
    skill_id='extract_document',
    name='Document Extraction',
    description='Extract structured data from PDF or CSV',
    method='extract_document',
    request_model=ExtractDocumentRequest,   # ← Pydantic model
    response_model=ExtractDocumentResponse,  # ← Pydantic model
    tags=['extraction', 'pdf', 'csv'],
    avg_processing_time_ms=2500
)
```

**Benefits:**
- ✅ Automatic JSON Schema generation for Agent Cards
- ✅ Type-safe validation with better error messages
- ✅ Auto-completion in IDEs
- ✅ Runtime validation before method execution

### Method 2: Manual Validation in Handlers

```python
from pydantic_models import ProcessDocumentRequest

async def handle_process_document(self, params: dict):
    # Validate with Pydantic
    try:
        request = ProcessDocumentRequest.model_validate(params)
        # Use typed fields
        s3_key = request.s3_key
        priority = request.priority
    except ValidationError as e:
        return {"error": str(e)}
    
    # ... process document
```

---

## 📚 Example: Updating an Agent

### Before (JSON Schema only)

```python
from agent_card import AgentSkill

def _define_skills(self):
    return [
        AgentSkill(
            skill_id='extract_document',
            name='Document Extraction',
            description='Extract data from documents',
            method='extract_document',
            input_schema={  # ← Manual JSON Schema
                'type': 'object',
                'required': ['s3_key'],
                'properties': {
                    's3_key': {'type': 'string'}
                }
            },
            output_schema={  # ← Manual JSON Schema
                'type': 'object',
                'properties': {
                    's3_key': {'type': 'string'},
                    'document_type': {'type': 'string'}
                }
            }
        )
    ]
```

### After (with Pydantic)

```python
from agent_card import AgentSkill
from pydantic_models import ExtractDocumentRequest, ExtractDocumentResponse

def _define_skills(self):
    return [
        AgentSkill.from_pydantic(  # ← Use from_pydantic()
            skill_id='extract_document',
            name='Document Extraction',
            description='Extract data from documents',
            method='extract_document',
            request_model=ExtractDocumentRequest,   # ← Pydantic model
            response_model=ExtractDocumentResponse,  # ← Pydantic model
            tags=['extraction', 'pdf', 'csv']
        )
    ]
```

**Result:**
- JSON Schemas auto-generated from Pydantic models
- Better validation error messages
- Type safety in your handlers

---

## 🎯 Available Pydantic Models

### Orchestrator Models

| Model | Purpose |
|-------|---------|
| `ProcessDocumentRequest` | Request to process a document |
| `ProcessDocumentResponse` | Task creation response |
| `ProcessBatchRequest` | Batch processing request |
| `ProcessBatchResponse` | Batch creation response |
| `GetTaskStatusRequest` | Task status query |
| `GetTaskStatusResponse` | Task status with stages |
| `ListPendingDocumentsRequest` | List pending documents |

### Extractor Models

| Model | Purpose |
|-------|---------|
| `ExtractDocumentRequest` | Extract document request |
| `ExtractDocumentResponse` | Extraction result |
| `PDFExtractedData` | PDF extraction result |
| `CSVExtractedData` | CSV extraction result |

### Validator Models

| Model | Purpose |
|-------|---------|
| `ValidateDocumentRequest` | Validation request |
| `ValidateDocumentResponse` | Validation result with score |
| `GetValidationRulesRequest` | Get validation rules |
| `GetValidationRulesResponse` | Rules list |

### Archivist Models

| Model | Purpose |
|-------|---------|
| `ArchiveDocumentRequest` | Archive document |
| `ArchiveDocumentResponse` | Archive confirmation |
| `GetDocumentRequest` | Get document by ID or s3_key |
| `DocumentRecord` | Complete document record |
| `SearchDocumentsRequest` | Search with filters |
| `SearchDocumentsResponse` | Search results |
| `GetDocumentStatsResponse` | Statistics |

---

## 🔍 Validation in Action

### Automatic Validation (via Agent Cards)

When a skill is defined with Pydantic models, validation happens **automatically**:

```python
# Request comes in
POST /message
{
  "jsonrpc": "2.0",
  "method": "process_document",
  "params": {
    "s3_key": "",  # ← Invalid: empty string
    "priority": "urgent"  # ← Invalid: must be low|normal|high
  }
}

# Response (automatic validation error)
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32602,
    "message": "Invalid params: s3_key: String should have at least 1 character; priority: Input should be 'low', 'normal' or 'high'"
  }
}
```

### Manual Validation

```python
from pydantic_models import ProcessDocumentRequest, validate_with_pydantic

async def handle_process_document(self, params: dict):
    # Validate manually
    is_valid, error, validated = validate_with_pydantic(
        ProcessDocumentRequest, params
    )
    
    if not is_valid:
        return {"error": error}
    
    # Use validated data (typed)
    s3_key = validated.s3_key
    priority = validated.priority
```

---

## 🎨 Creating Custom Pydantic Models

### Example: New Agent Skill

```python
from pydantic import BaseModel, Field
from typing import Literal, Optional

class AnalyzeDocumentRequest(BaseModel):
    """Request to analyze document sentiment"""
    s3_key: str = Field(..., min_length=1, description="Document S3 key")
    analysis_type: Literal["sentiment", "keywords", "summary"] = Field(
        default="sentiment",
        description="Type of analysis to perform"
    )
    language: str = Field(default="en", pattern="^[a-z]{2}$")

class AnalyzeDocumentResponse(BaseModel):
    """Analysis result"""
    s3_key: str
    analysis_type: str
    result: dict
    confidence: float = Field(..., ge=0.0, le=1.0)
    processing_time_ms: int

# Use in skill definition
skill = AgentSkill.from_pydantic(
    skill_id='analyze_document',
    name='Document Analysis',
    description='Analyze document content',
    method='analyze_document',
    request_model=AnalyzeDocumentRequest,
    response_model=AnalyzeDocumentResponse
)
```

---

## 🔄 Migration Strategy

### Phase 1: Install Pydantic (✅ Done)
```bash
pip install pydantic>=2.5.0
```

### Phase 2: Define Models (✅ Done)
All models in `pydantic_models.py`

### Phase 3: Update Agent Skills (Gradual)

**Option A: Update all agents at once**
```bash
# Update each agent's _define_skills() method
# Use AgentSkill.from_pydantic()
```

**Option B: Hybrid approach** (recommended)
```python
def _define_skills(self):
    return [
        # New skills use Pydantic
        AgentSkill.from_pydantic(
            skill_id='new_skill',
            request_model=NewRequest,
            response_model=NewResponse,
            ...
        ),
        # Old skills keep JSON Schema
        AgentSkill(
            skill_id='old_skill',
            input_schema={...},
            output_schema={...},
            ...
        )
    ]
```

### Phase 4: Update Handlers (Optional)

Add type hints and use Pydantic models:
```python
async def handle_process_document(self, params: dict):
    # Before: manual parsing
    s3_key = params.get('s3_key')
    priority = params.get('priority', 'normal')
    
    # After: validated model
    request = ProcessDocumentRequest.model_validate(params)
    s3_key = request.s3_key
    priority = request.priority
```

---

## 🚨 Error Messages Comparison

### JSON Schema Error
```
Validation error: 's3_key' is a required property
```

### Pydantic Error (Better!)
```
s3_key: Field required; priority: Input should be 'low', 'normal' or 'high'
```

Pydantic provides:
- ✅ Multiple errors in one message
- ✅ Field path for nested validation
- ✅ Clear error descriptions
- ✅ Type coercion hints

---

## 💡 Best Practices

### 1. **Use Field() for Constraints**
```python
from pydantic import BaseModel, Field

class MyRequest(BaseModel):
    s3_key: str = Field(..., min_length=1, max_length=500)
    score: float = Field(..., ge=0.0, le=100.0)
    tags: list[str] = Field(default_factory=list, max_length=10)
```

### 2. **Use Literal for Enums**
```python
from typing import Literal

class MyRequest(BaseModel):
    status: Literal["pending", "processing", "completed"]
```

### 3. **Add field_validator for Custom Logic**
```python
from pydantic import field_validator

class MyRequest(BaseModel):
    s3_key: str
    
    @field_validator('s3_key')
    @classmethod
    def validate_s3_key(cls, v: str) -> str:
        if not v.startswith('documents/'):
            raise ValueError('s3_key must start with documents/')
        return v
```

### 4. **Keep JSON Schema Compatibility**
```python
# Generate JSON Schema for documentation
from pydantic_models import ProcessDocumentRequest

schema = ProcessDocumentRequest.model_json_schema()
# Use in OpenAPI, Agent Cards, etc.
```

---

## 🧪 Testing

### Test Validation
```python
import pytest
from pydantic import ValidationError
from pydantic_models import ProcessDocumentRequest

def test_valid_request():
    data = {"s3_key": "documents/test.pdf", "priority": "normal"}
    request = ProcessDocumentRequest.model_validate(data)
    assert request.s3_key == "documents/test.pdf"
    assert request.priority == "normal"

def test_invalid_request():
    with pytest.raises(ValidationError) as exc_info:
        ProcessDocumentRequest.model_validate({"s3_key": ""})
    
    errors = exc_info.value.errors()
    assert any('s3_key' in str(e['loc']) for e in errors)
```

---

## 📖 Resources

- **Pydantic Docs**: https://docs.pydantic.dev/
- **Pydantic v2 Migration**: https://docs.pydantic.dev/latest/migration/
- **JSON Schema**: https://json-schema.org/

---

## ✅ Summary

**What you get with Pydantic:**
- ✅ Type-safe validation
- ✅ Better error messages
- ✅ IDE auto-completion
- ✅ Automatic JSON Schema generation
- ✅ Runtime type checking
- ✅ Data coercion (strings to int, etc.)

**Backward compatibility:**
- ✅ JSON Schema still works
- ✅ No breaking changes
- ✅ Gradual migration supported

**Next steps:**
1. Update agent skills to use `AgentSkill.from_pydantic()`
2. Add type hints to handler methods
3. Use Pydantic models in handler implementation
4. Enjoy better validation and type safety! 🎉
