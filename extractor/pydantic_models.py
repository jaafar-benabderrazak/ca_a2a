"""
Pydantic Models for Agent Request/Response Validation
Type-safe models with automatic validation for all agent operations
"""
from typing import Optional, Dict, Any, List, Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator
from datetime import datetime


# ============================================================================
# Common Models
# ============================================================================

class BaseRequest(BaseModel):
    """Base class for all agent requests"""
    model_config = ConfigDict(extra='forbid')  # Reject unknown fields


class BaseResponse(BaseModel):
    """Base class for all agent responses"""
    model_config = ConfigDict(extra='allow')  # Allow additional fields


# ============================================================================
# Orchestrator Models
# ============================================================================

class ProcessDocumentRequest(BaseRequest):
    """Request to process a single document"""
    s3_key: str = Field(..., description="S3 key of the document to process", min_length=1)
    priority: Literal["low", "normal", "high"] = Field(default="normal", description="Processing priority")
    
    @field_validator('s3_key')
    @classmethod
    def validate_s3_key(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("s3_key cannot be empty")
        return v.strip()


class ProcessDocumentResponse(BaseResponse):
    """Response from document processing"""
    task_id: str
    s3_key: str
    status: Literal["pending", "processing", "completed", "failed"]
    message: str


class ProcessBatchRequest(BaseRequest):
    """Request to process a batch of documents"""
    prefix: Optional[str] = Field(default=None, description="S3 prefix to filter documents")
    file_extension: str = Field(default=".pdf", description="File extension filter")
    limit: Optional[int] = Field(default=None, ge=1, le=1000, description="Maximum documents to process")


class ProcessBatchResponse(BaseResponse):
    """Response from batch processing"""
    batch_id: str
    total_documents: int
    task_ids: List[str]
    status: str
    message: str


class GetTaskStatusRequest(BaseRequest):
    """Request to get task status"""
    task_id: str = Field(..., description="Task ID to query")


class TaskStage(BaseModel):
    """Status of a single stage in the pipeline"""
    status: Literal["pending", "processing", "completed", "failed"]
    result: Optional[Dict[str, Any]] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None


class GetTaskStatusResponse(BaseResponse):
    """Response with task status"""
    task_id: str
    s3_key: str
    status: Literal["pending", "processing", "completed", "failed"]
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    current_stage: str
    stages: Dict[str, TaskStage]
    document_id: Optional[int] = None


class ListPendingDocumentsRequest(BaseRequest):
    """Request to list pending documents"""
    limit: int = Field(default=50, ge=1, le=1000, description="Maximum documents to return")


# ============================================================================
# Extractor Models
# ============================================================================

class ExtractDocumentRequest(BaseRequest):
    """Request to extract document data"""
    s3_key: str = Field(..., description="S3 key of the document", min_length=1)


class PDFPageData(BaseModel):
    """Extracted data from a single PDF page"""
    page_number: int
    text: str
    char_count: int


class PDFTableData(BaseModel):
    """Extracted table from PDF"""
    page: int
    table_index: int
    headers: List[str]
    rows: List[List[str]]
    row_count: int
    column_count: int


class PDFExtractedData(BaseModel):
    """Complete PDF extraction result"""
    pages: List[PDFPageData]
    tables: List[PDFTableData]
    metadata: Dict[str, Any]
    total_pages: int
    text_content: str


class CSVExtractedData(BaseModel):
    """Complete CSV extraction result"""
    row_count: int
    column_count: int
    columns: List[str]
    column_types: Dict[str, str]
    data: List[Dict[str, Any]]
    summary_statistics: Optional[Dict[str, Dict[str, float]]] = None
    missing_values: Dict[str, int]


class ExtractDocumentResponse(BaseResponse):
    """Response from document extraction"""
    s3_key: str
    document_type: Literal["pdf", "csv", "unknown"]
    file_name: str
    file_size: int
    extracted_data: Dict[str, Any]  # PDFExtractedData or CSVExtractedData
    metadata: Dict[str, Any]
    extraction_status: Literal["success", "partial", "failed"]


# ============================================================================
# Validator Models
# ============================================================================

class ValidateDocumentRequest(BaseRequest):
    """Request to validate document"""
    s3_key: str = Field(..., description="S3 key of the document")
    extracted_data: Dict[str, Any] = Field(..., description="Extracted data to validate")
    document_type: Literal["pdf", "csv"] = Field(..., description="Type of document")


class ValidationRuleResult(BaseModel):
    """Result from a single validation rule"""
    rule: str
    passed: bool
    score: float = Field(..., ge=0, le=100)
    weight: float = Field(..., ge=0)
    message: str


class ValidateDocumentResponse(BaseResponse):
    """Response from document validation"""
    s3_key: str
    document_type: str
    score: float = Field(..., ge=0, le=100, description="Overall validation score")
    status: Literal["excellent", "good", "acceptable", "poor", "failed"]
    all_rules_passed: bool
    validation_timestamp: str
    details: Dict[str, Any]


class GetValidationRulesRequest(BaseRequest):
    """Request to get validation rules"""
    document_type: Optional[Literal["pdf", "csv"]] = None


class ValidationRule(BaseModel):
    """Definition of a validation rule"""
    name: str
    weight: float
    description: Optional[str] = None


class GetValidationRulesResponse(BaseResponse):
    """Response with validation rules"""
    document_type: Optional[str]
    rules: List[ValidationRule]


# ============================================================================
# Archivist Models
# ============================================================================

class ArchiveDocumentRequest(BaseRequest):
    """Request to archive document"""
    s3_key: str = Field(..., description="S3 key of the document")
    document_type: Literal["pdf", "csv"]
    extracted_data: Dict[str, Any]
    validation_score: float = Field(..., ge=0, le=100)
    validation_details: Dict[str, Any]
    metadata: Optional[Dict[str, Any]] = None


class ArchiveDocumentResponse(BaseResponse):
    """Response from archiving document"""
    document_id: int
    s3_key: str
    status: Literal["validated", "validated_with_warnings", "validation_failed", "processed"]
    action: Literal["created", "updated"]
    validation_score: float
    archived_at: str


class GetDocumentRequest(BaseRequest):
    """Request to get a document"""
    document_id: Optional[int] = Field(default=None, description="Document ID")
    s3_key: Optional[str] = Field(default=None, description="S3 key")
    
    @field_validator('document_id', 's3_key')
    @classmethod
    def validate_at_least_one(cls, v, info):
        # At least one of document_id or s3_key must be provided
        if info.data.get('document_id') is None and info.data.get('s3_key') is None:
            raise ValueError("Either document_id or s3_key must be provided")
        return v


class DocumentRecord(BaseModel):
    """Document record from database"""
    id: int
    s3_key: str
    document_type: str
    file_name: str
    file_size: Optional[int] = None
    upload_date: Optional[str] = None
    processing_date: str
    status: str
    validation_score: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None
    extracted_data: Optional[Dict[str, Any]] = None
    validation_details: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    created_at: str
    updated_at: str


class GetDocumentResponse(BaseResponse):
    """Response with document data"""
    document: DocumentRecord


class UpdateDocumentStatusRequest(BaseRequest):
    """Request to update document status"""
    document_id: int = Field(..., ge=1)
    status: str = Field(..., min_length=1)
    error_message: Optional[str] = None


class UpdateDocumentStatusResponse(BaseResponse):
    """Response from status update"""
    document_id: int
    status: str
    updated_at: str


class SearchDocumentsRequest(BaseRequest):
    """Request to search documents"""
    status: Optional[str] = None
    document_type: Optional[Literal["pdf", "csv"]] = None
    min_score: Optional[float] = Field(default=None, ge=0, le=100)
    max_score: Optional[float] = Field(default=None, ge=0, le=100)
    limit: int = Field(default=50, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class SearchDocumentsResponse(BaseResponse):
    """Response with search results"""
    documents: List[DocumentRecord]
    total_count: int
    limit: int
    offset: int


class GetDocumentStatsResponse(BaseResponse):
    """Response with document statistics"""
    total_documents: int
    recent_activity_24h: int
    average_validation_score: Optional[float]
    by_status: Dict[str, int]
    by_type: Dict[str, int]


# ============================================================================
# Agent Discovery Models
# ============================================================================

class DiscoverAgentsResponse(BaseResponse):
    """Response from agent discovery"""
    discovered_agents: int
    total_skills: int
    available_skills: List[str]


class GetAgentRegistryResponse(BaseResponse):
    """Response with agent registry"""
    total_agents: int
    active_agents: int
    total_skills: int
    available_skills: List[str]
    agents: List[Dict[str, Any]]


# ============================================================================
# Health & Status Models
# ============================================================================

class HealthCheckResponse(BaseModel):
    """Health check response"""
    status: Literal["healthy", "degraded", "unhealthy"]
    agent: str
    version: str
    uptime_seconds: float
    dependencies: Optional[Dict[str, Dict[str, Any]]] = None


class StatusResponse(BaseModel):
    """Agent status response"""
    agent: str
    status: Literal["running", "starting", "stopping", "stopped"]
    host: str
    port: int
    uptime_seconds: float
    version: str
    performance: Optional[Dict[str, Any]] = None
    additional_info: Optional[Dict[str, Any]] = None
    model_config = ConfigDict(extra='allow')


# ============================================================================
# Helper Functions
# ============================================================================

def model_to_json_schema(model: type[BaseModel]) -> Dict[str, Any]:
    """Convert Pydantic model to JSON Schema for Agent Cards"""
    return model.model_json_schema()


def validate_with_pydantic(model: type[BaseModel], data: Dict[str, Any]) -> tuple[bool, Optional[str], Optional[BaseModel]]:
    """
    Validate data with Pydantic model
    Returns (is_valid, error_message, validated_model)
    """
    try:
        validated = model.model_validate(data)
        return True, None, validated
    except Exception as e:
        return False, str(e), None
