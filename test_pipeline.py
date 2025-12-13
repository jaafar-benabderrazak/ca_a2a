"""
Basic tests for the multi-agent pipeline
Run with: pytest test_pipeline.py
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
import json

from a2a_protocol import A2AMessage, A2AProtocol, ErrorCodes
from validator_agent import (
    DataCompletenessRule,
    DataQualityRule,
    DataConsistencyRule,
    DataFormatRule
)


class TestA2AProtocol:
    """Test A2A protocol implementation"""
    
    def test_create_request(self):
        """Test creating a request message"""
        msg = A2AMessage.create_request("test_method", {"param": "value"})
        
        assert msg.jsonrpc == "2.0"
        assert msg.method == "test_method"
        assert msg.params == {"param": "value"}
        assert msg.id is not None
    
    def test_create_response(self):
        """Test creating a response message"""
        msg = A2AMessage.create_response("request-id", {"result": "success"})
        
        assert msg.jsonrpc == "2.0"
        assert msg.id == "request-id"
        assert msg.result == {"result": "success"}
        assert msg.error is None
    
    def test_create_error(self):
        """Test creating an error message"""
        msg = A2AMessage.create_error("request-id", -32001, "Test error")
        
        assert msg.jsonrpc == "2.0"
        assert msg.id == "request-id"
        assert msg.error["code"] == -32001
        assert msg.error["message"] == "Test error"
    
    def test_create_notification(self):
        """Test creating a notification message"""
        msg = A2AMessage.create_notification("notify_method", {"data": "value"})
        
        assert msg.jsonrpc == "2.0"
        assert msg.method == "notify_method"
        assert msg.params == {"data": "value"}
        assert msg.id is None
    
    def test_message_serialization(self):
        """Test message JSON serialization"""
        msg = A2AMessage.create_request("test", {"key": "value"})
        json_str = msg.to_json()
        
        # Should be valid JSON
        data = json.loads(json_str)
        assert data["jsonrpc"] == "2.0"
        assert data["method"] == "test"
        assert data["params"]["key"] == "value"
    
    def test_message_deserialization(self):
        """Test message JSON deserialization"""
        json_str = '{"jsonrpc": "2.0", "id": "1", "method": "test", "params": {}}'
        msg = A2AMessage.from_json(json_str)
        
        assert msg.jsonrpc == "2.0"
        assert msg.id == "1"
        assert msg.method == "test"
    
    @pytest.mark.asyncio
    async def test_protocol_handler_registration(self):
        """Test registering handlers"""
        protocol = A2AProtocol()
        
        async def test_handler(params):
            return {"status": "ok"}
        
        protocol.register_handler("test_method", test_handler)
        
        assert "test_method" in protocol.handlers
    
    @pytest.mark.asyncio
    async def test_protocol_handle_request(self):
        """Test handling a request"""
        protocol = A2AProtocol()
        
        async def test_handler(params):
            return {"result": params.get("value", 0) * 2}
        
        protocol.register_handler("multiply", test_handler)
        
        request = A2AMessage.create_request("multiply", {"value": 5})
        response = await protocol.handle_message(request)
        
        assert response is not None
        assert response.result == {"result": 10}
        assert response.id == request.id
    
    @pytest.mark.asyncio
    async def test_protocol_method_not_found(self):
        """Test handling unknown method"""
        protocol = A2AProtocol()
        
        request = A2AMessage.create_request("unknown_method", {})
        response = await protocol.handle_message(request)
        
        assert response.error is not None
        assert response.error["code"] == -32601


class TestValidationRules:
    """Test validation rules"""
    
    def test_completeness_rule_all_present(self):
        """Test completeness rule with all fields present"""
        rule = DataCompletenessRule(["field1", "field2", "field3"])
        data = {"field1": "value1", "field2": "value2", "field3": "value3"}
        
        passed, score, message = rule.validate(data)
        
        assert passed is True
        assert score == 100.0
        assert "All required fields present" in message
    
    def test_completeness_rule_missing_fields(self):
        """Test completeness rule with missing fields"""
        rule = DataCompletenessRule(["field1", "field2", "field3"])
        data = {"field1": "value1"}
        
        passed, score, message = rule.validate(data)
        
        assert passed is False
        assert score < 100.0
        assert "Missing fields" in message
    
    def test_completeness_rule_empty_fields(self):
        """Test completeness rule with empty fields"""
        rule = DataCompletenessRule(["field1", "field2"])
        data = {"field1": "value1", "field2": ""}
        
        passed, score, message = rule.validate(data)
        
        assert passed is False
        assert "Empty fields" in message
    
    def test_format_rule_valid(self):
        """Test format rule with valid data"""
        rule = DataFormatRule({"email": r"^[\w\.-]+@[\w\.-]+\.\w+$"})
        data = {"email": "test@example.com"}
        
        passed, score, message = rule.validate(data)
        
        assert passed is True
        assert score == 100.0
    
    def test_format_rule_invalid(self):
        """Test format rule with invalid data"""
        rule = DataFormatRule({"email": r"^[\w\.-]+@[\w\.-]+\.\w+$"})
        data = {"email": "invalid-email"}
        
        passed, score, message = rule.validate(data)
        
        assert passed is False
        assert score == 0.0
        assert "Invalid format" in message
    
    def test_quality_rule_pdf_short_text(self):
        """Test quality rule for PDF with short text"""
        rule = DataQualityRule(min_text_length=100)
        data = {"text_content": "Short text"}
        
        passed, score, message = rule.validate(data)
        
        assert passed is False
        assert score < 100.0
        assert "Text too short" in message
    
    def test_quality_rule_pdf_adequate_text(self):
        """Test quality rule for PDF with adequate text"""
        rule = DataQualityRule(min_text_length=10)
        data = {"text_content": "This is a long enough text for the test"}
        
        passed, score, message = rule.validate(data)
        
        assert passed is True
        assert score == 100.0
    
    def test_quality_rule_csv_high_missing(self):
        """Test quality rule for CSV with high missing rate"""
        rule = DataQualityRule()
        data = {
            "row_count": 100,
            "column_count": 4,
            "missing_values": {"col1": 80, "col2": 70, "col3": 90, "col4": 60}
        }
        
        passed, score, message = rule.validate(data)
        
        assert passed is False
        assert score < 100.0
        assert "missing data" in message.lower()
    
    def test_consistency_rule_table(self):
        """Test consistency rule for tables"""
        rule = DataConsistencyRule()
        data = {
            "tables": [
                {
                    "column_count": 3,
                    "rows": [
                        ["a", "b", "c"],
                        ["d", "e"],  # Inconsistent row
                        ["f", "g", "h"]
                    ]
                }
            ]
        }
        
        passed, score, message = rule.validate(data)
        
        assert passed is False
        assert score < 100.0
        assert "inconsistent rows" in message.lower()


class TestDocumentExtraction:
    """Test document extraction logic"""
    
    def test_get_document_type_pdf(self):
        """Test document type detection for PDF"""
        from extractor_agent import ExtractorAgent
        
        agent = ExtractorAgent()
        
        assert agent._get_document_type("file.pdf") == "pdf"
        assert agent._get_document_type("FILE.PDF") == "pdf"
        assert agent._get_document_type("path/to/document.pdf") == "pdf"
    
    def test_get_document_type_csv(self):
        """Test document type detection for CSV"""
        from extractor_agent import ExtractorAgent
        
        agent = ExtractorAgent()
        
        assert agent._get_document_type("file.csv") == "csv"
        assert agent._get_document_type("FILE.CSV") == "csv"
        assert agent._get_document_type("path/to/data.csv") == "csv"
    
    def test_get_document_type_unknown(self):
        """Test document type detection for unknown"""
        from extractor_agent import ExtractorAgent
        
        agent = ExtractorAgent()
        
        assert agent._get_document_type("file.txt") == "unknown"
        assert agent._get_document_type("file.docx") == "unknown"


class TestErrorCodes:
    """Test error code constants"""
    
    def test_standard_error_codes(self):
        """Test standard JSON-RPC error codes"""
        assert ErrorCodes.PARSE_ERROR == -32700
        assert ErrorCodes.INVALID_REQUEST == -32600
        assert ErrorCodes.METHOD_NOT_FOUND == -32601
        assert ErrorCodes.INVALID_PARAMS == -32602
        assert ErrorCodes.INTERNAL_ERROR == -32603
    
    def test_custom_error_codes(self):
        """Test custom error codes"""
        assert ErrorCodes.EXTRACTION_ERROR == -32001
        assert ErrorCodes.VALIDATION_ERROR == -32002
        assert ErrorCodes.PERSISTENCE_ERROR == -32003
        assert ErrorCodes.S3_ERROR == -32004
        assert ErrorCodes.DATABASE_ERROR == -32005


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

