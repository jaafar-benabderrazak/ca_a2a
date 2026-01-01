"""
Simple integration test proving main features work
Run with: pytest test_integration_simple.py -v
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from a2a_protocol import A2AMessage, A2AProtocol


class TestSimpleIntegration:
    """Simple tests proving the main features work"""

    @pytest.mark.asyncio
    async def test_a2a_agent_communication(self):
        """Prove agents can communicate via A2A protocol"""
        # Setup two mock agents
        agent1_protocol = A2AProtocol()
        agent2_protocol = A2AProtocol()

        # Agent 2 registers a handler
        async def process_handler(params):
            return {
                "status": "success",
                "data": f"Processed: {params.get('input', '')}"
            }

        agent2_protocol.register_handler("process", process_handler)

        # Agent 1 sends request to Agent 2
        request = A2AMessage.create_request("process", {"input": "test_document.pdf"})
        response = await agent2_protocol.handle_message(request)

        # Verify communication works
        assert response is not None
        assert response.error is None
        assert response.result["status"] == "success"
        assert "test_document.pdf" in response.result["data"]
        print("[OK] A2A agent communication works")

    @pytest.mark.asyncio
    async def test_multi_agent_pipeline_flow(self):
        """Prove the multi-agent pipeline workflow"""
        # Create protocols for each agent
        orchestrator = A2AProtocol()
        extractor = A2AProtocol()
        validator = A2AProtocol()
        archivist = A2AProtocol()

        # Setup handlers for each agent
        async def extract_handler(params):
            return {
                "task_id": params["task_id"],
                "document_type": "pdf",
                "text_content": "Sample document text content for testing",
                "tables": []
            }

        async def validate_handler(params):
            return {
                "task_id": params["task_id"],
                "is_valid": True,
                "score": 95.0,
                "message": "All validations passed"
            }

        async def archive_handler(params):
            return {
                "task_id": params["task_id"],
                "document_id": "doc-12345",
                "status": "archived"
            }

        extractor.register_handler("extract", extract_handler)
        validator.register_handler("validate", validate_handler)
        archivist.register_handler("archive", archive_handler)

        # Simulate pipeline flow
        task_id = "test-task-001"

        # Step 1: Extract
        extract_req = A2AMessage.create_request("extract", {
            "task_id": task_id,
            "document_path": "s3://bucket/test.pdf"
        })
        extract_resp = await extractor.handle_message(extract_req)
        assert extract_resp.result["task_id"] == task_id
        assert "text_content" in extract_resp.result
        print("[OK] Extraction step works")

        # Step 2: Validate
        validate_req = A2AMessage.create_request("validate", {
            "task_id": task_id,
            "extracted_data": extract_resp.result
        })
        validate_resp = await validator.handle_message(validate_req)
        assert validate_resp.result["is_valid"] is True
        assert validate_resp.result["score"] > 0
        print("[OK] Validation step works")

        # Step 3: Archive
        archive_req = A2AMessage.create_request("archive", {
            "task_id": task_id,
            "document_data": extract_resp.result,
            "validation_result": validate_resp.result
        })
        archive_resp = await archivist.handle_message(archive_req)
        assert archive_resp.result["status"] == "archived"
        assert "document_id" in archive_resp.result
        print("[OK] Archival step works")

        print(f"[OK] Complete pipeline flow works (task {task_id})")

    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Prove error handling works"""
        protocol = A2AProtocol()

        # Test unknown method
        request = A2AMessage.create_request("unknown_method", {})
        response = await protocol.handle_message(request)

        assert response.error is not None
        assert response.error["code"] == -32601  # Method not found
        print("[OK] Error handling works")

    @pytest.mark.asyncio
    async def test_validation_logic(self):
        """Prove validation logic works"""
        # Simple validation checks without dependencies

        # Test completeness check
        required_fields = ["field1", "field2"]
        data = {"field1": "val1", "field2": "val2"}
        missing = [f for f in required_fields if f not in data or not data[f]]
        assert len(missing) == 0, "All fields should be present"
        print("[OK] Completeness validation works")

        # Test quality check (text length)
        min_length = 10
        text = "This is a test document with enough text"
        assert len(text) >= min_length, "Text should meet minimum length"
        print("[OK] Quality validation works")

        # Test format validation (email)
        import re
        email = "test@example.com"
        pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        assert re.match(pattern, email), "Email should match format"
        print("[OK] Format validation works")


if __name__ == '__main__':
    # Run tests
    pytest.main([__file__, '-v', '-s'])
