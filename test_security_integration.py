"""
Integration Tests for Enhanced Security with Real Agents
Tests the complete security implementation with actual agent instances
"""
import pytest
import asyncio
import aiohttp
import json
from aiohttp import web
from dataclasses import dataclass

from base_agent import BaseAgent
from agent_card import AgentSkill
from a2a_protocol import A2AMessage
from security import SecurityManager


class SecureTestAgent(BaseAgent):
    """Test agent for integration testing"""
    
    def _register_handlers(self):
        """Register test handlers"""
        self.protocol.register_handler("echo", self.handle_echo)
        self.protocol.register_handler("add", self.handle_add)
        self.protocol.register_handler("error_test", self.handle_error)
    
    def _define_skills(self):
        """Define test skills"""
        return [
            AgentSkill(
                skill_id="echo",
                name="Echo",
                description="Echo back the input",
                method="echo",
                input_schema={"type": "object", "properties": {"message": {"type": "string"}}}
            ),
            AgentSkill(
                skill_id="add",
                name="Add Numbers",
                description="Add two numbers",
                method="add",
                input_schema={
                    "type": "object",
                    "properties": {
                        "a": {"type": "number"},
                        "b": {"type": "number"}
                    },
                    "required": ["a", "b"]
                }
            ),
            AgentSkill(
                skill_id="error_test",
                name="Error Test",
                description="Test error handling",
                method="error_test"
            )
        ]
    
    async def handle_echo(self, params):
        """Echo handler"""
        return {"message": params.get("message", "")}
    
    async def handle_add(self, params):
        """Add handler"""
        return {"result": params.get("a", 0) + params.get("b", 0)}
    
    async def handle_error(self, params):
        """Error handler for testing"""
        raise ValueError("Test error")
    
    async def initialize(self):
        """Initialize"""
        pass
    
    async def cleanup(self):
        """Cleanup"""
        pass


class TestEnhancedSecurityIntegration:
    """Integration tests for enhanced security with real agents"""
    
    @pytest.mark.asyncio
    async def test_agent_with_message_integrity(self):
        """Test agent with message integrity enabled"""
        # Create agent with message integrity
        agent = SecureTestAgent(
            name="test-agent",
            host="127.0.0.1",
            port=9001,
            enable_auth=True,
            enable_enhanced_security=True,
            enable_message_integrity=True
        )
        
        # Register API key
        agent.security_manager.register_api_key(
            "test-key-123",
            "test-client",
            ["*"]
        )
        
        # Start agent
        runner = web.AppRunner(agent.app)
        await runner.setup()
        site = web.TCPSite(runner, agent.host, agent.port)
        await site.start()
        
        try:
            # Create message
            message = {
                "jsonrpc": "2.0",
                "id": "test-1",
                "method": "echo",
                "params": {"message": "Hello"}
            }
            
            # Sign message
            integrity_headers = agent.enhanced_security.sign_outgoing_message(message)
            
            # Make request
            headers = {
                'X-API-Key': 'test-key-123',
                'Content-Type': 'application/json',
                **integrity_headers
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://{agent.host}:{agent.port}/message",
                    json=message,
                    headers=headers
                ) as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data['result']['message'] == "Hello"
        
        finally:
            await runner.cleanup()
    
    @pytest.mark.asyncio
    async def test_agent_rejects_tampered_message(self):
        """Test agent rejects tampered messages"""
        agent = SecureTestAgent(
            name="test-agent-2",
            host="127.0.0.1",
            port=9002,
            enable_auth=True,
            enable_enhanced_security=True,
            enable_message_integrity=True
        )
        
        agent.security_manager.register_api_key("test-key", "test-client", ["*"])
        
        runner = web.AppRunner(agent.app)
        await runner.setup()
        site = web.TCPSite(runner, agent.host, agent.port)
        await site.start()
        
        try:
            message = {
                "jsonrpc": "2.0",
                "id": "test-2",
                "method": "add",
                "params": {"a": 10, "b": 20}
            }
            
            # Sign original message
            integrity_headers = agent.enhanced_security.sign_outgoing_message(message)
            
            # Tamper with message
            message["params"]["a"] = 100  # Change value
            
            headers = {
                'X-API-Key': 'test-key',
                'Content-Type': 'application/json',
                **integrity_headers
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://{agent.host}:{agent.port}/message",
                    json=message,
                    headers=headers
                ) as resp:
                    # Should reject tampered message
                    assert resp.status == 403
                    data = await resp.json()
                    assert 'violations' in data['error']['data']
        
        finally:
            await runner.cleanup()
    
    @pytest.mark.asyncio
    async def test_agent_with_zero_trust(self):
        """Test agent with zero-trust enforcement"""
        agent = SecureTestAgent(
            name="test-agent-3",
            host="127.0.0.1",
            port=9003,
            enable_auth=True,
            enable_enhanced_security=True,
            enable_zero_trust=True
        )
        
        agent.security_manager.register_api_key(
            "limited-key",
            "limited-client",
            ["echo"]  # Only echo permission
        )
        
        runner = web.AppRunner(agent.app)
        await runner.setup()
        site = web.TCPSite(runner, agent.host, agent.port)
        await site.start()
        
        try:
            # Test allowed method
            message1 = {
                "jsonrpc": "2.0",
                "id": "test-3a",
                "method": "echo",
                "params": {"message": "test"}
            }
            
            headers = {
                'X-API-Key': 'limited-key',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                # Should succeed
                async with session.post(
                    f"http://{agent.host}:{agent.port}/message",
                    json=message1,
                    headers=headers
                ) as resp:
                    assert resp.status == 200
                
                # Test denied method
                message2 = {
                    "jsonrpc": "2.0",
                    "id": "test-3b",
                    "method": "add",  # Not in permissions
                    "params": {"a": 1, "b": 2}
                }
                
                async with session.post(
                    f"http://{agent.host}:{agent.port}/message",
                    json=message2,
                    headers=headers
                ) as resp:
                    # Should deny
                    assert resp.status == 403
        
        finally:
            await runner.cleanup()
    
    @pytest.mark.asyncio
    async def test_agent_with_anomaly_detection(self):
        """Test agent with anomaly detection"""
        agent = SecureTestAgent(
            name="test-agent-4",
            host="127.0.0.1",
            port=9004,
            enable_auth=True,
            enable_enhanced_security=True,
            enable_anomaly_detection=True
        )
        
        agent.security_manager.register_api_key("test-key", "test-client", ["*"])
        
        runner = web.AppRunner(agent.app)
        await runner.setup()
        site = web.TCPSite(runner, agent.host, agent.port)
        await site.start()
        
        try:
            headers = {
                'X-API-Key': 'test-key',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                # Make several successful requests
                for i in range(5):
                    message = {
                        "jsonrpc": "2.0",
                        "id": f"test-4-{i}",
                        "method": "echo",
                        "params": {"message": f"test {i}"}
                    }
                    
                    async with session.post(
                        f"http://{agent.host}:{agent.port}/message",
                        json=message,
                        headers=headers
                    ) as resp:
                        assert resp.status == 200
                
                # Make several failed requests
                for i in range(10):
                    message = {
                        "jsonrpc": "2.0",
                        "id": f"test-4-error-{i}",
                        "method": "error_test",
                        "params": {}
                    }
                    
                    async with session.post(
                        f"http://{agent.host}:{agent.port}/message",
                        json=message,
                        headers=headers
                    ) as resp:
                        assert resp.status == 500  # Internal error
                
                # Check for anomalies
                anomalies = agent.enhanced_security.check_for_anomalies("test-client")
                
                # Should detect high error rate
                assert len(anomalies) > 0
                error_anomalies = [a for a in anomalies if a['type'] == 'high_error_rate']
                assert len(error_anomalies) > 0
        
        finally:
            await runner.cleanup()
    
    @pytest.mark.asyncio
    async def test_agent_without_enhanced_security(self):
        """Test agent still works without enhanced security"""
        agent = SecureTestAgent(
            name="test-agent-5",
            host="127.0.0.1",
            port=9005,
            enable_auth=True,
            enable_enhanced_security=False  # Disabled
        )
        
        agent.security_manager.register_api_key("test-key", "test-client", ["*"])
        
        runner = web.AppRunner(agent.app)
        await runner.setup()
        site = web.TCPSite(runner, agent.host, agent.port)
        await site.start()
        
        try:
            message = {
                "jsonrpc": "2.0",
                "id": "test-5",
                "method": "add",
                "params": {"a": 5, "b": 10}
            }
            
            headers = {
                'X-API-Key': 'test-key',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://{agent.host}:{agent.port}/message",
                    json=message,
                    headers=headers
                ) as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data['result']['result'] == 15
        
        finally:
            await runner.cleanup()
    
    @pytest.mark.asyncio
    async def test_rate_limiting_with_enhanced_security(self):
        """Test rate limiting works with enhanced security"""
        agent = SecureTestAgent(
            name="test-agent-6",
            host="127.0.0.1",
            port=9006,
            enable_auth=True,
            enable_rate_limiting=True,
            enable_enhanced_security=True,
            enable_zero_trust=True
        )
        
        agent.security_manager.register_api_key("test-key", "test-client", ["*"])
        
        # Set very low rate limit for testing
        agent.security_manager.rate_limiter.rpm_limit = 3
        
        runner = web.AppRunner(agent.app)
        await runner.setup()
        site = web.TCPSite(runner, agent.host, agent.port)
        await site.start()
        
        try:
            headers = {
                'X-API-Key': 'test-key',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                # Make requests up to limit
                for i in range(3):
                    message = {
                        "jsonrpc": "2.0",
                        "id": f"test-6-{i}",
                        "method": "echo",
                        "params": {"message": "test"}
                    }
                    
                    async with session.post(
                        f"http://{agent.host}:{agent.port}/message",
                        json=message,
                        headers=headers
                    ) as resp:
                        assert resp.status == 200
                
                # Next request should be rate limited
                message = {
                    "jsonrpc": "2.0",
                    "id": "test-6-limit",
                    "method": "echo",
                    "params": {"message": "test"}
                }
                
                async with session.post(
                    f"http://{agent.host}:{agent.port}/message",
                    json=message,
                    headers=headers
                ) as resp:
                    assert resp.status == 403  # Denied by zero-trust
                    data = await resp.json()
                    assert 'violations' in data['error']['data']
        
        finally:
            await runner.cleanup()


class TestMultiAgentSecureCommunication:
    """Test secure communication between multiple agents"""
    
    @pytest.mark.asyncio
    async def test_agent_to_agent_with_integrity(self):
        """Test agent-to-agent communication with message integrity"""
        # Create two agents
        agent1 = SecureTestAgent(
            name="agent-1",
            host="127.0.0.1",
            port=9101,
            enable_auth=True,
            enable_enhanced_security=True,
            enable_message_integrity=True
        )
        
        agent2 = SecureTestAgent(
            name="agent-2",
            host="127.0.0.1",
            port=9102,
            enable_auth=True,
            enable_enhanced_security=True,
            enable_message_integrity=True
        )
        
        # Register API keys
        agent1.security_manager.register_api_key("agent1-key", "agent-1", ["*"])
        agent2.security_manager.register_api_key("agent2-key", "agent-2", ["*"])
        
        # Start both agents
        runner1 = web.AppRunner(agent1.app)
        await runner1.setup()
        site1 = web.TCPSite(runner1, agent1.host, agent1.port)
        await site1.start()
        
        runner2 = web.AppRunner(agent2.app)
        await runner2.setup()
        site2 = web.TCPSite(runner2, agent2.host, agent2.port)
        await site2.start()
        
        try:
            # Agent 1 sends message to Agent 2
            message = {
                "jsonrpc": "2.0",
                "id": "a2a-1",
                "method": "add",
                "params": {"a": 100, "b": 200}
            }
            
            # Sign message
            integrity_headers = agent1.enhanced_security.sign_outgoing_message(message)
            
            headers = {
                'X-API-Key': 'agent2-key',
                'Content-Type': 'application/json',
                **integrity_headers
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://{agent2.host}:{agent2.port}/message",
                    json=message,
                    headers=headers
                ) as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data['result']['result'] == 300
                    
                    # Response should also be signed
                    assert '_meta' in data
                    assert 'X-Message-HMAC' in data['_meta']
        
        finally:
            await runner1.cleanup()
            await runner2.cleanup()


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])

