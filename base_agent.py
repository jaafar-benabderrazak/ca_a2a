"""
Base Agent Class
Provides common functionality for all agents including A2A communication and HTTP server
Implements A2A best practices: retry logic, circuit breakers, structured logging, tracing
"""
import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from aiohttp import web
import signal

from a2a_protocol import A2AProtocol, A2AMessage
from agent_card import AgentCard, AgentSkill
from utils import (
    StructuredLogger,
    PerformanceMonitor,
    generate_correlation_id,
    validate_json_schema,
    IdempotencyStore
)


class BaseAgent(ABC):
    """
    Abstract base class for all agents
    Handles A2A protocol communication and HTTP server setup
    """
    
    def __init__(self, name: str, host: str, port: int, version: str = "1.0.0", description: str = ""):
        self.name = name
        self.host = host
        self.port = port
        self.version = version
        self.description = description
        self.protocol = A2AProtocol()
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.logger = logging.getLogger(f"{__name__}.{name}")
        
        # A2A best practices: structured logging, monitoring, idempotency
        self.structured_logger = StructuredLogger(name)
        self.performance_monitor = PerformanceMonitor()
        self.idempotency_store = IdempotencyStore()
        
        # Agent card for capability discovery
        self.agent_card: Optional[AgentCard] = None
        
        # Setup routes
        self.app.router.add_post('/message', self.handle_http_message)
        self.app.router.add_get('/health', self.health_check)
        self.app.router.add_get('/status', self.get_status)
        self.app.router.add_get('/card', self.get_agent_card)
        self.app.router.add_get('/skills', self.get_skills)
        
        # Register handlers
        self._register_handlers()
        
        # Initialize agent card with skills
        self._initialize_agent_card()
    
    @abstractmethod
    def _register_handlers(self):
        """Register A2A message handlers - to be implemented by subclasses"""
        pass
    
    @abstractmethod
    def _define_skills(self) -> List[AgentSkill]:
        """Define agent skills - to be implemented by subclasses"""
        pass
    
    def _initialize_agent_card(self):
        """Initialize agent card with skills and metadata"""
        endpoint = f"http://{self.host}:{self.port}"
        
        # Create agent card
        self.agent_card = AgentCard(
            name=self.name,
            version=self.version,
            description=self.description,
            endpoint=endpoint
        )
        
        # Add skills defined by subclass
        skills = self._define_skills()
        for skill in skills:
            self.agent_card.add_skill(skill)
        
        self.logger.info(f"Agent card initialized with {len(skills)} skills")
    
    @abstractmethod
    async def initialize(self):
        """Initialize agent resources - to be implemented by subclasses"""
        pass
    
    @abstractmethod
    async def cleanup(self):
        """Cleanup agent resources - to be implemented by subclasses"""
        pass
    
    async def handle_http_message(self, request: web.Request) -> web.Response:
        """
        Handle incoming A2A messages via HTTP
        Implements: correlation IDs, structured logging, performance monitoring, validation
        """
        start_time = time.time()
        correlation_id = request.headers.get('X-Correlation-ID', generate_correlation_id())
        
        try:
            data = await request.json()
            message = A2AMessage(**data)
            
            # Structured logging with correlation ID
            self.structured_logger.log_request(
                method=message.method,
                params=message.params,
                correlation_id=correlation_id
            )
            
            # Validate input against skill schema if defined
            if message.method and message.params:
                skill = self.agent_card.get_skill(message.method) if self.agent_card else None
                if skill and skill.input_schema:
                    is_valid, error_msg = validate_json_schema(message.params, skill.input_schema)
                    if not is_valid:
                        self.logger.warning(f"Input validation failed for {message.method}: {error_msg}")
                        error_response = A2AMessage.create_error(
                            message.id, -32602, f"Invalid params: {error_msg}"
                        )
                        return web.json_response(error_response.to_dict(), status=400)
            
            # Process message through A2A protocol
            response_message = await self.protocol.handle_message(message)
            
            # Record performance metrics
            duration_ms = (time.time() - start_time) * 1000
            self.performance_monitor.record_request(
                message.method or "unknown",
                duration_ms,
                success=True
            )
            
            self.structured_logger.log_response(
                method=message.method,
                duration_ms=duration_ms,
                success=True,
                correlation_id=correlation_id
            )
            
            if response_message:
                response_dict = response_message.to_dict()
                response_dict.setdefault('_meta', {})['correlation_id'] = correlation_id
                return web.json_response(response_dict)
            else:
                return web.Response(status=204)  # No content for notifications
                
        except json.JSONDecodeError as e:
            error_msg = A2AMessage.create_error(None, -32700, "Parse error")
            return web.json_response(error_msg.to_dict(), status=400)
        except Exception as e:
            # Record failure metrics
            duration_ms = (time.time() - start_time) * 1000
            method = data.get('method', 'unknown') if 'data' in locals() else 'unknown'
            self.performance_monitor.record_request(method, duration_ms, success=False)
            
            self.structured_logger.log_error(method, e, correlation_id)
            
            error_msg = A2AMessage.create_error(None, -32603, f"Internal error: {str(e)}")
            return web.json_response(error_msg.to_dict(), status=500)
    
    async def health_check(self, request: web.Request) -> web.Response:
        """
        Enhanced health check endpoint
        Checks agent health AND dependency health
        """
        health_status = {
            'status': 'healthy',
            'agent': self.name,
            'version': self.version,
            'timestamp': asyncio.get_event_loop().time(),
            'uptime_seconds': time.time() - getattr(self, '_start_time', time.time())
        }
        
        # Check dependencies (implemented by subclasses)
        try:
            dependency_health = await self._check_dependencies()
            health_status['dependencies'] = dependency_health
            
            # If any dependency is unhealthy, mark agent as degraded
            if any(not dep.get('healthy', True) for dep in dependency_health.values()):
                health_status['status'] = 'degraded'
        except Exception as e:
            health_status['status'] = 'unhealthy'
            health_status['error'] = str(e)
        
        status_code = 200 if health_status['status'] == 'healthy' else 503
        return web.json_response(health_status, status=status_code)
    
    async def _check_dependencies(self) -> Dict[str, Dict[str, Any]]:
        """
        Check health of dependencies (S3, PostgreSQL, etc.)
        Override in subclasses to implement specific checks
        """
        return {}
    
    async def get_status(self, request: web.Request) -> web.Response:
        """
        Enhanced status endpoint with performance metrics
        """
        status = await self._get_agent_status()
        
        # Add performance metrics
        status['performance'] = {
            'metrics_by_skill': self.performance_monitor.get_metrics(),
            'total_requests': sum(
                m.get('total_requests', 0)
                for m in self.performance_monitor.metrics.values()
            )
        }
        
        return web.json_response(status)
    
    async def get_agent_card(self, request: web.Request) -> web.Response:
        """Return complete agent card with capabilities"""
        if not self.agent_card:
            return web.json_response(
                {"error": "Agent card not initialized"},
                status=500
            )
        
        return web.json_response(self.agent_card.to_dict())
    
    async def get_skills(self, request: web.Request) -> web.Response:
        """Return list of agent skills"""
        if not self.agent_card:
            return web.json_response(
                {"error": "Agent card not initialized"},
                status=500
            )
        
        return web.json_response({
            "agent": self.name,
            "version": self.version,
            "skills": [skill.to_dict() for skill in self.agent_card.skills],
            "total_skills": len(self.agent_card.skills)
        })
    
    async def _get_agent_status(self) -> Dict[str, Any]:
        """Get agent-specific status - can be overridden by subclasses"""
        return {
            'agent': self.name,
            'host': self.host,
            'port': self.port,
            'status': 'running'
        }
    
    async def send_message_to_agent(self, agent_url: str, message: A2AMessage) -> Optional[Any]:
        """Send A2A message to another agent"""
        import aiohttp
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{agent_url}/message",
                    json=message.to_dict(),
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 204:
                        return None
                    
                    response_data = await response.json()
                    response_message = A2AMessage(**response_data)
                    
                    if response_message.error:
                        raise Exception(f"Agent error: {response_message.error}")
                    
                    return response_message.result
                    
        except Exception as e:
            self.logger.error(f"Error sending message to {agent_url}: {str(e)}")
            raise
    
    async def start(self):
        """Start the agent HTTP server with initialization tracking"""
        try:
            # Record start time for uptime tracking
            self._start_time = time.time()
            
            # Initialize agent resources
            await self.initialize()
            
            # Start HTTP server
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            self.site = web.TCPSite(self.runner, self.host, self.port)
            await self.site.start()
            
            self.logger.info(
                f"Agent '{self.name}' v{self.version} started on http://{self.host}:{self.port}"
            )
            self.logger.info(f"Skills available: {len(self.agent_card.skills) if self.agent_card else 0}")
            
        except Exception as e:
            self.logger.error(f"Failed to start agent: {str(e)}")
            raise
    
    async def stop(self):
        """Stop the agent HTTP server"""
        try:
            # Cleanup agent resources
            await self.cleanup()
            
            # Stop HTTP server
            if self.site:
                await self.site.stop()
            if self.runner:
                await self.runner.cleanup()
            
            self.logger.info(f"Agent '{self.name}' stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping agent: {str(e)}")
            raise
    
    async def run(self):
        """Run the agent until interrupted"""
        await self.start()
        
        # Setup signal handlers for graceful shutdown
        loop = asyncio.get_event_loop()
        
        def signal_handler():
            self.logger.info("Received shutdown signal")
            asyncio.create_task(self.stop())
        
        # Register signal handlers
        try:
            loop.add_signal_handler(signal.SIGTERM, signal_handler)
            loop.add_signal_handler(signal.SIGINT, signal_handler)
        except NotImplementedError:
            # Signal handlers not supported on Windows
            self.logger.warning("Signal handlers not supported on this platform")
        
        try:
            # Keep running until stopped
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Received keyboard interrupt")
        finally:
            await self.stop()

