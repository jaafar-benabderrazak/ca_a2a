"""
Base Agent Class
Provides common functionality for all agents including A2A communication and HTTP server
Implements A2A best practices: retry logic, circuit breakers, structured logging, tracing
Security: JWT/API key authentication, rate limiting, audit logging
"""
import asyncio
import json
import logging
import os
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
from security import SecurityManager, AuthContext

# Import enhanced security (optional)
try:
    from a2a_security_enhanced import EnhancedSecurityManager
    ENHANCED_SECURITY_AVAILABLE = True
except ImportError:
    ENHANCED_SECURITY_AVAILABLE = False
    EnhancedSecurityManager = None


class BaseAgent(ABC):
    """
    Abstract base class for all agents
    Handles A2A protocol communication and HTTP server setup
    Includes security: authentication, authorization, rate limiting
    """
    
    def __init__(
        self, 
        name: str, 
        host: str, 
        port: int, 
        version: str = "1.0.0", 
        description: str = "",
        enable_auth: bool = True,
        enable_rate_limiting: bool = True,
        enable_enhanced_security: bool = False,
        enable_message_integrity: bool = False,
        enable_zero_trust: bool = False,
        enable_anomaly_detection: bool = False
    ):
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
        
        # Security manager
        self.enable_auth = enable_auth
        self.security_manager: Optional[SecurityManager] = None
        self.enhanced_security = None
        
        if enable_auth or enable_rate_limiting:
            self.security_manager = SecurityManager(
                enable_jwt=enable_auth,
                enable_api_keys=enable_auth,
                enable_rate_limiting=enable_rate_limiting,
                enable_signatures=False  # Can be enabled later
            )
            self.logger.info(f"Security enabled: auth={enable_auth}, rate_limiting={enable_rate_limiting}")
        
        # Enhanced security (optional)
        if enable_enhanced_security and ENHANCED_SECURITY_AVAILABLE and self.security_manager:
            self.enhanced_security = EnhancedSecurityManager(
                base_security=self.security_manager,
                enable_tls=False,  # TLS handled at server level
                enable_message_integrity=enable_message_integrity,
                enable_zero_trust=enable_zero_trust,
                enable_anomaly_detection=enable_anomaly_detection
            )
            self.logger.info(
                f"Enhanced security enabled: integrity={enable_message_integrity}, "
                f"zero_trust={enable_zero_trust}, anomaly={enable_anomaly_detection}"
            )
        
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
        Implements: authentication, authorization, correlation IDs, structured logging, 
                   performance monitoring, rate limiting, validation
        """
        start_time = time.time()
        correlation_id = request.headers.get('X-Correlation-ID', generate_correlation_id())
        auth_context: Optional[AuthContext] = None
        
        try:
            # Parse message first (needed for enhanced security)
            data = await request.json()
            message_dict = data if isinstance(data, dict) else {}
            
            # Enhanced security verification (if enabled)
            if self.enhanced_security:
                allowed, auth_context, violations = await self.enhanced_security.verify_secure_request(
                    headers=dict(request.headers),
                    message=message_dict,
                    source_ip=request.remote
                )
                
                if not allowed:
                    self.logger.warning(f"Enhanced security violation: {violations}")
                    error_msg = A2AMessage.create_error(
                        message_dict.get('id'),
                        -32000,
                        "Security verification failed",
                        data={'violations': violations}
                    )
                    return web.json_response(error_msg.to_dict(), status=403)
                
                self.logger.debug(f"Enhanced security passed: {auth_context.agent_id if auth_context else 'unknown'}")
            
            # Standard security checks (if no enhanced security)
            elif self.security_manager and self.enable_auth:
                # Step 1: Authenticate request
                success, auth_context, error = await self.security_manager.authenticate_request(
                    dict(request.headers),
                    source_ip=request.remote
                )
                
                if not success:
                    self.logger.warning(f"Authentication failed: {error}")
                    error_msg = A2AMessage.create_error(None, -32001, f"Authentication failed: {error}")
                    return web.json_response(error_msg.to_dict(), status=401)
                
                self.logger.debug(f"Authenticated: {auth_context.agent_id}")
                
                # Step 2: Check rate limits
                if auth_context:
                    allowed, error = self.security_manager.check_rate_limit(auth_context.agent_id)
                    
                    if not allowed:
                        self.logger.warning(f"Rate limit exceeded for {auth_context.agent_id}: {error}")
                        error_msg = A2AMessage.create_error(None, -32002, f"Rate limit exceeded: {error}")
                        return web.json_response(error_msg.to_dict(), status=429)
            
            # Parse message
            message = A2AMessage(**message_dict)
            
            # Step 3: Check authorization (permission for specific method)
            if self.security_manager and auth_context and message.method:
                if not self.security_manager.check_permission(auth_context, message.method):
                    self.logger.warning(
                        f"Authorization failed: {auth_context.agent_id} attempted {message.method}"
                    )
                    error_msg = A2AMessage.create_error(
                        message.id, 
                        -32003, 
                        f"Permission denied for method: {message.method}"
                    )
                    return web.json_response(error_msg.to_dict(), status=403)
            
            # Structured logging with correlation ID
            self.structured_logger.log_request(
                method=message.method,
                params=message.params,
                correlation_id=correlation_id
            )
            
            # Step 5: Validate input against skill schema if defined
            # Validate input using Pydantic (preferred) or JSON Schema (fallback)
            if message.method and self.agent_card:
                skill = self.agent_card.get_skill(message.method) if self.agent_card else None
                if skill and message.params:
                    # Try Pydantic validation first (better error messages)
                    is_valid, error_msg, validated_data = skill.validate_request(message.params)
                    if not is_valid:
                        self.logger.warning(f"Input validation failed for {message.method}: {error_msg}")
                        error_response = A2AMessage.create_error(
                            message.id, -32602, f"Invalid params: {error_msg}"
                        )
                        return web.json_response(error_response.to_dict(), status=400)
                    
                    # Replace params with validated data (Pydantic models or validated dict)
                    if validated_data is not None:
                        # If it's a Pydantic model, convert to dict
                        try:
                            from pydantic import BaseModel
                            if isinstance(validated_data, BaseModel):
                                message.params = validated_data.model_dump()
                        except ImportError:
                            pass
            
            # Process message through A2A protocol
            response_message = await self.protocol.handle_message(message)
            
            # Record performance metrics
            duration_ms = (time.time() - start_time) * 1000
            success = (response_message is None or response_message.error is None)
            
            self.performance_monitor.record_request(
                message.method or "unknown",
                duration_ms,
                success=success
            )
            
            # Record for anomaly detection (if enabled)
            if self.enhanced_security and auth_context:
                self.enhanced_security.record_request_for_anomaly_detection(
                    agent_id=auth_context.agent_id,
                    method=message.method or "unknown",
                    success=success,
                    response_time=duration_ms / 1000  # Convert to seconds
                )
                
                # Check for anomalies
                anomalies = self.enhanced_security.check_for_anomalies(auth_context.agent_id)
                if anomalies:
                    self.logger.warning(
                        f"Anomalies detected for {auth_context.agent_id}: {anomalies}"
                    )
            
            self.structured_logger.log_response(
                method=message.method,
                duration_ms=duration_ms,
                success=success,
                correlation_id=correlation_id
            )
            
            if response_message:
                response_dict = response_message.to_dict()
                response_dict.setdefault('_meta', {})['correlation_id'] = correlation_id
                
                # Sign outgoing message (if enhanced security enabled)
                if self.enhanced_security:
                    integrity_headers = self.enhanced_security.sign_outgoing_message(response_dict)
                    # Add integrity headers to response metadata
                    response_dict['_meta'].update(integrity_headers)
                
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
        """
        Send A2A message to another agent with authentication
        Automatically includes JWT token or API key from environment
        """
        import aiohttp
        
        try:
            # Prepare headers with authentication
            headers = {
                'Content-Type': 'application/json',
                'X-Correlation-ID': generate_correlation_id()
            }
            
            # Add authentication credentials
            # Priority: JWT token > API key
            jwt_token = os.getenv('AGENT_JWT_TOKEN')
            api_key = os.getenv('AGENT_API_KEY')
            
            if jwt_token:
                headers['Authorization'] = f'Bearer {jwt_token}'
                self.logger.debug("Using JWT authentication for inter-agent call")
            elif api_key:
                headers['X-API-Key'] = api_key
                self.logger.debug("Using API key authentication for inter-agent call")
            elif self.enable_auth:
                self.logger.warning(
                    "Authentication enabled but no credentials found. "
                    "Set AGENT_JWT_TOKEN or AGENT_API_KEY environment variable."
                )
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{agent_url}/message",
                    json=message.to_dict(),
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 401:
                        raise Exception("Authentication failed when calling agent")
                    elif response.status == 403:
                        raise Exception("Permission denied when calling agent")
                    elif response.status == 429:
                        raise Exception("Rate limit exceeded when calling agent")
                    elif response.status == 204:
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

