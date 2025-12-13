"""
Base Agent Class
Provides common functionality for all agents including A2A communication and HTTP server
"""
import asyncio
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from aiohttp import web
import signal

from a2a_protocol import A2AProtocol, A2AMessage


class BaseAgent(ABC):
    """
    Abstract base class for all agents
    Handles A2A protocol communication and HTTP server setup
    """
    
    def __init__(self, name: str, host: str, port: int):
        self.name = name
        self.host = host
        self.port = port
        self.protocol = A2AProtocol()
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.logger = logging.getLogger(f"{__name__}.{name}")
        
        # Setup routes
        self.app.router.add_post('/message', self.handle_http_message)
        self.app.router.add_get('/health', self.health_check)
        self.app.router.add_get('/status', self.get_status)
        
        # Register handlers
        self._register_handlers()
    
    @abstractmethod
    def _register_handlers(self):
        """Register A2A message handlers - to be implemented by subclasses"""
        pass
    
    @abstractmethod
    async def initialize(self):
        """Initialize agent resources - to be implemented by subclasses"""
        pass
    
    @abstractmethod
    async def cleanup(self):
        """Cleanup agent resources - to be implemented by subclasses"""
        pass
    
    async def handle_http_message(self, request: web.Request) -> web.Response:
        """Handle incoming A2A messages via HTTP"""
        try:
            data = await request.json()
            message = A2AMessage(**data)
            
            self.logger.info(f"Received message: method={message.method}, id={message.id}")
            
            # Process message through A2A protocol
            response_message = await self.protocol.handle_message(message)
            
            if response_message:
                return web.json_response(response_message.to_dict())
            else:
                return web.Response(status=204)  # No content for notifications
                
        except json.JSONDecodeError:
            error_msg = A2AMessage.create_error(None, -32700, "Parse error")
            return web.json_response(error_msg.to_dict(), status=400)
        except Exception as e:
            self.logger.error(f"Error handling message: {str(e)}")
            error_msg = A2AMessage.create_error(None, -32603, f"Internal error: {str(e)}")
            return web.json_response(error_msg.to_dict(), status=500)
    
    async def health_check(self, request: web.Request) -> web.Response:
        """Health check endpoint"""
        return web.json_response({
            'status': 'healthy',
            'agent': self.name,
            'timestamp': asyncio.get_event_loop().time()
        })
    
    async def get_status(self, request: web.Request) -> web.Response:
        """Status endpoint with agent details"""
        status = await self._get_agent_status()
        return web.json_response(status)
    
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
        """Start the agent HTTP server"""
        try:
            # Initialize agent resources
            await self.initialize()
            
            # Start HTTP server
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            self.site = web.TCPSite(self.runner, self.host, self.port)
            await self.site.start()
            
            self.logger.info(f"Agent '{self.name}' started on http://{self.host}:{self.port}")
            
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
            while self.site and not self.site._runner._cleanup_closed:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Received keyboard interrupt")
        finally:
            await self.stop()

