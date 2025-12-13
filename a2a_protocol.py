"""
A2A Protocol Implementation (JSON-RPC 2.0)
Handles inter-agent communication with asynchronous message passing
"""
import json
import uuid
import asyncio
from typing import Any, Dict, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class MessageType(Enum):
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"


@dataclass
class A2AMessage:
    """JSON-RPC 2.0 compliant message structure"""
    jsonrpc: str = "2.0"
    id: Optional[str] = None
    method: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary, removing None values"""
        data = asdict(self)
        return {k: v for k, v in data.items() if v is not None}

    def to_json(self) -> str:
        """Convert message to JSON string"""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> 'A2AMessage':
        """Create message from JSON string"""
        data = json.loads(json_str)
        return cls(**data)

    @classmethod
    def create_request(cls, method: str, params: Dict[str, Any] = None) -> 'A2AMessage':
        """Create a new request message"""
        return cls(
            id=str(uuid.uuid4()),
            method=method,
            params=params or {}
        )

    @classmethod
    def create_response(cls, request_id: str, result: Any) -> 'A2AMessage':
        """Create a response message"""
        return cls(
            id=request_id,
            result=result
        )

    @classmethod
    def create_error(cls, request_id: str, code: int, message: str, data: Any = None) -> 'A2AMessage':
        """Create an error message"""
        error = {
            "code": code,
            "message": message
        }
        if data:
            error["data"] = data
        return cls(
            id=request_id,
            error=error
        )

    @classmethod
    def create_notification(cls, method: str, params: Dict[str, Any] = None) -> 'A2AMessage':
        """Create a notification message (no response expected)"""
        return cls(
            method=method,
            params=params or {}
        )


class A2AProtocol:
    """
    A2A Protocol handler for asynchronous agent communication
    Implements JSON-RPC 2.0 specification
    """

    def __init__(self):
        self.handlers: Dict[str, Callable] = {}
        self.pending_requests: Dict[str, asyncio.Future] = {}
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def register_handler(self, method: str, handler: Callable):
        """Register a handler for a specific method"""
        self.handlers[method] = handler
        self.logger.info(f"Registered handler for method: {method}")

    async def handle_message(self, message: A2AMessage) -> Optional[A2AMessage]:
        """
        Handle incoming message and return response if needed
        """
        try:
            # Handle response to our request
            if message.result is not None or message.error is not None:
                if message.id in self.pending_requests:
                    future = self.pending_requests.pop(message.id)
                    if message.error:
                        future.set_exception(Exception(json.dumps(message.error)))
                    else:
                        future.set_result(message.result)
                return None

            # Handle incoming request
            if message.method:
                if message.method not in self.handlers:
                    if message.id:
                        return A2AMessage.create_error(
                            message.id,
                            -32601,
                            f"Method not found: {message.method}"
                        )
                    return None

                handler = self.handlers[message.method]
                
                # Execute handler
                try:
                    result = await handler(message.params or {})
                    
                    # Only send response if message has an ID (not a notification)
                    if message.id:
                        return A2AMessage.create_response(message.id, result)
                    return None
                    
                except Exception as e:
                    self.logger.error(f"Error executing handler for {message.method}: {str(e)}")
                    if message.id:
                        return A2AMessage.create_error(
                            message.id,
                            -32603,
                            f"Internal error: {str(e)}"
                        )
                    return None

        except Exception as e:
            self.logger.error(f"Error handling message: {str(e)}")
            if message.id:
                return A2AMessage.create_error(
                    message.id,
                    -32603,
                    f"Internal error: {str(e)}"
                )
        return None

    async def send_request(self, method: str, params: Dict[str, Any] = None, 
                          timeout: float = 30.0) -> Any:
        """
        Send a request and wait for response
        """
        message = A2AMessage.create_request(method, params)
        future = asyncio.Future()
        self.pending_requests[message.id] = future

        # The actual sending will be done by the transport layer
        # This method prepares the request and waits for the response
        
        try:
            result = await asyncio.wait_for(future, timeout=timeout)
            return result
        except asyncio.TimeoutError:
            self.pending_requests.pop(message.id, None)
            raise TimeoutError(f"Request {message.id} timed out after {timeout}s")

    def send_notification(self, method: str, params: Dict[str, Any] = None) -> A2AMessage:
        """
        Send a notification (no response expected)
        """
        return A2AMessage.create_notification(method, params)


class ErrorCodes:
    """Standard JSON-RPC 2.0 error codes"""
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    
    # Custom error codes
    EXTRACTION_ERROR = -32001
    VALIDATION_ERROR = -32002
    PERSISTENCE_ERROR = -32003
    S3_ERROR = -32004
    DATABASE_ERROR = -32005

