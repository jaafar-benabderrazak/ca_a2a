"""
Utility functions for A2A agents
Implements best practices from A2A protocol and production patterns
"""
import asyncio
import time
import json
import hashlib
from typing import Any, Callable, Dict, Optional, TypeVar
from functools import wraps
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CircuitBreaker:
    """
    Circuit breaker pattern for external service calls
    Prevents cascading failures by failing fast when service is degraded
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type = Exception
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = "closed"  # closed, open, half-open
        
    def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with circuit breaker protection"""
        if self.state == "open":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "half-open"
                logger.info("Circuit breaker transitioning to half-open")
            else:
                raise Exception("Circuit breaker is OPEN - service unavailable")
        
        try:
            result = func(*args, **kwargs)
            if self.state == "half-open":
                self.state = "closed"
                self.failure_count = 0
                logger.info("Circuit breaker closed - service recovered")
            return result
        except self.expected_exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                logger.error(f"Circuit breaker opened after {self.failure_count} failures")
            
            raise


async def retry_with_backoff(
    func: Callable,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    exceptions: tuple = (Exception,)
) -> Any:
    """
    Retry function with exponential backoff
    Based on A2A best practices for resilient agent communication
    """
    last_exception = None
    
    for attempt in range(max_retries + 1):
        try:
            if asyncio.iscoroutinefunction(func):
                return await func()
            else:
                return func()
        except exceptions as e:
            last_exception = e
            
            if attempt == max_retries:
                logger.error(f"All {max_retries} retry attempts failed: {str(e)}")
                raise
            
            # Calculate delay with exponential backoff
            delay = min(base_delay * (exponential_base ** attempt), max_delay)
            
            logger.warning(
                f"Attempt {attempt + 1}/{max_retries + 1} failed: {str(e)}. "
                f"Retrying in {delay:.2f}s..."
            )
            
            await asyncio.sleep(delay)
    
    raise last_exception


def generate_idempotency_key(operation: str, params: Dict[str, Any]) -> str:
    """
    Generate idempotency key for write operations
    Ensures operations can be safely retried without duplicates
    """
    # Sort params for consistent hashing
    sorted_params = json.dumps(params, sort_keys=True)
    content = f"{operation}:{sorted_params}"
    return hashlib.sha256(content.encode()).hexdigest()


def generate_correlation_id() -> str:
    """
    Generate correlation ID for request tracing
    Allows tracking requests across multiple agents
    """
    timestamp = datetime.now().isoformat()
    random_suffix = hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
    return f"{timestamp}-{random_suffix}"


class StructuredLogger:
    """
    Structured logging helper for A2A agents
    Provides consistent log format with context
    """
    
    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.logger = logging.getLogger(f"agent.{agent_name}")
    
    def log_request(
        self,
        method: str,
        params: Dict[str, Any],
        correlation_id: Optional[str] = None
    ):
        """Log incoming request with structured context"""
        self.logger.info(
            "Request received",
            extra={
                "agent": self.agent_name,
                "method": method,
                "correlation_id": correlation_id,
                "params_keys": list(params.keys()) if params else []
            }
        )
    
    def log_response(
        self,
        method: str,
        duration_ms: float,
        success: bool,
        correlation_id: Optional[str] = None
    ):
        """Log response with performance metrics"""
        self.logger.info(
            "Request completed",
            extra={
                "agent": self.agent_name,
                "method": method,
                "duration_ms": duration_ms,
                "success": success,
                "correlation_id": correlation_id
            }
        )
    
    def log_error(
        self,
        method: str,
        error: Exception,
        correlation_id: Optional[str] = None
    ):
        """Log error with context"""
        self.logger.error(
            f"Error in {method}: {str(error)}",
            extra={
                "agent": self.agent_name,
                "method": method,
                "error_type": type(error).__name__,
                "correlation_id": correlation_id
            },
            exc_info=True
        )


def validate_json_schema(data: Dict[str, Any], schema: Dict[str, Any]) -> tuple[bool, Optional[str]]:
    """
    Validate data against JSON Schema
    Returns (is_valid, error_message)
    """
    try:
        from jsonschema import validate, ValidationError
        validate(instance=data, schema=schema)
        return True, None
    except ValidationError as e:
        return False, str(e)
    except ImportError:
        logger.warning("jsonschema not installed, skipping validation")
        return True, None


class PerformanceMonitor:
    """
    Monitor agent performance metrics
    Tracks latency, throughput, and error rates per skill
    """
    
    def __init__(self):
        self.metrics: Dict[str, Dict[str, Any]] = {}
    
    def record_request(self, skill_id: str, duration_ms: float, success: bool):
        """Record request metrics for a skill"""
        if skill_id not in self.metrics:
            self.metrics[skill_id] = {
                "total_requests": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "total_duration_ms": 0,
                "min_duration_ms": float('inf'),
                "max_duration_ms": 0
            }
        
        metrics = self.metrics[skill_id]
        metrics["total_requests"] += 1
        
        if success:
            metrics["successful_requests"] += 1
        else:
            metrics["failed_requests"] += 1
        
        metrics["total_duration_ms"] += duration_ms
        metrics["min_duration_ms"] = min(metrics["min_duration_ms"], duration_ms)
        metrics["max_duration_ms"] = max(metrics["max_duration_ms"], duration_ms)
    
    def get_metrics(self, skill_id: Optional[str] = None) -> Dict[str, Any]:
        """Get metrics for a specific skill or all skills"""
        if skill_id:
            if skill_id not in self.metrics:
                return {}
            
            metrics = self.metrics[skill_id]
            return {
                **metrics,
                "avg_duration_ms": metrics["total_duration_ms"] / metrics["total_requests"] if metrics["total_requests"] > 0 else 0,
                "success_rate": metrics["successful_requests"] / metrics["total_requests"] if metrics["total_requests"] > 0 else 0
            }
        
        return {
            skill_id: self.get_metrics(skill_id)
            for skill_id in self.metrics.keys()
        }


def timeout_decorator(seconds: float):
    """
    Decorator to add timeout to async functions
    Prevents hanging on slow operations
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=seconds)
            except asyncio.TimeoutError:
                logger.error(f"Function {func.__name__} timed out after {seconds}s")
                raise TimeoutError(f"Operation timed out after {seconds}s")
        return wrapper
    return decorator


class IdempotencyStore:
    """
    Simple in-memory idempotency store
    In production, use Redis or DynamoDB
    """
    
    def __init__(self, ttl_seconds: int = 3600):
        self.store: Dict[str, tuple[Any, float]] = {}
        self.ttl_seconds = ttl_seconds
    
    def get(self, key: str) -> Optional[Any]:
        """Get cached result if exists and not expired"""
        if key in self.store:
            result, timestamp = self.store[key]
            if time.time() - timestamp < self.ttl_seconds:
                return result
            else:
                del self.store[key]
        return None
    
    def set(self, key: str, value: Any):
        """Store result with current timestamp"""
        self.store[key] = (value, time.time())
    
    def cleanup_expired(self):
        """Remove expired entries"""
        current_time = time.time()
        expired_keys = [
            key for key, (_, timestamp) in self.store.items()
            if current_time - timestamp >= self.ttl_seconds
        ]
        for key in expired_keys:
            del self.store[key]
