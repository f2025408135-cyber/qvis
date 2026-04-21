import time
from typing import Callable, Any
import structlog
from functools import wraps
import asyncio

logger = structlog.get_logger(__name__)

class CircuitBreaker:
    """
    A robust asynchronous Circuit Breaker pattern to protect external API calls.
    Transitions: CLOSED -> OPEN -> HALF-OPEN -> CLOSED
    """
    def __init__(self, failure_threshold: int = 3, recovery_timeout: int = 30):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "CLOSED"

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "HALF-OPEN"
                logger.info("circuit_breaker_half_open")
            else:
                logger.warning("circuit_breaker_open_rejected_call")
                raise Exception("Circuit Breaker OPEN - Call rejected")

        try:
            result = await func(*args, **kwargs)
            
            if self.state == "HALF-OPEN":
                logger.info("circuit_breaker_closed_recovered")
                self.state = "CLOSED"
                self.failure_count = 0
                
            return result
            
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                if self.state != "OPEN":
                    logger.critical("circuit_breaker_tripped", threshold=self.failure_threshold)
                self.state = "OPEN"
            
            raise e

def circuit_breaker(failure_threshold: int = 3, recovery_timeout: int = 30):
    cb = CircuitBreaker(failure_threshold, recovery_timeout)
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await cb.call(func, *args, **kwargs)
        return wrapper
    return decorator
