"""
Resilience utilities for external service calls.

Provides:
- Circuit breaker pattern for external dependencies
- Retry with exponential backoff
- Graceful degradation for non-critical failures
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(str, Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject calls
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""

    failure_threshold: int = 5  # Failures before opening
    success_threshold: int = 2  # Successes in half-open before closing
    timeout_seconds: float = 30.0  # Time before trying again (half-open)
    excluded_exceptions: tuple = ()  # Exceptions that don't count as failures


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker monitoring."""

    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: float | None = None
    last_state_change: float = field(default_factory=time.time)
    total_failures: int = 0
    total_successes: int = 0
    total_rejected: int = 0


class CircuitBreaker:
    """
    Circuit breaker implementation for external service calls.

    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Service is failing, requests are rejected immediately
    - HALF_OPEN: Testing if service recovered, limited requests allowed

    Usage:
        breaker = CircuitBreaker("github_oauth")

        @breaker
        def call_github_api():
            ...
    """

    _instances: dict[str, CircuitBreaker] = {}
    _lock = threading.Lock()

    def __init__(self, name: str, config: CircuitBreakerConfig | None = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.stats = CircuitBreakerStats()
        self._lock = threading.Lock()

    @classmethod
    def get(
        cls, name: str, config: CircuitBreakerConfig | None = None
    ) -> CircuitBreaker:
        """Get or create a circuit breaker by name."""
        with cls._lock:
            if name not in cls._instances:
                cls._instances[name] = cls(name, config)
            return cls._instances[name]

    @classmethod
    def get_all_stats(cls) -> dict[str, dict]:
        """Get stats for all circuit breakers."""
        return {
            name: {
                "state": cb.stats.state.value,
                "failure_count": cb.stats.failure_count,
                "success_count": cb.stats.success_count,
                "total_failures": cb.stats.total_failures,
                "total_successes": cb.stats.total_successes,
                "total_rejected": cb.stats.total_rejected,
            }
            for name, cb in cls._instances.items()
        }

    def _should_allow_request(self) -> bool:
        """Check if request should be allowed based on current state."""
        with self._lock:
            if self.stats.state == CircuitState.CLOSED:
                return True

            if self.stats.state == CircuitState.OPEN:
                # Check if timeout has elapsed
                elapsed = time.time() - self.stats.last_state_change
                if elapsed >= self.config.timeout_seconds:
                    # Transition to half-open
                    self.stats.state = CircuitState.HALF_OPEN
                    self.stats.last_state_change = time.time()
                    self.stats.success_count = 0
                    logger.info(
                        f"Circuit breaker '{self.name}' entering half-open state",
                        extra={"circuit": self.name},
                    )
                    return True
                return False

            # HALF_OPEN: allow limited requests
            return True

    def _record_success(self) -> None:
        """Record a successful call."""
        with self._lock:
            self.stats.total_successes += 1

            if self.stats.state == CircuitState.HALF_OPEN:
                self.stats.success_count += 1
                if self.stats.success_count >= self.config.success_threshold:
                    # Transition to closed
                    self.stats.state = CircuitState.CLOSED
                    self.stats.last_state_change = time.time()
                    self.stats.failure_count = 0
                    logger.info(
                        f"Circuit breaker '{self.name}' closed (service recovered)",
                        extra={"circuit": self.name},
                    )

    def _record_failure(self, exception: Exception) -> None:
        """Record a failed call."""
        # Check if exception is excluded
        if isinstance(exception, self.config.excluded_exceptions):
            return

        with self._lock:
            self.stats.failure_count += 1
            self.stats.total_failures += 1
            self.stats.last_failure_time = time.time()

            if self.stats.state == CircuitState.HALF_OPEN:
                # Immediate transition back to open
                self.stats.state = CircuitState.OPEN
                self.stats.last_state_change = time.time()
                logger.warning(
                    f"Circuit breaker '{self.name}' re-opened (failure in half-open)",
                    extra={"circuit": self.name, "exception": str(exception)},
                )
            elif self.stats.state == CircuitState.CLOSED:
                if self.stats.failure_count >= self.config.failure_threshold:
                    # Transition to open
                    self.stats.state = CircuitState.OPEN
                    self.stats.last_state_change = time.time()
                    logger.warning(
                        f"Circuit breaker '{self.name}' opened (failure threshold reached)",
                        extra={
                            "circuit": self.name,
                            "failures": self.stats.failure_count,
                            "exception": str(exception),
                        },
                    )

    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator to wrap a function with circuit breaker."""

        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if not self._should_allow_request():
                self.stats.total_rejected += 1
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.name}' is open",
                    circuit_name=self.name,
                )

            try:
                result = func(*args, **kwargs)
                self._record_success()
                return result
            except Exception as e:
                self._record_failure(e)
                raise

        return wrapper


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open and rejecting requests."""

    def __init__(self, message: str, circuit_name: str):
        super().__init__(message)
        self.circuit_name = circuit_name


# ============================================================================
# Retry with backoff
# ============================================================================


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_attempts: int = 3
    base_delay: float = 1.0  # Initial delay in seconds
    max_delay: float = 30.0  # Maximum delay
    exponential_base: float = 2.0  # Multiplier for exponential backoff
    jitter: bool = True  # Add randomness to delay
    retryable_exceptions: tuple = (Exception,)  # Exceptions to retry on


def retry_with_backoff(
    config: RetryConfig | None = None,
    on_retry: Callable[[int, Exception, float], None] | None = None,
) -> Callable:
    """
    Decorator for retry with exponential backoff.

    Usage:
        @retry_with_backoff(RetryConfig(max_attempts=3))
        def call_external_service():
            ...
    """
    _config = config or RetryConfig()

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            import random

            last_exception: Exception | None = None

            for attempt in range(1, _config.max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except _config.retryable_exceptions as e:
                    last_exception = e

                    if attempt == _config.max_attempts:
                        logger.warning(
                            f"Retry exhausted for {func.__name__} after {attempt} attempts",
                            extra={
                                "function": func.__name__,
                                "attempts": attempt,
                                "exception": str(e),
                            },
                        )
                        raise

                    # Calculate delay with exponential backoff
                    delay = min(
                        _config.base_delay
                        * (_config.exponential_base ** (attempt - 1)),
                        _config.max_delay,
                    )

                    # Add jitter
                    if _config.jitter:
                        delay = delay * (0.5 + random.random())

                    logger.info(
                        f"Retrying {func.__name__} (attempt {attempt}/{_config.max_attempts}) after {delay:.2f}s",
                        extra={
                            "function": func.__name__,
                            "attempt": attempt,
                            "delay": delay,
                            "exception": str(e),
                        },
                    )

                    if on_retry:
                        on_retry(attempt, e, delay)

                    time.sleep(delay)

            # Should not reach here, but just in case
            if last_exception:
                raise last_exception
            raise RuntimeError("Unexpected retry loop exit")

        return wrapper

    return decorator


# ============================================================================
# Combined resilience decorator
# ============================================================================


def resilient(
    circuit_name: str,
    circuit_config: CircuitBreakerConfig | None = None,
    retry_config: RetryConfig | None = None,
) -> Callable:
    """
    Combined decorator for resilient external service calls.

    Applies:
    1. Circuit breaker (fail fast when service is down)
    2. Retry with exponential backoff (handle transient failures)

    Usage:
        @resilient("github_api", retry_config=RetryConfig(max_attempts=2))
        def fetch_github_user(token: str):
            ...
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        # Get or create circuit breaker
        breaker = CircuitBreaker.get(circuit_name, circuit_config)

        # Apply retry first (inner), then circuit breaker (outer)
        if retry_config:
            func = retry_with_backoff(retry_config)(func)

        return breaker(func)

    return decorator


# ============================================================================
# Graceful degradation helpers
# ============================================================================


def with_fallback(
    fallback_value: T | Callable[[], T],
    log_errors: bool = True,
) -> Callable:
    """
    Decorator that returns a fallback value on failure instead of raising.

    Usage:
        @with_fallback(fallback_value={"user": None})
        def get_optional_user_data():
            ...
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_errors:
                    logger.warning(
                        f"Function {func.__name__} failed, returning fallback",
                        extra={
                            "function": func.__name__,
                            "exception_type": type(e).__name__,
                            "exception": str(e),
                        },
                    )

                if callable(fallback_value):
                    return fallback_value()
                return fallback_value

        return wrapper

    return decorator
