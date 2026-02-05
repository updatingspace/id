"""Tests for resilience module (circuit breaker, retry)."""
import pytest
import time
from unittest.mock import Mock, patch
from core.resilience import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    retry_with_backoff,
    resilient,
)


class TestCircuitBreaker:
    """Tests for CircuitBreaker class."""

    def test_initial_state_closed(self):
        """Circuit breaker starts in CLOSED state."""
        cb = CircuitBreaker(name="test", failure_threshold=3)
        assert cb.state == CircuitState.CLOSED

    def test_transitions_to_open_after_failures(self):
        """Opens after failure threshold reached."""
        cb = CircuitBreaker(name="test", failure_threshold=2)

        # Record failures
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_open_circuit_raises_error(self):
        """Open circuit raises CircuitBreakerOpenError."""
        cb = CircuitBreaker(
            name="test", failure_threshold=1, recovery_timeout=60
        )
        cb.record_failure()

        with pytest.raises(CircuitBreakerOpenError):
            with cb:
                pass

    def test_success_resets_failure_count(self):
        """Success resets the failure counter."""
        cb = CircuitBreaker(name="test", failure_threshold=3)

        cb.record_failure()
        cb.record_failure()
        assert cb._failure_count == 2

        cb.record_success()
        assert cb._failure_count == 0

    def test_half_open_transitions_to_closed(self):
        """Successful call in HALF_OPEN transitions to CLOSED."""
        cb = CircuitBreaker(
            name="test",
            failure_threshold=1,
            recovery_timeout=0.01,  # Very short timeout
        )
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Wait for recovery timeout
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN

        # Successful call
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_transitions_to_open(self):
        """Failed call in HALF_OPEN transitions back to OPEN."""
        cb = CircuitBreaker(
            name="test",
            failure_threshold=1,
            recovery_timeout=0.01,
        )
        cb.record_failure()
        time.sleep(0.02)  # Wait for half-open

        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_context_manager_success(self):
        """Context manager records success on normal exit."""
        cb = CircuitBreaker(name="test", failure_threshold=3)
        cb._failure_count = 2

        with cb:
            pass  # Successful execution

        assert cb._failure_count == 0

    def test_context_manager_failure(self):
        """Context manager records failure on exception."""
        cb = CircuitBreaker(name="test", failure_threshold=3)

        with pytest.raises(ValueError):
            with cb:
                raise ValueError("Test error")

        assert cb._failure_count == 1


class TestRetryWithBackoff:
    """Tests for retry_with_backoff decorator."""

    def test_succeeds_without_retry(self):
        """Successful call doesn't trigger retry."""
        call_count = 0

        @retry_with_backoff(max_retries=3, base_delay=0.01)
        def success_func():
            nonlocal call_count
            call_count += 1
            return "success"

        result = success_func()

        assert result == "success"
        assert call_count == 1

    def test_retries_on_failure(self):
        """Retries specified number of times on failure."""
        call_count = 0

        @retry_with_backoff(
            max_retries=3, base_delay=0.01, exceptions=(ValueError,)
        )
        def failing_func():
            nonlocal call_count
            call_count += 1
            raise ValueError("Always fails")

        with pytest.raises(ValueError):
            failing_func()

        assert call_count == 4  # Initial + 3 retries

    def test_succeeds_after_retry(self):
        """Eventually succeeds after retries."""
        call_count = 0

        @retry_with_backoff(max_retries=3, base_delay=0.01)
        def eventual_success():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RuntimeError("Transient error")
            return "success"

        result = eventual_success()

        assert result == "success"
        assert call_count == 3


class TestResilientDecorator:
    """Tests for combined resilient decorator."""

    def test_combines_retry_and_circuit_breaker(self):
        """Resilient decorator combines both patterns."""
        call_count = 0
        cb = CircuitBreaker(name="test", failure_threshold=5)

        @resilient(circuit_breaker=cb, max_retries=2, base_delay=0.01)
        def test_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise RuntimeError("Transient")
            return "ok"

        result = test_func()

        assert result == "ok"
        assert cb._failure_count == 0  # Success resets
