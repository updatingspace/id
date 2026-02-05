"""Tests for resilience module (circuit breaker, retry)."""

from __future__ import annotations

import time

import pytest

from core.resilience import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
    RetryConfig,
    resilient,
    retry_with_backoff,
)


class TestCircuitBreaker:
    """Tests for CircuitBreaker class."""

    def test_initial_state_closed(self):
        cb = CircuitBreaker(
            name="test", config=CircuitBreakerConfig(failure_threshold=3)
        )
        assert cb.stats.state == CircuitState.CLOSED

    def test_transitions_to_open_after_failures(self):
        cb = CircuitBreaker(
            name="test", config=CircuitBreakerConfig(failure_threshold=2)
        )

        @cb
        def fail_once():
            raise RuntimeError("boom")

        for _ in range(2):
            with pytest.raises(RuntimeError):
                fail_once()

        assert cb.stats.state == CircuitState.OPEN

    def test_open_circuit_raises_error(self):
        cb = CircuitBreaker(
            name="test",
            config=CircuitBreakerConfig(failure_threshold=1, timeout_seconds=60),
        )

        @cb
        def always_fail():
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            always_fail()
        with pytest.raises(CircuitBreakerOpenError):
            always_fail()

    def test_success_resets_failure_count(self):
        cb = CircuitBreaker(
            name="test", config=CircuitBreakerConfig(failure_threshold=3)
        )

        @cb
        def fail():
            raise RuntimeError("x")

        @cb
        def ok():
            return "ok"

        with pytest.raises(RuntimeError):
            fail()
        assert cb.stats.failure_count == 1

        ok()
        assert cb.stats.failure_count == 1

    def test_half_open_transitions_to_closed(self):
        cb = CircuitBreaker(
            name="test",
            config=CircuitBreakerConfig(
                failure_threshold=1, success_threshold=1, timeout_seconds=0.01
            ),
        )

        @cb
        def sometimes_ok(flag: bool):
            if not flag:
                raise RuntimeError("fail")
            return "ok"

        with pytest.raises(RuntimeError):
            sometimes_ok(False)
        assert cb.stats.state == CircuitState.OPEN

        time.sleep(0.02)
        assert sometimes_ok(True) == "ok"
        assert cb.stats.state == CircuitState.CLOSED

    def test_half_open_transitions_to_open(self):
        cb = CircuitBreaker(
            name="test",
            config=CircuitBreakerConfig(failure_threshold=1, timeout_seconds=0.01),
        )

        @cb
        def always_fail():
            raise RuntimeError("fail")

        with pytest.raises(RuntimeError):
            always_fail()
        time.sleep(0.02)

        with pytest.raises(RuntimeError):
            always_fail()
        assert cb.stats.state == CircuitState.OPEN


class TestRetryWithBackoff:
    """Tests for retry_with_backoff decorator."""

    def test_succeeds_without_retry(self):
        call_count = 0

        @retry_with_backoff(RetryConfig(max_attempts=3, base_delay=0.01, jitter=False))
        def success_func():
            nonlocal call_count
            call_count += 1
            return "success"

        result = success_func()

        assert result == "success"
        assert call_count == 1

    def test_retries_on_failure(self):
        call_count = 0

        @retry_with_backoff(
            RetryConfig(
                max_attempts=3,
                base_delay=0.01,
                jitter=False,
                retryable_exceptions=(ValueError,),
            )
        )
        def failing_func():
            nonlocal call_count
            call_count += 1
            raise ValueError("Always fails")

        with pytest.raises(ValueError):
            failing_func()

        assert call_count == 3

    def test_succeeds_after_retry(self):
        call_count = 0

        @retry_with_backoff(RetryConfig(max_attempts=3, base_delay=0.01, jitter=False))
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
        call_count = 0

        @resilient(
            "test-resilient",
            circuit_config=CircuitBreakerConfig(failure_threshold=5),
            retry_config=RetryConfig(max_attempts=2, base_delay=0.01, jitter=False),
        )
        def test_func():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise RuntimeError("Transient")
            return "ok"

        result = test_func()

        assert result == "ok"
