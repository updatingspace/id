from __future__ import annotations

import logging
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import wraps
from typing import Callable

from django.conf import settings
from django.core.cache import cache
from ninja.errors import HttpError

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RateLimitDecision:
    blocked: bool
    retry_after: int | None
    remaining: int | None
    limit: int


class RateLimitService:
    """Lightweight, cache-backed rate limiter for auth-sensitive endpoints."""

    LOGIN_LIMIT = 5
    LOGIN_WINDOW_SEC = 5 * 60
    REGISTER_LIMIT = 3
    REGISTER_WINDOW_SEC = 10 * 60

    # OIDC endpoint limits (configurable via settings)
    OIDC_TOKEN_LIMIT = getattr(settings, "RATE_LIMIT_OIDC_TOKEN", 60)
    OIDC_TOKEN_WINDOW_SEC = 60
    OIDC_USERINFO_LIMIT = getattr(settings, "RATE_LIMIT_OIDC_USERINFO", 120)
    OIDC_USERINFO_WINDOW_SEC = 60
    OIDC_AUTHORIZE_LIMIT = getattr(settings, "RATE_LIMIT_OIDC_AUTHORIZE", 30)
    OIDC_AUTHORIZE_WINDOW_SEC = 60

    PREFIX = "rl"

    @classmethod
    def _key(cls, scope: str, identifier: str) -> str:
        safe_id = identifier.replace(" ", "_")
        return f"{cls.PREFIX}:{scope}:{safe_id}"

    @classmethod
    def _increment(cls, key: str, *, limit: int, window_sec: int) -> RateLimitDecision:
        now = int(time.time())
        cached = cache.get(key) or {}
        count = int(cached.get("count", 0)) + 1
        reset_at = int(cached.get("reset_at", now + window_sec))
        if reset_at <= now:
            reset_at = now + window_sec
            count = 1
        ttl = max(reset_at - now, 1)
        cache.set(key, {"count": count, "reset_at": reset_at}, ttl)
        blocked = count > limit
        retry_after = max(reset_at - now, 0) if blocked else None
        remaining = max(limit - count, 0) if not blocked else 0
        return RateLimitDecision(
            blocked=blocked,
            retry_after=retry_after,
            remaining=remaining,
            limit=limit,
        )

    @classmethod
    def _register_attempt(
        cls,
        scope: str,
        identifiers: Sequence[str],
        *,
        limit: int,
        window_sec: int,
    ) -> RateLimitDecision:
        decisions = [
            cls._increment(
                cls._key(scope, ident),
                limit=limit,
                window_sec=window_sec,
            )
            for ident in identifiers
        ]
        blocked = [d for d in decisions if d.blocked]
        if blocked:
            retry_after = max((d.retry_after or 0) for d in blocked) or None
            logger.info(
                "Rate limit triggered",
                extra={
                    "scope": scope,
                    "identifiers": list(identifiers),
                    "retry_after": retry_after,
                },
            )
            return RateLimitDecision(
                blocked=True,
                retry_after=retry_after,
                remaining=0,
                limit=limit,
            )
        remaining_values = [d.remaining for d in decisions if d.remaining is not None]
        remaining = min(remaining_values) if remaining_values else limit
        return RateLimitDecision(
            blocked=False,
            retry_after=None,
            remaining=remaining,
            limit=limit,
        )

    @classmethod
    def reset(cls, scope: str, identifiers: Iterable[str]) -> None:
        for ident in identifiers:
            cache.delete(cls._key(scope, ident))

    @classmethod
    def login_attempt(cls, *, ip: str | None, email: str | None) -> RateLimitDecision:
        identifiers: list[str] = []
        if ip:
            identifiers.append(f"ip:{ip}")
        if email:
            identifiers.append(f"email:{email.lower().strip()}")
        if not identifiers:
            identifiers.append("unknown")
        return cls._register_attempt(
            "login",
            identifiers,
            limit=cls.LOGIN_LIMIT,
            window_sec=cls.LOGIN_WINDOW_SEC,
        )

    @classmethod
    def register_attempt(
        cls, *, ip: str | None, email: str | None
    ) -> RateLimitDecision:
        identifiers: list[str] = []
        if ip:
            identifiers.append(f"ip:{ip}")
        if email:
            identifiers.append(f"email:{email.lower().strip()}")
        if not identifiers:
            identifiers.append("unknown")
        return cls._register_attempt(
            "register",
            identifiers,
            limit=cls.REGISTER_LIMIT,
            window_sec=cls.REGISTER_WINDOW_SEC,
        )

    # ========================================================================
    # OIDC Rate Limiting
    # ========================================================================

    @classmethod
    def oidc_token_attempt(
        cls, *, ip: str | None, client_id: str | None
    ) -> RateLimitDecision:
        """Rate limit for OIDC token endpoint."""
        identifiers: list[str] = []
        if ip:
            identifiers.append(f"ip:{ip}")
        if client_id:
            identifiers.append(f"client:{client_id}")
        if not identifiers:
            identifiers.append("unknown")
        return cls._register_attempt(
            "oidc_token",
            identifiers,
            limit=cls.OIDC_TOKEN_LIMIT,
            window_sec=cls.OIDC_TOKEN_WINDOW_SEC,
        )

    @classmethod
    def oidc_userinfo_attempt(cls, *, ip: str | None) -> RateLimitDecision:
        """Rate limit for OIDC userinfo endpoint."""
        identifiers = [f"ip:{ip}"] if ip else ["unknown"]
        return cls._register_attempt(
            "oidc_userinfo",
            identifiers,
            limit=cls.OIDC_USERINFO_LIMIT,
            window_sec=cls.OIDC_USERINFO_WINDOW_SEC,
        )

    @classmethod
    def oidc_authorize_attempt(
        cls, *, ip: str | None, user_id: str | None
    ) -> RateLimitDecision:
        """Rate limit for OIDC authorization endpoint."""
        identifiers: list[str] = []
        if ip:
            identifiers.append(f"ip:{ip}")
        if user_id:
            identifiers.append(f"user:{user_id}")
        if not identifiers:
            identifiers.append("unknown")
        return cls._register_attempt(
            "oidc_authorize",
            identifiers,
            limit=cls.OIDC_AUTHORIZE_LIMIT,
            window_sec=cls.OIDC_AUTHORIZE_WINDOW_SEC,
        )


def get_client_ip(request) -> str | None:
    """Extract client IP from request, handling proxies."""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    x_real_ip = request.META.get("HTTP_X_REAL_IP")
    if x_real_ip:
        return x_real_ip.strip()
    return request.META.get("REMOTE_ADDR")


def rate_limit_oidc(
    scope: str,
    get_identifiers: Callable | None = None,
) -> Callable:
    """
    Decorator to apply rate limiting to OIDC endpoints.

    Usage:
        @rate_limit_oidc("token", lambda req, payload: {"client_id": payload.client_id})
        def token_endpoint(request, payload):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            ip = get_client_ip(request)

            # Get additional identifiers from the callable
            extra_ids = {}
            if get_identifiers:
                try:
                    extra_ids = get_identifiers(request, *args, **kwargs) or {}
                except Exception:
                    pass

            # Select appropriate rate limit method
            if scope == "token":
                decision = RateLimitService.oidc_token_attempt(
                    ip=ip, client_id=extra_ids.get("client_id")
                )
            elif scope == "userinfo":
                decision = RateLimitService.oidc_userinfo_attempt(ip=ip)
            elif scope == "authorize":
                user = getattr(request, "auth", None)
                user_id = str(user.pk) if user and hasattr(user, "pk") else None
                decision = RateLimitService.oidc_authorize_attempt(
                    ip=ip, user_id=user_id
                )
            else:
                # Generic fallback
                decision = RateLimitService._register_attempt(
                    scope,
                    [f"ip:{ip}"] if ip else ["unknown"],
                    limit=60,
                    window_sec=60,
                )

            if decision.blocked:
                from core.monitoring import track_rate_limit

                track_rate_limit(scope, "ip" if ip else "unknown")

                raise HttpError(
                    429,
                    {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": f"Too many requests. Retry after {decision.retry_after} seconds.",
                        "retry_after": decision.retry_after,
                    },
                )

            return func(request, *args, **kwargs)

        return wrapper

    return decorator
