from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from ninja.errors import HttpError

from accounts.services.rate_limit import (
    RateLimitService,
    get_client_ip,
    rate_limit_oidc,
)


class RateLimitServiceTests(TestCase):
    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def test_login_attempt_blocks_after_limit(self):
        decision = None
        for _ in range(RateLimitService.LOGIN_LIMIT + 1):
            decision = RateLimitService.login_attempt(
                ip="127.0.0.1",
                email="user@example.com",
            )
        assert decision is not None
        self.assertTrue(decision.blocked)
        self.assertIsNotNone(decision.retry_after)

    def test_reset_unblocks_identifier(self):
        for _ in range(RateLimitService.LOGIN_LIMIT + 1):
            RateLimitService.login_attempt(ip="10.0.0.1", email="reset@example.com")

        RateLimitService.reset("login", ["ip:10.0.0.1", "email:reset@example.com"])
        decision = RateLimitService.login_attempt(
            ip="10.0.0.1",
            email="reset@example.com",
        )
        self.assertFalse(decision.blocked)

    def test_oidc_token_rate_limit_uses_ip_and_client(self):
        original_limit = RateLimitService.OIDC_TOKEN_LIMIT
        try:
            RateLimitService.OIDC_TOKEN_LIMIT = 2
            first = RateLimitService.oidc_token_attempt(
                ip="192.168.0.1",
                client_id="portal-client",
            )
            second = RateLimitService.oidc_token_attempt(
                ip="192.168.0.1",
                client_id="portal-client",
            )
            third = RateLimitService.oidc_token_attempt(
                ip="192.168.0.1",
                client_id="portal-client",
            )
            self.assertFalse(first.blocked)
            self.assertFalse(second.blocked)
            self.assertTrue(third.blocked)
        finally:
            RateLimitService.OIDC_TOKEN_LIMIT = original_limit

    def test_register_attempt_uses_unknown_identifier_without_ip_or_email(self):
        first = RateLimitService.register_attempt(ip=None, email=None)
        self.assertFalse(first.blocked)
        self.assertEqual(first.limit, RateLimitService.REGISTER_LIMIT)

    def test_login_attempt_normalizes_email_before_keying(self):
        first = RateLimitService.login_attempt(ip=None, email="USER@Example.COM")
        second = RateLimitService.login_attempt(ip=None, email="user@example.com")
        self.assertFalse(first.blocked)
        self.assertEqual(second.remaining, RateLimitService.LOGIN_LIMIT - 2)

    def test_login_attempt_uses_unknown_when_identifiers_absent(self):
        decision = RateLimitService.login_attempt(ip=None, email=None)
        self.assertFalse(decision.blocked)
        self.assertEqual(decision.limit, RateLimitService.LOGIN_LIMIT)

    def test_oidc_userinfo_limit_blocks_after_threshold(self):
        original_limit = RateLimitService.OIDC_USERINFO_LIMIT
        try:
            RateLimitService.OIDC_USERINFO_LIMIT = 1
            first = RateLimitService.oidc_userinfo_attempt(ip="10.0.0.3")
            second = RateLimitService.oidc_userinfo_attempt(ip="10.0.0.3")
            self.assertFalse(first.blocked)
            self.assertTrue(second.blocked)
            self.assertIsNotNone(second.retry_after)
        finally:
            RateLimitService.OIDC_USERINFO_LIMIT = original_limit

    def test_oidc_authorize_limit_tracks_user_dimension(self):
        original_limit = RateLimitService.OIDC_AUTHORIZE_LIMIT
        try:
            RateLimitService.OIDC_AUTHORIZE_LIMIT = 1
            first = RateLimitService.oidc_authorize_attempt(
                ip="10.0.0.4",
                user_id="u-1",
            )
            second = RateLimitService.oidc_authorize_attempt(
                ip="10.0.0.4",
                user_id="u-1",
            )
            self.assertFalse(first.blocked)
            self.assertTrue(second.blocked)
        finally:
            RateLimitService.OIDC_AUTHORIZE_LIMIT = original_limit

    def test_get_client_ip_precedence(self):
        request = SimpleNamespace(
            META={
                "HTTP_X_FORWARDED_FOR": "1.1.1.1, 2.2.2.2",
                "HTTP_X_REAL_IP": "3.3.3.3",
                "REMOTE_ADDR": "4.4.4.4",
            }
        )
        self.assertEqual(get_client_ip(request), "1.1.1.1")
        request.META.pop("HTTP_X_FORWARDED_FOR")
        self.assertEqual(get_client_ip(request), "3.3.3.3")
        request.META.pop("HTTP_X_REAL_IP")
        self.assertEqual(get_client_ip(request), "4.4.4.4")

    def test_rate_limit_decorator_allows_request_when_under_limit(self):
        @rate_limit_oidc("token", lambda _req, payload: {"client_id": payload["cid"]})
        def handler(_request, payload):
            return payload["cid"]

        request = SimpleNamespace(META={"REMOTE_ADDR": "127.0.0.1"}, auth=None)
        result = handler(request, {"cid": "portal"})
        self.assertEqual(result, "portal")

    def test_rate_limit_decorator_blocks_and_reports_metric(self):
        @rate_limit_oidc("token", lambda _req, payload: {"client_id": payload["cid"]})
        def handler(_request, payload):  # pragma: no cover - should not execute
            return payload["cid"]

        request = SimpleNamespace(META={"REMOTE_ADDR": "127.0.0.2"}, auth=None)
        original_limit = RateLimitService.OIDC_TOKEN_LIMIT
        try:
            RateLimitService.OIDC_TOKEN_LIMIT = 0
            with patch("core.monitoring.track_rate_limit") as track_mock:
                with self.assertRaises(HttpError) as exc:
                    handler(request, {"cid": "portal"})
            self.assertEqual(exc.exception.status_code, 429)
            self.assertEqual(exc.exception.message["code"], "RATE_LIMIT_EXCEEDED")
            track_mock.assert_called_once()
        finally:
            RateLimitService.OIDC_TOKEN_LIMIT = original_limit

    def test_rate_limit_decorator_ignores_identifier_builder_errors(self):
        @rate_limit_oidc(
            "unknown", lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError)
        )
        def handler(_request):
            return "ok"

        request = SimpleNamespace(META={}, auth=None)
        self.assertEqual(handler(request), "ok")

    def test_increment_resets_expired_window(self):
        key = RateLimitService._key("login", "ip:10.10.10.10")
        cache.set(key, {"count": 99, "reset_at": 1}, timeout=60)
        decision = RateLimitService._increment(key, limit=5, window_sec=10)
        self.assertFalse(decision.blocked)
        self.assertEqual(decision.remaining, 4)

    def test_register_attempt_builds_identifiers_for_ip_and_email(self):
        decision = RateLimitService.register_attempt(ip="10.0.0.9", email="u@e.com")
        self.assertFalse(decision.blocked)
        self.assertLess(decision.remaining or 0, RateLimitService.REGISTER_LIMIT)

    def test_oidc_attempts_support_unknown_fallback_identifier(self):
        token_decision = RateLimitService.oidc_token_attempt(ip=None, client_id=None)
        authorize_decision = RateLimitService.oidc_authorize_attempt(
            ip=None, user_id=None
        )
        self.assertFalse(token_decision.blocked)
        self.assertFalse(authorize_decision.blocked)

    def test_rate_limit_decorator_userinfo_and_authorize_paths(self):
        @rate_limit_oidc("userinfo")
        def userinfo_handler(_request):
            return "userinfo-ok"

        @rate_limit_oidc("authorize")
        def authorize_handler(_request):
            return "authorize-ok"

        request_userinfo = SimpleNamespace(META={"REMOTE_ADDR": "10.2.0.1"}, auth=None)
        request_authorize = SimpleNamespace(
            META={"REMOTE_ADDR": "10.2.0.2"},
            auth=SimpleNamespace(pk=1001),
        )
        self.assertEqual(userinfo_handler(request_userinfo), "userinfo-ok")
        self.assertEqual(authorize_handler(request_authorize), "authorize-ok")
