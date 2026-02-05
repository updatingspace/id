from __future__ import annotations

from types import SimpleNamespace

from django.test import SimpleTestCase
from ninja.errors import HttpError

from core.http import RequestContext, require_context, require_request_id


class RequestContextTests(SimpleTestCase):
    def _request(self, headers: dict[str, str]):
        return SimpleNamespace(headers=headers)

    def test_require_request_id_returns_header(self):
        request = self._request({"X-Request-Id": "rid-1"})
        self.assertEqual(require_request_id(request), "rid-1")

    def test_require_request_id_raises_without_header(self):
        request = self._request({})
        with self.assertRaises(HttpError) as exc:
            require_request_id(request)
        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.message["code"], "MISSING_REQUEST_ID")

    def test_require_context_builds_dataclass(self):
        request = self._request(
            {
                "X-Request-Id": "rid-2",
                "X-Tenant-Id": "tenant-id",
                "X-Tenant-Slug": "tenant-slug",
            }
        )
        ctx = require_context(request)
        self.assertEqual(
            ctx,
            RequestContext(
                request_id="rid-2",
                tenant_id="tenant-id",
                tenant_slug="tenant-slug",
            ),
        )

    def test_require_context_raises_when_tenant_headers_missing(self):
        request = self._request({"X-Request-Id": "rid-3"})
        with self.assertRaises(HttpError) as exc:
            require_context(request)
        self.assertEqual(exc.exception.status_code, 400)
        self.assertEqual(exc.exception.message["code"], "MISSING_TENANT_CONTEXT")
