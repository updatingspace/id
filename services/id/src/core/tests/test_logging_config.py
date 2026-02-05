from __future__ import annotations

import json
import logging
import sys
from unittest.mock import patch

from django.test import SimpleTestCase

from core.logging_config import (
    ConsoleFormatter,
    JsonFormatter,
    EMAIL_FIELD_MARKER,
    SENSITIVE_FIELD_MARKER,
    _mask_email,
    clear_context,
    configure_logging,
    generate_correlation_id,
    log_auth_event,
    log_oidc_event,
    sanitize_log_data,
    set_correlation_id,
    set_user_context,
)


class LoggingRedactionTests(SimpleTestCase):
    def tearDown(self):
        clear_context()

    def test_sanitize_log_data_redacts_sensitive_values(self):
        payload = {
            "email": "user@example.com",
            "password": "secret",
            "headers": {"Authorization": "Bearer abc.def.ghi"},
            "details": ["token=abc123", "ok"],
        }
        sanitized = sanitize_log_data(payload)
        self.assertEqual(sanitized["password"], SENSITIVE_FIELD_MARKER)
        self.assertEqual(sanitized["headers"]["Authorization"], SENSITIVE_FIELD_MARKER)
        self.assertIn(EMAIL_FIELD_MARKER, sanitized["email"])
        self.assertIn("[REDACTED]", sanitized["details"][0])

    def test_json_formatter_redacts_message_and_extra_fields(self):
        formatter = JsonFormatter(include_hostname=False)
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname=__file__,
            lineno=42,
            msg="login for user@example.com with token=abcdef",
            args=(),
            exc_info=None,
        )
        record.authorization = "Bearer test-token"
        output = json.loads(formatter.format(record))

        self.assertEqual(output["authorization"], SENSITIVE_FIELD_MARKER)
        self.assertIn(EMAIL_FIELD_MARKER, output["message"])
        self.assertIn("[REDACTED]", output["message"])

    def test_json_formatter_redacts_exception_message(self):
        formatter = JsonFormatter(include_hostname=False)
        try:
            raise ValueError("password=super-secret for user@example.com")
        except ValueError:
            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.ERROR,
            pathname=__file__,
            lineno=73,
            msg="request failed",
            args=(),
            exc_info=exc_info,
        )
        output = json.loads(formatter.format(record))
        self.assertIn("exception", output)
        self.assertIn("[REDACTED]", output["exception"]["message"])
        self.assertIn(EMAIL_FIELD_MARKER, output["exception"]["message"])

    def test_console_formatter_redacts_message(self):
        formatter = ConsoleFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname=__file__,
            lineno=99,
            msg="session token=abc123 for user@example.com",
            args=(),
            exc_info=None,
        )
        line = formatter.format(record)
        self.assertIn("[REDACTED]", line)
        self.assertIn(EMAIL_FIELD_MARKER, line)

    def test_json_formatter_includes_context_fields(self):
        set_correlation_id("cid-1")
        set_user_context(user_id="user-1", tenant_id="tenant-1")
        formatter = JsonFormatter(include_hostname=False)
        record = logging.LogRecord(
            name="test.ctx",
            level=logging.WARNING,
            pathname=__file__,
            lineno=11,
            msg="warn",
            args=(),
            exc_info=None,
        )
        payload = json.loads(formatter.format(record))
        self.assertEqual(payload["correlation_id"], "cid-1")
        self.assertEqual(payload["user_id"], "user-1")
        self.assertEqual(payload["tenant_id"], "tenant-1")
        self.assertIn("source", payload)

    def test_mask_email_handles_short_and_invalid_values(self):
        self.assertEqual(_mask_email("a@x.com"), "*@x.com")
        self.assertEqual(_mask_email("ab@x.com"), "**@x.com")
        self.assertEqual(_mask_email("abc@x.com"), "a*c@x.com")
        self.assertEqual(_mask_email("no-at-symbol"), "***")

    def test_log_auth_event_masks_email_and_uses_warning_on_failure(self):
        with patch("core.logging_config.logging.getLogger") as get_logger:
            logger = get_logger.return_value
            log_auth_event(
                "login",
                user_id="u1",
                email="user@example.com",
                success=False,
                reason="invalid_password",
                ip_address="1.2.3.4",
            )
        logger.log.assert_called_once()
        level, message = logger.log.call_args.args[:2]
        extra = logger.log.call_args.kwargs["extra"]
        self.assertEqual(level, logging.WARNING)
        self.assertEqual(message, "Auth event: login")
        self.assertEqual(extra["email_masked"], "u**r@example.com")

    def test_log_oidc_event_logs_client_and_error_code(self):
        with patch("core.logging_config.logging.getLogger") as get_logger:
            logger = get_logger.return_value
            log_oidc_event(
                "token",
                client_id="portal",
                user_id="u2",
                grant_type="refresh_token",
                success=False,
                error_code="INVALID_REFRESH_TOKEN",
            )
        logger.log.assert_called_once()
        level = logger.log.call_args.args[0]
        extra = logger.log.call_args.kwargs["extra"]
        self.assertEqual(level, logging.WARNING)
        self.assertEqual(extra["client_id"], "portal")
        self.assertEqual(extra["error_code"], "INVALID_REFRESH_TOKEN")

    def test_configure_logging_sets_json_formatter(self):
        root_logger = logging.getLogger()
        previous_handlers = list(root_logger.handlers)
        previous_level = root_logger.level
        try:
            configure_logging(
                json_format=True, log_level="DEBUG", service_name="id-test"
            )
            self.assertEqual(root_logger.level, logging.DEBUG)
            self.assertTrue(root_logger.handlers)
            handler = root_logger.handlers[0]
            self.assertIsInstance(handler.formatter, JsonFormatter)
        finally:
            root_logger.handlers.clear()
            for handler in previous_handlers:
                root_logger.addHandler(handler)
            root_logger.setLevel(previous_level)

    def test_configure_logging_sets_console_formatter(self):
        root_logger = logging.getLogger()
        previous_handlers = list(root_logger.handlers)
        previous_level = root_logger.level
        try:
            configure_logging(json_format=False, log_level="INFO")
            self.assertTrue(root_logger.handlers)
            handler = root_logger.handlers[0]
            self.assertIsInstance(handler.formatter, ConsoleFormatter)
        finally:
            root_logger.handlers.clear()
            for handler in previous_handlers:
                root_logger.addHandler(handler)
            root_logger.setLevel(previous_level)

    def test_generate_correlation_id_returns_uuid_like_string(self):
        corr_id = generate_correlation_id()
        self.assertEqual(len(corr_id), 36)
