"""Private WSGI entrypoint; only the scheduler has YC container invoke rights.

This application is deployed separately and is not mounted in the public API.
"""

import logging
import os

import django
from django.core.management import call_command
from django.db import close_old_connections

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "app.settings")
django.setup()
logger = logging.getLogger(__name__)


def application(environ, start_response):
    status, body = "404 Not Found", b"Not found"
    if environ.get("PATH_INFO") == "/refresh-gravatars":
        if environ.get("REQUEST_METHOD") != "POST":
            status, body = "405 Method Not Allowed", b"POST required"
        else:
            close_old_connections()
            try:
                limit = int(os.environ.get("GRAVATAR_BATCH_LIMIT", "25"))
                if not 1 <= limit <= 100:
                    raise ValueError("GRAVATAR_BATCH_LIMIT must be between 1 and 100")
                call_command("refresh_gravatars", limit=limit)
                status, body = "200 OK", b"Completed"
            except Exception:
                logger.exception("Scheduled Gravatar refresh failed")
                status, body = "500 Internal Server Error", b"Job failed"
            finally:
                close_old_connections()
    start_response(
        status, [("Content-Type", "text/plain"), ("Cache-Control", "no-store")]
    )
    return [body]
