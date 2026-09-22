"""Prepare import-only state before Gunicorn advertises its listening socket."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gunicorn.arbiter import Arbiter


def on_starting(server: "Arbiter") -> None:
    from app.startup import prepare_application
    from core.telemetry import prepare_telemetry_dependencies

    # Do not preload the WSGI application: exporters and their threads belong
    # to workers. This hook runs before Gunicorn opens the listening socket.
    prepare_application()
    prepare_telemetry_dependencies()
