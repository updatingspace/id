from django.core.wsgi import get_wsgi_application

from app.startup import prepare_application
from core.telemetry import configure_telemetry

prepare_application()
# Create exporters only in the serving process, after Gunicorn forks. Instrument
# Django before constructing its handler so tracing middleware is installed.
configure_telemetry()
application = get_wsgi_application()
