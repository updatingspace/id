import os

from django.core.wsgi import get_wsgi_application
from django.urls import get_resolver

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "app.settings")

application = get_wsgi_application()

# Django normally imports the URL tree on the first request in each worker.
# Resolve it during worker initialization so prepared instances have their API
# schemas, routes and telemetry setup loaded before serving account requests.
# Keep Gunicorn's per-worker loading: preloading the master could fork SDK threads.
get_resolver().url_patterns
