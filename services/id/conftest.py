"""Pytest configuration for ID service tests."""
import os

# Configure environment defaults at import-time so pytest-django sees them
# before it initializes Django settings from --ds/pytest.ini.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "app.settings")
os.environ.setdefault("DJANGO_SECRET_KEY", "test-secret-key-min-32-characters-long")
os.environ.setdefault("DJANGO_DEBUG", "1")
