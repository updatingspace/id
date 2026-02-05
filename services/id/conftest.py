"""Pytest configuration for ID service tests."""
import os
import sys
import django
from pathlib import Path


# Add src to path
src_path = Path(__file__).parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))


def pytest_configure(config):
    """Configure Django settings for pytest."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "app.settings")
    os.environ.setdefault("DJANGO_SECRET_KEY", "test-secret-key")
    os.environ.setdefault("DJANGO_DEBUG", "1")

    django.setup()
