"""Pytest configuration for ID service tests."""
import os


def pytest_configure(config):
    """Configure essential environment defaults for pytest runs."""
    os.environ.setdefault("DJANGO_SECRET_KEY", "test-secret-key")
    os.environ.setdefault("DJANGO_DEBUG", "1")
