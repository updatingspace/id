"""Prepare application code without starting per-process SDK resources."""

import os

import django
from django.urls import get_resolver


def prepare_application() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "app.settings")
    django.setup()

    # Load route schemas and imports before a prepared container starts listening.
    get_resolver().url_patterns

    # Service packages import models, so import only after Django is initialized.
    from accounts.services.timezone import TimezoneService

    TimezoneService.get_all_timezones()
