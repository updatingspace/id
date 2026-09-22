"""Refresh saved Gravatar images outside authentication/profile requests."""

import logging

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db.models import Q
from django.utils import timezone

from accounts.models import UserProfile
from accounts.services.profile import ProfileService

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Refresh a bounded batch of due Gravatar images (run as a scheduled job)."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=100)

    def handle(self, *args, **options):
        limit = options["limit"]
        if limit < 1:
            raise CommandError("--limit must be positive")
        if not getattr(settings, "GRAVATAR_AUTOLOAD_ENABLED", True):
            self.stdout.write("Gravatar refresh is disabled")
            return

        cutoff = timezone.now() - ProfileService.GRAVATAR_TTL
        profiles = (
            UserProfile.objects.filter(gravatar_enabled=True)
            .exclude(avatar_source=UserProfile.AvatarSource.UPLOAD)
            .filter(
                Q(gravatar_checked_at__isnull=True) | Q(gravatar_checked_at__lt=cutoff)
            )
            .order_by("gravatar_checked_at", "pk")[:limit]
        )
        checked = updated = failed = 0
        for profile in profiles:
            checked += 1
            try:
                updated += bool(ProfileService.maybe_refresh_gravatar(profile.user))
            except Exception:
                failed += 1
                logger.exception(
                    "Gravatar job failed", extra={"user_id": profile.user_id}
                )

        self.stdout.write(f"Checked {checked}; updated {updated}; failed {failed}")
        if failed:
            raise CommandError(f"Failed to refresh {failed} profiles; see job logs")
