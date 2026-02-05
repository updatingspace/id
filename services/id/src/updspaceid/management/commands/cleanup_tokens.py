from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from updspaceid.models import ActivationToken, MagicLinkToken, OAuthState


class Command(BaseCommand):
    help = "Cleanup expired/used tokens for UpdSpaceID."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print counts without deleting.",
        )
        parser.add_argument(
            "--retention-days",
            type=int,
            default=7,
            help="Days to keep used tokens before deletion.",
        )

    def handle(self, *args, **options):
        now = timezone.now()
        retention_days = int(options.get("retention_days") or 7)
        retention_cutoff = now - timedelta(days=retention_days)

        act_qs = ActivationToken.objects.filter(
            Q(expires_at__lte=now) | Q(used_at__lte=retention_cutoff)
        )
        magic_qs = MagicLinkToken.objects.filter(
            Q(expires_at__lte=now) | Q(used_at__lte=retention_cutoff)
        )
        oauth_qs = OAuthState.objects.filter(
            Q(expires_at__lte=now) | Q(used_at__lte=retention_cutoff)
        )

        if options.get("dry_run"):
            self.stdout.write(f"ActivationToken: {act_qs.count()} to delete")
            self.stdout.write(f"MagicLinkToken: {magic_qs.count()} to delete")
            self.stdout.write(f"OAuthState: {oauth_qs.count()} to delete")
            return

        deleted_act = act_qs.delete()[0]
        deleted_magic = magic_qs.delete()[0]
        deleted_oauth = oauth_qs.delete()[0]

        self.stdout.write(f"ActivationToken deleted: {deleted_act}")
        self.stdout.write(f"MagicLinkToken deleted: {deleted_magic}")
        self.stdout.write(f"OAuthState deleted: {deleted_oauth}")
