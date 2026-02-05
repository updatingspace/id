"""
Management command to create/update the Portal OIDC client for local development.

Usage:
    python manage.py setup_portal_client
    python manage.py setup_portal_client --show-secret
"""

from django.contrib.sites.models import Site
from django.core.management.base import BaseCommand

from idp.models import OidcClient


class Command(BaseCommand):
    help = "Create or update the Portal OIDC client and django_site entry"

    def add_arguments(self, parser):
        parser.add_argument(
            "--show-secret",
            action="store_true",
            help="Display the client secret after creation/update",
        )
        parser.add_argument(
            "--reset-secret",
            action="store_true",
            help="Generate a new client secret",
        )
        parser.add_argument(
            "--secret",
            type=str,
            default=None,
            help="Set a specific client secret (useful for dev environment)",
        )

    def handle(self, *args, **options):
        # Ensure django_site entry exists
        site, site_created = Site.objects.update_or_create(
            id=1,
            defaults={
                "domain": "id.localhost",
                "name": "UpdSpace ID",
            },
        )
        if site_created:
            self.stdout.write(self.style.SUCCESS("✓ Created django_site entry"))
        else:
            self.stdout.write(self.style.SUCCESS("✓ django_site entry already exists"))

        # Portal OIDC client configuration
        portal_client_id = "portal-dev-client"
        portal_config = {
            "name": "AEF Portal",
            "description": "Main portal application for AEF voting system",
            "redirect_uris": [
                # New OIDC callback endpoints
                "http://aef.localhost/api/v1/auth/callback",
                "http://localhost:5173/api/v1/auth/callback",
                # Legacy session callback (magic link)
                "http://aef.localhost/api/v1/session/callback",
                "http://localhost:5173/api/v1/session/callback",
                # Direct callback (if needed)
                "http://aef.localhost/callback",
                "http://localhost:5173/callback",
            ],
            "allowed_scopes": [
                "openid",
                "profile",
                "email",
                "offline_access",
            ],
            "grant_types": [
                "authorization_code",
                "refresh_token",
            ],
            "response_types": [
                "code",
            ],
            "is_public": False,
            "is_first_party": True,
        }

        client = OidcClient.objects.filter(client_id=portal_client_id).first()
        created = False
        if client is None:
            client = OidcClient.objects.filter(name=portal_config["name"]).first()
            if client is None:
                client = OidcClient(client_id=portal_client_id)
                created = True
            else:
                client.client_id = portal_client_id

        secret_generated = False
        if created or options["reset_secret"] or options["secret"]:
            secret = client.set_secret(options["secret"])
            secret_generated = True
        else:
            secret = None

        # Update client with latest config.
        for key, value in portal_config.items():
            setattr(client, key, value)
        client.save()

        if created:
            self.stdout.write(
                self.style.SUCCESS(f"✓ Created OIDC client: {client.name}")
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(f"✓ Updated OIDC client: {client.name}")
            )

        self.stdout.write(f"  Client ID: {client.client_id}")

        if options["show_secret"] and secret_generated:
            self.stdout.write(self.style.WARNING(f"  Client Secret: {secret}"))
            self.stdout.write(
                self.style.NOTICE("  ⚠ Save this secret! It cannot be retrieved later.")
            )
        elif options["show_secret"] and not secret_generated:
            self.stdout.write(
                self.style.NOTICE(
                    "  Client secret was not changed. Use --reset-secret to generate a new one."
                )
            )

        self.stdout.write(f"  Redirect URIs: {client.redirect_uris}")
        self.stdout.write(f"  Allowed Scopes: {client.allowed_scopes}")
        self.stdout.write(f"  First Party: {client.is_first_party}")
