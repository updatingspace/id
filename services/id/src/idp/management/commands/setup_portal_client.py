"""
Management command to create/update the Portal OIDC client.

Usage:
    python manage.py setup_portal_client
    python manage.py setup_portal_client --show-secret
    python manage.py setup_portal_client --portal-base-url https://updspace.com --client-id updspace-portal
"""

import os
from urllib.parse import urlparse

from django.contrib.sites.models import Site
from django.core.management.base import BaseCommand

from idp.models import OidcClient

LOCAL_REDIRECT_URIS = [
    # New OIDC callback endpoints
    "http://aef.localhost/api/v1/auth/callback",
    "http://localhost:5173/api/v1/auth/callback",
    # Legacy session callback (magic link)
    "http://aef.localhost/api/v1/session/callback",
    "http://localhost:5173/api/v1/session/callback",
    # Direct callback (if needed)
    "http://aef.localhost/callback",
    "http://localhost:5173/callback",
]


def _portal_redirect_uris(base_url: str) -> list[str]:
    base = base_url.rstrip("/")
    if not base:
        return []
    return [
        f"{base}/api/v1/auth/callback",
        f"{base}/api/v1/session/callback",
        f"{base}/callback",
    ]


def _unique(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _is_local_url(value: str) -> bool:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost")


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
        parser.add_argument(
            "--client-id",
            type=str,
            default=os.environ.get("PORTAL_OIDC_CLIENT_ID", "portal-dev-client"),
            help="Portal OIDC client_id",
        )
        parser.add_argument(
            "--client-name",
            type=str,
            default=os.environ.get("PORTAL_OIDC_CLIENT_NAME", "AEF Portal"),
            help="Portal OIDC client display name",
        )
        parser.add_argument(
            "--portal-base-url",
            type=str,
            action="append",
            default=None,
            help="Portal public base URL used to derive callback redirect URIs",
        )
        parser.add_argument(
            "--redirect-uri",
            type=str,
            action="append",
            default=None,
            help="Additional explicit redirect URI. Can be passed more than once.",
        )
        parser.add_argument(
            "--site-domain",
            type=str,
            default=os.environ.get("DJANGO_SITE_DOMAIN", "id.localhost"),
            help="django_site domain for the ID service",
        )
        parser.add_argument(
            "--site-name",
            type=str,
            default=os.environ.get("DJANGO_SITE_NAME", "UpdSpace ID"),
            help="django_site display name",
        )

    def handle(self, *args, **options):
        # Ensure django_site entry exists
        site, site_created = Site.objects.update_or_create(
            id=1,
            defaults={
                "domain": options["site_domain"],
                "name": options["site_name"],
            },
        )
        if site_created:
            self.stdout.write(self.style.SUCCESS("✓ Created django_site entry"))
        else:
            self.stdout.write(self.style.SUCCESS("✓ django_site entry already exists"))

        # Portal OIDC client configuration
        portal_client_id = options["client_id"]
        portal_base_urls = options["portal_base_url"] or []
        env_portal_base_url = os.environ.get("PORTAL_PUBLIC_BASE_URL", "")
        if env_portal_base_url:
            portal_base_urls.append(env_portal_base_url)
        has_public_portal_base_url = any(
            base_url and not _is_local_url(base_url) for base_url in portal_base_urls
        )
        redirect_uris = [] if has_public_portal_base_url else list(LOCAL_REDIRECT_URIS)
        for base_url in portal_base_urls:
            redirect_uris.extend(_portal_redirect_uris(base_url))
        redirect_uris.extend(options["redirect_uri"] or [])

        portal_config = {
            "name": options["client_name"],
            "description": "Main portal application for UpdSpace",
            "redirect_uris": _unique(redirect_uris),
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
