from unittest.mock import patch

from django.db import DatabaseError
from django.test import SimpleTestCase

from accounts.services.oauth import OAuthService


class PublicOAuthProvidersTests(SimpleTestCase):
    def test_no_installed_providers_needs_no_database(self):
        with (
            patch("accounts.services.oauth.registry.as_choices", return_value=[]),
            patch.object(
                OAuthService,
                "configured_provider_ids",
                side_effect=DatabaseError("database unavailable"),
            ) as configured,
        ):
            response = self.client.get("/api/v1/auth/oauth/providers")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"providers": []})
        self.assertEqual(response["Cache-Control"], "private, no-store")
        configured.assert_not_called()

    def test_installed_providers_reflect_configuration_changes(self):
        with (
            patch(
                "accounts.services.oauth.registry.as_choices",
                return_value=[("first", "First"), ("second", "Second")],
            ),
            patch.object(
                OAuthService,
                "configured_provider_ids",
                side_effect=[{"first", "uninstalled"}, {"second"}, set()],
            ) as configured,
        ):
            self.assertEqual(
                OAuthService.list_providers(), [{"id": "first", "name": "First"}]
            )
            self.assertEqual(
                OAuthService.list_providers(), [{"id": "second", "name": "Second"}]
            )
            self.assertEqual(OAuthService.list_providers(), [])
            self.assertEqual(configured.call_count, 3)

    def test_empty_registry_result_does_not_cache_a_later_provider(self):
        with (
            patch(
                "accounts.services.oauth.registry.as_choices",
                side_effect=[[], [("first", "First")]],
            ),
            patch.object(
                OAuthService, "configured_provider_ids", return_value={"first"}
            ) as configured,
        ):
            self.assertEqual(OAuthService.list_providers(), [])
            self.assertEqual(
                OAuthService.list_providers(), [{"id": "first", "name": "First"}]
            )
            configured.assert_called_once()

    def test_database_failure_with_installed_providers_is_not_hidden(self):
        with (
            patch(
                "accounts.services.oauth.registry.as_choices",
                return_value=[("first", "First")],
            ),
            patch.object(
                OAuthService,
                "configured_provider_ids",
                side_effect=DatabaseError("database unavailable"),
            ),
            self.assertRaises(DatabaseError),
        ):
            OAuthService.list_providers()
