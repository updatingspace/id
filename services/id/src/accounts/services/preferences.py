from __future__ import annotations

import logging
from dataclasses import dataclass

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from accounts.models import AccountEvent, UserConsent, UserPreferences
from accounts.services.timezone import TimezoneService

logger = logging.getLogger(__name__)


ALLOWED_SCOPE_POLICIES = {"allow", "ask", "deny"}
DEFAULT_SCOPE_POLICIES = {
    "profile_basic": "allow",
    "email": "ask",
    "phone": "ask",
    "profile_extended": "ask",
}


def _policy_or_default(value: str | None) -> str:
    if value in ALLOWED_SCOPE_POLICIES:
        return value
    return "ask"


@dataclass(slots=True)
class PreferencesService:
    @staticmethod
    def _ensure(user) -> UserPreferences:
        prefs, _ = UserPreferences.objects.get_or_create(
            user=user,
            defaults={"privacy_scope_defaults": DEFAULT_SCOPE_POLICIES},
        )
        if not prefs.privacy_scope_defaults:
            prefs.privacy_scope_defaults = DEFAULT_SCOPE_POLICIES
            prefs.save(update_fields=["privacy_scope_defaults", "updated_at"])
        return prefs

    @staticmethod
    def get(user) -> dict:
        prefs = PreferencesService._ensure(user)
        return {
            "language": prefs.language,
            "timezone": prefs.timezone,
            "marketing_opt_in": prefs.marketing_opt_in,
            "marketing_opt_in_at": prefs.marketing_opt_in_at,
            "marketing_opt_out_at": prefs.marketing_opt_out_at,
            "privacy_scope_defaults": prefs.privacy_scope_defaults or {},
        }

    @staticmethod
    @transaction.atomic
    def update(
        user,
        *,
        language: str | None = None,
        timezone_name: str | None = None,
        marketing_opt_in: bool | None = None,
        privacy_scope_defaults: dict | None = None,
        source: str = "user",
    ) -> UserPreferences:
        prefs = PreferencesService._ensure(user)
        updated_fields: list[str] = []
        now = timezone.now()
        if language is not None:
            prefs.language = language.strip() or prefs.language
            updated_fields.append("language")
        if timezone_name is not None:
            # Validate and normalize timezone
            normalized_tz = TimezoneService.normalize_timezone(timezone_name)
            prefs.timezone = normalized_tz
            updated_fields.append("timezone")
        if marketing_opt_in is not None:
            if marketing_opt_in and not prefs.marketing_opt_in:
                prefs.marketing_opt_in = True
                prefs.marketing_opt_in_at = now
                prefs.marketing_opt_out_at = None
                updated_fields.extend(
                    ["marketing_opt_in", "marketing_opt_in_at", "marketing_opt_out_at"]
                )
            elif not marketing_opt_in and prefs.marketing_opt_in:
                prefs.marketing_opt_in = False
                prefs.marketing_opt_out_at = now
                updated_fields.extend(["marketing_opt_in", "marketing_opt_out_at"])
        if privacy_scope_defaults is not None:
            cleaned: dict[str, str] = {}
            for key, value in privacy_scope_defaults.items():
                cleaned[str(key)] = _policy_or_default(str(value))
            prefs.privacy_scope_defaults = {
                **DEFAULT_SCOPE_POLICIES,
                **cleaned,
            }
            updated_fields.append("privacy_scope_defaults")
        if updated_fields:
            updated_fields.append("updated_at")
            prefs.save(update_fields=updated_fields)
            AccountEvent.objects.create(
                user=user,
                action="preferences_updated",
                meta={"fields": updated_fields, "source": source},
            )
        return prefs


class ConsentService:
    @staticmethod
    def grant(
        user,
        *,
        kind: str,
        version: str | None = None,
        source: str = "user",
        meta: dict | None = None,
    ) -> UserConsent:
        record = UserConsent.objects.create(
            user=user,
            kind=kind,
            version=version or "",
            source=source,
            granted_at=timezone.now(),
            meta=meta or {},
        )
        AccountEvent.objects.create(
            user=user,
            action="consent_granted",
            meta={"kind": kind, "version": record.version, "source": source},
        )
        return record

    @staticmethod
    def revoke(user, *, kind: str, source: str = "user") -> UserConsent | None:
        record = (
            UserConsent.objects.filter(user=user, kind=kind, revoked_at__isnull=True)
            .order_by("-granted_at")
            .first()
        )
        if not record:
            return None
        record.revoked_at = timezone.now()
        record.save(update_fields=["revoked_at"])
        AccountEvent.objects.create(
            user=user,
            action="consent_revoked",
            meta={"kind": kind, "source": source},
        )
        return record

    @staticmethod
    def current(user) -> dict[str, dict | None]:
        latest: dict[str, dict | None] = {}
        qs = UserConsent.objects.filter(user=user).order_by("-granted_at")
        for record in qs:
            if record.kind not in latest:
                latest[record.kind] = {
                    "kind": record.kind,
                    "version": record.version,
                    "granted_at": record.granted_at,
                    "revoked_at": record.revoked_at,
                    "source": record.source,
                }
        return latest

    @staticmethod
    def data_processing_version() -> str:
        return str(getattr(settings, "DATA_PROCESSING_CONSENT_VERSION", "v1"))

    @staticmethod
    def marketing_version() -> str:
        return str(getattr(settings, "MARKETING_CONSENT_VERSION", "v1"))

    @staticmethod
    def parental_version() -> str:
        return str(getattr(settings, "PARENTAL_CONSENT_VERSION", "v1"))
