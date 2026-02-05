from __future__ import annotations

import logging
from dataclasses import dataclass

from allauth.account.models import EmailAddress
from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.utils import timezone

from accounts.models import DataExportRequest, LoginEvent, UserConsent
from accounts.services.preferences import PreferencesService
from accounts.services.sessions import SessionService

logger = logging.getLogger(__name__)
User = get_user_model()


@dataclass(slots=True)
class ExportService:
    @staticmethod
    def build_payload(request, user) -> dict:
        prefs = PreferencesService.get(user)
        profile = getattr(user, "profile", None)
        primary = EmailAddress.objects.filter(user=user, primary=True).first()
        social = list(
            SocialAccount.objects.filter(user=user).values(
                "provider", "uid", "last_login"
            )
        )
        consents = list(
            UserConsent.objects.filter(user=user)
            .order_by("-granted_at")[:200]
            .values("kind", "version", "granted_at", "revoked_at", "source", "meta")
        )
        sessions = SessionService.list(request, user)
        logins = list(
            LoginEvent.objects.filter(user=user)
            .order_by("-created_at")[:100]
            .values(
                "status",
                "ip_address",
                "user_agent",
                "device_id",
                "is_new_device",
                "reason",
                "created_at",
            )
        )
        payload = {
            "user": {
                "id": getattr(user, "id", None),
                "username": getattr(user, "username", None),
                "email": getattr(user, "email", None),
                "email_verified": bool(primary and primary.verified),
                "first_name": getattr(user, "first_name", None),
                "last_name": getattr(user, "last_name", None),
                "is_active": getattr(user, "is_active", None),
                "date_joined": getattr(user, "date_joined", None),
            },
            "profile": {
                "phone_number": getattr(profile, "phone_number", None)
                if profile
                else None,
                "phone_verified": getattr(profile, "phone_verified", None)
                if profile
                else None,
                "birth_date": getattr(profile, "birth_date", None) if profile else None,
                "avatar_source": getattr(profile, "avatar_source", None)
                if profile
                else None,
                "avatar_url": getattr(profile, "avatar", None).url
                if profile and getattr(profile, "avatar", None)
                else None,
            },
            "preferences": prefs,
            "consents": consents,
            "sessions": [s.dict() for s in sessions],
            "login_events": logins,
            "oauth_accounts": social,
            "generated_at": timezone.now(),
        }
        return payload

    @staticmethod
    def create_request(user) -> DataExportRequest:
        req = DataExportRequest.objects.create(
            user=user, status=DataExportRequest.Status.PENDING
        )
        return req

    @staticmethod
    def mark_ready(req: DataExportRequest) -> None:
        req.status = DataExportRequest.Status.READY
        req.completed_at = timezone.now()
        req.save(update_fields=["status", "completed_at"])

    @staticmethod
    def mark_failed(req: DataExportRequest, error: str) -> None:
        req.status = DataExportRequest.Status.FAILED
        req.completed_at = timezone.now()
        req.error = (error or "")[:256]
        req.save(update_fields=["status", "completed_at", "error"])
