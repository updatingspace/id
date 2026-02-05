from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from allauth.account.models import EmailAddress
from allauth.socialaccount.models import SocialAccount, SocialToken
from allauth.usersessions.models import UserSession
from django.contrib.auth import get_user_model
from django.contrib.auth import logout as dj_logout
from django.contrib.sessions.models import Session
from django.db import transaction
from django.utils import timezone

from accounts.models import (
    AccountDeletionRequest,
    UserConsent,
    UserPreferences,
    UserProfile,
)
from core.models import UserSessionMeta, UserSessionToken

logger = logging.getLogger(__name__)
User = get_user_model()


@dataclass(slots=True)
class AccountDeletionService:
    @staticmethod
    @transaction.atomic
    def delete_account(
        request, user, *, reason: str | None = None
    ) -> AccountDeletionRequest:
        now = timezone.now()
        deletion = AccountDeletionRequest.objects.create(
            user=user,
            status=AccountDeletionRequest.Status.PENDING,
            requested_at=now,
            reason=(reason or "")[:256],
        )

        AccountDeletionService._revoke_sessions(user, request=request)
        AccountDeletionService._anonymize_user(user)

        deletion.status = AccountDeletionRequest.Status.EXECUTED
        deletion.executed_at = timezone.now()
        deletion.save(update_fields=["status", "executed_at"])
        logger.info("Account deleted", extra={"user_id": getattr(user, "id", None)})
        return deletion

    @staticmethod
    def _revoke_sessions(user, *, request=None) -> None:
        now = timezone.now()
        UserSessionMeta.objects.filter(user=user).update(
            revoked_at=now, revoked_reason="account_deleted"
        )
        UserSessionToken.objects.filter(user=user).update(revoked_at=now)
        UserSession.objects.filter(user=user).delete()
        if request is not None:
            dj_logout(request)
        Session.objects.filter(expire_date__lte=now).delete()

    @staticmethod
    def _anonymize_user(user) -> None:
        anon_id = uuid.uuid4().hex
        user.is_active = False
        if hasattr(user, "email"):
            user.email = f"deleted-{anon_id}@deleted.local"
        if hasattr(user, "username"):
            user.username = f"deleted-{anon_id}"
        if hasattr(user, "first_name"):
            user.first_name = ""
        if hasattr(user, "last_name"):
            user.last_name = ""
        user.set_unusable_password()
        user.save()

        UserProfile.objects.filter(user=user).update(
            phone_number="",
            phone_verified=False,
            birth_date=None,
            avatar=None,
            avatar_source=UserProfile.AvatarSource.NONE,
            gravatar_enabled=False,
            gravatar_checked_at=timezone.now(),
            updated_at=timezone.now(),
        )
        UserPreferences.objects.filter(user=user).update(
            marketing_opt_in=False,
            marketing_opt_in_at=None,
            marketing_opt_out_at=timezone.now(),
            privacy_scope_defaults={},
            timezone="",
            language="en",
            updated_at=timezone.now(),
        )
        UserConsent.objects.filter(user=user, revoked_at__isnull=True).update(
            revoked_at=timezone.now()
        )
        EmailAddress.objects.filter(user=user).delete()
        SocialToken.objects.filter(account__user=user).delete()
        SocialAccount.objects.filter(user=user).delete()
        try:
            from idp.models import OidcConsent, OidcToken

            OidcToken.objects.filter(user=user).update(revoked_at=timezone.now())
            OidcConsent.objects.filter(user=user).delete()
        except Exception:
            logger.warning(
                "Failed to revoke OIDC artifacts on delete",
                extra={"user_id": getattr(user, "id", None)},
                exc_info=True,
            )
