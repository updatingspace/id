from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass

from allauth.account.internal.flows.login import record_authentication
from allauth.core import context
from allauth.core.exceptions import ReauthenticationRequired
from django.conf import settings
from django.contrib.auth import login as dj_login
from django.db import transaction
from ninja.errors import HttpError

from accounts.transport.schemas import AuthenticatorOut, AuthenticatorsOut
from accounts.services.activity import ActivityService

logger = logging.getLogger(__name__)


def _passkeys_imports():
    if "allauth.mfa" not in getattr(settings, "INSTALLED_APPS", []):
        raise HttpError(501, "passkeys_not_enabled")
    from allauth.mfa.models import Authenticator
    from allauth.mfa.webauthn.internal import auth as webauthn_auth
    from allauth.mfa.webauthn.internal import flows

    return Authenticator, webauthn_auth, flows


@dataclass(slots=True)
class PasskeyService:
    @staticmethod
    def list_authenticators(user) -> AuthenticatorsOut:
        Authenticator, _webauthn_auth, _flows = _passkeys_imports()
        auths = (
            Authenticator.objects.filter(user=user, type=Authenticator.Type.WEBAUTHN)
            .order_by("-created_at")
            .all()
        )
        return AuthenticatorsOut(
            authenticators=[
                AuthenticatorOut(
                    id=str(a.id),
                    name=a.data.get("name"),
                    type="webauthn",
                    created_at=int(a.created_at.timestamp()),
                    last_used_at=(
                        int(a.last_used_at.timestamp()) if a.last_used_at else None
                    ),
                    is_passwordless=bool(
                        a.data.get("credential", {})
                        .get("clientExtensionResults", {})
                        .get("credProps", {})
                        .get("rk")
                    ),
                )
                for a in auths
            ]
        )

    @staticmethod
    def begin_registration(request, user, *, passwordless: bool = False) -> dict:
        _Authenticator, _webauthn_auth, flows = _passkeys_imports()
        try:
            with context.request_context(request):
                logger.info(
                    "Passkey registration started",
                    extra={
                        "user_id": getattr(user, "id", None),
                        "passwordless": passwordless,
                    },
                )
                return flows.begin_registration(
                    request, user, passwordless, signup=False
                )
        except ReauthenticationRequired as err:
            logger.warning(
                "Passkey registration requires reauthentication",
                extra={"user_id": getattr(user, "id", None)},
            )
            raise HttpError(401, "reauth_required") from err

    @staticmethod
    def complete_registration(request, name: str, credential: dict):
        _Authenticator, _webauthn_auth, flows = _passkeys_imports()
        try:
            with context.request_context(request):
                auth, rc = flows.add_authenticator(
                    request, name=name, credential=credential
                )
                logger.info(
                    "Passkey registration completed",
                    extra={
                        "user_id": getattr(request.user, "id", None),
                        "authenticator_id": str(getattr(auth, "id", "")),
                        "auth_name": name,
                    },
                )
                return auth, rc
        except ReauthenticationRequired as err:
            logger.warning(
                "Passkey registration completion requires reauthentication",
                extra={"user_id": getattr(request.user, "id", None)},
            )
            raise HttpError(401, "reauth_required") from err

    @staticmethod
    @transaction.atomic
    def delete(request, user, ids: Iterable[str]) -> int:
        Authenticator, _webauthn_auth, flows = _passkeys_imports()
        auths = list(
            Authenticator.objects.filter(
                user=user, type=Authenticator.Type.WEBAUTHN, id__in=list(ids)
            )
        )
        try:
            with context.request_context(request):
                flows.remove_authenticators(request, auths)
        except ReauthenticationRequired as err:
            logger.warning(
                "Passkey removal requires reauthentication",
                extra={"user_id": getattr(user, "id", None), "ids": list(ids)},
            )
            raise HttpError(401, "reauth_required") from err
        logger.info(
            "Passkeys removed",
            extra={
                "user_id": getattr(user, "id", None),
                "count": len(auths),
            },
        )
        return len(auths)

    @staticmethod
    def rename(request, authenticator_id: str, new_name: str) -> None:
        Authenticator, _webauthn_auth, flows = _passkeys_imports()
        auth = Authenticator.objects.filter(
            user=request.user,
            type=Authenticator.Type.WEBAUTHN,
            id=authenticator_id,
        ).first()
        if not auth:
            return
        try:
            with context.request_context(request):
                flows.rename_authenticator(request, auth, new_name)
        except ReauthenticationRequired as err:
            logger.warning(
                "Passkey rename requires reauthentication",
                extra={"user_id": getattr(request.user, "id", None)},
            )
            raise HttpError(401, "reauth_required") from err
        logger.info(
            "Passkey renamed",
            extra={
                "user_id": getattr(request.user, "id", None),
                "authenticator_id": authenticator_id,
            },
        )

    @staticmethod
    def begin_login(request, user=None) -> dict:
        _Authenticator, webauthn_auth, _flows = _passkeys_imports()
        with context.request_context(request):
            logger.info(
                "Passkey login started",
                extra={"user_id": getattr(user, "id", None)},
            )
            return webauthn_auth.begin_authentication(user)

    @staticmethod
    def complete_login(request, credential: dict):
        _Authenticator, webauthn_auth, _flows = _passkeys_imports()
        with context.request_context(request):
            user = webauthn_auth.extract_user_from_response(credential)
            authenticator = webauthn_auth.complete_authentication(user, credential)
            record_authentication(
                request,
                user,
                method="mfa",
                type="webauthn",
                passwordless=True,
            )
            backend = getattr(user, "backend", None) or (
                settings.AUTHENTICATION_BACKENDS[0]
                if getattr(settings, "AUTHENTICATION_BACKENDS", None)
                else None
            )
            dj_login(request, user, backend=backend)
            ActivityService.record_login(
                request,
                user=user,
                success=True,
                meta={"method": "passkey"},
            )
            logger.info(
                "Passkey login completed",
                extra={
                    "user_id": getattr(user, "id", None),
                    "authenticator_id": getattr(authenticator, "id", None),
                },
            )
            return user, authenticator


__all__ = ["PasskeyService"]
