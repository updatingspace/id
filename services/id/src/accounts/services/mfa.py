from __future__ import annotations

import base64
import logging
from dataclasses import dataclass

from allauth.core import context
from allauth.core.exceptions import ReauthenticationRequired
from django.conf import settings
from django.shortcuts import get_object_or_404
from ninja.errors import HttpError
from allauth.mfa.totp.internal import auth as totp_auth

from accounts.services.emailing import EmailService

from accounts.transport.schemas import (
    MfaStatusOut,
    TotpBeginOut,
)

logger = logging.getLogger(__name__)


def _mfa_imports():
    if "allauth.mfa" not in getattr(settings, "INSTALLED_APPS", []):
        raise HttpError(501, "mfa_not_enabled")
    from allauth.mfa.adapter import get_adapter as get_mfa_adapter
    from allauth.mfa.models import Authenticator
    from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes
    from allauth.mfa.totp.forms import ActivateTOTPForm, DeactivateTOTPForm
    from allauth.mfa.totp.internal import flows as totp_flows

    return (
        get_mfa_adapter,
        Authenticator,
        RecoveryCodes,
        ActivateTOTPForm,
        DeactivateTOTPForm,
        totp_flows,
    )


@dataclass(slots=True)
class MfaService:
    @staticmethod
    def status(user) -> MfaStatusOut:
        (
            _get_mfa_adapter,
            Authenticator,
            RecoveryCodes,
            _ActivateTOTPForm,
            _DeactivateTOTPForm,
            _totp_flows,
        ) = _mfa_imports()
        auths = Authenticator.objects.filter(user=user)
        has_totp = auths.filter(type=Authenticator.Type.TOTP).exists()
        has_webauthn = auths.filter(type=Authenticator.Type.WEBAUTHN).exists()
        rc = auths.filter(type=Authenticator.Type.RECOVERY_CODES).first()
        recovery_left = len(RecoveryCodes(rc).get_unused_codes()) if rc else 0
        return MfaStatusOut(
            has_totp=has_totp,
            has_webauthn=has_webauthn,
            has_recovery_codes=bool(rc),
            recovery_codes_left=recovery_left,
        )

    @staticmethod
    def totp_begin(request) -> TotpBeginOut:
        user = request.user
        if not EmailService.status(user)["verified"]:
            logger.info(
                "TOTP setup blocked: email not verified",
                extra={"user_id": getattr(user, "id", None)},
            )
            raise HttpError(
                400,
                {
                    "code": "EMAIL_VERIFICATION_REQUIRED",
                    "message": "Verify your email before enabling two-factor authentication",
                },
            )
        (
            get_mfa_adapter,
            _Authenticator,
            _RecoveryCodes,
            ActivateTOTPForm,
            _DeactivateTOTPForm,
            _totp_flows,
        ) = _mfa_imports()
        try:
            with context.request_context(request):
                form = ActivateTOTPForm(user=request.user)
                secret = form.secret
                # Persist the generated secret in the session so confirm can reuse it reliably.
                request.session[totp_auth.SECRET_SESSION_KEY] = secret
                request.session.modified = True
                adapter = get_mfa_adapter()
                otpauth_url = adapter.build_totp_url(request.user, secret)
                totp_svg = adapter.build_totp_svg(otpauth_url)
        except ReauthenticationRequired as err:
            logger.warning(
                "TOTP setup requires reauthentication",
                extra={"user_id": getattr(request.user, "id", None)},
            )
            raise HttpError(401, "reauth_required") from err
        svg_data_uri = "data:image/svg+xml;base64," + base64.b64encode(
            totp_svg.encode("utf-8")
        ).decode("utf-8")
        logger.info(
            "TOTP setup initiated",
            extra={"user_id": getattr(request.user, "id", None)},
        )
        return TotpBeginOut(
            secret=secret,
            otpauth_url=otpauth_url,
            svg=totp_svg,
            svg_data_uri=svg_data_uri,
        )

    @staticmethod
    def totp_confirm(request, code: str) -> list[str] | None:
        (
            _get_mfa_adapter,
            _Authenticator,
            RecoveryCodes,
            ActivateTOTPForm,
            _DeactivateTOTPForm,
            totp_flows,
        ) = _mfa_imports()
        # Ensure the secret from the begin step is present; otherwise force restarting setup.
        session_secret = request.session.get(totp_auth.SECRET_SESSION_KEY)
        if not session_secret:
            logger.info(
                "TOTP confirmation attempted without session secret",
                extra={"user_id": getattr(request.user, "id", None)},
            )
            raise HttpError(
                400,
                {
                    "code": "TOTP_SETUP_REQUIRED",
                    "message": "Начните настройку заново",
                },
            )
        clean_code = (code or "").strip().replace(" ", "").replace("-", "")
        try:
            with context.request_context(request):
                form = ActivateTOTPForm(user=request.user, data={"code": clean_code})
                if not form.is_valid():
                    logger.info(
                        "TOTP confirmation failed validation",
                        extra={
                            "user_id": getattr(request.user, "id", None),
                            "errors": form.errors,
                        },
                    )
                    raise HttpError(400, form.errors)
                totp_auth_obj, rc_auth = totp_flows.activate_totp(request, form)
                # Clear the secret to avoid stale reuse after successful activation.
                request.session.pop(totp_auth.SECRET_SESSION_KEY, None)
                request.session.modified = True
                if rc_auth:
                    logger.info(
                        "TOTP confirmed with recovery codes issued",
                        extra={
                            "user_id": getattr(request.user, "id", None),
                            "recovery_codes": True,
                        },
                    )
                    return RecoveryCodes(rc_auth).get_unused_codes()
                logger.info(
                    "TOTP confirmed",
                    extra={"user_id": getattr(request.user, "id", None)},
                )
                return None
        except ReauthenticationRequired as err:
            logger.warning(
                "TOTP confirmation requires reauthentication",
                extra={"user_id": getattr(request.user, "id", None)},
            )
            raise HttpError(401, "reauth_required") from err

    @staticmethod
    def totp_disable(request) -> None:
        (
            _get_mfa_adapter,
            Authenticator,
            _RecoveryCodes,
            _ActivateTOTPForm,
            DeactivateTOTPForm,
            totp_flows,
        ) = _mfa_imports()
        auth = get_object_or_404(
            Authenticator,
            user=request.user,
            type=Authenticator.Type.TOTP,
        )
        try:
            with context.request_context(request):
                form = DeactivateTOTPForm(authenticator=auth, data={})
                if not form.is_valid():
                    logger.info(
                        "TOTP disable failed validation",
                        extra={
                            "user_id": getattr(request.user, "id", None),
                            "errors": form.errors,
                        },
                    )
                    raise HttpError(400, form.errors)
                totp_flows.deactivate_totp(request, auth)
        except ReauthenticationRequired as err:
            logger.warning(
                "TOTP disable requires reauthentication",
                extra={"user_id": getattr(request.user, "id", None)},
            )
            raise HttpError(401, "reauth_required") from err
        logger.info(
            "TOTP disabled",
            extra={
                "user_id": getattr(request.user, "id", None),
                "authenticator_id": getattr(auth, "id", None),
            },
        )

    @staticmethod
    def regenerate_recovery_codes(request) -> list[str]:
        (
            _get_mfa_adapter,
            Authenticator,
            RecoveryCodes,
            _ActivateTOTPForm,
            _DeactivateTOTPForm,
            _totp_flows,
        ) = _mfa_imports()
        try:
            with context.request_context(request):
                has_factor = Authenticator.objects.filter(
                    user=request.user,
                    type__in=[Authenticator.Type.TOTP, Authenticator.Type.WEBAUTHN],
                ).exists()
                if not has_factor:
                    logger.info(
                        "Recovery code regeneration blocked: MFA not enabled",
                        extra={"user_id": getattr(request.user, "id", None)},
                    )
                    raise HttpError(
                        400,
                        {
                            "code": "MFA_REQUIRED",
                            "message": "Сначала включите MFA",
                        },
                    )
                rc = Authenticator.objects.filter(
                    user=request.user, type=Authenticator.Type.RECOVERY_CODES
                ).first()
                if rc:
                    rc.delete()
                rc_new = RecoveryCodes.activate(request.user)
                codes = RecoveryCodes(rc_new.instance).get_unused_codes()
                logger.info(
                    "Recovery codes regenerated",
                    extra={"user_id": getattr(request.user, "id", None)},
                )
                return codes
        except ReauthenticationRequired as err:
            logger.warning(
                "Recovery code regeneration requires reauthentication",
                extra={"user_id": getattr(request.user, "id", None)},
            )
            raise HttpError(401, "reauth_required") from err
        raise HttpError(400, "unable to regenerate codes")

    @staticmethod
    def rotate_recovery_codes(user) -> list[str]:
        (
            _get_mfa_adapter,
            Authenticator,
            RecoveryCodes,
            _ActivateTOTPForm,
            _DeactivateTOTPForm,
            _totp_flows,
        ) = _mfa_imports()
        rc = Authenticator.objects.filter(
            user=user, type=Authenticator.Type.RECOVERY_CODES
        ).first()
        if rc:
            rc.delete()
        rc_new = RecoveryCodes.activate(user)
        return RecoveryCodes(rc_new.instance).get_unused_codes()


__all__ = ["MfaService"]
