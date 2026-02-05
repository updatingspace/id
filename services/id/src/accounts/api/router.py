from allauth.headless.contrib.ninja.security import x_session_token_auth
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from ninja import Body, File, Router
from ninja.errors import HttpError
from ninja.files import UploadedFile

from accounts.services.deletion import AccountDeletionService
from accounts.services.emailing import EmailService
from accounts.services.export import ExportService
from accounts.services.mfa import MfaService
from accounts.services.passkeys import PasskeyService
from accounts.services.preferences import ConsentService, PreferencesService
from accounts.services.profile import ProfileService
from accounts.services.reauth import ReauthService
from accounts.services.sessions import SessionService
from accounts.services.timezone import TimezoneService
from accounts.transport.schemas import (
    AuthenticatorsOut,
    AvatarOut,
    AuthorizedAppsOut,
    AuthorizedAppOut,
    ChangeEmailIn,
    ConsentListOut,
    ConsentRecordOut,
    DataExportOut,
    EmailStatusOut,
    ErrorOut,
    LoginEventOut,
    LoginHistoryOut,
    MfaStatusOut,
    OkOut,
    PreferencesOut,
    PreferencesUpdateIn,
    PasskeyBeginIn,
    PasskeyBeginOut,
    PasskeyCompleteIn,
    PasskeyCompleteOut,
    PasskeyDeleteIn,
    PasskeyRenameIn,
    ProfileUpdateIn,
    RecoveryCodesOut,
    RevokeOut,
    RevokeSessionsIn,
    AccountDeleteIn,
    ReauthIn,
    RevokeAppIn,
    SessionsOut,
    TimezoneInfo,
    TimezonesOut,
    TotpBeginOut,
    TotpConfirmIn,
    TotpConfirmOut,
)
from idp.models import OidcConsent, OidcToken

User = get_user_model()
account_router = Router(tags=["Account"], auth=[x_session_token_auth])
REQUIRED_BODY = Body(...)
REQUIRED_FILE = File(...)


def _require_authenticated_user(request) -> User:
    user = getattr(request, "auth", None)
    if not user or not getattr(user, "is_authenticated", False):
        raise HttpError(
            401,
            {"code": "UNAUTHORIZED", "message": "Требуется авторизация"},
        )
    # Make sure downstream allauth flows see the authenticated user
    request.user = user
    return user


@account_router.patch(
    "/profile",
    response={200: OkOut, 401: ErrorOut},
    summary="Update profile fields",
    operation_id="account_update_profile",
)
@transaction.atomic
def account_update_profile(request, payload: ProfileUpdateIn = REQUIRED_BODY):
    user = _require_authenticated_user(request)
    ProfileService.update_name(
        user, first=payload.first_name, last=payload.last_name
    )
    if payload.phone_number is not None or payload.birth_date is not None:
        birth_date = None
        if payload.birth_date:
            try:
                from datetime import date

                birth_date = date.fromisoformat(payload.birth_date)
            except Exception:
                raise HttpError(
                    400,
                    {
                        "code": "VALIDATION_ERROR",
                        "message": "Неверный формат birth_date (YYYY-MM-DD)",
                    },
                )
        ProfileService.update_profile_fields(
            user,
            phone_number=payload.phone_number,
            birth_date=birth_date,
        )
    return OkOut(ok=True, message="Профиль обновлён")


@account_router.post(
    "/avatar",
    response={200: AvatarOut, 400: ErrorOut, 401: ErrorOut},
    summary="Upload/replace user avatar",
    operation_id="account_upload_avatar",
)
def upload_avatar(request, avatar: UploadedFile = REQUIRED_FILE):
    user = _require_authenticated_user(request)
    SessionService.assert_session_allowed(request)
    SessionService.touch(request, user)
    ProfileService.save_avatar(user, avatar)
    state = ProfileService.avatar_state(user, request)
    return AvatarOut(
        ok=True,
        message="Аватар обновлён",
        avatar_url=state.url,
        avatar_source=state.source,
        avatar_gravatar_enabled=state.gravatar_enabled,
    )


@account_router.delete(
    "/avatar",
    response={200: AvatarOut, 401: ErrorOut},
    summary="Delete avatar and fallback to initials",
    operation_id="account_delete_avatar",
)
def delete_avatar(request):
    user = _require_authenticated_user(request)
    SessionService.assert_session_allowed(request)
    SessionService.touch(request, user)
    ProfileService.remove_avatar(user)
    state = ProfileService.avatar_state(user, request)
    return AvatarOut(
        ok=True,
        message="Аватар удалён, будет показана заглушка",
        avatar_url=state.url,
        avatar_source=state.source,
        avatar_gravatar_enabled=state.gravatar_enabled,
    )


@account_router.get(
    "/email",
    response={200: EmailStatusOut, 401: ErrorOut},
    summary="Get primary email & verification state",
    operation_id="account_email_status",
)
def account_email_status(request):
    user = _require_authenticated_user(request)
    return EmailService.status(user)


@account_router.post(
    "/email/change",
    response={200: OkOut, 400: ErrorOut, 401: ErrorOut},
    summary="Request email change (sends confirmation)",
    operation_id="account_change_email",
)
@transaction.atomic
def account_change_email(request, payload: ChangeEmailIn = REQUIRED_BODY):
    user = _require_authenticated_user(request)
    EmailService.request_change(request, user, new_email=payload.new_email)
    return OkOut(
        ok=True, message="Проверьте почту, чтобы подтвердить новый адрес"
    )


@account_router.post(
    "/email/resend",
    response={200: OkOut, 401: ErrorOut},
    summary="Resend email confirmation",
    operation_id="account_resend_email",
)
def account_resend_email_verification(request):
    user = _require_authenticated_user(request)
    EmailService.resend_confirmation(request, user)
    return OkOut(ok=True, message="Письмо с подтверждением отправлено")


@account_router.get(
    "/sessions",
    response={200: SessionsOut, 401: ErrorOut},
    summary="List current user sessions",
    operation_id="account_list_sessions",
)
def list_sessions(request):
    user = _require_authenticated_user(request)
    SessionService.assert_session_allowed(request)
    SessionService.touch(request, user)
    return SessionsOut(sessions=SessionService.list(request, user))


@account_router.get(
    "/preferences",
    response={200: PreferencesOut, 401: ErrorOut},
    summary="Get privacy and communication preferences",
    operation_id="account_preferences_get",
)
def account_preferences_get(request):
    user = _require_authenticated_user(request)
    prefs = PreferencesService.get(user)
    return PreferencesOut(**prefs)


@account_router.patch(
    "/preferences",
    response={200: PreferencesOut, 401: ErrorOut},
    summary="Update privacy and communication preferences",
    operation_id="account_preferences_update",
)
def account_preferences_update(
    request, payload: PreferencesUpdateIn = REQUIRED_BODY
):
    user = _require_authenticated_user(request)
    PreferencesService.update(
        user,
        language=payload.language,
        timezone_name=payload.timezone,
        marketing_opt_in=payload.marketing_opt_in,
        privacy_scope_defaults=payload.privacy_scope_defaults,
        source="account",
    )
    return PreferencesOut(**PreferencesService.get(user))


@account_router.get(
    "/timezones",
    response={200: TimezonesOut},
    summary="Get list of available timezones",
    operation_id="account_timezones_list",
    auth=None,  # Public endpoint
)
def account_timezones_list(request):
    """
    Get list of all available timezones with display names and UTC offsets.
    This is a public endpoint that doesn't require authentication.
    """
    timezones_info = TimezoneService.get_all_timezones()
    return TimezonesOut(
        timezones=[
            TimezoneInfo(
                name=tz.name,
                display_name=tz.display_name,
                offset=tz.offset,
            )
            for tz in timezones_info
        ]
    )


@account_router.get(
    "/consents",
    response={200: ConsentListOut, 401: ErrorOut},
    summary="List user consents",
    operation_id="account_consents_list",
)
def account_consents_list(request):
    user = _require_authenticated_user(request)
    consents = [
        ConsentRecordOut(
            kind=c.kind,
            version=c.version,
            granted_at=c.granted_at,
            revoked_at=c.revoked_at,
            source=c.source,
            meta=c.meta,
        )
        for c in user.consents.order_by("-granted_at")[:200]
    ]
    return ConsentListOut(consents=consents)


@account_router.post(
    "/consents/revoke",
    response={200: OkOut, 400: ErrorOut, 401: ErrorOut},
    summary="Revoke consent by type",
    operation_id="account_consents_revoke",
)
def account_consents_revoke(request, kind: str):
    user = _require_authenticated_user(request)
    if kind == "data_processing":
        raise HttpError(
            400,
            {
                "code": "CONSENT_REQUIRED",
                "message": "Отзыв согласия на обработку данных требует удаления аккаунта",
            },
        )
    record = ConsentService.revoke(user, kind=kind, source="account")
    if not record:
        raise HttpError(
            400,
            {"code": "CONSENT_NOT_FOUND", "message": "Согласие не найдено"},
        )
    if kind == "marketing":
        PreferencesService.update(user, marketing_opt_in=False, source="account")
    return OkOut(ok=True, message="Согласие отозвано")


@account_router.get(
    "/login-history",
    response={200: LoginHistoryOut, 401: ErrorOut},
    summary="List recent login events",
    operation_id="account_login_history",
)
def account_login_history(request):
    user = _require_authenticated_user(request)
    events = [
        LoginEventOut(
            status=e.status,
            ip_address=e.ip_address,
            user_agent=e.user_agent,
            device_id=e.device_id,
            is_new_device=e.is_new_device,
            reason=e.reason,
            created_at=e.created_at,
        )
        for e in user.login_events.order_by("-created_at")[:100]
    ]
    return LoginHistoryOut(events=events)


@account_router.get(
    "/oauth/apps",
    response={200: AuthorizedAppsOut, 401: ErrorOut},
    summary="List authorized OAuth/OIDC applications",
    operation_id="account_oauth_apps_list",
)
def account_oauth_apps_list(request):
    user = _require_authenticated_user(request)
    consents = (
        OidcConsent.objects.filter(user=user)
        .select_related("client")
        .order_by("-updated_at")
    )
    items = [
        AuthorizedAppOut(
            client_id=c.client.client_id,
            name=c.client.name,
            logo_url=c.client.logo_url or None,
            scopes=list(c.scopes or []),
            last_used_at=c.last_used_at,
            created_at=c.created_at,
        )
        for c in consents
    ]
    return AuthorizedAppsOut(items=items)


@account_router.post(
    "/oauth/apps/revoke",
    response={200: OkOut, 400: ErrorOut, 401: ErrorOut},
    summary="Revoke OAuth/OIDC application access",
    operation_id="account_oauth_apps_revoke",
)
def account_oauth_apps_revoke(request, payload: RevokeAppIn = REQUIRED_BODY):
    user = _require_authenticated_user(request)
    consent = (
        OidcConsent.objects.filter(user=user, client__client_id=payload.client_id)
        .select_related("client")
        .first()
    )
    if not consent:
        raise HttpError(
            400,
            {"code": "APP_NOT_FOUND", "message": "Приложение не найдено"},
        )
    OidcToken.objects.filter(user=user, client=consent.client).update(
        revoked_at=timezone.now()
    )
    consent.delete()
    return OkOut(ok=True, message="Доступ отозван")


@account_router.post(
    "/data/export",
    response={200: DataExportOut, 400: ErrorOut, 401: ErrorOut},
    summary="Export user data (requires reauthentication)",
    operation_id="account_data_export",
)
def account_data_export(request, payload: ReauthIn = REQUIRED_BODY):
    user = _require_authenticated_user(request)
    ReauthService.verify(
        user,
        password=payload.password,
        mfa_code=payload.mfa_code,
        recovery_code=payload.recovery_code,
    )
    export_req = ExportService.create_request(user)
    try:
        payload_data = ExportService.build_payload(request, user)
        ExportService.mark_ready(export_req)
        return DataExportOut(ok=True, payload=payload_data)
    except Exception as exc:
        ExportService.mark_failed(export_req, str(exc))
        raise


@account_router.post(
    "/account/delete",
    response={200: OkOut, 400: ErrorOut, 401: ErrorOut},
    summary="Delete account (requires reauthentication)",
    operation_id="account_delete",
)
def account_delete(request, payload: AccountDeleteIn = REQUIRED_BODY):
    user = _require_authenticated_user(request)
    ReauthService.verify(
        user,
        password=payload.password,
        mfa_code=payload.mfa_code,
        recovery_code=payload.recovery_code,
    )
    AccountDeletionService.delete_account(
        request, user, reason=payload.reason
    )
    return OkOut(ok=True, message="Аккаунт удалён")


@account_router.post(
    "/sessions/bulk",
    response={200: RevokeOut, 401: ErrorOut},
    summary="Revoke sessions in bulk",
    operation_id="account_revoke_sessions_bulk",
)
def revoke_sessions_bulk(request, payload: RevokeSessionsIn = REQUIRED_BODY):
    _require_authenticated_user(request)
    return SessionService.revoke_bulk(request, payload)


@account_router.post(
    "/sessions/_bulk",
    response={200: RevokeOut, 401: ErrorOut},
    summary="Revoke sessions in bulk (compat)",
    operation_id="account_revoke_sessions_bulk_compat",
)
def revoke_sessions_bulk_compat(request, payload: RevokeSessionsIn = REQUIRED_BODY):
    _require_authenticated_user(request)
    return SessionService.revoke_bulk(request, payload)


@account_router.delete(
    "/sessions/{sid}",
    response={200: RevokeOut, 401: ErrorOut, 404: ErrorOut},
    summary="Revoke single session",
    operation_id="account_revoke_session",
)
def revoke_session(request, sid: str, reason: str | None = None):
    _require_authenticated_user(request)
    return SessionService.revoke_single(request, sid=sid, reason=reason)


@account_router.get(
    "/passkeys",
    response={200: AuthenticatorsOut, 401: ErrorOut},
    summary="List WebAuthn authenticators (passkeys)",
    operation_id="passkeys_list",
)
def list_passkeys(request):
    user = _require_authenticated_user(request)
    return PasskeyService.list_authenticators(user)


@account_router.post(
    "/passkeys/begin",
    response={200: PasskeyBeginOut, 401: ErrorOut},
    summary="Begin WebAuthn registration ceremony",
    operation_id="passkeys_begin",
)
def passkeys_begin(request, payload: PasskeyBeginIn = REQUIRED_BODY):
    user = _require_authenticated_user(request)
    options = PasskeyService.begin_registration(
        request, user, passwordless=payload.passwordless
    )
    return PasskeyBeginOut(creation_options=options)


@account_router.post(
    "/passkeys/delete",
    response={200: OkOut, 401: ErrorOut},
    summary="Delete WebAuthn authenticators",
    operation_id="passkeys_delete",
)
def delete_passkeys(request, payload: PasskeyDeleteIn = REQUIRED_BODY):
    user = _require_authenticated_user(request)
    count = PasskeyService.delete(request, user, payload.ids)
    return OkOut(ok=True, message=f"Удалено {count} Passkey")


@account_router.post(
    "/passkeys/rename",
    response={200: OkOut, 401: ErrorOut},
    summary="Rename WebAuthn authenticator",
    operation_id="passkeys_rename",
)
def rename_passkey(request, payload: PasskeyRenameIn = REQUIRED_BODY):
    _require_authenticated_user(request)
    PasskeyService.rename(
        request,
        authenticator_id=payload.authenticator_id,
        new_name=payload.new_name,
    )
    return OkOut(ok=True, message="Название обновлено")


@account_router.post(
    "/passkeys/complete",
    response={200: PasskeyCompleteOut, 401: ErrorOut, 400: ErrorOut},
    summary="Complete WebAuthn registration",
    operation_id="passkeys_complete",
)
def passkeys_complete(request, payload: PasskeyCompleteIn = REQUIRED_BODY):
    _require_authenticated_user(request)
    name = payload.name or "Passkey"
    auth, rc = PasskeyService.complete_registration(
        request, name=name, credential=payload.credential
    )
    rc_codes = None
    if rc and rc.type == rc.Type.RECOVERY_CODES:
        from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes

        rc_codes = RecoveryCodes(rc).get_unused_codes()
    auth_out = {
        "id": str(auth.id),
        "name": auth.data.get("name"),
        "type": "webauthn",
        "created_at": int(auth.created_at.timestamp()),
        "last_used_at": (
            int(auth.last_used_at.timestamp()) if auth.last_used_at else None
        ),
        "is_passwordless": bool(
            auth.data.get("credential", {})
            .get("clientExtensionResults", {})
            .get("credProps", {})
            .get("rk")
        ),
    }
    return PasskeyCompleteOut(ok=True, authenticator=auth_out, recovery_codes=rc_codes)


@account_router.get(
    "/mfa/status",
    response={200: MfaStatusOut, 401: ErrorOut},
    summary="MFA status (TOTP/WebAuthn/recovery)",
    operation_id="mfa_status",
)
def mfa_status(request):
    user = _require_authenticated_user(request)
    return MfaService.status(user)


@account_router.post(
    "/mfa/totp/begin",
    response={200: TotpBeginOut, 401: ErrorOut},
    summary="Start TOTP setup (returns QR + secret)",
    operation_id="mfa_totp_begin",
)
def mfa_totp_begin(request):
    _require_authenticated_user(request)
    return MfaService.totp_begin(request)


@account_router.post(
    "/mfa/totp/confirm",
    response={200: TotpConfirmOut, 400: ErrorOut, 401: ErrorOut},
    summary="Confirm TOTP code and activate",
    operation_id="mfa_totp_confirm",
)
def mfa_totp_confirm(request, payload: TotpConfirmIn = REQUIRED_BODY):
    _require_authenticated_user(request)
    rc = MfaService.totp_confirm(request, payload.code)
    return TotpConfirmOut(ok=True, recovery_codes=rc)


@account_router.post(
    "/mfa/totp/disable",
    response={200: OkOut, 400: ErrorOut, 401: ErrorOut, 404: ErrorOut},
    summary="Disable TOTP",
    operation_id="mfa_totp_disable",
)
def mfa_totp_disable(request):
    _require_authenticated_user(request)
    MfaService.totp_disable(request)
    return OkOut(ok=True, message="TOTP отключена")


@account_router.post(
    "/mfa/recovery/regenerate",
    response={200: RecoveryCodesOut, 400: ErrorOut, 401: ErrorOut, 404: ErrorOut},
    summary="Regenerate recovery codes",
    operation_id="mfa_recovery_regenerate",
)
def mfa_recovery_regenerate(request):
    _require_authenticated_user(request)
    codes = MfaService.regenerate_recovery_codes(request)
    return RecoveryCodesOut(recovery_codes=codes)
