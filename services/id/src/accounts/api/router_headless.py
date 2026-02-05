from ninja import Body, Router
from ninja.errors import HttpError
from ninja.responses import Response

from accounts.services.auth import AuthService
from accounts.services.form_token import FormTokenPurpose, FormTokenService
from accounts.services.headless import HeadlessService
from accounts.services.passkeys import PasskeyService
from accounts.services.rate_limit import RateLimitService
from accounts.transport.schemas import (
    ErrorOut,
    FormTokenOut,
    LoginIn,
    LoginOut,
    PasskeyLoginBeginOut,
    PasskeyLoginCompleteIn,
    PasskeyLoginOut,
    SignupIn,
)

headless_router = Router(tags=["Auth"])
REQUIRED_BODY = Body(...)


def _client_ip(request) -> str | None:
    forwarded_for = request.headers.get("X-Forwarded-For") or ""
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _extract_form_token(request, payload) -> str | None:
    token = getattr(payload, "form_token", None)
    if token:
        return token
    header_token = request.headers.get("X-Form-Token")
    return header_token


@headless_router.post(
    "/login",
    response={
        200: LoginOut,
        400: ErrorOut,
        401: ErrorOut,
        429: ErrorOut,
        500: ErrorOut,
    },
    summary="Headless login, issues X-Session-Token",
    operation_id="headless_login",
)
def login(request, payload: LoginIn = REQUIRED_BODY):
    client_ip = _client_ip(request)
    form_token = _extract_form_token(request, payload)
    FormTokenService.consume(
        form_token, purpose=FormTokenPurpose.LOGIN, client_ip=client_ip
    )
    rate = RateLimitService.login_attempt(ip=client_ip, email=payload.email)
    if rate.blocked:
        body = {
            "code": "LOGIN_RATE_LIMITED",
            "message": "Слишком много попыток входа, попробуйте позже",
            "retry_after_seconds": rate.retry_after or 0,
        }
        headers = {"Retry-After": str(rate.retry_after or 0)}
        return Response(body, status=429, headers=headers)

    result = HeadlessService.login(
        request,
        payload.email,
        payload.password,
        mfa_code=getattr(payload, "mfa_code", None),
        recovery_code=getattr(payload, "recovery_code", None),
    )
    st = result.get("session_token") or ""
    recovery_codes = result.get("recovery_codes")
    identifiers = []
    if client_ip:
        identifiers.append(f"ip:{client_ip}")
    if payload.email:
        identifiers.append(f"email:{payload.email.strip().lower()}")
    RateLimitService.reset("login", identifiers)
    user_profile = None
    try:
        user_profile = AuthService.profile(request.user, request=request)
    except Exception:
        user_profile = None
    token_pair = AuthService.issue_pair_for_session(request, request.user)
    body = {
        "meta": {"session_token": st},
        "user": user_profile,
        "access_token": token_pair.access,
        "refresh_token": token_pair.refresh,
        "recovery_codes": recovery_codes,
    }
    return Response(
        body,
        headers={"X-Session-Token": st, "Cache-Control": "no-store"},
    )


@headless_router.post(
    "/signup",
    response={
        201: LoginOut,
        200: LoginOut,
        400: ErrorOut,
        409: ErrorOut,
        429: ErrorOut,
    },
    summary="Headless signup + login, issues X-Session-Token",
    operation_id="headless_signup",
)
def signup(request, payload: SignupIn = REQUIRED_BODY):
    client_ip = _client_ip(request)
    form_token = _extract_form_token(request, payload)
    FormTokenService.consume(
        form_token, purpose=FormTokenPurpose.REGISTER, client_ip=client_ip
    )
    rate = RateLimitService.register_attempt(ip=client_ip, email=payload.email)
    if rate.blocked:
        body = {
            "code": "REGISTER_RATE_LIMITED",
            "message": "Слишком много попыток регистрации, попробуйте позже",
            "retry_after_seconds": rate.retry_after or 0,
        }
        headers = {"Retry-After": str(rate.retry_after or 0)}
        return Response(body, status=429, headers=headers)

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

    st = HeadlessService.signup(
        request,
        payload.username,
        payload.email,
        payload.password,
        language=payload.language,
        timezone_name=payload.timezone,
        consent_data_processing=bool(payload.consent_data_processing),
        consent_marketing=bool(payload.consent_marketing),
        is_minor=bool(payload.is_minor),
        guardian_email=payload.guardian_email,
        guardian_consent=bool(payload.guardian_consent),
        birth_date=birth_date,
    )
    identifiers = []
    if client_ip:
        identifiers.append(f"ip:{client_ip}")
    if payload.email:
        identifiers.append(f"email:{payload.email.strip().lower()}")
    RateLimitService.reset("register", identifiers)

    token_pair = AuthService.issue_pair_for_session(request, request.user)
    return Response(
        {
            "meta": {"session_token": st},
            "user": AuthService.profile(request.user, request=request),
            "access_token": token_pair.access,
            "refresh_token": token_pair.refresh,
        },
        status=201,
        headers={"X-Session-Token": st, "Cache-Control": "no-store"},
    )


@headless_router.get(
    "/form_token",
    response={200: FormTokenOut, 400: ErrorOut},
    summary="Issue single-use form token for auth forms",
    operation_id="headless_form_token",
)
def form_token(request, purpose: str):
    if not FormTokenPurpose.is_allowed(purpose):
        raise HttpError(
            400,
            {
                "code": "VALIDATION_ERROR",
                "message": "Недопустимое значение purpose",
            },
        )
    issued = FormTokenService.issue(
        purpose=purpose,
        client_ip=_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    return FormTokenOut(form_token=issued.token, expires_in=issued.expires_in)


@headless_router.post(
    "/passkeys/login/begin",
    response={200: PasskeyLoginBeginOut},
    summary="Begin passkey authentication",
    operation_id="headless_passkey_login_begin",
)
def passkey_login_begin(request):
    opts = PasskeyService.begin_login(request)
    return PasskeyLoginBeginOut(request_options=opts)


@headless_router.post(
    "/passkeys/login/complete",
    response={200: PasskeyLoginOut, 400: ErrorOut},
    summary="Complete passkey authentication",
    operation_id="headless_passkey_login_complete",
)
def passkey_login_complete(request, payload: PasskeyLoginCompleteIn = REQUIRED_BODY):
    user, _ = PasskeyService.complete_login(request, payload.credential)
    st = HeadlessService.issue_session_token(request)
    user_profile = None
    try:
        user_profile = AuthService.profile(user, request=request)
    except Exception:
        user_profile = None
    token_pair = AuthService.issue_pair_for_session(request, user)
    return Response(
        {
            "meta": {"session_token": st},
            "user": user_profile,
            "access_token": token_pair.access,
            "refresh_token": token_pair.refresh,
        },
        headers={"X-Session-Token": st, "Cache-Control": "no-store"},
    )
