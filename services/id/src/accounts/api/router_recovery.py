from ninja import Router, Schema
from pydantic import Field

from accounts.services.form_token import FormTokenPurpose, FormTokenService
from accounts.services.rate_limit import get_client_ip
from accounts.services.recovery import RecoveryService
from accounts.transport.schemas import ErrorOut, OkOut

recovery_router = Router(tags=["Auth"])
RESPONSES = {200: OkOut, 400: ErrorOut, 429: ErrorOut}


class RecoveryEmailIn(Schema):
    email: str = Field(min_length=3, max_length=254)
    form_token: str = Field(max_length=256)


class RecoveryKeyIn(Schema):
    key: str = Field(min_length=1, max_length=512)


class ResetPasswordIn(RecoveryKeyIn):
    password: str = Field(min_length=1, max_length=4096)


def consume_form(request, payload, purpose):
    FormTokenService.consume(
        payload.form_token, purpose=purpose, client_ip=get_client_ip(request)
    )
    RecoveryService.throttle(request, scope=purpose, email=payload.email)


@recovery_router.post("/password/reset/request", response=RESPONSES)
def request_password_reset(request, payload: RecoveryEmailIn):
    consume_form(request, payload, FormTokenPurpose.PASSWORD_RESET)
    RecoveryService.request_reset(request, payload.email)
    return {
        "ok": True,
        "message": "Если аккаунт с таким email существует, вы получите письмо для восстановления доступа.",
    }


@recovery_router.post("/password/reset/confirm", response=RESPONSES)
def confirm_password_reset(request, payload: ResetPasswordIn):
    RecoveryService.throttle(request, scope="password_reset_confirm")
    RecoveryService.reset_password(request, key=payload.key, password=payload.password)
    return {"ok": True, "message": "Пароль изменён. Войдите с новым паролем."}


@recovery_router.post("/email/verification/request", response=RESPONSES)
def request_email_verification(request, payload: RecoveryEmailIn):
    consume_form(request, payload, FormTokenPurpose.EMAIL_VERIFICATION)
    RecoveryService.resend_verification(request, payload.email)
    return {
        "ok": True,
        "message": "Если адрес ожидает подтверждения, вы получите письмо со ссылкой.",
    }


@recovery_router.post("/email/verification/confirm", response=RESPONSES)
def confirm_email(request, payload: RecoveryKeyIn):
    RecoveryService.throttle(request, scope="email_verification_confirm")
    RecoveryService.confirm_email(request, payload.key)
    return {"ok": True, "message": "Email подтверждён. Теперь можно войти в аккаунт."}
