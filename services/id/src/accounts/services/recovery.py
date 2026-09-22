from __future__ import annotations

import hashlib
import logging
from smtplib import SMTPException

from allauth.account.adapter import get_adapter
from allauth.account.forms import ResetPasswordForm, ResetPasswordKeyForm, UserTokenForm
from allauth.account.models import (
    EmailAddress,
    EmailConfirmation,
    EmailConfirmationHMAC,
)
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.forms import EmailField
from django.contrib.auth.password_validation import password_changed
from django.db import transaction
from ninja.errors import HttpError

from accounts.services.rate_limit import RateLimitService, get_client_ip
from accounts.services.sessions import SessionService

logger = logging.getLogger(__name__)
User = get_user_model()


def invalid_link() -> HttpError:
    return HttpError(
        400,
        {
            "code": "INVALID_RECOVERY_LINK",
            "message": "Ссылка недействительна или уже использована. Запросите новое письмо.",
        },
    )


class RecoveryService:
    @staticmethod
    def throttle(request, *, scope: str, email: str = "") -> None:
        identifiers = [f"ip:{get_client_ip(request) or 'unknown'}"]
        if email:
            identifiers.append(
                "email:" + hashlib.sha256(email.strip().lower().encode()).hexdigest()
            )
        rate = RateLimitService._register_attempt(
            scope, identifiers, limit=5, window_sec=600
        )
        if rate.blocked:
            raise HttpError(
                429,
                {
                    "code": "RECOVERY_RATE_LIMITED",
                    "message": "Слишком много запросов. Попробуйте через несколько минут.",
                    "retry_after_seconds": rate.retry_after,
                },
            )

    @staticmethod
    def request_reset(request, email: str) -> None:
        form = ResetPasswordForm(data={"email": email.strip()})
        if not form.is_valid():
            raise HttpError(
                400,
                {"code": "VALIDATION_ERROR", "message": "Введите корректный email."},
            )
        # Unknown/inactive addresses get the same response, without unsolicited mail.
        if form.users:
            try:
                form.save(request)
            except (SMTPException, OSError):
                # Do not reveal account existence through transport failures.
                logger.error("Password reset email delivery failed")

    @staticmethod
    @transaction.atomic
    def reset_password(request, *, key: str, password: str) -> None:
        uid, separator, token = key.partition("-")
        if not separator or not uid or not token:
            raise invalid_link()
        token_form = UserTokenForm(data={"uidb36": uid, "key": token})
        try:
            valid = token_form.is_valid()
        except (ValueError, OverflowError, TypeError):
            valid = False
        if not valid or not token_form.reset_user.is_active:
            raise invalid_link()
        user = token_form.reset_user
        form = ResetPasswordKeyForm(
            user=user, data={"password1": password, "password2": password}
        )
        if not form.is_valid():
            raise HttpError(
                400,
                {
                    "code": "VALIDATION_ERROR",
                    "message": " ".join(
                        message
                        for messages in form.errors.values()
                        for message in messages
                    ),
                },
            )
        previous = user.password
        user.set_password(password)
        # Compare-and-swap makes concurrent consumption single-use without row locks.
        if (
            User.objects.filter(pk=user.pk, password=previous, is_active=True).update(
                password=user.password
            )
            != 1
        ):
            raise invalid_link()
        password_changed(password, user=user)
        SessionService.revoke_all(user, reason="password_reset")
        adapter = get_adapter(request)
        transaction.on_commit(
            lambda: adapter.send_notification_mail("account/email/password_reset", user)
        )

    @staticmethod
    def resend_verification(request, email: str) -> None:
        try:
            email = EmailField().clean(email.strip())
        except ValidationError as err:
            raise HttpError(
                400,
                {"code": "VALIDATION_ERROR", "message": "Введите корректный email."},
            ) from err
        # Match the login address, not an unrelated pending secondary address.
        for user in User.objects.filter(email__iexact=email.strip(), is_active=True):
            address, _ = EmailAddress.objects.get_or_create(
                user=user,
                email=user.email,
                defaults={"primary": True, "verified": False},
            )
            if not address.verified:
                try:
                    address.send_confirmation(request)
                except (SMTPException, OSError):
                    logger.error("Email confirmation delivery failed")

    @staticmethod
    @transaction.atomic
    def confirm_email(request, key: str) -> None:
        confirmation = EmailConfirmationHMAC.from_key(
            key
        ) or EmailConfirmation.from_key(key)
        if not confirmation or not confirmation.email_address.user.is_active:
            raise invalid_link()
        address = confirmation.confirm(request)
        if not address:
            raise invalid_link()
        adapter = get_adapter(request)
        transaction.on_commit(
            lambda: adapter.send_notification_mail(
                "account/email/email_confirmed", address.user, email=address.email
            )
        )
