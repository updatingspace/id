from __future__ import annotations

import logging
from smtplib import SMTPException
from urllib.parse import urlencode

from allauth.account import app_settings
from allauth.account.adapter import DefaultAccountAdapter
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.db import transaction

logger = logging.getLogger(__name__)

NOTIFICATIONS = {
    "account/email/password_changed": (
        "Пароль изменён",
        "Пароль вашего аккаунта UpdSpace ID был изменён.",
    ),
    "account/email/password_reset": (
        "Пароль восстановлен",
        "Для вашего аккаунта UpdSpace ID установлен новый пароль. Старые сессии завершены. Для входа используйте новый пароль и настроенный способ MFA.",
    ),
    "account/email/email_confirmed": (
        "Email подтверждён",
        "Ваш адрес электронной почты подтверждён в UpdSpace ID. Теперь вы можете войти в аккаунт.",
    ),
    "account/email/email_changed": (
        "Email аккаунта изменён",
        "Адрес электронной почты вашего аккаунта UpdSpace ID был изменён.",
    ),
    "mfa/email/totp_activated": (
        "Двухфакторная защита включена",
        "Для вашего аккаунта UpdSpace ID включена проверка кодом из приложения-аутентификатора.",
    ),
    "mfa/email/totp_deactivated": (
        "Двухфакторная защита отключена",
        "В вашем аккаунте UpdSpace ID отключена проверка кодом из приложения-аутентификатора.",
    ),
    "mfa/email/recovery_codes_generated": (
        "Резервные коды обновлены",
        "Для вашего аккаунта UpdSpace ID созданы новые резервные коды. Храните их в безопасном месте.",
    ),
    "mfa/email/webauthn_added": (
        "Ключ доступа добавлен",
        "В ваш аккаунт UpdSpace ID добавлен ключ доступа (Passkey).",
    ),
    "mfa/email/webauthn_removed": (
        "Ключ доступа удалён",
        "Из вашего аккаунта UpdSpace ID удалён ключ доступа (Passkey).",
    ),
}


def frontend_url(path: str, **params: str) -> str:
    url = f"{settings.ID_FRONTEND_BASE_URL}{path}"
    # Fragments keep recovery secrets out of HTTP access logs and Referer headers.
    return f"{url}#{urlencode(params)}" if params else url


class AccountAdapter(DefaultAccountAdapter):
    @transaction.atomic
    def set_password(self, user, password):
        from accounts.services.sessions import SessionService

        super().set_password(user, password)
        # Keep legacy allauth password forms consistent with the public API.
        SessionService.revoke_all(user, reason="password_changed")

    def send_password_reset_mail(self, user, email, context):
        # Pending secondary addresses must not provide a route to take over an account.
        if email.strip().casefold() != (user.email or "").strip().casefold():
            return
        return super().send_password_reset_mail(user, email, context)

    def get_reset_password_from_key_url(self, key: str) -> str:
        return frontend_url("/reset-password", key=key)

    def get_email_confirmation_url(self, request, emailconfirmation) -> str:
        return frontend_url("/verify-email", key=emailconfirmation.key)

    def render_mail(self, template_prefix, email, context, headers=None):
        action_url = frontend_url("/account")
        action_label = "Открыть аккаунт"
        if template_prefix in {
            "account/email/email_confirmation",
            "account/email/email_confirmation_signup",
        }:
            title = "Подтвердите email"
            message = (
                "Подтвердите адрес электронной почты для вашего аккаунта UpdSpace ID."
            )
            action_url = context["activate_url"]
            action_label = "Подтвердить email"
            note = f"Ссылка действует {app_settings.EMAIL_CONFIRMATION_EXPIRE_DAYS} дн. Если вы не запрашивали письмо, просто проигнорируйте его."
        elif template_prefix == "account/email/password_reset_key":
            title = "Восстановление пароля"
            message = "Мы получили запрос на сброс пароля вашего аккаунта UpdSpace ID. Перейдите по ссылке, чтобы установить новый пароль."
            action_url = context["password_reset_url"]
            action_label = "Установить новый пароль"
            note = f"Ссылка действует {settings.PASSWORD_RESET_TIMEOUT // 60} мин. и перестанет работать после смены пароля. Если это были не вы, проигнорируйте письмо: пароль останется прежним."
        elif template_prefix in NOTIFICATIONS:
            title, message = NOTIFICATIONS[template_prefix]
            note = "Если вы не выполняли это действие, восстановите пароль и проверьте безопасность аккаунта."
        else:
            return super().render_mail(template_prefix, email, context, headers=headers)
        data = {
            "title": title,
            "message": message,
            "action_url": action_url,
            "action_label": action_label,
            "note": note,
            "recovery_url": frontend_url("/forgot-password"),
        }
        mail = EmailMultiAlternatives(
            subject=f"[UpdSpace ID] {title}",
            body=render_to_string("accounts/email/message.txt", data),
            from_email=self.get_from_email(),
            to=[email] if isinstance(email, str) else email,
            headers=headers,
        )
        mail.attach_alternative(
            render_to_string("accounts/email/message.html", data), "text/html"
        )
        return mail

    def send_notification_mail(self, template_prefix, user, context=None, email=None):
        # A transport outage must not undo a completed security action.
        try:
            super().send_notification_mail(
                template_prefix, user, context=context, email=email or user.email
            )
        except (SMTPException, OSError):
            logger.error(
                "Security email delivery failed", extra={"template": template_prefix}
            )
