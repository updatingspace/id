from __future__ import annotations

from allauth.socialaccount.models import SocialAccount


def user_has_telegram_link(user) -> bool:
    """
    Проверяет, есть ли у пользователя связанный Telegram через социальные аккаунты.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False

    try:
        return SocialAccount.objects.filter(
            user=user, provider__iexact="telegram"
        ).exists()
    except Exception:
        # Консервативно допускаем отсутствие таблиц/провайдера
        return False


__all__ = ["user_has_telegram_link"]
