from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import urlencode

from allauth.socialaccount.models import SocialAccount, SocialToken
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers import registry
from django.conf import settings as dj_settings
from django.urls import NoReverseMatch, reverse
from ninja.errors import HttpError

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class OAuthService:
    @staticmethod
    def configured_provider_ids() -> set[str]:
        from_db = set(SocialApp.objects.values_list("provider", flat=True))
        from_settings = set()
        providers_cfg = getattr(dj_settings, "SOCIALACCOUNT_PROVIDERS", {}) or {}
        for pid, conf in providers_cfg.items():
            apps = conf.get("APPS") or conf.get("apps")
            if apps:
                from_settings.add(pid)
        return from_db | from_settings

    @staticmethod
    def list_providers() -> list[dict]:
        configured = OAuthService.configured_provider_ids()
        providers = [
            {"id": pid, "name": name}
            for pid, name in registry.as_choices()
            if pid in configured
        ]
        logger.info(
            "OAuth providers listed",
            extra={"configured": sorted(configured), "count": len(providers)},
        )
        return providers

    @staticmethod
    def link_provider(provider: str, next_path: str = "/account/security") -> dict:
        installed = {pid for pid, _ in registry.as_choices()}
        if provider not in installed:
            logger.warning(
                "OAuth link request rejected: unknown provider",
                extra={"provider": provider},
            )
            raise HttpError(404, "unknown provider")
        try:
            path = reverse("socialaccount_login", kwargs={"provider": provider})
        except NoReverseMatch:
            try:
                path = reverse(f"{provider}_login")
            except NoReverseMatch as inner_err:
                raise HttpError(404, "unknown provider") from inner_err
        method = (
            "GET"
            if getattr(dj_settings, "SOCIALACCOUNT_LOGIN_ON_GET", False)
            else "POST"
        )
        url = f"{path}?{urlencode({'process': 'connect', 'next': next_path})}"
        logger.info(
            "OAuth link URL issued",
            extra={
                "provider": provider,
                "method": method,
                "next_path": next_path,
            },
        )
        return {"authorize_url": url, "method": method}

    @staticmethod
    def login_provider(provider: str, next_path: str = "/") -> dict:
        installed = {pid for pid, _ in registry.as_choices()}
        if provider not in installed:
            logger.warning(
                "OAuth login request rejected: unknown provider",
                extra={"provider": provider},
            )
            raise HttpError(404, "unknown provider")
        try:
            path = reverse("socialaccount_login", kwargs={"provider": provider})
        except NoReverseMatch:
            try:
                path = reverse(f"{provider}_login")
            except NoReverseMatch as inner_err:
                raise HttpError(404, "unknown provider") from inner_err
        method = (
            "GET"
            if getattr(dj_settings, "SOCIALACCOUNT_LOGIN_ON_GET", False)
            else "POST"
        )
        url = f"{path}?{urlencode({'process': 'login', 'next': next_path})}"
        logger.info(
            "OAuth login URL issued",
            extra={"provider": provider, "method": method, "next_path": next_path},
        )
        return {"authorize_url": url, "method": method}

    @staticmethod
    def unlink_provider(user, provider: str) -> None:
        account = SocialAccount.objects.filter(user=user, provider=provider).first()
        if not account:
            raise HttpError(404, "not linked")
        SocialToken.objects.filter(account=account).delete()
        account.delete()
        logger.info(
            "OAuth provider unlinked",
            extra={"user_id": getattr(user, "id", None), "provider": provider},
        )
