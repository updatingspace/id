from __future__ import annotations

from urllib.parse import urlencode

from django.conf import settings
from django.core.mail import send_mail


def build_activation_link(*, token: str, tenant_slug: str) -> str:
    base = str(getattr(settings, "ID_ACTIVATION_BASE_URL", "") or "").rstrip("/")
    path = str(getattr(settings, "ID_ACTIVATION_PATH", "/activate") or "/activate")
    if not path.startswith("/"):
        path = "/" + path
    query = urlencode({"token": token, "tenant": tenant_slug})
    return f"{base}{path}?{query}"


def build_magic_link_url(*, token: str, redirect_to: str) -> str:
    base = str(getattr(settings, "ID_PUBLIC_BASE_URL", "") or "").rstrip("/")
    query = urlencode({"token": token, "redirect_to": redirect_to})
    return f"{base}/auth/magic-link/consume?{query}"


def send_activation_email(
    *,
    email: str,
    tenant_slug: str,
    token: str,
    expires_at,
) -> None:
    link = build_activation_link(token=token, tenant_slug=tenant_slug)
    subject = "Activate your UpdSpace account"
    body = (
        "Your account has been approved.\n\n"
        f"Activate your account using this link:\n{link}\n\n"
        f"Expires at: {expires_at.isoformat() if expires_at else 'unknown'}\n"
    )
    send_mail(
        subject=subject,
        message=body,
        from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
        recipient_list=[email],
        fail_silently=True,
    )


def send_magic_link_email(
    *,
    email: str,
    link: str,
    expires_at,
) -> None:
    subject = "Your UpdSpace magic link"
    body = (
        "Use this link to sign in:\n"
        f"{link}\n\n"
        f"Expires at: {expires_at.isoformat() if expires_at else 'unknown'}\n"
    )
    send_mail(
        subject=subject,
        message=body,
        from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
        recipient_list=[email],
        fail_silently=True,
    )
