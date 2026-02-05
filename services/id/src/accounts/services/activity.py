from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from django.conf import settings
from django.utils import timezone

from accounts.models import LoginEvent, UserDevice
from accounts.services.emailing import EmailService

logger = logging.getLogger(__name__)


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class ActivityService:
    @staticmethod
    def _client_ip(request) -> str | None:
        forwarded_for = (
            request.headers.get("X-Forwarded-For")
            or request.META.get("HTTP_X_FORWARDED_FOR")
            or ""
        )
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR")

    @staticmethod
    def _user_agent(request) -> str:
        return (request.META.get("HTTP_USER_AGENT", "") or "")[:512]

    @staticmethod
    def _device_id(user_id: int | str | None, user_agent: str, ip: str | None) -> str:
        salt = str(getattr(settings, "DEVICE_FINGERPRINT_SALT", "device-salt"))
        ip_part = ""
        if ip and "." in ip:
            chunks = ip.split(".")
            ip_part = ".".join(chunks[:3]) + ".0"
        raw = f"{user_id}:{user_agent}:{ip_part}:{salt}"
        return _hash_value(raw)[:64]

    @staticmethod
    def record_login(
        request,
        *,
        user,
        success: bool,
        reason: str = "",
        meta: dict | None = None,
    ) -> LoginEvent:
        ip = ActivityService._client_ip(request)
        ua = ActivityService._user_agent(request)
        device_id = ActivityService._device_id(getattr(user, "id", None), ua, ip)
        now = timezone.now()
        is_new_device = False
        if success:
            device, created = UserDevice.objects.get_or_create(
                user=user,
                device_id=device_id,
                defaults={
                    "user_agent": ua,
                    "first_seen": now,
                    "last_seen": now,
                    "last_ip": ip,
                },
            )
            if not created:
                device.user_agent = ua or device.user_agent
                device.last_seen = now
                device.last_ip = ip
                device.save(update_fields=["user_agent", "last_seen", "last_ip"])
            is_new_device = bool(created)
        event = LoginEvent.objects.create(
            user=user,
            status=LoginEvent.Status.SUCCESS if success else LoginEvent.Status.FAILURE,
            ip_address=ip or None,
            ip_hash=_hash_value(ip or "") if ip else "",
            user_agent=ua,
            device_id=device_id,
            is_new_device=is_new_device,
            reason=reason,
            meta=meta or {},
        )
        if success and is_new_device:
            try:
                EmailService.send_new_device_alert(user, ip=ip, user_agent=ua)
            except Exception:
                logger.warning(
                    "Failed to send new device alert",
                    extra={"user_id": getattr(user, "id", None)},
                    exc_info=True,
                )
        return event

