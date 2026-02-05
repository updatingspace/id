from __future__ import annotations

import hashlib
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import timedelta
from io import BytesIO

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction
from django.utils import timezone
from ninja.errors import HttpError
from PIL import Image, ImageOps

from accounts.models import UserProfile

User = get_user_model()
logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AvatarState:
    url: str | None
    source: str
    gravatar_enabled: bool


@dataclass(slots=True)
class ProfileService:
    AVATAR_SIZE = 512
    MAX_FILE_BYTES = 6 * 1024 * 1024
    GRAVATAR_TTL = timedelta(days=7)
    AVATAR_FORMAT = "JPEG"
    AVATAR_QUALITY = 88

    @staticmethod
    def _ensure_profile(user: User) -> UserProfile:
        profile, _ = UserProfile.objects.get_or_create(user=user)
        return profile

    @staticmethod
    @transaction.atomic
    def update_name(
        user: User, *, first: str | None = None, last: str | None = None
    ) -> None:
        to_update: list[str] = []
        if first is not None:
            user.first_name = (first or "").strip()
            to_update.append("first_name")
        if last is not None:
            user.last_name = (last or "").strip()
            to_update.append("last_name")
        if to_update:
            user.save(update_fields=to_update)
            logger.info(
                "User profile name updated",
                extra={
                    "user_id": getattr(user, "id", None),
                    "fields": to_update,
                },
            )

    @staticmethod
    @transaction.atomic
    def update_profile_fields(
        user: User,
        *,
        phone_number: str | None = None,
        birth_date=None,
    ) -> None:
        profile = ProfileService._ensure_profile(user)
        to_update: list[str] = []
        if phone_number is not None:
            profile.phone_number = phone_number.strip()
            profile.phone_verified = False
            to_update.extend(["phone_number", "phone_verified"])
        if birth_date is not None:
            profile.birth_date = birth_date
            to_update.append("birth_date")
        if to_update:
            profile.save(update_fields=to_update + ["updated_at"])
            logger.info(
                "User profile fields updated",
                extra={"user_id": getattr(user, "id", None), "fields": to_update},
            )

    @classmethod
    def _read_bytes(cls, avatar: UploadedFile) -> bytes:
        avatar.seek(0)
        data = avatar.read()
        if not data:
            raise HttpError(400, "Файл пустой")
        if len(data) > cls.MAX_FILE_BYTES:
            raise HttpError(400, "Файл слишком большой (макс 6 МБ)")
        return data

    @classmethod
    def _process_image(cls, raw: bytes) -> bytes:
        if len(raw) > cls.MAX_FILE_BYTES:
            raise HttpError(400, "Файл слишком большой (макс 6 МБ)")
        try:
            with Image.open(BytesIO(raw)) as img:
                img = ImageOps.exif_transpose(img)
                img = img.convert("RGB")
                width, height = img.size
                if width == 0 or height == 0:
                    raise ValueError("invalid image dimensions")
                side = min(width, height)
                left = (width - side) // 2
                upper = (height - side) // 2
                img = img.crop((left, upper, left + side, upper + side))
                img = img.resize(
                    (cls.AVATAR_SIZE, cls.AVATAR_SIZE),
                    resample=Image.Resampling.LANCZOS,
                )
                buffer = BytesIO()
                img.save(
                    buffer,
                    cls.AVATAR_FORMAT,
                    quality=cls.AVATAR_QUALITY,
                    optimize=True,
                )
                return buffer.getvalue()
        except HttpError:
            raise
        except Exception as exc:
            logger.info("Avatar processing failed", exc_info=exc)
            raise HttpError(400, "Не удалось прочитать изображение") from exc

    @classmethod
    def _avatar_filename(cls, user: User, prefix: str = "avatar") -> str:
        suffix = timezone.now().strftime("%Y%m%dT%H%M%S")
        return f"{prefix}_{getattr(user, 'id', 'user')}_{suffix}.jpg"

    @classmethod
    def _replace_avatar(
        cls,
        profile: UserProfile,
        data: bytes,
        filename: str,
        *,
        source: str,
        disable_gravatar: bool,
        touched_at=None,
    ) -> AvatarState:
        touched_at = touched_at or timezone.now()
        if profile.avatar:
            profile.avatar.delete(save=False)
        profile.avatar.save(filename, ContentFile(data), save=False)
        profile.avatar_source = source
        if disable_gravatar:
            profile.gravatar_enabled = False
        profile.gravatar_checked_at = touched_at
        profile.save(
            update_fields=[
                "avatar",
                "avatar_source",
                "gravatar_enabled",
                "gravatar_checked_at",
                "updated_at",
            ]
        )
        return AvatarState(
            url=profile.avatar.url,
            source=profile.avatar_source,
            gravatar_enabled=profile.gravatar_enabled,
        )

    @classmethod
    def save_avatar(cls, user: User, avatar: UploadedFile) -> AvatarState:
        """
        Store uploaded avatar with mandatory processing (square, downscaled).
        Disables future Gravatar auto-sync.
        """
        profile = cls._ensure_profile(user)
        processed = cls._process_image(cls._read_bytes(avatar))
        result = cls._replace_avatar(
            profile,
            processed,
            cls._avatar_filename(user, "upload"),
            source=UserProfile.AvatarSource.UPLOAD,
            disable_gravatar=True,
        )
        logger.info(
            "Avatar updated from upload",
            extra={
                "user_id": getattr(user, "id", None),
                "source": result.source,
                "gravatar_enabled": result.gravatar_enabled,
            },
        )
        return result

    @classmethod
    def remove_avatar(cls, user: User) -> AvatarState:
        profile = cls._ensure_profile(user)
        if profile.avatar:
            profile.avatar.delete(save=True)
        UserProfile.objects.filter(pk=profile.pk).update(
            avatar=None,
            avatar_source=UserProfile.AvatarSource.NONE,
            gravatar_enabled=False,
            gravatar_checked_at=timezone.now(),
            updated_at=timezone.now(),
        )
        refreshed = UserProfile.objects.get(pk=profile.pk)
        user.profile = refreshed
        logger.info(
            "Avatar removed",
            extra={"user_id": getattr(user, "id", None)},
        )
        return AvatarState(
            url=None,
            source=refreshed.avatar_source,
            gravatar_enabled=refreshed.gravatar_enabled,
        )

    @classmethod
    def avatar_state(cls, user: User, request=None) -> AvatarState:
        profile = cls._ensure_profile(user)
        url = None
        if profile.avatar:
            try:
                if not profile.avatar.storage.exists(profile.avatar.name):
                    logger.warning(
                        "Avatar file missing in storage",
                        extra={"user_id": getattr(user, "id", None), "avatar_name": profile.avatar.name},
                    )
                    return AvatarState(
                        url=None,
                        source=profile.avatar_source,
                        gravatar_enabled=profile.gravatar_enabled,
                    )
                url = profile.avatar.url
                if request:
                    url = request.build_absolute_uri(url)
                    proto = (
                        request.headers.get("X-Forwarded-Proto")
                        or request.META.get("HTTP_X_FORWARDED_PROTO")
                        or ""
                    ).split(",")[0]
                    if proto.strip().lower() == "https" and url.startswith("http://"):
                        url = "https://" + url[len("http://") :]
                    elif getattr(request, "is_secure", lambda: False)():
                        url = url.replace("http://", "https://", 1)
            except Exception:
                url = None
        return AvatarState(
            url=url,
            source=profile.avatar_source,
            gravatar_enabled=profile.gravatar_enabled,
        )

    @classmethod
    def _fetch_gravatar(cls, email: str) -> bytes | None:
        normalized = email.strip().lower()
        if not normalized:
            return None
        email_hash = hashlib.md5(normalized.encode("utf-8")).hexdigest()
        url = (
            "https://www.gravatar.com/avatar/" f"{email_hash}?d=404&s={cls.AVATAR_SIZE}"
        )
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "AEF Vote avatar sync",
                "Accept": "image/png,image/jpeg,image/webp,*/*;q=0.8",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as resp:
                if resp.status == 200:
                    return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            logger.warning(
                "Gravatar returned HTTP error",
                extra={"status": exc.code, "email_hash": email_hash},
            )
        except Exception as exc:  # pragma: no cover - сеть в тестах замокаем
            logger.warning(
                "Gravatar fetch failed",
                exc_info=exc,
                extra={"email_hash": email_hash},
            )
        return None

    @classmethod
    def maybe_refresh_gravatar(cls, user: User, *, force: bool = False) -> bool:
        """
        Pull avatar from Gravatar when allowed.

        - Works only if gravatar_enabled is True and user has not uploaded
          their own avatar.
        - Refreshes at most once per GRAVATAR_TTL unless forced.
        """
        if not getattr(settings, "GRAVATAR_AUTOLOAD_ENABLED", True):
            return False
        profile = cls._ensure_profile(user)
        if not profile.gravatar_enabled:
            return False
        if profile.avatar_source == UserProfile.AvatarSource.UPLOAD:
            return False
        email = (getattr(user, "email", "") or "").strip()
        if not email:
            return False
        now = timezone.now()
        if (
            not force
            and profile.gravatar_checked_at
            and now - profile.gravatar_checked_at < cls.GRAVATAR_TTL
        ):
            return False
        raw = cls._fetch_gravatar(email)
        profile.gravatar_checked_at = now
        if not raw:
            profile.save(update_fields=["gravatar_checked_at", "updated_at"])
            return False
        try:
            processed = cls._process_image(raw)
        except HttpError:
            profile.save(update_fields=["gravatar_checked_at", "updated_at"])
            return False
        cls._replace_avatar(
            profile,
            processed,
            cls._avatar_filename(user, "gravatar"),
            source=UserProfile.AvatarSource.GRAVATAR,
            disable_gravatar=False,
            touched_at=now,
        )
        logger.info(
            "Avatar refreshed from Gravatar",
            extra={"user_id": getattr(user, "id", None), "email": email},
        )
        return True
