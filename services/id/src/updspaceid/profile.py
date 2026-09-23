"""Read an account snapshot through its immutable identity binding."""

from types import SimpleNamespace

from accounts.models import AccountIdentity, UserPreferences, UserProfile
from updspaceid.models import User


def read_account_profile(identity: User) -> SimpleNamespace | None:
    binding = (
        AccountIdentity.objects.filter(identity=identity).select_related("user").first()
    )
    if not binding or not binding.user.is_active:
        return None
    profile = UserProfile.objects.filter(user=binding.user).first()
    prefs = UserPreferences.objects.filter(user=binding.user).first()
    return SimpleNamespace(
        first_name=binding.user.first_name or None,
        last_name=binding.user.last_name or None,
        phone_number=profile.phone_number if profile else None,
        phone_verified=profile.phone_verified if profile else None,
        birth_date=profile.birth_date.isoformat()
        if profile and profile.birth_date
        else None,
        language=prefs.language if prefs else None,
        timezone=prefs.timezone if prefs else None,
        avatar_url=profile.avatar.url if profile and profile.avatar else None,
        avatar_source=profile.avatar_source if profile else None,
        avatar_gravatar_enabled=profile.gravatar_enabled if profile else None,
    )
