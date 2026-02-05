from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScopeDefinition:
    name: str
    description: str
    required: bool = False
    claims: tuple[str, ...] = ()


SCOPES: dict[str, ScopeDefinition] = {
    "openid": ScopeDefinition(
        name="openid",
        description="Идентификатор пользователя",
        required=True,
        claims=("sub",),
    ),
    "profile": ScopeDefinition(
        name="profile",
        description="Базовый профиль (имя, аватар, язык)",
        claims=("name", "given_name", "family_name", "picture", "locale"),
    ),
    "profile_basic": ScopeDefinition(
        name="profile_basic",
        description="Имя и аватар",
        claims=("name", "picture"),
    ),
    "profile_extended": ScopeDefinition(
        name="profile_extended",
        description="Расширенный профиль (дата рождения, язык, имя, аватар)",
        claims=("name", "given_name", "family_name", "picture", "birthdate", "locale"),
    ),
    "email": ScopeDefinition(
        name="email",
        description="Адрес электронной почты",
        claims=("email", "email_verified"),
    ),
    "phone": ScopeDefinition(
        name="phone",
        description="Номер телефона",
        claims=("phone_number", "phone_number_verified"),
    ),
    "address": ScopeDefinition(
        name="address",
        description="Почтовый адрес",
        claims=("address",),
    ),
    "offline_access": ScopeDefinition(
        name="offline_access",
        description="Доступ без присутствия пользователя (refresh token)",
    ),
}


def normalize_scopes(raw: str | None) -> list[str]:
    if not raw:
        return []
    parts = [p for p in str(raw).split() if p]
    return list(dict.fromkeys(parts))


def scope_definitions(scopes: list[str]) -> list[ScopeDefinition]:
    return [SCOPES[s] for s in scopes if s in SCOPES]
