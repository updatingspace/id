from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _kid_from_public(public_pem: str) -> str:
    return hashlib.sha256(public_pem.encode("utf-8")).hexdigest()[:16]


@dataclass(slots=True)
class KeyPair:
    private_key_pem: str
    public_key_pem: str
    kid: str
    active: bool = True


def _generate_keypair() -> KeyPair:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return KeyPair(
        private_key_pem=priv_pem.decode("ascii"),
        public_key_pem=pub_pem.decode("ascii"),
        kid=_kid_from_public(pub_pem.decode("ascii")),
    )


def _parse_key_entries(raw: str | dict | Iterable[dict]) -> list[KeyPair]:
    entries: list[dict] = []
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return []
        entries = parsed if isinstance(parsed, list) else [parsed] if isinstance(parsed, dict) else []
    elif isinstance(raw, dict):
        entries = [raw]
    elif isinstance(raw, Iterable):
        entries = list(raw)
    else:
        return []

    pairs: list[KeyPair] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        priv = entry.get("private_key_pem") or entry.get("private_key")
        pub = entry.get("public_key_pem") or entry.get("public_key")
        if not isinstance(priv, str) or not isinstance(pub, str):
            continue
        kid = entry.get("kid") or _kid_from_public(pub)
        active = bool(entry.get("active", entry.get("enabled", True)))
        pairs.append(
            KeyPair(
                private_key_pem=priv,
                public_key_pem=pub,
                kid=kid,
                active=active,
            )
        )
    return pairs


def _configured_keypairs() -> list[KeyPair]:
    raw = getattr(settings, "OIDC_KEY_PAIRS", None)
    if not raw:
        return []
    return _parse_key_entries(raw)


def _single_keypair() -> KeyPair | None:
    priv = getattr(settings, "OIDC_PRIVATE_KEY_PEM", None)
    pub = getattr(settings, "OIDC_PUBLIC_KEY_PEM", None)
    if isinstance(priv, str) and isinstance(pub, str):
        kid = getattr(settings, "OIDC_KEY_KID", None) or _kid_from_public(pub)
        return KeyPair(private_key_pem=priv, public_key_pem=pub, kid=kid)
    return None


_CACHED_KEYPAIRS: list[KeyPair] | None = None


def load_keypairs() -> list[KeyPair]:
    global _CACHED_KEYPAIRS
    if _CACHED_KEYPAIRS:
        return _CACHED_KEYPAIRS
    pairs = _configured_keypairs()
    if not pairs:
        single = _single_keypair()
        if single:
            pairs = [single]
    if not pairs:
        pairs = [_generate_keypair()]
    _CACHED_KEYPAIRS = pairs
    return _CACHED_KEYPAIRS


def load_keypair() -> KeyPair:
    pairs = load_keypairs()
    for pair in pairs:
        if pair.active:
            return pair
    return pairs[0]


def keypair_for_kid(kid: str | None) -> KeyPair | None:
    if not kid:
        return None
    pairs = load_keypairs()
    for pair in pairs:
        if pair.kid == kid:
            return pair
    return None


def public_key_for_kid(kid: str | None) -> str | None:
    pair = keypair_for_kid(kid)
    if pair:
        return pair.public_key_pem
    return None


def jwk_from_public_key(public_pem: str, kid: str) -> dict:
    key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    numbers = key.public_numbers()
    n = _b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"))
    e = _b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))
    return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e}


def clear_key_cache_for_tests() -> None:
    global _CACHED_KEYPAIRS
    _CACHED_KEYPAIRS = None
