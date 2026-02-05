from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import urlencode, urlparse, urlunparse

import jwt
from jwt import InvalidTokenError
from allauth.account.models import EmailAddress
from django.conf import settings
from django.utils import timezone
from ninja.errors import HttpError

from accounts.services.preferences import PreferencesService
from accounts.services.profile import ProfileService
from idp.keys import (
    jwk_from_public_key,
    load_keypair,
    load_keypairs,
    public_key_for_kid,
)
from idp.models import (
    OidcAuthorizationCode,
    OidcAuthorizationRequest,
    OidcClient,
    OidcConsent,
    OidcToken,
)
from idp.scopes import SCOPES, normalize_scopes, scope_definitions
from updspaceid.enums import UserStatus
from updspaceid.models import User as UpdspaceIdUser
from updspaceid.services import require_active_user

logger = logging.getLogger(__name__)


AUTH_REQUEST_TTL = timedelta(minutes=10)
AUTH_CODE_TTL = timedelta(minutes=5)
ACCESS_TOKEN_TTL = timedelta(minutes=30)
ID_TOKEN_TTL = timedelta(minutes=10)
REFRESH_TOKEN_TTL = timedelta(days=30)


def _issuer() -> str:
    return str(getattr(settings, "OIDC_ISSUER", "https://id.localhost"))


def _hash_token(token: str) -> str:
    secret = str(getattr(settings, "OIDC_REFRESH_TOKEN_SALT", settings.SECRET_KEY))
    return hashlib.sha256((token + secret).encode("utf-8")).hexdigest()


def _build_redirect(uri: str, params: dict[str, str]) -> str:
    parsed = urlparse(uri)
    query = parsed.query
    extra = urlencode(params)
    combined = query + ("&" if query else "") + extra
    return urlunparse(parsed._replace(query=combined))


def _normalize_scope_request(raw: str, client: OidcClient) -> list[str]:
    requested = normalize_scopes(raw)
    allowed = set(client.allowed_scopes or [])
    if not allowed:
        allowed = set(SCOPES.keys())
    allowed.add("openid")
    filtered = [s for s in requested if s in allowed]
    if "openid" not in filtered:
        filtered.insert(0, "openid")
    return filtered


def _apply_privacy_prefs(scopes: list[str], prefs: dict) -> list[str]:
    defaults = prefs.get("privacy_scope_defaults") or {}
    final_scopes: list[str] = []
    for scope in scopes:
        policy = defaults.get(scope)
        if policy == "deny":
            continue
        final_scopes.append(scope)
    if "openid" not in final_scopes:
        final_scopes.insert(0, "openid")
    return final_scopes


def _resolve_updspace_user(user) -> UpdspaceIdUser | None:
    email = (getattr(user, "email", "") or "").strip().lower()
    if not email:
        return None
    return UpdspaceIdUser.objects.filter(email=email).first()


def _resolve_subject_id(user, upd_user: UpdspaceIdUser | None = None) -> str:
    """
    Prefer UpdSpace identity UUID for OIDC subjects when available.
    """
    if upd_user is None:
        upd_user = _resolve_updspace_user(user)
    if upd_user:
        return str(upd_user.user_id)
    return str(getattr(user, "id", ""))


def _master_flags_for_user(
    upd_user: UpdspaceIdUser | None,
) -> dict:
    flags = {
        "suspended": False,
        "banned": False,
        "system_admin": False,
        "email_verified": False,
    }
    if not upd_user:
        return flags
    status = str(upd_user.status or "")
    flags.update(
        {
            "suspended": status == UserStatus.SUSPENDED,
            "banned": status == UserStatus.BANNED,
            "system_admin": bool(upd_user.system_admin),
            "email_verified": bool(upd_user.email_verified),
            "status": status,
        }
    )
    return flags


def _ensure_user_active(user, *, upd_user: UpdspaceIdUser | None = None) -> None:
    target = upd_user if upd_user is not None else _resolve_updspace_user(user)
    if target:
        require_active_user(target)


def _verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if not code_challenge:
        return False
    verifier = (code_verifier or "").strip()
    if not verifier:
        return False
    if method.upper() != "S256":
        return False
    hashed = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(hashed).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(computed, code_challenge)


def _resolve_token_public_key(token: str) -> str:
    try:
        header = jwt.get_unverified_header(token)
    except InvalidTokenError as exc:
        raise HttpError(
            401, {"code": "INVALID_TOKEN", "message": "invalid token"}
        ) from exc
    kid = header.get("kid")
    if kid:
        key = public_key_for_kid(kid)
        if key:
            return key
        raise HttpError(
            401,
            {
                "code": "UNKNOWN_KEY",
                "message": "unknown token key",
            },
        )
    return load_keypair().public_key_pem


def _decode_jwt_token(token: str) -> dict:
    public_key = _resolve_token_public_key(token)
    try:
        return jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=None,
            options={"verify_aud": False},
        )
    except InvalidTokenError as exc:
        raise HttpError(
            401, {"code": "INVALID_TOKEN", "message": "invalid token"}
        ) from exc


def _claims_for_scopes(
    user,
    scopes: list[str],
    request=None,
    subject_id: str | None = None,
) -> dict:
    profile = ProfileService._ensure_profile(user)
    prefs = PreferencesService.get(user)
    primary = EmailAddress.objects.filter(user=user, primary=True).first()
    upd_user = _resolve_updspace_user(user)
    subject_id = subject_id or _resolve_subject_id(user, upd_user)
    claims: dict = {"sub": subject_id, "user_id": subject_id}
    base_url = str(getattr(settings, "OIDC_PUBLIC_BASE_URL", _issuer())).rstrip("/")
    for scope in scopes:
        if scope not in SCOPES:
            continue
        for claim in SCOPES[scope].claims:
            if claim == "name":
                claims["name"] = (
                    f"{getattr(user, 'first_name', '')} {getattr(user, 'last_name', '')}"
                ).strip()
            elif claim == "given_name":
                claims["given_name"] = getattr(user, "first_name", "") or ""
            elif claim == "family_name":
                claims["family_name"] = getattr(user, "last_name", "") or ""
            elif claim == "picture":
                avatar = ProfileService.avatar_state(user, request=request)
                if avatar.url:
                    claims["picture"] = avatar.url
                elif base_url:
                    claims["picture"] = ""
            elif claim == "locale":
                claims["locale"] = prefs.get("language") or "en"
            elif claim == "email":
                claims["email"] = getattr(user, "email", "") or ""
            elif claim == "email_verified":
                claims["email_verified"] = bool(primary and primary.verified)
            elif claim == "phone_number":
                claims["phone_number"] = profile.phone_number or ""
            elif claim == "phone_number_verified":
                claims["phone_number_verified"] = bool(profile.phone_verified)
            elif claim == "birthdate":
                claims["birthdate"] = (
                    profile.birth_date.isoformat() if profile.birth_date else ""
                )
            elif claim == "address":
                claims["address"] = {}
    claims["master_flags"] = _master_flags_for_user(upd_user)
    return claims


@dataclass(slots=True)
class OidcService:
    @staticmethod
    def prepare_authorization(user, params: dict) -> dict:
        client_id = params.get("client_id") or ""
        redirect_uri = params.get("redirect_uri") or ""
        scope_raw = params.get("scope") or ""
        response_type = params.get("response_type") or ""
        state = params.get("state") or ""
        nonce = params.get("nonce") or ""
        code_challenge = params.get("code_challenge") or ""
        code_challenge_method = params.get("code_challenge_method") or ""
        prompt = params.get("prompt") or ""

        if response_type != "code":
            raise HttpError(
                400,
                {
                    "code": "UNSUPPORTED_RESPONSE_TYPE",
                    "message": "response_type must be code",
                },
            )

        client = OidcClient.objects.filter(client_id=client_id).first()
        if not client:
            raise HttpError(
                404, {"code": "CLIENT_NOT_FOUND", "message": "client not found"}
            )
        if redirect_uri not in (client.redirect_uris or []):
            raise HttpError(
                400,
                {"code": "INVALID_REDIRECT_URI", "message": "redirect_uri not allowed"},
            )
        if client.response_types and "code" not in (client.response_types or []):
            raise HttpError(
                400,
                {
                    "code": "UNSUPPORTED_RESPONSE_TYPE",
                    "message": "response_type not allowed",
                },
            )
        challenge_method = (code_challenge_method or "").strip().upper()
        if code_challenge and challenge_method != "S256":
            raise HttpError(
                400,
                {
                    "code": "INVALID_PKCE_METHOD",
                    "message": "code_challenge_method must be S256",
                },
            )
        if code_challenge_method and not code_challenge:
            raise HttpError(
                400,
                {
                    "code": "INVALID_PKCE_METHOD",
                    "message": "code_challenge is required when code_challenge_method is set",
                },
            )
        if client.is_public and not code_challenge:
            raise HttpError(
                400,
                {
                    "code": "PKCE_REQUIRED",
                    "message": "code_challenge required for public clients",
                },
            )
        if client.is_public and challenge_method != "S256":
            raise HttpError(
                400,
                {
                    "code": "INVALID_PKCE_METHOD",
                    "message": "public clients must use S256 PKCE",
                },
            )

        scopes = _normalize_scope_request(scope_raw, client)
        prefs = PreferencesService.get(user)
        scopes = _apply_privacy_prefs(scopes, prefs)

        expires_at = timezone.now() + AUTH_REQUEST_TTL
        request_id = secrets.token_urlsafe(24)
        OidcAuthorizationRequest.objects.create(
            request_id=request_id,
            client=client,
            user=user,
            redirect_uri=redirect_uri,
            scope=" ".join(scopes),
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            prompt=prompt,
            expires_at=expires_at,
        )

        consent = OidcConsent.objects.filter(user=user, client=client).first()
        consent_scopes = set(consent.scopes or []) if consent else set()
        consent_required = True
        if consent and set(scopes).issubset(consent_scopes) and prompt != "consent":
            consent_required = False

        definitions = scope_definitions(scopes)
        scope_rows = [
            {
                "name": s.name,
                "description": s.description,
                "required": bool(s.required),
                "granted": bool(s.name in scopes),
            }
            for s in definitions
        ]
        return {
            "request_id": request_id,
            "client": {
                "client_id": client.client_id,
                "name": client.name,
                "logo_url": client.logo_url,
            },
            "scopes": scope_rows,
            "consent_required": consent_required,
            "state": state,
            "redirect_uri": redirect_uri,
        }

    @staticmethod
    def approve_authorization(
        user,
        *,
        request_id: str,
        approved_scopes: list[str] | None = None,
        remember: bool = True,
    ) -> str:
        req = OidcAuthorizationRequest.objects.filter(request_id=request_id).first()
        if not req or req.user_id != getattr(user, "id", None):
            raise HttpError(
                404, {"code": "REQUEST_NOT_FOUND", "message": "request not found"}
            )
        if req.expires_at < timezone.now():
            req.delete()
            raise HttpError(
                400, {"code": "REQUEST_EXPIRED", "message": "request expired"}
            )

        requested_scopes = normalize_scopes(req.scope)
        if approved_scopes:
            final_scopes = [s for s in approved_scopes if s in requested_scopes]
        else:
            final_scopes = requested_scopes
        if "openid" not in final_scopes:
            final_scopes.insert(0, "openid")

        code = secrets.token_urlsafe(32)
        OidcAuthorizationCode.objects.create(
            code=code,
            client=req.client,
            user=req.user,
            redirect_uri=req.redirect_uri,
            scope=" ".join(final_scopes),
            nonce=req.nonce,
            code_challenge=req.code_challenge,
            code_challenge_method=req.code_challenge_method,
            expires_at=timezone.now() + AUTH_CODE_TTL,
        )
        if remember:
            OidcConsent.objects.update_or_create(
                user=req.user,
                client=req.client,
                defaults={"scopes": final_scopes, "last_used_at": timezone.now()},
            )
        redirect = _build_redirect(
            req.redirect_uri,
            {"code": code, "state": req.state},
        )
        req.delete()
        return redirect

    @staticmethod
    def deny_authorization(user, *, request_id: str) -> str:
        req = OidcAuthorizationRequest.objects.filter(request_id=request_id).first()
        if not req or req.user_id != getattr(user, "id", None):
            raise HttpError(
                404, {"code": "REQUEST_NOT_FOUND", "message": "request not found"}
            )
        redirect = _build_redirect(
            req.redirect_uri,
            {"error": "access_denied", "state": req.state},
        )
        req.delete()
        return redirect

    @staticmethod
    def authenticate_client(request, payload: dict) -> OidcClient:
        auth = request.headers.get("Authorization") or ""
        client_id = payload.get("client_id") or ""
        client_secret = payload.get("client_secret") or ""
        if auth.lower().startswith("basic "):
            raw = auth.split(" ", 1)[1].strip()
            try:
                decoded = base64.b64decode(raw).decode("utf-8")
                client_id, client_secret = decoded.split(":", 1)
            except Exception:
                raise HttpError(
                    400, {"code": "INVALID_CLIENT", "message": "invalid basic auth"}
                )
        client = OidcClient.objects.filter(client_id=client_id).first()
        if not client or not client.check_secret(client_secret):
            raise HttpError(
                401, {"code": "INVALID_CLIENT", "message": "invalid client"}
            )
        return client

    @staticmethod
    def exchange_code(payload: dict, request=None) -> dict:
        client = OidcService.authenticate_client(request, payload)
        if client.grant_types and "authorization_code" not in (
            client.grant_types or []
        ):
            raise HttpError(
                400,
                {"code": "UNSUPPORTED_GRANT_TYPE", "message": "grant_type not allowed"},
            )
        code = payload.get("code") or ""
        redirect_uri = payload.get("redirect_uri") or ""
        code_verifier = payload.get("code_verifier") or ""
        code_obj = OidcAuthorizationCode.objects.filter(code=code).first()
        if not code_obj or code_obj.client_id != client.id:
            raise HttpError(400, {"code": "INVALID_CODE", "message": "invalid code"})
        if code_obj.used_at or code_obj.expires_at < timezone.now():
            raise HttpError(400, {"code": "CODE_EXPIRED", "message": "code expired"})
        if redirect_uri and redirect_uri != code_obj.redirect_uri:
            raise HttpError(
                400, {"code": "INVALID_REDIRECT_URI", "message": "redirect mismatch"}
            )
        if code_obj.code_challenge:
            if (code_obj.code_challenge_method or "").strip().upper() != "S256":
                raise HttpError(
                    400,
                    {
                        "code": "INVALID_PKCE_METHOD",
                        "message": "code_challenge_method must be S256",
                    },
                )
            if not _verify_pkce(
                code_verifier, code_obj.code_challenge, code_obj.code_challenge_method
            ):
                raise HttpError(
                    400, {"code": "INVALID_PKCE", "message": "pkce check failed"}
                )

        code_obj.used_at = timezone.now()
        code_obj.save(update_fields=["used_at"])
        return OidcService._issue_tokens(
            user=code_obj.user,
            client=client,
            scope=code_obj.scope,
            nonce=code_obj.nonce,
            request=request,
        )

    @staticmethod
    def refresh_tokens(payload: dict, request=None) -> dict:
        client = OidcService.authenticate_client(request, payload)
        if client.grant_types and "refresh_token" not in (client.grant_types or []):
            raise HttpError(
                400,
                {"code": "UNSUPPORTED_GRANT_TYPE", "message": "grant_type not allowed"},
            )
        refresh_token = payload.get("refresh_token") or ""
        refresh_hash = _hash_token(refresh_token)
        token = (
            OidcToken.objects.filter(
                client=client,
                refresh_token_hash=refresh_hash,
                revoked_at__isnull=True,
            )
            .order_by("-created_at")
            .first()
        )
        if not token or (
            token.refresh_expires_at and token.refresh_expires_at < timezone.now()
        ):
            raise HttpError(
                400,
                {"code": "INVALID_REFRESH_TOKEN", "message": "invalid refresh token"},
            )
        _ensure_user_active(token.user)
        token.revoked_at = timezone.now()
        token.save(update_fields=["revoked_at"])
        return OidcService._issue_tokens(
            user=token.user,
            client=client,
            scope=token.scope,
            nonce="",
            request=request,
        )

    @staticmethod
    def _issue_tokens(
        *, user, client: OidcClient, scope: str, nonce: str, request=None
    ) -> dict:
        _ensure_user_active(user)
        scope_list = normalize_scopes(scope)
        subject_id = _resolve_subject_id(user)
        keypair = load_keypair()
        now = timezone.now()
        jti = uuid.uuid4().hex
        access_payload = {
            "iss": _issuer(),
            "sub": subject_id,
            "aud": client.client_id,
            "exp": int((now + ACCESS_TOKEN_TTL).timestamp()),
            "iat": int(now.timestamp()),
            "jti": jti,
            "scope": " ".join(scope_list),
        }
        access_token = jwt.encode(
            access_payload,
            keypair.private_key_pem,
            algorithm="RS256",
            headers={"kid": keypair.kid},
        )
        id_jti = uuid.uuid4().hex
        claims = _claims_for_scopes(
            user,
            scope_list,
            request=request,
            subject_id=subject_id,
        )
        id_payload = {
            "iss": _issuer(),
            "sub": subject_id,
            "aud": client.client_id,
            "exp": int((now + ID_TOKEN_TTL).timestamp()),
            "iat": int(now.timestamp()),
            "jti": id_jti,
            "nonce": nonce or "",
            **claims,
        }
        id_token = jwt.encode(
            id_payload,
            keypair.private_key_pem,
            algorithm="RS256",
            headers={"kid": keypair.kid},
        )

        refresh_token = None
        refresh_hash = ""
        refresh_expires_at = None
        if "offline_access" in scope_list:
            refresh_token = secrets.token_urlsafe(32)
            refresh_hash = _hash_token(refresh_token)
            refresh_expires_at = now + REFRESH_TOKEN_TTL

        OidcToken.objects.create(
            user=user,
            client=client,
            access_jti=jti,
            id_jti=id_jti,
            refresh_token_hash=refresh_hash,
            scope=" ".join(scope_list),
            access_expires_at=now + ACCESS_TOKEN_TTL,
            refresh_expires_at=refresh_expires_at,
        )

        consent = OidcConsent.objects.filter(user=user, client=client).first()
        if consent:
            consent.last_used_at = now
            consent.save(update_fields=["last_used_at"])

        return {
            "access_token": access_token,
            "id_token": id_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": int(ACCESS_TOKEN_TTL.total_seconds()),
            "scope": " ".join(scope_list),
        }

    @staticmethod
    def jwks() -> dict:
        return {
            "keys": [
                jwk_from_public_key(pair.public_key_pem, pair.kid)
                for pair in load_keypairs()
            ]
        }

    @staticmethod
    def userinfo(access_token: str, request=None) -> dict:
        payload = _decode_jwt_token(access_token)
        jti = str(payload.get("jti") or "")
        token = OidcToken.objects.filter(
            access_jti=jti, revoked_at__isnull=True
        ).first()
        if not token:
            raise HttpError(401, {"code": "TOKEN_REVOKED", "message": "token revoked"})
        scope_list = normalize_scopes(payload.get("scope") or "")
        return _claims_for_scopes(token.user, scope_list, request=request)

    @staticmethod
    def revoke_token(token_str: str) -> None:
        if not token_str:
            return
        refresh_hash = _hash_token(token_str)
        token = OidcToken.objects.filter(refresh_token_hash=refresh_hash).first()
        if token:
            token.revoked_at = timezone.now()
            token.save(update_fields=["revoked_at"])
            return
        try:
            payload = _decode_jwt_token(token_str)
        except HttpError:
            return
        jti = str(payload.get("jti") or "")
        token = OidcToken.objects.filter(access_jti=jti).first()
        if token and not token.revoked_at:
            token.revoked_at = timezone.now()
            token.save(update_fields=["revoked_at"])
