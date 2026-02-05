from __future__ import annotations

from typing import Any

from ninja import Schema


class AuthorizationPrepareOut(Schema):
    request_id: str
    client: dict
    scopes: list[dict]
    consent_required: bool
    state: str | None = None
    redirect_uri: str


class AuthorizationApproveIn(Schema):
    request_id: str
    scopes: list[str] | None = None
    remember: bool = True


class AuthorizationDenyIn(Schema):
    request_id: str


class AuthorizationDecisionOut(Schema):
    redirect_uri: str


class TokenRequestIn(Schema):
    grant_type: str | None = None
    code: str | None = None
    redirect_uri: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    code_verifier: str | None = None
    refresh_token: str | None = None


class TokenResponseOut(Schema):
    access_token: str
    id_token: str
    refresh_token: str | None = None
    token_type: str
    expires_in: int
    scope: str


class UserInfoOut(Schema):
    claims: dict[str, Any]


class RevokeIn(Schema):
    token: str
