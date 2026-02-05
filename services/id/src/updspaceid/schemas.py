from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from ninja import Schema


class ErrorBody(Schema):
    code: str
    message: str
    details: dict[str, Any] | None = None
    request_id: str


class ErrorEnvelopeOut(Schema):
    error: ErrorBody


class OkOut(Schema):
    ok: Literal[True] = True


class ApplicationCreateIn(Schema):
    tenant_slug: str
    payload_json: dict[str, Any]


class ApplicationOut(Schema):
    id: int
    tenant_slug: str
    payload_json: dict[str, Any]
    status: str
    created_at: datetime


class ApplicationListOut(Schema):
    items: list[ApplicationOut]


class ApproveOut(Schema):
    activation_token: str
    activation_expires_at: datetime


class RejectOut(OkOut):
    pass


class ActivateIn(Schema):
    token: str


class ActivateOut(OkOut):
    user_id: UUID


class MagicLinkRequestIn(Schema):
    email: str


class MagicLinkRequestOut(OkOut):
    sent: bool


class MagicLinkConsumeIn(Schema):
    token: str


class MagicLinkConsumeOut(OkOut):
    user_id: UUID
    session_token: str


class TenantMembershipOut(Schema):
    tenant_id: UUID
    tenant_slug: str
    status: str
    base_role: str


class MeOut(Schema):
    user: dict[str, Any]
    memberships: list[TenantMembershipOut]


class OAuthStartOut(Schema):
    authorization_url: str
    state: str
    nonce: str


class OAuthStartIn(Schema):
    redirect_uri: str


class OAuthCallbackIn(Schema):
    state: str
    code: str | None = None
    # For Steam/OpenID callback simulation/transport
    claimed_id: str | None = None
    openid_params: dict[str, str] | None = None


class OAuthLoginOut(OkOut):
    user_id: UUID
    session_token: str


class MigrationImportIn(Schema):
    items: list[dict[str, Any]]


class MigrationImportOut(Schema):
    imported: int


class ClaimTokenOut(Schema):
    activation_token: str
    activation_expires_at: datetime
