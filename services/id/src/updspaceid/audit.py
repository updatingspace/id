from __future__ import annotations

from typing import Any

from updspaceid.models import AuditLog, OutboxEvent, Tenant, User


def record_audit(
    *,
    action: str,
    actor_user: User | None = None,
    target_type: str = "",
    target_id: str | int | None = None,
    tenant: Tenant | None = None,
    meta: dict[str, Any] | None = None,
) -> AuditLog:
    return AuditLog.objects.create(
        actor_user=actor_user,
        action=action,
        target_type=target_type or "",
        target_id=str(target_id or ""),
        tenant=tenant,
        meta_json=meta or {},
    )


def enqueue_outbox(
    *,
    event_type: str,
    tenant: Tenant,
    payload: dict[str, Any] | None = None,
) -> OutboxEvent:
    return OutboxEvent.objects.create(
        tenant=tenant,
        event_type=event_type,
        payload_json=payload or {},
    )
