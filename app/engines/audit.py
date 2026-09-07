"""Immutable audit engine: append-only, hash-chained events."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.hashing import sha256_json
from app.db.base import utcnow
from app.models.audit import AuditEvent
from app.models.enums import AuditEventType


def _compute_event_hash(
    *,
    sequence: int,
    event_type: str,
    session_id: str,
    tenant_id: str,
    actor: str,
    created_at: str,
    payload: dict[str, Any],
    document_hash: str | None,
    previous_event_hash: str | None,
) -> str:
    return sha256_json(
        {
            "sequence": sequence,
            "event_type": event_type,
            "session_id": session_id,
            "tenant_id": tenant_id,
            "actor": actor,
            "created_at": created_at,
            "payload": payload,
            "document_hash": document_hash,
            "previous_event_hash": previous_event_hash,
        }
    )


def record_event(
    db: Session,
    *,
    tenant_id: str,
    session_id: str,
    event_type: AuditEventType | str,
    payload: dict[str, Any] | None = None,
    actor: str = "SYSTEM",
    ip: str | None = None,
    user_agent: str | None = None,
    document_hash: str | None = None,
) -> AuditEvent:
    last = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.session_id == session_id)
        .order_by(AuditEvent.sequence.desc())
        .limit(1)
    ).first()

    event = AuditEvent(
        created_at=utcnow(),
        tenant_id=tenant_id,
        session_id=session_id,
        sequence=(last.sequence + 1) if last else 1,
        event_type=str(event_type),
        actor=actor,
        ip=ip,
        user_agent=user_agent,
        payload=payload or {},
        document_hash=document_hash,
        previous_event_hash=last.event_hash if last else None,
        event_hash="",
    )
    event.event_hash = _compute_event_hash(
        sequence=event.sequence,
        event_type=event.event_type,
        session_id=session_id,
        tenant_id=tenant_id,
        actor=event.actor,
        created_at=event.created_at.isoformat(),
        payload=event.payload,
        document_hash=event.document_hash,
        previous_event_hash=event.previous_event_hash,
    )
    db.add(event)
    db.flush()
    return event


def list_events(db: Session, session_id: str) -> list[AuditEvent]:
    return list(
        db.scalars(
            select(AuditEvent)
            .where(AuditEvent.session_id == session_id)
            .order_by(AuditEvent.sequence.asc())
        )
    )


def verify_chain(db: Session, session_id: str) -> dict[str, Any]:
    """Recompute the whole chain; used by audit exports and integrity checks."""
    events = list_events(db, session_id)
    previous_hash: str | None = None
    for index, event in enumerate(events, start=1):
        expected = _compute_event_hash(
            sequence=event.sequence,
            event_type=event.event_type,
            session_id=event.session_id,
            tenant_id=event.tenant_id,
            actor=event.actor,
            created_at=event.created_at.isoformat(),
            payload=event.payload,
            document_hash=event.document_hash,
            previous_event_hash=event.previous_event_hash,
        )
        broken = (
            event.sequence != index
            or event.previous_event_hash != previous_hash
            or event.event_hash != expected
        )
        if broken:
            return {"valid": False, "events": len(events), "broken_at": event.sequence}
        previous_hash = event.event_hash
    return {"valid": True, "events": len(events), "head_hash": previous_hash}


def event_count(db: Session, session_id: str) -> int:
    return int(
        db.scalar(select(func.count(AuditEvent.id)).where(AuditEvent.session_id == session_id)) or 0
    )
