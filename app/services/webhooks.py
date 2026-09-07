"""Outbound webhooks: signed, retried, and always mirrored by the pull API."""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.orm import Session

from app.core.hashing import canonical_json
from app.core.security import sign_webhook
from app.db.base import utcnow
from app.models.session import KycSession
from app.models.tenant import Tenant
from app.models.webhook import WebhookDelivery

_EVENT_BY_STATUS = {
    "VERIFIED": "KYC_VERIFIED",
    "REJECTED": "KYC_REJECTED",
    "REVIEW": "KYC_REVIEW_REQUIRED",
    "EXPIRED": "KYC_EXPIRED",
}


def build_payload(session: KycSession, event_name: str) -> dict[str, Any]:
    return {
        "event": event_name,
        "session_id": session.id,
        "customer_reference": session.customer_reference,
        "flow": session.flow,
        "status": str(session.status),
        "occurred_at": utcnow().isoformat(),
    }


def queue_session_event(db: Session, session: KycSession) -> WebhookDelivery | None:
    tenant = db.get(Tenant, session.tenant_id)
    event_name = _EVENT_BY_STATUS.get(str(session.status))
    if tenant is None or not tenant.webhook_url or event_name is None:
        return None

    delivery = WebhookDelivery(
        tenant_id=tenant.id,
        session_id=session.id,
        event=event_name,
        url=tenant.webhook_url,
        payload=build_payload(session, event_name),
    )
    db.add(delivery)
    db.flush()
    _dispatch_after_commit(db, delivery.id)
    return delivery


def _dispatch_after_commit(db: Session, delivery_id: str) -> None:
    @event.listens_for(db, "after_commit", once=True)
    def _dispatch(_session: Session) -> None:  # pragma: no cover - thin scheduling glue
        from app.workers.tasks import deliver_webhook

        deliver_webhook.delay(delivery_id)


def signed_headers(secret: str | None, body: bytes, event_name: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "X-EKYC-Event": event_name}
    if secret:
        timestamp = str(int(utcnow().timestamp()))
        headers["X-EKYC-Timestamp"] = timestamp
        headers["X-EKYC-Signature"] = f"sha256={sign_webhook(secret, timestamp, body)}"
    return headers


def serialize(payload: dict[str, Any]) -> bytes:
    return canonical_json(payload).encode()
