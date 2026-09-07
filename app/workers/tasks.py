"""Heavy processing runs outside the request cycle (OCR, biometrics, delivery)."""

from __future__ import annotations

import logging

import httpx

from app.core.config import settings
from app.db.base import utcnow
from app.db.session import db_session
from app.engines import audit, biometrics, identity
from app.models.document import Artifact, Document
from app.models.enums import AuditEventType
from app.models.session import KycSession
from app.models.tenant import Tenant
from app.models.webhook import WebhookDelivery
from app.services import kyc, webhooks
from app.services.archive import read_artifact
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="ekyc.process_document")
def process_document(document_id: str) -> str:
    with db_session() as db:
        document = db.get(Document, document_id)
        if document is None:
            return "MISSING_DOCUMENT"
        session = db.get(KycSession, document.session_id)
        artifact = db.get(Artifact, document.artifact_id)
        if session is None or artifact is None:
            return "MISSING_SESSION"
        identity.process_document(db, session, document, read_artifact(artifact))
        return str(kyc.evaluate(db, session))


@celery_app.task(name="ekyc.process_selfie")
def process_selfie(session_id: str, artifact_id: str) -> str:
    with db_session() as db:
        session = db.get(KycSession, session_id)
        artifact = db.get(Artifact, artifact_id)
        if session is None or artifact is None:
            return "MISSING_SESSION"
        biometrics.process_selfie(db, session, read_artifact(artifact))
        return str(kyc.evaluate(db, session))


@celery_app.task(
    name="ekyc.deliver_webhook",
    bind=True,
    autoretry_for=(httpx.HTTPError,),
    retry_backoff=True,
    retry_kwargs={"max_retries": settings.webhook_max_attempts},
)
def deliver_webhook(self, delivery_id: str) -> str:  # noqa: ANN001 - celery bound task
    with db_session() as db:
        delivery = db.get(WebhookDelivery, delivery_id)
        if delivery is None:
            return "MISSING_DELIVERY"
        tenant = db.get(Tenant, delivery.tenant_id)
        body = webhooks.serialize(delivery.payload)
        headers = webhooks.signed_headers(
            tenant.webhook_secret if tenant else None, body, delivery.event
        )
        delivery.attempts += 1

        try:
            response = httpx.post(
                delivery.url,
                content=body,
                headers=headers,
                timeout=settings.webhook_timeout_seconds,
            )
            delivery.response_code = response.status_code
            response.raise_for_status()
        except httpx.HTTPError as exc:
            delivery.status = "FAILED"
            delivery.last_error = str(exc)[:1000]
            if delivery.session_id:
                audit.record_event(
                    db,
                    tenant_id=delivery.tenant_id,
                    session_id=delivery.session_id,
                    event_type=AuditEventType.WEBHOOK_FAILED,
                    payload={"event": delivery.event, "attempts": delivery.attempts},
                )
            logger.warning("Webhook delivery %s failed: %s", delivery_id, exc)
            raise

        delivery.status = "DELIVERED"
        delivery.delivered_at = utcnow()
        if delivery.session_id:
            audit.record_event(
                db,
                tenant_id=delivery.tenant_id,
                session_id=delivery.session_id,
                event_type=AuditEventType.WEBHOOK_DELIVERED,
                payload={"event": delivery.event, "response_code": delivery.response_code},
            )
        return "DELIVERED"
