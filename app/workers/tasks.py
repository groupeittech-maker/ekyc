"""Heavy processing runs outside the request cycle (OCR, biometrics, delivery)."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select

from app.core.config import settings
from app.db.base import utcnow
from app.db.session import db_session
from app.engines import audit, biometrics, identity
from app.models.document import Artifact, Document
from app.models.enums import (
    TERMINAL_STATUSES,
    AuditEventType,
    CheckStatus,
    SessionStatus,
    Step,
)
from app.models.session import KycSession
from app.models.tenant import Tenant
from app.models.webhook import WebhookDelivery
from app.services import kyc, retention, webhooks
from app.services.archive import read_artifact
from app.services.storage import UnknownVaultError
from app.services.vault import VaultError
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

# Permanent failures: retrying cannot succeed (missing artifact/model/keys or a
# programmer error). Everything else — DB blips, network, worker restarts — is
# retried with bounded exponential backoff.
_PERMANENT_FAILURES = (
    FileNotFoundError,
    ValueError,
    TypeError,
    VaultError,
    UnknownVaultError,
)
_TASK_MAX_RETRIES = 3


def _check_pending(session: KycSession, step: Step) -> bool:
    return str(session.checks.get(str(step), CheckStatus.PENDING)) == str(CheckStatus.PENDING)


def _processing_failed(
    exc: BaseException, task_name: str, session_id: str, steps: list[Step]
) -> None:
    """Retries exhausted or permanent failure: the session must stay traceable
    and recoverable — pending checks go to REVIEW for a human, never to an
    automatic identity rejection."""
    try:
        with db_session() as db:
            session = db.get(KycSession, session_id)
            if session is None or session.status in TERMINAL_STATUSES:
                return
            pending = [s for s in steps if _check_pending(session, s)]
            audit.record_event(
                db,
                tenant_id=session.tenant_id,
                session_id=session.id,
                event_type=AuditEventType.PROCESSING_FAILED,
                payload={
                    "task": task_name,
                    "error": str(exc)[:500],
                    "pending_steps": [str(s) for s in pending],
                },
            )
            for step in pending:
                kyc.set_check(
                    db,
                    session,
                    step,
                    CheckStatus.REVIEW,
                    internal={"reason": "TASK_FAILED", "task": task_name},
                )
            kyc.evaluate(db, session)
    except Exception:
        logger.exception("processing-failure hook failed for %s", task_name)


def _log_gpu_task(name: str, session: KycSession, started: float) -> None:
    """Per-task inference time feeds the cost-per-KYC KPI."""
    logger.info(
        "gpu_task=%s tenant=%s session=%s duration_ms=%.1f",
        name,
        session.tenant_id,
        session.id,
        (time.perf_counter() - started) * 1000,
    )


@celery_app.task(
    name="ekyc.process_document",
    bind=True,
    autoretry_for=(Exception,),
    dont_autoretry_for=_PERMANENT_FAILURES,
    retry_backoff=True,
    retry_jitter=True,
    retry_kwargs={"max_retries": _TASK_MAX_RETRIES},
)
def process_document(self, document_id: str) -> str:  # noqa: ANN001
    with db_session() as db:
        document = db.get(Document, document_id)
        if document is None:
            return "MISSING_DOCUMENT"
        session = db.get(KycSession, document.session_id)
        artifact = db.get(Artifact, document.artifact_id)
        if session is None or artifact is None:
            return "MISSING_SESSION"
        # Idempotent apply: a re-queued or duplicated execution is a no-op once
        # the check has been decided (PASSED/FAILED/REVIEW).
        if not _check_pending(session, Step.DOCUMENT_VERIFICATION):
            return "ALREADY_APPLIED"
        started = time.perf_counter()
        identity.process_document(db, session, document, read_artifact(artifact))
        _log_gpu_task("process_document", session, started)
        return str(kyc.evaluate(db, session))


def _on_document_failure(exc, task_id, args, kwargs, einfo) -> None:  # noqa: ANN001
    document_id = args[0] if args else None
    if document_id is None:
        return
    with db_session() as db:
        document = db.get(Document, document_id)
        session_id = document.session_id if document else None
    if session_id:
        _processing_failed(exc, "ekyc.process_document", session_id, [Step.DOCUMENT_VERIFICATION])


process_document.on_failure = _on_document_failure


@celery_app.task(
    name="ekyc.process_selfie",
    bind=True,
    autoretry_for=(Exception,),
    dont_autoretry_for=_PERMANENT_FAILURES,
    retry_backoff=True,
    retry_jitter=True,
    retry_kwargs={"max_retries": _TASK_MAX_RETRIES},
)
def process_selfie(self, session_id: str, artifact_id: str) -> str:  # noqa: ANN001
    with db_session() as db:
        session = db.get(KycSession, session_id)
        artifact = db.get(Artifact, artifact_id)
        if session is None or artifact is None:
            return "MISSING_SESSION"
        if not _check_pending(session, Step.LIVENESS):
            return "ALREADY_APPLIED"
        started = time.perf_counter()
        biometrics.process_selfie(db, session, read_artifact(artifact))
        _log_gpu_task("process_selfie", session, started)
        return str(kyc.evaluate(db, session))


def _on_selfie_failure(exc, task_id, args, kwargs, einfo) -> None:  # noqa: ANN001
    session_id = args[0] if args else None
    if session_id is None:
        return
    _processing_failed(
        exc,
        "ekyc.process_selfie",
        session_id,
        [Step.LIVENESS, Step.FACE_MATCH],
    )


process_selfie.on_failure = _on_selfie_failure


@celery_app.task(name="ekyc.reconcile_stuck_sessions")
def reconcile_stuck_sessions() -> dict:
    """Requeue work for sessions stuck mid-flight (lost task, worker crash).

    A session is stuck when it has been non-terminal for longer than
    ``EKYC_STUCK_SESSION_MINUTES``. Expired sessions are closed; sessions with
    an uploaded document/selfie whose check is still PENDING get their task
    requeued — throttled by ``internal.reconciled_at`` so a legitimate in-flight
    run is never duplicated, and the tasks themselves apply idempotently.
    """
    cutoff = utcnow() - timedelta(minutes=settings.stuck_session_minutes)
    now = utcnow()
    report: dict = {"expired": [], "requeued": [], "scanned": 0}
    to_dispatch: list[tuple[object, tuple]] = []

    with db_session() as db:
        sessions = db.scalars(
            select(KycSession).where(
                KycSession.status.in_(
                    [
                        str(SessionStatus.CREATED),
                        str(SessionStatus.IN_PROGRESS),
                        str(SessionStatus.PROCESSING),
                    ]
                ),
                KycSession.updated_at <= cutoff,
            )
        ).all()
        report["scanned"] = len(sessions)

        for session in sessions:
            if session.expires_at <= now:
                kyc.expire(db, session)
                report["expired"].append(session.id)
                continue

            reconciled_at = (session.internal or {}).get("reconciled_at")
            if reconciled_at and datetime.fromisoformat(reconciled_at) > cutoff:
                continue  # already requeued recently — let the run finish

            queued = False
            if _check_pending(session, Step.DOCUMENT_VERIFICATION):
                document = db.scalars(
                    select(Document)
                    .where(Document.session_id == session.id)
                    .order_by(Document.created_at.desc())
                    .limit(1)
                ).first()
                if document is not None:
                    to_dispatch.append((process_document, (document.id,)))
                    queued = True
            if _check_pending(session, Step.LIVENESS):
                selfie = db.scalars(
                    select(Artifact)
                    .where(
                        Artifact.session_id == session.id,
                        Artifact.kind == "SELFIE",
                    )
                    .order_by(Artifact.created_at.desc())
                    .limit(1)
                ).first()
                if selfie is not None:
                    to_dispatch.append((process_selfie, (session.id, selfie.id)))
                    queued = True

            if queued:
                session = kyc.lock_session(db, session.id)
                session.internal = {
                    **(session.internal or {}),
                    "reconciled_at": now.isoformat(),
                }
                db.flush()
                report["requeued"].append(session.id)

    # Dispatch only after the scan transaction commits: workers read committed
    # rows, and in eager mode tasks must not deadlock on our session row lock.
    for task, args in to_dispatch:
        task.delay(*args)  # type: ignore[attr-defined]
    return report


@celery_app.task(name="ekyc.purge_expired_sessions")
def purge_expired_sessions() -> dict:
    """Nightly retention sweep — see app.services.retention."""
    with db_session() as db:
        report = retention.purge_expired_sessions(db)
        if report["sessions_purged"]:
            logger.info("retention purge: %s", report)
        return report


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
        if delivery.status == "DELIVERED":
            return "DELIVERED"  # idempotent re-execution — never re-notify
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
