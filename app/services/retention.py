"""Retention & purge: regulatory data minimisation over time.

Each session carries ``retention_days`` (snapshotted by the regulatory
orchestrator). Once ``created_at + retention_days`` has passed *and* the
session is in a terminal status, its personal data is purged:

* artifact **blobs** are deleted from their vaults (the DB row stays as a
  registry: ``sha256`` still anchors the integrity proofs),
* PII JSON fields are wiped: ``identity``, ``internal`` (OCR/score payloads),
  ``metadata``, ``documents.ocr/verification``, ``biometric_checks.details``,
  OTP challenge rows, and ``ip``/``user_agent`` on audit events,
* ``consent`` is reduced to its probative core (accepted / at / policy_version)
  — the identifiers are gone but the fact of consent remains provable,
* the purge itself is recorded as a ``DATA_PURGED`` checkpoint in the audit
  chain *before* anything is deleted, listing the artifact hashes — the chain
  stays verifiable and documents what was removed.

Signed-digest anchors (``signed_documents``, artifact rows, audit events) are
kept: a third party can still verify a sealed document's signature after the
payload is gone — the proof outlives the data, which is the point.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.engines import audit
from app.models.audit import AuditEvent
from app.models.biometrics import BiometricCheck
from app.models.document import Artifact, Document
from app.models.enums import TERMINAL_STATUSES, AuditEventType
from app.models.otp import OtpChallenge
from app.models.session import KycSession
from app.services.storage import get_vault

logger = logging.getLogger(__name__)


def _eligible(db: Session, now: datetime, batch_size: int) -> list[KycSession]:
    candidates = db.scalars(
        select(KycSession).where(
            KycSession.purged_at.is_(None),
            KycSession.status.in_([str(s) for s in TERMINAL_STATUSES]),
        )
    ).all()
    expired = [s for s in candidates if s.created_at + timedelta(days=s.retention_days) <= now]
    return expired[:batch_size]


def _purge_session(db: Session, session: KycSession, now: datetime) -> dict[str, Any]:
    artifacts = db.scalars(select(Artifact).where(Artifact.session_id == session.id)).all()

    # 1. Evidence checkpoint FIRST — proves what existed before deletion.
    audit.record_event(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        event_type=AuditEventType.DATA_PURGED,
        payload={
            "retention_days": session.retention_days,
            "jurisdiction": session.jurisdiction,
            "artifact_count": len(artifacts),
            "artifact_sha256": [a.sha256 for a in artifacts],
        },
        actor="SYSTEM",
    )

    # 2. Delete the blobs (registry rows kept, marked purged_at).
    deleted = missing = failed = 0
    freed = 0
    for artifact in artifacts:
        if artifact.purged_at is not None:
            continue
        try:
            removed = get_vault(artifact.vault_profile).delete(artifact.storage_key)
        except Exception:
            logger.exception(
                "purge: failed to delete %s (vault=%s)",
                artifact.storage_key,
                artifact.vault_profile,
            )
            failed += 1
            continue
        if removed:
            deleted += 1
            freed += artifact.size_bytes or 0
        else:
            missing += 1  # already gone — safe to mark purged
        artifact.purged_at = now

    # 3. Wipe personal data (DB rows stay; payloads gone).
    session.identity = {}
    session.internal = {}
    session.metadata_ = {}
    consent = dict(session.consent or {})
    for key in ("ip", "user_agent"):
        consent.pop(key, None)
    session.consent = consent

    for document in db.scalars(select(Document).where(Document.session_id == session.id)):
        document.ocr = {}
        document.verification = {}

    for check in db.scalars(select(BiometricCheck).where(BiometricCheck.session_id == session.id)):
        check.details = {}

    for challenge in db.scalars(select(OtpChallenge).where(OtpChallenge.session_id == session.id)):
        db.delete(challenge)

    # ip/user_agent are NOT part of the hash chain — safe to clear.
    for event in db.scalars(select(AuditEvent).where(AuditEvent.session_id == session.id)):
        event.ip = None
        event.user_agent = None

    session.purged_at = now
    db.flush()
    return {
        "artifacts_deleted": deleted,
        "artifacts_missing": missing,
        "artifacts_failed": failed,
        "bytes_freed": freed,
    }


def purge_expired_sessions(
    db: Session, *, now: datetime | None = None, batch_size: int = 200
) -> dict[str, Any]:
    """Purge personal data of sessions past their retention period."""
    now = now or utcnow()
    report: dict[str, Any] = {
        "ran_at": now.isoformat(),
        "sessions_purged": 0,
        "artifacts_deleted": 0,
        "artifacts_missing": 0,
        "artifacts_failed": 0,
        "bytes_freed": 0,
        "session_ids": [],
    }
    for session in _eligible(db, now, batch_size):
        result = _purge_session(db, session, now)
        report["sessions_purged"] += 1
        report["artifacts_deleted"] += result["artifacts_deleted"]
        report["artifacts_missing"] += result["artifacts_missing"]
        report["artifacts_failed"] += result["artifacts_failed"]
        report["bytes_freed"] += result["bytes_freed"]
        report["session_ids"].append(session.id)
    return report
