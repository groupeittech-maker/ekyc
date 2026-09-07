"""Biometric engine: liveness first, then face matching against the document."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.config import settings
from app.engines import audit, identity
from app.engines.providers import get_face_provider
from app.models.biometrics import BiometricCheck
from app.models.enums import AuditEventType, CheckStatus, Step
from app.models.session import KycSession
from app.services import kyc


def _record(
    db: Session, session: KycSession, kind: str, status: CheckStatus, score: float, details: dict
) -> BiometricCheck:
    check = BiometricCheck(
        session_id=session.id,
        tenant_id=session.tenant_id,
        kind=kind,
        status=str(status),
        score=score,
        details=details,
    )
    db.add(check)
    db.flush()
    return check


def process_selfie(db: Session, session: KycSession, selfie: bytes) -> dict[str, CheckStatus]:
    provider = get_face_provider()
    policy = kyc.policy_of(session)
    results: dict[str, CheckStatus] = {}

    liveness = provider.liveness(selfie)
    liveness_status = (
        CheckStatus.PASSED if liveness.score >= settings.liveness_threshold else CheckStatus.FAILED
    )
    _record(db, session, str(Step.LIVENESS), liveness_status, liveness.score, liveness.details)
    audit.record_event(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        event_type=(
            AuditEventType.LIVENESS_PASSED
            if liveness_status == CheckStatus.PASSED
            else AuditEventType.LIVENESS_FAILED
        ),
        payload={"provider": liveness.provider},
    )
    if policy.requires(Step.LIVENESS):
        kyc.set_check(
            db,
            session,
            Step.LIVENESS,
            liveness_status,
            internal={"score": liveness.score, "provider": liveness.provider},
        )
        results[str(Step.LIVENESS)] = liveness_status

    if not policy.requires(Step.FACE_MATCH):
        return results

    if liveness_status == CheckStatus.FAILED:
        # A spoofed capture must not be matched: matching it would be meaningless.
        kyc.set_check(db, session, Step.FACE_MATCH, CheckStatus.FAILED, internal={"skipped": True})
        results[str(Step.FACE_MATCH)] = CheckStatus.FAILED
        return results

    document = identity.document_image(db, session.id)
    if document is None:
        kyc.set_check(
            db, session, Step.FACE_MATCH, CheckStatus.FAILED, internal={"reason": "NO_DOCUMENT"}
        )
        results[str(Step.FACE_MATCH)] = CheckStatus.FAILED
        return results

    match = provider.match(selfie, document[1])
    match_status = (
        CheckStatus.PASSED if match.score >= settings.face_match_threshold else CheckStatus.FAILED
    )
    _record(db, session, str(Step.FACE_MATCH), match_status, match.score, match.details)
    audit.record_event(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        event_type=(
            AuditEventType.FACE_MATCH_PASSED
            if match_status == CheckStatus.PASSED
            else AuditEventType.FACE_MATCH_FAILED
        ),
        payload={"provider": match.provider},
    )
    kyc.set_check(
        db,
        session,
        Step.FACE_MATCH,
        match_status,
        internal={"score": match.score, "provider": match.provider},
    )
    results[str(Step.FACE_MATCH)] = match_status
    return results
