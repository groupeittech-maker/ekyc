"""Biometric engine: liveness first, then face matching against the document.

Quality failures (no face detected, blurry capture) return RETRY while the
user still has attempts — a poor capture is not proof of spoofing. A genuine
liveness or match failure after the retry budget still fails the check.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core import runtime_config as runtime
from app.engines import audit, identity
from app.engines.providers import get_face_provider
from app.models.biometrics import BiometricCheck
from app.models.document import Artifact
from app.models.enums import ArtifactKind, AuditEventType, CheckStatus, Step
from app.models.session import KycSession
from app.services import kyc

# Match failure reasons that mean "capture again", not "different person".
_QUALITY_REASONS = {"NO_FACE_IN_SELFIE", "NO_FACE_IN_DOCUMENT", "NO_FACE"}


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


def _selfie_attempts(db: Session, session_id: str) -> int:
    return int(
        db.scalar(
            select(func.count(Artifact.id)).where(
                Artifact.session_id == session_id,
                Artifact.kind == ArtifactKind.SELFIE.value,
            )
        )
        or 0
    )


def process_selfie(db: Session, session: KycSession, selfie: bytes) -> dict[str, CheckStatus]:
    provider = get_face_provider()
    policy = kyc.policy_of(session)
    results: dict[str, CheckStatus] = {}
    attempts = _selfie_attempts(db, session.id)
    can_retry = attempts < settings.selfie_max_attempts

    liveness = provider.liveness(selfie)
    if liveness.score >= runtime.get("liveness_threshold"):
        liveness_status = CheckStatus.PASSED
    else:
        liveness_status = CheckStatus.RETRY if can_retry else CheckStatus.FAILED
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
        payload={
            "provider": liveness.provider,
            "status": str(liveness_status),
            "attempt": attempts,
        },
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

    if liveness_status != CheckStatus.PASSED:
        # A capture that may still be retried leaves the match pending; a
        # definitive spoof means matching it would be meaningless.
        if liveness_status == CheckStatus.FAILED:
            kyc.set_check(
                db, session, Step.FACE_MATCH, CheckStatus.FAILED, internal={"skipped": True}
            )
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
    if match.score >= runtime.get("face_match_threshold"):
        match_status = CheckStatus.PASSED
    elif match.details.get("reason") in _QUALITY_REASONS and can_retry:
        match_status = CheckStatus.RETRY
    else:
        match_status = CheckStatus.FAILED
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
        payload={
            "provider": match.provider,
            "status": str(match_status),
            "attempt": attempts,
        },
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
