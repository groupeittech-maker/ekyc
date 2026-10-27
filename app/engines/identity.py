"""Identity engine: OCR -> document verification -> structured identity.

OCR only reads what is printed; document verification decides whether the
document looks authentic; identity verification consolidates the result.

Capture-quality failures (unreadable MRZ, missing fields) return RETRY so the
user can re-capture — a blurry photo is not fraud evidence. Retries are
bounded; once attempts are exhausted the check escalates instead of
auto-rejecting a human being on a technicality.
"""

from __future__ import annotations

from datetime import date

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.base import utcnow
from app.engines import audit
from app.engines.providers import get_ocr_provider
from app.engines.providers.base import OcrResult
from app.models.document import Artifact, Document
from app.models.enums import ArtifactKind, AuditEventType, CheckStatus, Step
from app.models.session import KycSession
from app.services import kyc
from app.services.archive import read_artifact

_IDENTITY_FIELDS = (
    "first_name",
    "last_name",
    "date_of_birth",
    "document_number",
    "nationality",
    "issuing_country",
    "document_type",
    "expiry_date",
    "sex",
)


def _is_expired(expiry: str | None) -> bool:
    if not expiry:
        return False
    try:
        return date.fromisoformat(expiry) < date.today()
    except ValueError:
        return False


def document_attempts(db: Session, session_id: str) -> int:
    """Number of document sides captured so far — bounds recapture loops."""
    return int(
        db.scalar(
            select(func.count(Artifact.id)).where(
                Artifact.session_id == session_id,
                Artifact.kind == ArtifactKind.DOCUMENT_IMAGE.value,
            )
        )
        or 0
    )


def _extract(images: list[bytes], provider, document_type: str) -> OcrResult:
    """OCR each side (recto then verso); the MRZ of a TD1 card is on the back."""
    best = OcrResult(fields={}, provider=getattr(provider, "name", "unknown"))
    raw_texts: list[str] = []
    side_index = -1
    for index, image in enumerate(images):
        try:
            result = provider.extract(image, document_type)
        except Exception:
            result = OcrResult(fields={}, provider=getattr(provider, "name", "unknown"))
        raw_texts.append(result.raw_text or "")
        if result.fields and (side_index < 0 or result.confidence > best.confidence):
            best = result
            side_index = index
    best.raw_text = "\n".join(t for t in raw_texts if t)
    best.fields["mrz_side"] = side_index  # -1 = no MRZ found on any side
    return best


def _classify(
    ocr: OcrResult, authenticity, expired: bool, attempts: int
) -> tuple[CheckStatus, str | None]:
    can_retry = attempts < settings.document_max_attempts
    if not ocr.fields:
        # Nothing readable at all — almost always a capture-quality problem.
        return (CheckStatus.RETRY if can_retry else CheckStatus.REVIEW), "UNREADABLE"
    if expired:
        # Definitive: no recapture will change the expiry date.
        return CheckStatus.FAILED, "EXPIRED"
    if not authenticity.authentic:
        # Check-digit failure / weak authenticity may still be OCR noise:
        # allow recapture first, then let the policy decide (reject or review).
        if can_retry:
            return CheckStatus.RETRY, "AUTHENTICITY_LOW"
        return CheckStatus.FAILED, "AUTHENTICITY_FAILED"
    if authenticity.confidence < settings.document_review_threshold:
        if can_retry:
            return CheckStatus.RETRY, "LOW_CONFIDENCE"
        return CheckStatus.REVIEW, "UNCERTAIN"
    return CheckStatus.PASSED, None


def process_document(
    db: Session, session: KycSession, document: Document, images: list[bytes]
) -> Document:
    provider = get_ocr_provider()
    attempts = document_attempts(db, session.id)

    ocr = _extract(images, provider, document.document_type)
    document.ocr = {
        "fields": ocr.fields,
        "confidence": ocr.confidence,
        "provider": ocr.provider,
    }
    audit.record_event(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        event_type=AuditEventType.OCR_COMPLETED,
        payload={"provider": ocr.provider, "confidence": ocr.confidence},
    )

    # Authenticity signals run on the recto (portrait, ELA); MRZ fields may
    # come from the verso for card-format documents.
    authenticity = provider.check_authenticity(images[0], ocr)
    expired = _is_expired(ocr.fields.get("expiry_date"))
    document.verification = {
        "authentic": authenticity.authentic,
        "confidence": authenticity.confidence,
        "signals": authenticity.signals,
        "expired": expired,
        "provider": authenticity.provider,
    }
    document.confidence = authenticity.confidence
    document.processed_at = utcnow()

    status, reason = _classify(ocr, authenticity, expired, attempts)
    document.status = status

    audit.record_event(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        event_type=(
            AuditEventType.DOCUMENT_VERIFIED
            if status == CheckStatus.PASSED
            else AuditEventType.DOCUMENT_REJECTED
        ),
        payload={
            "status": str(status),
            "reason": reason,
            "expired": expired,
            "attempt": attempts,
            "document_id": document.id,
        },
    )

    if status == CheckStatus.PASSED:
        session.identity = {
            **session.identity,
            **{key: ocr.fields.get(key) for key in _IDENTITY_FIELDS if ocr.fields.get(key)},
        }

    kyc.set_check(
        db,
        session,
        Step.DOCUMENT_VERIFICATION,
        status,
        internal={
            "ocr_confidence": ocr.confidence,
            "authenticity_confidence": authenticity.confidence,
            "provider": authenticity.provider,
            "retry_reason": reason,
            "attempt": attempts,
        },
    )
    db.flush()
    return document


def document_image(db: Session, session_id: str) -> tuple[Artifact, bytes] | None:
    """The recto artifact — the side that carries the portrait for face match."""
    document = db.scalars(
        select(Document)
        .where(Document.session_id == session_id)
        .order_by(Document.created_at.desc())
    ).first()
    if document is None:
        return None
    artifact = db.get(Artifact, document.artifact_id)
    if artifact is None:
        return None
    return artifact, read_artifact(artifact)
