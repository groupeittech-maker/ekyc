"""Identity engine: OCR -> document verification -> structured identity.

OCR only reads what is printed; document verification decides whether the
document looks authentic; identity verification consolidates the result.
"""

from __future__ import annotations

from datetime import date

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.base import utcnow
from app.engines import audit
from app.engines.providers import get_ocr_provider
from app.models.document import Artifact, Document
from app.models.enums import AuditEventType, CheckStatus, Step
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


def process_document(
    db: Session, session: KycSession, document: Document, image: bytes
) -> Document:
    provider = get_ocr_provider()

    ocr = provider.extract(image, document.document_type)
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

    authenticity = provider.check_authenticity(image, ocr)
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

    if expired or not authenticity.authentic:
        status = CheckStatus.FAILED
    elif authenticity.confidence < settings.document_review_threshold:
        status = CheckStatus.REVIEW
    else:
        status = CheckStatus.PASSED
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
        payload={"status": str(status), "expired": expired, "document_id": document.id},
    )

    if status != CheckStatus.FAILED:
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
        },
    )
    db.flush()
    return document


def document_image(db: Session, session_id: str) -> tuple[Artifact, bytes] | None:
    from sqlalchemy import select

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
