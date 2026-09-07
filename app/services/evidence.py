"""Evidence pipeline: PDF -> SHA-256 -> signature -> timestamp -> audit -> archive."""

from __future__ import annotations

import io
from typing import Any

from pypdf import PdfReader, PdfWriter
from sqlalchemy.orm import Session

from app.core.hashing import sha256_bytes
from app.db.base import utcnow
from app.engines import audit
from app.engines.signature import sign_digest
from app.engines.timestamp import request_timestamp
from app.models.enums import ArtifactKind, AuditEventType
from app.models.session import KycSession
from app.models.signature import SignedDocument
from app.services.archive import store_artifact


def _embed_evidence(pdf_bytes: bytes, evidence: dict[str, Any]) -> bytes:
    """Write the proof elements into the PDF metadata for offline verification."""
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    metadata = {f"/{key}": str(value) for key, value in evidence.items()}
    writer.add_metadata(metadata)
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def seal_document(
    db: Session,
    session: KycSession,
    *,
    pdf_bytes: bytes,
    document_reference: str | None = None,
    filename: str = "document.pdf",
) -> SignedDocument:
    tenant_id = session.tenant_id

    source = store_artifact(
        db,
        tenant_id=tenant_id,
        session_id=session.id,
        kind=ArtifactKind.CONTRACT,
        filename=filename,
        data=pdf_bytes,
        content_type="application/pdf",
    )
    audit.record_event(
        db,
        tenant_id=tenant_id,
        session_id=session.id,
        event_type=AuditEventType.CONTRACT_GENERATED,
        payload={"artifact_id": source.id, "reference": document_reference},
        document_hash=source.sha256,
    )

    digest = source.sha256
    audit.record_event(
        db,
        tenant_id=tenant_id,
        session_id=session.id,
        event_type=AuditEventType.HASH_GENERATED,
        payload={"algorithm": "SHA-256"},
        document_hash=digest,
    )

    signature = sign_digest(bytes.fromhex(digest))
    audit.record_event(
        db,
        tenant_id=tenant_id,
        session_id=session.id,
        event_type=AuditEventType.DOCUMENT_SIGNED,
        payload={
            "algorithm": signature.algorithm,
            "certificate_fingerprint": signature.certificate_fingerprint,
        },
        document_hash=digest,
    )

    token = request_timestamp(digest)
    token_artifact = store_artifact(
        db,
        tenant_id=tenant_id,
        session_id=session.id,
        kind=ArtifactKind.TIMESTAMP_TOKEN,
        filename=f"{digest[:16]}.tsr",
        data=token.token,
        content_type="application/timestamp-reply",
    )
    audit.record_event(
        db,
        tenant_id=tenant_id,
        session_id=session.id,
        event_type=AuditEventType.TIMESTAMPED,
        payload={
            "authority": token.authority,
            "qualified": token.qualified,
            "issued_at": token.issued_at,
        },
        document_hash=digest,
    )

    sealed_bytes = _embed_evidence(
        pdf_bytes,
        {
            "KycSessionId": session.id,
            "DocumentReference": document_reference or "",
            "DocumentSha256": digest,
            "Signature": signature.b64,
            "SignatureAlgorithm": signature.algorithm,
            "CertificateFingerprint": signature.certificate_fingerprint or "",
            "TimestampAuthority": token.authority,
            "TimestampedAt": token.issued_at,
            "TimestampQualified": token.qualified,
        },
    )
    sealed = store_artifact(
        db,
        tenant_id=tenant_id,
        session_id=session.id,
        kind=ArtifactKind.SIGNED_CONTRACT,
        filename=f"signed_{filename}",
        data=sealed_bytes,
        content_type="application/pdf",
    )
    audit.record_event(
        db,
        tenant_id=tenant_id,
        session_id=session.id,
        event_type=AuditEventType.DOCUMENT_ARCHIVED,
        payload={"artifact_id": sealed.id, "storage_key": sealed.storage_key},
        document_hash=sealed.sha256,
    )

    signed = SignedDocument(
        tenant_id=tenant_id,
        session_id=session.id,
        document_reference=document_reference,
        source_artifact_id=source.id,
        signed_artifact_id=sealed.id,
        sha256=digest,
        signature=signature.b64,
        signature_algorithm=signature.algorithm,
        certificate_fingerprint=signature.certificate_fingerprint,
        timestamp_authority=token.authority,
        timestamp_token_artifact_id=token_artifact.id,
        timestamped_at=utcnow(),
        timestamp_details={"qualified": token.qualified, **token.details},
    )
    db.add(signed)
    db.flush()
    return signed


def verify_integrity(pdf_bytes: bytes, expected_sha256: str) -> bool:
    return sha256_bytes(pdf_bytes) == expected_sha256
