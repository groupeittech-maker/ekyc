from __future__ import annotations

import base64
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select

from app.api.deps import CurrentTenant, DbSession, client_ip, get_tenant_session
from app.db.base import utcnow
from app.engines import audit
from app.engines.policy import UnknownFlowError
from app.models.document import Artifact
from app.models.session import KycSession
from app.models.signature import SignedDocument
from app.schemas import (
    AuditEventResponse,
    AuditExportResponse,
    ContractRequest,
    SessionCreateRequest,
    SessionCreateResponse,
    SessionResultResponse,
    SignedDocumentResponse,
)
from app.services import evidence, kyc
from app.services.archive import read_artifact
from app.services.pdf import render_contract, render_kyc_certificate

router = APIRouter(prefix="/kyc/sessions", tags=["kyc"])

TenantSession = Annotated[KycSession, Depends(get_tenant_session)]


@router.post("", response_model=SessionCreateResponse, status_code=status.HTTP_201_CREATED)
def create_session(
    payload: SessionCreateRequest, tenant: CurrentTenant, db: DbSession, request: Request
) -> SessionCreateResponse:
    try:
        session, token = kyc.create_session(
            db,
            tenant=tenant,
            flow=payload.flow,
            customer_reference=payload.customer_reference,
            metadata=payload.metadata,
            ip=client_ip(request),
        )
    except UnknownFlowError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc

    db.commit()
    return SessionCreateResponse(
        session_id=session.id,
        status=str(session.status),
        flow=session.flow,
        verification_url=kyc.verification_url(session, token),
        expires_at=session.expires_at,
    )


@router.get("/{session_id}", response_model=SessionResultResponse)
def get_session(session: TenantSession) -> SessionResultResponse:
    return SessionResultResponse(**kyc.public_result(session))


@router.get("/{session_id}/audit", response_model=AuditExportResponse)
def export_audit(session: TenantSession, db: DbSession) -> AuditExportResponse:
    events = audit.list_events(db, session.id)
    return AuditExportResponse(
        session_id=session.id,
        integrity=audit.verify_chain(db, session.id),
        events=[
            AuditEventResponse(
                sequence=item.sequence,
                event_type=item.event_type,
                actor=item.actor,
                occurred_at=item.created_at,
                document_hash=item.document_hash,
                previous_event_hash=item.previous_event_hash,
                event_hash=item.event_hash,
                payload=item.payload,
            )
            for item in events
        ],
    )


CERTIFICATE_REFERENCE = "KYC_CERTIFICATE"


@router.get("/{session_id}/certificate")
def kyc_certificate(session: TenantSession, db: DbSession, tenant: CurrentTenant) -> Response:
    """Return the KYC certificate, sealed by the evidence pipeline and archived."""
    signed = db.scalars(
        select(SignedDocument)
        .where(
            SignedDocument.session_id == session.id,
            SignedDocument.document_reference == CERTIFICATE_REFERENCE,
        )
        .order_by(SignedDocument.created_at.desc())
    ).first()

    if signed is None:
        pdf = render_kyc_certificate(
            session_id=session.id,
            tenant_name=tenant.name,
            flow=session.flow,
            status=str(session.status),
            identity=(kyc.public_result(session)["identity"] or {}),
            checks=session.checks,
            audit_head_hash=audit.verify_chain(db, session.id).get("head_hash"),
            issued_at=utcnow().isoformat(timespec="seconds"),
        )
        signed = evidence.seal_document(
            db,
            session,
            pdf_bytes=pdf,
            document_reference=CERTIFICATE_REFERENCE,
            filename=f"{session.id}-certificate.pdf",
        )
        db.commit()

    artifact = db.get(Artifact, signed.signed_artifact_id)
    if artifact is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Certificate artifact missing")
    return Response(
        content=read_artifact(artifact),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{session.id}-certificate.pdf"',
            "X-EKYC-Document-Sha256": signed.sha256,
            "X-EKYC-Signature-Algorithm": signed.signature_algorithm,
            "X-EKYC-Timestamp-Authority": signed.timestamp_authority or "",
            "X-EKYC-Timestamp-Qualified": str(bool(signed.timestamp_details.get("qualified"))),
        },
    )


def _signed_response(signed: SignedDocument) -> SignedDocumentResponse:
    return SignedDocumentResponse(
        signed_document_id=signed.id,
        session_id=signed.session_id,
        document_reference=signed.document_reference,
        sha256=signed.sha256,
        signature_algorithm=signed.signature_algorithm,
        certificate_fingerprint=signed.certificate_fingerprint,
        timestamp_authority=signed.timestamp_authority,
        timestamp_qualified=bool(signed.timestamp_details.get("qualified")),
        timestamped_at=signed.timestamped_at,
        download_url=f"/v1/kyc/sessions/{signed.session_id}/documents/{signed.id}",
    )


@router.post(
    "/{session_id}/documents",
    response_model=SignedDocumentResponse,
    status_code=status.HTTP_201_CREATED,
)
def seal_contract(
    payload: ContractRequest, session: TenantSession, db: DbSession, tenant: CurrentTenant
) -> SignedDocumentResponse:
    """Generate (or accept) a PDF, then hash, sign, timestamp, audit and archive it."""
    if payload.pdf_base64:
        try:
            pdf_bytes = base64.b64decode(payload.pdf_base64, validate=True)
        except ValueError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid base64 PDF") from exc
    else:
        identity = kyc.public_result(session)["identity"] or {}
        pdf_bytes = render_contract(
            title=payload.title,
            session_id=session.id,
            tenant_name=tenant.name,
            body=[*identity.items(), *payload.fields.items()],
            issued_at=utcnow().isoformat(timespec="seconds"),
        )

    signed = evidence.seal_document(
        db,
        session,
        pdf_bytes=pdf_bytes,
        document_reference=payload.document_reference,
        filename=f"{payload.document_reference or 'document'}.pdf",
    )
    db.commit()
    return _signed_response(signed)


@router.get("/{session_id}/documents/{signed_document_id}")
def download_signed_document(
    session: TenantSession, signed_document_id: str, db: DbSession
) -> Response:
    signed = db.get(SignedDocument, signed_document_id)
    if signed is None or signed.session_id != session.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Signed document not found")
    artifact = db.get(Artifact, signed.signed_artifact_id)
    if artifact is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Archived document not found")
    return Response(
        content=read_artifact(artifact),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{signed.id}.pdf"',
            "X-EKYC-Document-SHA256": signed.sha256,
        },
    )
