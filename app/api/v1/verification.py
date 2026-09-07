"""End-user facing API, consumed by the hosted verification UI.

Authenticated with the single-use session token embedded in ``verification_url``;
the tenant credentials are never exposed to the end-user's browser.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status

from app.api.deps import DbSession, client_ip, get_verification_session, require_open
from app.core.config import settings
from app.engines import otp as otp_engine
from app.engines.audit import record_event
from app.models.document import Document
from app.models.enums import ArtifactKind, AuditEventType, DocumentType, Step
from app.models.session import KycSession
from app.models.tenant import Tenant
from app.schemas import (
    DocumentUploadResponse,
    OtpSendRequest,
    OtpSendResponse,
    OtpVerifyRequest,
    OtpVerifyResponse,
    SessionContextResponse,
    StepResultResponse,
)
from app.services import kyc
from app.services.archive import store_artifact
from app.workers.tasks import process_document, process_selfie

router = APIRouter(prefix="/verification/{session_id}", tags=["verification"])

VerificationSession = Annotated[KycSession, Depends(get_verification_session)]

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


async def _read_upload(file: UploadFile) -> bytes:
    data = await file.read()
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty upload")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File too large")
    return data


def _step_result(db: DbSession, session: KycSession) -> StepResultResponse:
    db.refresh(session)
    return StepResultResponse(
        session_id=session.id, status=str(session.status), checks=session.checks
    )


@router.get("/context", response_model=SessionContextResponse)
def context(session: VerificationSession, db: DbSession) -> SessionContextResponse:
    policy = kyc.policy_of(session)
    tenant = db.get(Tenant, session.tenant_id)
    return SessionContextResponse(
        session_id=session.id,
        flow=policy.name,
        flow_label=policy.label,
        status=str(session.status),
        steps=[str(step) for step in policy.steps],
        accepted_documents=[str(doc) for doc in policy.accepted_documents],
        checks=session.checks,
        branding=tenant.branding if tenant else {},
        expires_at=session.expires_at,
    )


@router.post(
    "/document", response_model=DocumentUploadResponse, status_code=status.HTTP_202_ACCEPTED
)
async def upload_document(
    session: VerificationSession,
    db: DbSession,
    request: Request,
    document_type: Annotated[DocumentType, Form()],
    file: Annotated[UploadFile, File()],
) -> DocumentUploadResponse:
    require_open(session)
    policy = kyc.policy_of(session)
    if document_type not in policy.accepted_documents:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"{document_type} is not accepted for flow {policy.name}",
        )

    data = await _read_upload(file)
    artifact = store_artifact(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        kind=ArtifactKind.DOCUMENT_IMAGE,
        filename=file.filename or "document",
        data=data,
        content_type=file.content_type or "application/octet-stream",
    )
    document = Document(
        session_id=session.id,
        tenant_id=session.tenant_id,
        document_type=str(document_type),
        artifact_id=artifact.id,
    )
    db.add(document)
    db.flush()
    record_event(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        event_type=AuditEventType.DOCUMENT_UPLOADED,
        payload={"document_type": str(document_type), "document_id": document.id},
        actor="END_USER",
        ip=client_ip(request),
        document_hash=artifact.sha256,
    )
    document_id = document.id
    db.commit()

    process_document.delay(document_id)
    return DocumentUploadResponse(
        document_id=document_id,
        document_type=document_type,
        **_step_result(db, session).model_dump(),
    )


@router.post("/selfie", response_model=StepResultResponse, status_code=status.HTTP_202_ACCEPTED)
async def upload_selfie(
    session: VerificationSession,
    db: DbSession,
    request: Request,
    file: Annotated[UploadFile, File()],
) -> StepResultResponse:
    require_open(session)
    data = await _read_upload(file)
    artifact = store_artifact(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        kind=ArtifactKind.SELFIE,
        filename=file.filename or "selfie",
        data=data,
        content_type=file.content_type or "application/octet-stream",
    )
    record_event(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        event_type=AuditEventType.SELFIE_CAPTURED,
        payload={"artifact_id": artifact.id},
        actor="END_USER",
        ip=client_ip(request),
        document_hash=artifact.sha256,
    )
    artifact_id = artifact.id
    session_id = session.id
    db.commit()

    process_selfie.delay(session_id, artifact_id)
    return _step_result(db, session)


@router.post("/otp/send", response_model=OtpSendResponse)
def send_otp(
    payload: OtpSendRequest, session: VerificationSession, db: DbSession
) -> OtpSendResponse:
    require_open(session)
    if not kyc.policy_of(session).requires(Step.OTP):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OTP is not part of this flow")
    challenge = otp_engine.send_otp(db, session, payload.channel, payload.destination)
    db.commit()
    return OtpSendResponse(
        sent=True,
        channel=challenge.channel,
        destination=challenge.destination_masked,
        expires_in=settings.otp_ttl_seconds,
    )


@router.post("/otp/verify", response_model=OtpVerifyResponse)
def verify_otp(
    payload: OtpVerifyRequest, session: VerificationSession, db: DbSession
) -> OtpVerifyResponse:
    require_open(session)
    try:
        verified = otp_engine.verify_otp(db, session, payload.code)
    except otp_engine.OtpError as exc:
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if verified:
        kyc.evaluate(db, session)
    db.commit()
    return OtpVerifyResponse(verified=verified)


@router.get("/status", response_model=StepResultResponse)
def status_(session: VerificationSession, db: DbSession) -> StepResultResponse:
    return _step_result(db, session)
