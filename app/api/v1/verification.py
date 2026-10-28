"""End-user facing API, consumed by the hosted verification UI.

Authenticated with the session token embedded in ``verification_url`` or
obtained through the one-time transfer code (cross-device handoff); the
tenant credentials are never exposed to the end-user's browser.
"""

from __future__ import annotations

import base64
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status

from app.api.deps import (
    DbSession,
    client_ip,
    get_verification_session,
    require_open,
)
from app.core.config import settings
from app.core.security import hash_secret, verify_secret
from datetime import timedelta

from app.db.base import utcnow
from app.engines import otp as otp_engine
from app.engines import passport_pki
from app.engines.audit import record_event
from app.models.document import Document
from app.models.enums import ArtifactKind, AuditEventType, CheckStatus, DocumentType, Step
from app.models.session import KycSession
from app.models.tenant import Tenant
from app.schemas import (
    ConsentRequest,
    ConsentResponse,
    DocumentUploadResponse,
    NfcResultResponse,
    NfcSubmissionRequest,
    OtpSendRequest,
    OtpSendResponse,
    OtpVerifyRequest,
    OtpVerifyResponse,
    SessionContextResponse,
    StepResultResponse,
    TransferCreateResponse,
    TransferExchangeRequest,
    TransferExchangeResponse,
)
from app.services import kyc
from app.services.archive import store_artifact
from app.workers.tasks import process_document, process_selfie

router = APIRouter(prefix="/verification/{session_id}", tags=["verification"])

VerificationSession = Annotated[KycSession, Depends(get_verification_session)]

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_NFC_BYTES = 256 * 1024


async def _read_upload(file: UploadFile) -> bytes:
    data = await file.read()
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty upload")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "File too large")
    return data


def _sniff(data: bytes) -> str | None:
    """Real content type from magic bytes — the declared MIME is client input."""
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    return None


def _require_image(data: bytes, provider_name: str, field: str) -> None:
    """With real OCR/biometric providers, only decodable images are accepted.

    The dev ``stub`` providers deliberately accept text fixtures — they never
    run in production (startup refuses them), so the bypass cannot leak.
    """
    if provider_name == "stub":
        return
    if _sniff(data) is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{field}: an image capture (JPEG/PNG/WebP) is required",
        )


def _step_result(db: DbSession, session: KycSession) -> StepResultResponse:
    db.refresh(session)
    return StepResultResponse(
        session_id=session.id, status=str(session.status), checks=session.checks
    )


def _require_consent(session: KycSession) -> None:
    try:
        kyc.require_consent(session)
    except kyc.ConsentRequiredError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "CONSENT_REQUIRED") from exc


def _norm_destination(value: str) -> str:
    return otp_engine.normalize_destination(value)


@router.get("/context", response_model=SessionContextResponse)
def context(session: VerificationSession, db: DbSession) -> SessionContextResponse:
    policy = kyc.policy_of(session)
    tenant = db.get(Tenant, session.tenant_id)
    declared = (session.metadata_ or {}).get("otp_destination")
    masked = None
    if declared:
        normalized = _norm_destination(str(declared))
        masked = otp_engine.mask_destination(normalized if "@" not in normalized else normalized)
    return SessionContextResponse(
        session_id=session.id,
        flow=policy.name,
        flow_label=policy.label,
        status=str(session.status),
        steps=[str(step) for step in policy.steps],
        accepted_documents=[str(doc) for doc in policy.accepted_documents],
        checks=session.checks,
        branding=tenant.branding if tenant else {},
        consent={
            "required": policy.requires_consent,
            "given": bool((session.consent or {}).get("accepted")),
            "policy_version": (session.consent or {}).get("policy_version"),
        },
        otp_destination=masked,
        consent_policy_version=settings.consent_policy_version,
        expires_at=session.expires_at,
    )


@router.post("/consent", response_model=ConsentResponse)
def consent(
    payload: ConsentRequest,
    session: VerificationSession,
    db: DbSession,
    request: Request,
) -> ConsentResponse:
    require_open(session)
    if payload.policy_version != settings.consent_policy_version:
        # The evidence dossier must name a consent text the platform actually
        # publishes — a client-asserted version is refused.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "UNKNOWN_POLICY_VERSION")
    if payload.accepted:
        kyc.grant_consent(
            db,
            session,
            policy_version=payload.policy_version,
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent"),
            donate_samples=payload.donate_samples,
        )
        db.commit()
        return ConsentResponse(accepted=True, **_step_result(db, session).model_dump())
    kyc.decline_consent(db, session, policy_version=payload.policy_version, ip=client_ip(request))
    db.commit()
    raise HTTPException(status.HTTP_409_CONFLICT, "CONSENT_DECLINED")


@router.post(
    "/document", response_model=DocumentUploadResponse, status_code=status.HTTP_202_ACCEPTED
)
async def upload_document(
    session: VerificationSession,
    db: DbSession,
    request: Request,
    document_type: Annotated[DocumentType, Form()],
    file: Annotated[UploadFile, File()],
    file_verso: Annotated[UploadFile | None, File()] = None,
) -> DocumentUploadResponse:
    """Recto upload, plus the verso for card-format documents (TD1 MRZ is on
    the back while the face-match portrait stays on the front)."""
    require_open(session)
    _require_consent(session)
    policy = kyc.policy_of(session)
    if document_type not in policy.accepted_documents:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"{document_type} is not accepted for flow {policy.name}",
        )

    data = await _read_upload(file)
    _require_image(data, settings.ocr_provider, "file")
    artifact = store_artifact(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        kind=ArtifactKind.DOCUMENT_IMAGE,
        filename=file.filename or "document",
        data=data,
        content_type=file.content_type or "application/octet-stream",
        vault_profile=session.vault_profile,
    )
    verso_artifact = None
    if file_verso is not None:
        verso_data = await _read_upload(file_verso)
        _require_image(verso_data, settings.ocr_provider, "file_verso")
        verso_artifact = store_artifact(
            db,
            tenant_id=session.tenant_id,
            session_id=session.id,
            kind=ArtifactKind.DOCUMENT_VERSO,
            filename=file_verso.filename or "document-verso",
            data=verso_data,
            content_type=file_verso.content_type or "application/octet-stream",
            vault_profile=session.vault_profile,
        )
        record_event(
            db,
            tenant_id=session.tenant_id,
            session_id=session.id,
            event_type=AuditEventType.DOCUMENT_UPLOADED,
            payload={"side": "verso", "document_type": str(document_type)},
            actor="END_USER",
            ip=client_ip(request),
            document_hash=verso_artifact.sha256,
        )
    document = Document(
        session_id=session.id,
        tenant_id=session.tenant_id,
        document_type=str(document_type),
        artifact_id=artifact.id,
        verso_artifact_id=verso_artifact.id if verso_artifact else None,
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
    _require_consent(session)
    data = await _read_upload(file)
    _require_image(data, settings.face_provider, "file")
    artifact = store_artifact(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        kind=ArtifactKind.SELFIE,
        filename=file.filename or "selfie",
        data=data,
        content_type=file.content_type or "application/octet-stream",
        vault_profile=session.vault_profile,
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


def _decode_field(value: str | None, name: str) -> bytes | None:
    if value is None:
        return None
    try:
        data = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{name}: invalid base64") from exc
    if not data or len(data) > MAX_NFC_BYTES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{name}: bad size")
    return data


@router.post("/nfc", response_model=NfcResultResponse)
def submit_nfc(
    payload: NfcSubmissionRequest, session: VerificationSession, db: DbSession, request: Request
) -> NfcResultResponse:
    """eMRTD chip data read over NFC — passive authentication is recomputed
    server-side; a client-asserted "chip read OK" is never trusted."""
    require_open(session)
    _require_consent(session)
    if Step.NFC not in kyc.policy_of(session).optional_steps:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "NFC is not part of this flow")

    ef_com = _decode_field(payload.ef_com, "ef_com")
    ef_sod = _decode_field(payload.ef_sod, "ef_sod")
    dg1 = _decode_field(payload.dg1, "dg1")
    dg2 = _decode_field(payload.dg2, "dg2")

    for kind, blob in (
        (ArtifactKind.NFC_COM, ef_com),
        (ArtifactKind.NFC_SOD, ef_sod),
        (ArtifactKind.NFC_DG1, dg1),
        (ArtifactKind.NFC_DG2, dg2),
    ):
        if blob is None:
            continue
        stored = store_artifact(
            db,
            tenant_id=session.tenant_id,
            session_id=session.id,
            kind=kind,
            filename=f"{session.id}-{str(kind).lower()}.bin",
            data=blob,
            content_type="application/octet-stream",
            vault_profile=session.vault_profile,
        )
        record_event(
            db,
            tenant_id=session.tenant_id,
            session_id=session.id,
            event_type=AuditEventType.NFC_SUBMITTED,
            payload={"group": str(kind)},
            actor="END_USER",
            ip=client_ip(request),
            document_hash=stored.sha256,
        )

    result = passport_pki.verify_passport(ef_com=ef_com, ef_sod=ef_sod, dg1=dg1, dg2=dg2)
    check_status = {
        "VALID": CheckStatus.PASSED,
        "INVALID": CheckStatus.FAILED,
        "INDETERMINATE": CheckStatus.REVIEW,
    }[result.status]
    kyc.set_check(
        db,
        session,
        Step.NFC,
        check_status,
        internal={"nfc_status": result.status, "reason": result.reason, **result.details},
    )
    record_event(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        event_type=AuditEventType.NFC_VERIFIED,
        payload={"status": result.status, "reason": result.reason},
    )
    final = kyc.evaluate(db, session)
    db.commit()
    return NfcResultResponse(
        session_id=session.id,
        status=str(final),
        checks=session.checks,
        nfc_status=result.status,
        reason=result.reason,
    )


@router.post("/transfer", response_model=TransferCreateResponse)
def create_transfer(
    session: VerificationSession, db: DbSession, request: Request
) -> TransferCreateResponse:
    """Issue a one-time code the second device exchanges for a session token —
    lets a journey started on desktop continue on a phone (e.g. for NFC)."""
    require_open(session)
    code = secrets.token_urlsafe(24)
    session = kyc.lock_session(db, session.id)
    session.transfer_code_hash = hash_secret(code)
    session.transfer_expires_at = utcnow() + timedelta(seconds=settings.transfer_ttl_seconds)
    record_event(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        event_type=AuditEventType.SESSION_TRANSFER_CREATED,
        payload={},
        actor="END_USER",
        ip=client_ip(request),
    )
    db.commit()
    transfer_url = f"{settings.base_url.rstrip('/')}/verify/{session.id}?transfer={code}"
    return TransferCreateResponse(
        transfer_url=transfer_url,
        expires_in=settings.transfer_ttl_seconds,
        qr_data_uri=_qr_data_uri(transfer_url),
    )


def _qr_data_uri(url: str) -> str | None:
    """PNG QR as a data URI; None when the optional qrcode dep is absent."""
    try:
        import io

        import qrcode
    except ImportError:
        return None
    buffer = io.BytesIO()
    qrcode.make(url).save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode()


@router.post("/transfer/exchange", response_model=TransferExchangeResponse)
def exchange_transfer(
    payload: TransferExchangeRequest, session_id: str, db: DbSession, request: Request
) -> TransferExchangeResponse:
    """Swap a one-time transfer code for a scoped session bearer. The code is
    single-use and short-lived; the minted bearer is bound to this session."""
    session = db.get(KycSession, session_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    session = kyc.lock_session(db, session.id)
    code_hash = session.transfer_code_hash
    valid = (
        code_hash is not None
        and session.transfer_expires_at is not None
        and session.transfer_expires_at > utcnow()
        and verify_secret(payload.code, code_hash)
    )
    if not valid:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired transfer code")

    # One-time use: replace the code with the device bearer it just minted.
    device_token = secrets.token_urlsafe(32)
    session.transfer_code_hash = hash_secret(device_token)
    session.transfer_expires_at = session.expires_at
    record_event(
        db,
        tenant_id=session.tenant_id,
        session_id=session.id,
        event_type=AuditEventType.SESSION_TRANSFER_USED,
        payload={},
        actor="END_USER",
        ip=client_ip(request),
    )
    db.commit()
    return TransferExchangeResponse(session_id=session.id, token=device_token)





@router.post("/otp/send", response_model=OtpSendResponse)
def send_otp(
    payload: OtpSendRequest, session: VerificationSession, db: DbSession
) -> OtpSendResponse:
    require_open(session)
    _require_consent(session)
    if not kyc.policy_of(session).requires(Step.OTP):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OTP is not part of this flow")
    declared = (session.metadata_ or {}).get("otp_destination")
    if declared and _norm_destination(str(declared)) != _norm_destination(payload.destination):
        # The tenant declared the destination at session creation — the end
        # user cannot substitute another number (OTP then means "controls the
        # declared phone", not "controls some phone").
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OTP_DESTINATION_MISMATCH")
    try:
        challenge = otp_engine.send_otp(db, session, payload.channel, payload.destination)
    except otp_engine.OtpRateLimited as exc:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "OTP_RATE_LIMITED") from exc
    except otp_engine.OtpDeliveryError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "OTP_DELIVERY_UNAVAILABLE"
        ) from exc
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
    _require_consent(session)
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
