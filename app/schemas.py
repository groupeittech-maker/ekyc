from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.models.enums import DocumentType, OtpChannel


class TokenRequest(BaseModel):
    grant_type: Literal["client_credentials"] = "client_credentials"
    client_id: str
    client_secret: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int


class TenantCreateRequest(BaseModel):
    name: str
    webhook_url: str | None = None
    allowed_flows: list[str] = Field(default_factory=list)
    branding: dict[str, Any] = Field(default_factory=dict)
    retention_days: int = 3650
    # Tenant's home jurisdiction — used when a session does not assert one.
    default_jurisdiction: str | None = None


class TenantCredentialsResponse(BaseModel):
    tenant_id: str
    name: str
    client_id: str
    client_secret: str
    webhook_secret: str | None = None


class SessionCreateRequest(BaseModel):
    flow: str
    customer_reference: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    # Tenant-asserted OTP destination (the phone number on file). When set,
    # the end-user cannot substitute another number — OTP then proves control
    # of the declared number, not of an arbitrary one.
    otp_destination: str | None = None
    # Regulatory context of the operation (e.g. "CI", "EU", "GLOBAL"), asserted
    # by the tenant — NOT the document's country. Falls back to the tenant's
    # default jurisdiction, then the platform default.
    jurisdiction: str | None = None
    # Where the hosted UI sends the user once the flow reaches a terminal
    # state (deep link back into the tenant app). http(s) only — anything
    # else would let a tenant inject javascript: links into the hosted page.
    return_url: str | None = Field(default=None, pattern=r"^https?://")


class SessionCreateResponse(BaseModel):
    session_id: str
    status: str
    flow: str
    jurisdiction: str
    verification_url: str
    expires_at: datetime


class SessionResultResponse(BaseModel):
    session_id: str
    customer_reference: str | None
    flow: str
    jurisdiction: str
    status: str
    checks: dict[str, str]
    reasons: list[str]
    identity: dict[str, Any] | None
    # Per-check detail for the tenant's manual review (score, provider,
    # reason) — filtered scalars only, no engine internals.
    check_details: dict[str, Any] = Field(default_factory=dict)
    risk_score: float | None = None
    created_at: datetime
    completed_at: datetime | None


class EvidenceArtifactResponse(BaseModel):
    artifact_id: str
    kind: str
    content_type: str
    size_bytes: int
    sha256: str
    created_at: datetime
    purged: bool


class SessionEvidenceResponse(BaseModel):
    """Tenant-facing evidence bundle for manual review: what was submitted,
    how each check scored, and where the binary proofs live."""
    session_id: str
    customer_reference: str | None
    status: str
    checks: dict[str, str]
    check_details: dict[str, Any]
    reasons: list[str]
    identity: dict[str, Any] | None
    risk_score: float | None = None
    artifacts: list[EvidenceArtifactResponse]


class SessionContextResponse(BaseModel):
    session_id: str
    flow: str
    flow_label: str
    status: str
    steps: list[str]
    accepted_documents: list[str]
    checks: dict[str, str]
    branding: dict[str, Any]
    consent: dict[str, Any] = Field(default_factory=dict)
    # Masked tenant-declared OTP destination, when the session binds one.
    otp_destination: str | None = None
    # Server-side consent policy version the UI must submit.
    consent_policy_version: str = "v1"
    # Tenant deep link offered on the final screen (set at session creation).
    return_url: str | None = None
    expires_at: datetime


class ConsentRequest(BaseModel):
    accepted: bool
    policy_version: str = "v1"
    # Opt-in: donate document/selfie samples to the calibration dataset
    # (testers during the pilot phase). Never defaults to true.
    donate_samples: bool = False


class OtpSendRequest(BaseModel):
    channel: OtpChannel = OtpChannel.SMS
    # Optional when the tenant bound a destination at session creation: the
    # endpoint then uses the declared destination (and derives the channel
    # from it). May also echo the masked form shown in the verify UI.
    destination: str | None = None


class OtpSendResponse(BaseModel):
    sent: bool
    channel: str
    destination: str
    expires_in: int


class OtpVerifyRequest(BaseModel):
    code: str


class OtpVerifyResponse(BaseModel):
    verified: bool


class StepResultResponse(BaseModel):
    session_id: str
    status: str
    checks: dict[str, str]


class ConsentResponse(StepResultResponse):
    accepted: bool


class DocumentUploadResponse(StepResultResponse):
    document_id: str
    document_type: DocumentType


class TransferCreateResponse(BaseModel):
    transfer_url: str
    expires_in: int
    # PNG QR of the transfer URL as a data URI — rendered server-side so the
    # code never leaves through a third-party chart API or a URL query.
    qr_data_uri: str | None = None


class TransferExchangeRequest(BaseModel):
    code: str


class TransferExchangeResponse(BaseModel):
    session_id: str
    token: str


class NfcSubmissionRequest(BaseModel):
    """eMRTD data groups read over NFC by the mobile app (base64)."""

    ef_com: str
    ef_sod: str
    dg1: str | None = None
    dg2: str | None = None


class NfcResultResponse(StepResultResponse):
    nfc_status: str  # VALID | INVALID | INDETERMINATE
    reason: str


class ContractRequest(BaseModel):
    """Either a pre-built PDF (base64) or fields the platform renders itself."""

    document_reference: str | None = None
    title: str = "Contrat"
    fields: dict[str, Any] = Field(default_factory=dict)
    pdf_base64: str | None = None


class SignedDocumentResponse(BaseModel):
    signed_document_id: str
    session_id: str
    document_reference: str | None
    sha256: str
    signature_algorithm: str
    certificate_fingerprint: str | None
    timestamp_authority: str | None
    timestamp_qualified: bool
    timestamped_at: datetime | None
    download_url: str


class AuditEventResponse(BaseModel):
    sequence: int
    event_type: str
    actor: str
    occurred_at: datetime
    document_hash: str | None
    previous_event_hash: str | None
    event_hash: str
    payload: dict[str, Any]


class AuditExportResponse(BaseModel):
    session_id: str
    integrity: dict[str, Any]
    events: list[AuditEventResponse]
