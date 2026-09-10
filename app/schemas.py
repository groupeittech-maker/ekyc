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


class SessionCreateResponse(BaseModel):
    session_id: str
    status: str
    flow: str
    verification_url: str
    expires_at: datetime


class SessionResultResponse(BaseModel):
    session_id: str
    customer_reference: str | None
    flow: str
    status: str
    checks: dict[str, str]
    reasons: list[str]
    identity: dict[str, Any] | None
    risk_score: float | None = None
    created_at: datetime
    completed_at: datetime | None


class SessionContextResponse(BaseModel):
    session_id: str
    flow: str
    flow_label: str
    status: str
    steps: list[str]
    accepted_documents: list[str]
    checks: dict[str, str]
    branding: dict[str, Any]
    expires_at: datetime


class OtpSendRequest(BaseModel):
    channel: OtpChannel = OtpChannel.SMS
    destination: str


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


class DocumentUploadResponse(StepResultResponse):
    document_id: str
    document_type: DocumentType


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
