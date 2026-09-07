import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UTCDateTime, utcnow


class SignedDocument(Base):
    __tablename__ = "signed_documents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("kyc_sessions.id"), index=True)

    document_reference: Mapped[str | None] = mapped_column(String(128), default=None)
    source_artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id"))
    signed_artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id"))

    sha256: Mapped[str] = mapped_column(String(64), index=True)
    signature: Mapped[str] = mapped_column(Text)
    signature_algorithm: Mapped[str] = mapped_column(String(64))
    certificate_fingerprint: Mapped[str | None] = mapped_column(String(128), default=None)

    timestamp_authority: Mapped[str | None] = mapped_column(String(255), default=None)
    timestamp_token_artifact_id: Mapped[str | None] = mapped_column(String(64), default=None)
    timestamped_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
    timestamp_details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
