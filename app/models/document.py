import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UTCDateTime, utcnow
from app.models.enums import CheckStatus


def _uuid() -> str:
    return str(uuid.uuid4())


class Artifact(Base):
    """Any binary stored in the electronic archive (image, PDF, token, export)."""

    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    session_id: Mapped[str | None] = mapped_column(
        ForeignKey("kyc_sessions.id"), index=True, default=None
    )
    kind: Mapped[str] = mapped_column(String(32))
    storage_key: Mapped[str] = mapped_column(String(500))
    content_type: Mapped[str] = mapped_column(String(128), default="application/octet-stream")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Document(Base):
    """An identity document submitted in a KYC session."""

    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    session_id: Mapped[str] = mapped_column(ForeignKey("kyc_sessions.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)

    document_type: Mapped[str] = mapped_column(String(32))
    artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.id"))

    ocr: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    verification: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default=CheckStatus.PENDING)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    processed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
