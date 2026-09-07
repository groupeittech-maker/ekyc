from datetime import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UTCDateTime, utcnow
from app.models.enums import SessionStatus


class KycSession(Base):
    __tablename__ = "kyc_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)

    customer_reference: Mapped[str | None] = mapped_column(String(128), index=True, default=None)
    flow: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default=SessionStatus.CREATED)

    access_token_hash: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)

    # Structured identity extracted and consolidated by the identity engine.
    identity: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Per-step results, e.g. {"DOCUMENT": "PASSED", "LIVENESS": "PASSED"}.
    checks: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Internal scores and provider payloads; never exposed to tenants.
    internal: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    reasons: Mapped[list[str]] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, default=None)
