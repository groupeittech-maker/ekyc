import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UTCDateTime, utcnow


class AuditEvent(Base):
    """Append-only, hash-chained audit trail (one chain per KYC session)."""

    __tablename__ = "audit_events"
    __table_args__ = (UniqueConstraint("session_id", "sequence", name="uq_audit_session_sequence"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("kyc_sessions.id"), index=True)

    sequence: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(64), default="SYSTEM")
    ip: Mapped[str | None] = mapped_column(String(64), default=None)
    user_agent: Mapped[str | None] = mapped_column(String(255), default=None)

    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    document_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    previous_event_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    event_hash: Mapped[str] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
