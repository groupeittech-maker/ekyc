"""Per-document observations — NON-PERSONAL metadata only.

What is recorded: format, country, document type, parser outcome.
What is NEVER recorded: document number, name, MRZ text, dates, session
reference — a row cannot be tied back to a person.

Purpose (mission LOT E §6.3): detect unknown formats and recurring
errors across analyses without retaining documents or identity data.
"""

from __future__ import annotations

from datetime import datetime

import uuid

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UTCDateTime, utcnow


def _uuid() -> str:
    return uuid.uuid4().hex


class DocumentObservation(Base):
    __tablename__ = "document_observations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=_uuid)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)

    # Non-personal classification labels
    document_type: Mapped[str] = mapped_column(String(32), index=True)
    mrz_format: Mapped[str | None] = mapped_column(String(8), default=None, index=True)
    issuing_country: Mapped[str | None] = mapped_column(String(8), default=None, index=True)

    # Outcome — not identity data
    status: Mapped[str] = mapped_column(String(16))          # PASSED/RETRY/REVIEW/…
    checks_passed: Mapped[bool] = mapped_column(default=False)
    reason: Mapped[str | None] = mapped_column(String(64), default=None)
    ocr_confidence: Mapped[float | None] = mapped_column(default=None)
    # Signals as a compact string (e.g. "EXPIRED|CHECK_DIGIT") — no values
    signals: Mapped[str | None] = mapped_column(String(128), default=None)
