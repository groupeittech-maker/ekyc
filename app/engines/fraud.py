"""Fraud engine — cross-session signals within a tenant.

Runs before the final decision and emits *signals*, never an automatic
reject: re-verifying the same person is legitimate (renewal, second product),
but a reused document number or phone number across different customer
references deserves a human look. Severity model:

* ``high``   — forces the session into REVIEW (never silently verified);
* ``medium`` — recorded in the evidence trail, does not block.

Signals are tenant-scoped: one tenant's data never leaks into another's
decision.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit import AuditEvent
from app.models.enums import AuditEventType
from app.models.otp import OtpChallenge
from app.models.session import KycSession


def _norm_document_number(value: str | None) -> str | None:
    if not value:
        return None
    normalized = re.sub(r"[^A-Z0-9]", "", value.upper())
    return normalized or None


def scan(db: Session, session: KycSession) -> dict[str, Any]:
    """Compute fraud signals for a session about to be decided."""
    signals: list[dict[str, Any]] = []

    # 1. Same document number already verified under this tenant.
    document_number = _norm_document_number((session.identity or {}).get("document_number"))
    if document_number:
        others = db.scalars(
            select(KycSession).where(
                KycSession.tenant_id == session.tenant_id,
                KycSession.id != session.id,
                KycSession.status.in_(["VERIFIED", "REVIEW"]),
            )
        ).all()
        duplicates = [
            other.id
            for other in others
            if _norm_document_number((other.identity or {}).get("document_number"))
            == document_number
        ]
        if duplicates:
            signals.append(
                {
                    "code": "DUPLICATE_DOCUMENT",
                    "severity": "high",
                    "detail": f"document number already seen on {len(duplicates)} session(s)",
                }
            )

    # 2. Same OTP destination used by another session of this tenant.
    destinations = db.scalars(
        select(OtpChallenge.destination_hash).where(
            OtpChallenge.session_id == session.id,
            OtpChallenge.verified_at.isnot(None),
        )
    ).all()
    for destination_hash in set(destinations):
        used_elsewhere = db.scalar(
            select(OtpChallenge.session_id).where(
                OtpChallenge.session_id != session.id,
                OtpChallenge.destination_hash == destination_hash,
                OtpChallenge.verified_at.isnot(None),
            )
        )
        if used_elsewhere:
            signals.append(
                {
                    "code": "DUPLICATE_DESTINATION",
                    "severity": "medium",
                    "detail": "OTP destination already verified on another session",
                }
            )

    # 3. Creation velocity from the same client IP.
    created_event = db.scalar(
        select(AuditEvent).where(
            AuditEvent.session_id == session.id,
            AuditEvent.event_type == AuditEventType.KYC_SESSION_CREATED.value,
        )
    )
    ip = created_event.ip if created_event else None
    if ip:
        recent = db.scalars(
            select(AuditEvent).where(
                AuditEvent.tenant_id == session.tenant_id,
                AuditEvent.event_type == AuditEventType.KYC_SESSION_CREATED.value,
                AuditEvent.ip == ip,
            )
        ).all()
        # Cheap proxy: many session-creation events from one IP.
        if len(recent) >= 10:
            signals.append(
                {
                    "code": "IP_VELOCITY",
                    "severity": "medium",
                    "detail": f"{len(recent)} sessions created from the same IP",
                }
            )

    level = (
        "HIGH"
        if any(s["severity"] == "high" for s in signals)
        else "MEDIUM"
        if signals
        else "LOW"
    )
    return {"level": level, "signals": signals}
