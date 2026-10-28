from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.control_plane.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Instance(Base):
    """A registered national instance — holds ONLY its public key and
    technical state, never any tenant or biometric data."""

    __tablename__ = "instances"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    country_code: Mapped[str] = mapped_column(String(3), index=True)
    instance_public_key: Mapped[str] = mapped_column(Text)
    software_version: Mapped[str] = mapped_column(String(32), default="")
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="enrolled")
    activated: Mapped[bool] = mapped_column(Boolean, default=False)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_payload: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Attestation(Base):
    """Central-signed activation proof — mirrors
    app/core/country_profile.ActivationAttestation on the national side."""

    __tablename__ = "attestations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    instance_id: Mapped[str] = mapped_column(String(36), index=True)
    country: Mapped[str] = mapped_column(String(3))
    legal_review: Mapped[bool] = mapped_column(Boolean)
    hosting_approved: Mapped[bool] = mapped_column(Boolean)
    trust_services_validated: Mapped[bool] = mapped_column(Boolean)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    signature: Mapped[str] = mapped_column(Text)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SeenJti(Base):
    """Anti-replay ledger for instance JWTs — persists across restarts and
    workers. Rows are purged once the token could no longer be valid."""

    __tablename__ = "seen_jti"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Manifest(Base):
    """Signed software/config distribution for one instance."""

    __tablename__ = "manifests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    instance_id: Mapped[str] = mapped_column(String(36), index=True)
    version: Mapped[str] = mapped_column(String(32))
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    config_overlay: Mapped[dict] = mapped_column(JSON, default=dict)
    artifacts: Mapped[list] = mapped_column(JSON, default=list)
    signature: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
