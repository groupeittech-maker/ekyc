import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, UTCDateTime, utcnow


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255))
    client_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    client_secret_hash: Mapped[str] = mapped_column(String(128))
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    webhook_url: Mapped[str | None] = mapped_column(String(500), default=None)
    webhook_secret: Mapped[str | None] = mapped_column(String(128), default=None)

    allowed_flows: Mapped[list[str]] = mapped_column(JSON, default=list)
    branding: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    retention_days: Mapped[int] = mapped_column(Integer, default=3650)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
