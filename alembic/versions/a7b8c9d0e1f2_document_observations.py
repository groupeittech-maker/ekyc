"""document observations — non-personal coverage statistics

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-10-28 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

import app.db.base  # noqa: F401 - UTCDateTime custom type
from alembic import op

revision: str = "a7b8c9d0e1f2"
down_revision: str | None = "f6a7b8c9d0e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "document_observations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("created_at", app.db.base.UTCDateTime(), nullable=False),
        sa.Column("document_type", sa.String(32), nullable=False),
        sa.Column("mrz_format", sa.String(8), nullable=True),
        sa.Column("issuing_country", sa.String(8), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("checks_passed", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.String(64), nullable=True),
        sa.Column("ocr_confidence", sa.Float(), nullable=True),
        sa.Column("signals", sa.String(128), nullable=True),
    )
    op.create_index("ix_obs_created", "document_observations", ["created_at"])
    op.create_index("ix_obs_format", "document_observations", ["mrz_format"])
    op.create_index("ix_obs_country", "document_observations", ["issuing_country"])
    op.create_index("ix_obs_doctype", "document_observations", ["document_type"])


def downgrade() -> None:
    op.drop_table("document_observations")
