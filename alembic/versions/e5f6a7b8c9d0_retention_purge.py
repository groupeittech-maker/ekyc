"""retention purge markers

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-10-19 10:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

import app.db.base  # noqa: F401 - UTCDateTime custom type
from alembic import op

revision: str = "e5f6a7b8c9d0"
down_revision: str | None = "d4e5f6a7b8c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("artifacts", sa.Column("purged_at", app.db.base.UTCDateTime(), nullable=True))
    op.add_column("kyc_sessions", sa.Column("purged_at", app.db.base.UTCDateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("kyc_sessions", "purged_at")
    op.drop_column("artifacts", "purged_at")
