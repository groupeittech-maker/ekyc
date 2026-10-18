"""session consent evidence column

Revision ID: d4e5f6a7b8c9
Revises: b3f4a1c9d2e7
Create Date: 2026-10-18 14:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d4e5f6a7b8c9"
down_revision: str | None = "b3f4a1c9d2e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "kyc_sessions",
        sa.Column("consent", sa.JSON(), server_default=sa.text("'{}'"), nullable=False),
    )


def downgrade() -> None:
    op.drop_column("kyc_sessions", "consent")
