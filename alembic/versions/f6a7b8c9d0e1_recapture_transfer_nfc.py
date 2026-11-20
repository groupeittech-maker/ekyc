"""document verso + cross-device transfer fields

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-10-27 10:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

import app.db.base  # noqa: F401 - UTCDateTime custom type
from alembic import op

revision: str = "f6a7b8c9d0e1"
down_revision: str | None = "e5f6a7b8c9d0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Batch mode: SQLite has no ALTER ADD/DROP CONSTRAINT — the table is
    # rebuilt (copy-and-move). On other dialects this is a plain ALTER.
    with op.batch_alter_table("documents") as batch_op:
        batch_op.add_column(sa.Column("verso_artifact_id", sa.String(64), nullable=True))
        batch_op.create_foreign_key(
            "fk_documents_verso_artifact",
            "artifacts",
            ["verso_artifact_id"],
            ["id"],
        )
    op.add_column(
        "kyc_sessions", sa.Column("transfer_code_hash", sa.String(128), nullable=True)
    )
    op.add_column(
        "kyc_sessions",
        sa.Column("transfer_expires_at", app.db.base.UTCDateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("kyc_sessions", "transfer_expires_at")
    op.drop_column("kyc_sessions", "transfer_code_hash")
    with op.batch_alter_table("documents") as batch_op:
        batch_op.drop_constraint("fk_documents_verso_artifact", type_="foreignkey")
        batch_op.drop_column("verso_artifact_id")
