"""regulatory orchestrator: jurisdiction/vault/retention/trust-service snapshots

Revision ID: b3f4a1c9d2e7
Revises: c2b7c822e554
Create Date: 2026-10-18 12:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b3f4a1c9d2e7"
down_revision: str | None = "c2b7c822e554"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Sessions snapshot the resolved regulatory profile at creation.
    op.add_column(
        "kyc_sessions",
        sa.Column("jurisdiction", sa.String(length=16), server_default="GLOBAL", nullable=False),
    )
    op.add_column(
        "kyc_sessions",
        sa.Column("vault_profile", sa.String(length=64), server_default="default", nullable=False),
    )
    op.add_column(
        "kyc_sessions",
        sa.Column("retention_days", sa.Integer(), server_default="3650", nullable=False),
    )
    op.add_column(
        "kyc_sessions",
        sa.Column("tsa_policy", sa.String(length=32), server_default="internal", nullable=False),
    )
    op.add_column(
        "kyc_sessions",
        sa.Column(
            "signature_level", sa.String(length=32), server_default="platform", nullable=False
        ),
    )
    # Artifacts record which vault they were routed to.
    op.add_column(
        "artifacts",
        sa.Column("vault_profile", sa.String(length=64), server_default="default", nullable=False),
    )
    # Tenants may declare a home jurisdiction.
    op.add_column("tenants", sa.Column("default_jurisdiction", sa.String(length=16), nullable=True))


def downgrade() -> None:
    op.drop_column("tenants", "default_jurisdiction")
    op.drop_column("artifacts", "vault_profile")
    op.drop_column("kyc_sessions", "signature_level")
    op.drop_column("kyc_sessions", "tsa_policy")
    op.drop_column("kyc_sessions", "retention_days")
    op.drop_column("kyc_sessions", "vault_profile")
    op.drop_column("kyc_sessions", "jurisdiction")
