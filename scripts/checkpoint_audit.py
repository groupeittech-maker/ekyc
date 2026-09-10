"""Create an immutable, signed checkpoint of the KYC audit chain.

The checkpoint is stored as an artifact in object storage. When the bucket
supports Object Lock / WORM (MinIO, S3, GCS, Azure Blob), it becomes a
write-once, read-many integrity proof that cannot be altered after creation.

Intended use: cron or Celery beat every 24 hours.
"""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from app.core.hashing import sha256_bytes
from app.db.base import utcnow
from app.db.session import db_session
from app.engines import audit
from app.engines.signature import sign_digest
from app.models.enums import ArtifactKind
from app.models.session import KycSession
from app.services.archive import store_artifact


def build_checkpoint(since: datetime | None = None) -> dict:
    """Export every audit chain since `since` and sign the result."""
    with db_session() as db:
        query = select(KycSession)
        if since:
            query = query.where(KycSession.created_at >= since)
        sessions = db.scalars(query).all()

        chain_rows = []
        for session in sessions:
            chain = audit.verify_chain(db, session.id)
            chain_rows.append(
                {
                    "session_id": session.id,
                    "tenant_id": session.tenant_id,
                    "customer_reference": session.customer_reference,
                    "status": str(session.status),
                    "created_at": session.created_at.isoformat() if session.created_at else None,
                    "events": chain.get("events"),
                    "head_hash": chain.get("head_hash"),
                    "valid": chain.get("valid"),
                }
            )

        payload = {
            "checkpoint_id": str(uuid.uuid4()),
            "created_at": utcnow().isoformat(),
            "since": since.isoformat() if since else None,
            "sessions": chain_rows,
        }
        payload_bytes = json.dumps(payload, indent=2, sort_keys=True).encode()
        digest = sha256_bytes(payload_bytes)
        signature = sign_digest(bytes.fromhex(digest))

        result = {
            **payload,
            "sha256": digest,
            "signature": signature.b64,
            "signature_algorithm": signature.algorithm,
            "certificate_fingerprint": signature.certificate_fingerprint,
        }
        result_bytes = json.dumps(result, indent=2, sort_keys=True).encode()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"audit-checkpoint-{timestamp}-{result['checkpoint_id']}.json"

        # Store under a special tenant-independent session to keep it WORM-safe.
        store_artifact(
            db,
            tenant_id="_system",
            session_id=None,
            kind=ArtifactKind.AUDIT_CHECKPOINT,
            filename=filename,
            data=result_bytes,
            content_type="application/json",
        )
        db.commit()
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Seal the audit chain to object storage.")
    parser.add_argument(
        "--since",
        type=datetime.fromisoformat,
        help="Checkpoint only sessions created since this ISO date (e.g. 2026-09-01T00:00:00).",
    )
    args = parser.parse_args()
    result = build_checkpoint(args.since)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
