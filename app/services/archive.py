"""Archive service: writes bytes to object storage and registers the artifact."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.hashing import sha256_bytes
from app.models.document import Artifact
from app.models.enums import ArtifactKind
from app.services.storage import build_key, get_storage


def store_artifact(
    db: Session,
    *,
    tenant_id: str,
    session_id: str | None,
    kind: ArtifactKind | str,
    filename: str,
    data: bytes,
    content_type: str = "application/octet-stream",
) -> Artifact:
    key = build_key(tenant_id, session_id or "unscoped", str(kind), filename)
    get_storage().put(key, data, content_type)
    artifact = Artifact(
        tenant_id=tenant_id,
        session_id=session_id,
        kind=str(kind),
        storage_key=key,
        content_type=content_type,
        size_bytes=len(data),
        sha256=sha256_bytes(data),
    )
    db.add(artifact)
    db.flush()
    return artifact


def read_artifact(artifact: Artifact) -> bytes:
    return get_storage().get(artifact.storage_key)
