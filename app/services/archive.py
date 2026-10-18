"""Archive service: writes bytes to object storage and registers the artifact.

When ``EKYC_STORAGE_ENCRYPTION`` is on, payloads go through the vault
(``services/vault.py``) before hitting the backend: storage only ever sees
ciphertext, while ``sha256`` and ``size_bytes`` keep describing the plaintext.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.hashing import sha256_bytes
from app.models.document import Artifact
from app.models.enums import ArtifactKind
from app.services import vault
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
    payload = vault.seal(tenant_id, data) if settings.storage_encryption_enabled else data
    get_storage().put(key, payload, content_type)
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
    # vault.open() passes legacy plaintext through and decrypts sealed blobs.
    return vault.open(artifact.tenant_id, get_storage().get(artifact.storage_key))
