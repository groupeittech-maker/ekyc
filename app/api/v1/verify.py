"""Public proof verification — third parties check a document by its hash.

``GET /v1/verify/{sha256}`` answers: "did this platform seal a document with
this SHA-256, and are the signature and timestamp still cryptographically
sound?" The response intentionally exposes only trust metadata — no tenant
name, session id or identity data (data minimisation for third parties).

This is what makes the sealed dossier useful outside the platform: the PDF
embeds the digest, signature and timestamp metadata; this endpoint confirms
them against the platform's records and keys.
"""

from __future__ import annotations

import base64
from typing import Any

from fastapi import APIRouter
from sqlalchemy import select

from app.api.deps import DbSession
from app.engines import signature_manager, tsa
from app.models.document import Artifact
from app.models.signature import SignedDocument
from app.services.archive import read_artifact

router = APIRouter(prefix="/verify", tags=["verify"])


@router.get("/{sha256}")
def verify_document(sha256: str, db: DbSession) -> dict[str, Any]:
    signed = db.scalar(
        select(SignedDocument).where(SignedDocument.sha256 == sha256.lower()).limit(1)
    )
    if signed is None:
        return {"found": False, "sha256": sha256}

    digest_bytes = bytes.fromhex(signed.sha256)

    signature_verified: bool | None
    try:
        signature_verified = signature_manager.verify(
            digest_bytes, base64.b64decode(signed.signature)
        )
    except Exception:
        signature_verified = None

    timestamp_verification: dict[str, Any] | None = None
    if signed.timestamp_token_artifact_id:
        token_artifact = db.get(Artifact, signed.timestamp_token_artifact_id)
        if token_artifact is not None:
            details = signed.timestamp_details or {}
            timestamp_verification = tsa.verify_token(
                read_artifact(token_artifact),
                signed.sha256,
                issued_at=details.get("issued_at"),
                provider=details.get("provider"),
            )

    details = signed.timestamp_details or {}
    return {
        "found": True,
        "sha256": signed.sha256,
        "issued_at": signed.created_at.isoformat(),
        "signature": {
            "algorithm": signed.signature_algorithm,
            "certificate_fingerprint": signed.certificate_fingerprint,
            "verified": signature_verified,
        },
        "timestamp": {
            "authority": signed.timestamp_authority,
            "qualified": details.get("qualified"),
            "provider": details.get("provider"),
            "verification": timestamp_verification,
        },
    }
