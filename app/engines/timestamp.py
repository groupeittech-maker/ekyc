"""Trusted timestamping.

When an RFC 3161 TSA is configured the platform obtains a real timestamp token
for the document digest. Otherwise it falls back to a *soft* timestamp signed
by the platform key: usable for development, explicitly flagged as
non-qualified so it is never mistaken for a TSA token.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

import httpx

from app.core.config import settings
from app.db.base import utcnow


@dataclass
class TimestampToken:
    token: bytes
    authority: str
    issued_at: str
    qualified: bool
    details: dict[str, Any]


def _rfc3161_request(digest_hex: str) -> bytes:
    from app.engines.asn1 import build_timestamp_request

    return build_timestamp_request(bytes.fromhex(digest_hex))


def request_timestamp(digest_hex: str) -> TimestampToken:
    if settings.tsa_url:
        response = httpx.post(
            settings.tsa_url,
            content=_rfc3161_request(digest_hex),
            headers={"Content-Type": "application/timestamp-query"},
            timeout=15.0,
        )
        response.raise_for_status()
        return TimestampToken(
            token=response.content,
            authority=settings.tsa_url,
            issued_at=utcnow().isoformat(),
            qualified=True,
            details={"content_type": response.headers.get("content-type", "")},
        )

    from app.engines.signature import sign_digest

    issued_at = utcnow().isoformat()
    payload = f"{digest_hex}|{issued_at}".encode()
    signature = sign_digest(payload)
    return TimestampToken(
        token=base64.b64encode(signature.value),
        authority="local-soft-timestamp",
        issued_at=issued_at,
        qualified=False,
        details={"algorithm": signature.algorithm, "warning": "NOT_A_QUALIFIED_TSA_TOKEN"},
    )
