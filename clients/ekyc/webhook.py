"""Signed-webhook verification — framework-agnostic pure function.

The platform delivers ``POST`` requests with:

    X-EKYC-Signature: sha256=<HMAC_SHA256(secret, timestamp + "." + body)>
    X-EKYC-Timestamp: <unix seconds>

Verify the signature before trusting the payload; always return HTTP 200 once
accepted so the platform stops retrying, and persist an idempotency key
``(event, session_id)`` since deliveries are replayable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from .exceptions import WebhookVerificationError


def verify_webhook(
    secret: str,
    body: bytes,
    signature_header: str | None,
    timestamp_header: str | None,
    *,
    tolerance_seconds: int = 300,
) -> dict[str, Any]:
    """Verify an eKYC webhook and return the decoded JSON payload.

    Raises ``WebhookVerificationError`` on any mismatch, replay or malformed
    input. Comparison is constant-time.
    """
    if not signature_header or not timestamp_header:
        raise WebhookVerificationError("Missing signature or timestamp header")
    try:
        ts = int(timestamp_header)
    except ValueError as exc:
        raise WebhookVerificationError("Invalid timestamp header") from exc
    if tolerance_seconds and abs(time.time() - ts) > tolerance_seconds:
        raise WebhookVerificationError("Timestamp outside tolerance (possible replay)")

    provided = signature_header.split("=", 1)[-1] if "=" in signature_header else signature_header
    expected = hmac.new(
        secret.encode(), timestamp_header.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(provided, expected):
        raise WebhookVerificationError("Signature mismatch")
    return json.loads(body.decode())
