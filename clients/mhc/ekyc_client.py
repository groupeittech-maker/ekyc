"""Minimal, dependency-light eKYC client SDK for tenant applications.

Only ``httpx`` is required. The client handles OAuth2 client_credentials token
acquisition (with in-memory caching and refresh), the KYC session lifecycle and
document sealing. Webhook verification is a pure function so it can be wired
into any web framework.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


class EkycError(RuntimeError):
    """Raised when the eKYC API returns an error response."""


class WebhookVerificationError(RuntimeError):
    """Raised when an incoming webhook signature cannot be verified."""


@dataclass
class KycResult:
    session_id: str
    status: str
    flow: str | None = None
    identity: dict[str, Any] | None = None
    checks: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_verified(self) -> bool:
        return self.status == "VERIFIED"

    @property
    def is_terminal(self) -> bool:
        return self.status in {"VERIFIED", "REJECTED", "REVIEW", "EXPIRED"}


class EkycClient:
    """Client for the IT-TECH eKYC API, scoped to a single tenant."""

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        *,
        http_client: httpx.Client | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._external = http_client is not None
        self._http = http_client or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)
        self._token: str | None = None
        self._token_expiry: float = 0.0

    # -- lifecycle ---------------------------------------------------------- #
    def close(self) -> None:
        if not self._external:
            self._http.close()

    def __enter__(self) -> EkycClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- auth --------------------------------------------------------------- #
    def _access_token(self) -> str:
        if self._token and time.time() < self._token_expiry - 30:
            return self._token
        response = self._http.post(
            "/v1/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
        )
        data = _json_or_raise(response, "OAuth token request failed")
        token = data["access_token"]
        if not isinstance(token, str):
            raise EkycError("Access token is not a string")
        self._token = token
        self._token_expiry = time.time() + int(data.get("expires_in", 3600))
        return token

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._access_token()}"}

    # -- KYC sessions ------------------------------------------------------- #
    def create_session(
        self,
        *,
        customer_reference: str,
        flow: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a session; returns the payload including ``verification_url``."""
        body: dict[str, Any] = {"customer_reference": customer_reference, "flow": flow}
        if metadata:
            body["metadata"] = metadata
        response = self._http.post("/v1/kyc/sessions", json=body, headers=self._auth_headers())
        return _json_or_raise(response, "Session creation failed")

    def get_result(self, session_id: str) -> KycResult:
        response = self._http.get(f"/v1/kyc/sessions/{session_id}", headers=self._auth_headers())
        data = _json_or_raise(response, "Fetching session failed")
        return KycResult(
            session_id=data.get("session_id", session_id),
            status=data.get("status", "UNKNOWN"),
            flow=data.get("flow"),
            identity=data.get("identity"),
            checks=data.get("checks", {}),
            raw=data,
        )

    def wait_for_result(
        self, session_id: str, *, interval: float = 3.0, timeout: float = 300.0
    ) -> KycResult:
        """Poll until the session reaches a terminal status (fallback to webhooks)."""
        deadline = time.time() + timeout
        while True:
            result = self.get_result(session_id)
            if result.is_terminal or time.time() >= deadline:
                return result
            time.sleep(interval)

    def seal_document(
        self,
        session_id: str,
        *,
        document_reference: str,
        title: str | None = None,
        fields: dict[str, Any] | None = None,
        pdf_bytes: bytes | None = None,
    ) -> dict[str, Any]:
        """Seal a contract: SHA-256 + signature + timestamp + archive."""
        body: dict[str, Any] = {"document_reference": document_reference}
        if pdf_bytes is not None:
            body["pdf_base64"] = base64.b64encode(pdf_bytes).decode()
        else:
            body["title"] = title or document_reference
            body["fields"] = fields or {}
        response = self._http.post(
            f"/v1/kyc/sessions/{session_id}/documents",
            json=body,
            headers=self._auth_headers(),
        )
        return _json_or_raise(response, "Document sealing failed")


def _json_or_raise(response: httpx.Response, message: str) -> dict[str, Any]:
    if response.status_code >= 400:
        raise EkycError(f"{message}: {response.status_code} {response.text}")
    return response.json()


# --------------------------------------------------------------------------- #
# Webhook verification — framework-agnostic pure function.
# --------------------------------------------------------------------------- #
def verify_webhook(
    secret: str,
    body: bytes,
    signature_header: str | None,
    timestamp_header: str | None,
    *,
    tolerance_seconds: int = 300,
) -> dict[str, Any]:
    """Verify an eKYC webhook and return the decoded JSON payload.

    Signature scheme mirrors the platform:
        X-EKYC-Signature: sha256=HMAC_SHA256(secret, timestamp + "." + body)

    Raises ``WebhookVerificationError`` on any mismatch, replay or malformed
    input. Comparison is constant-time.
    """
    import json

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
