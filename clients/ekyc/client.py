"""Minimal, dependency-light eKYC client SDK for tenant applications.

Only ``httpx`` is required. The client handles OAuth2 client_credentials token
acquisition (with in-memory caching and refresh), the KYC session lifecycle,
audit export, certificate/document download and document sealing.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import httpx

from .exceptions import EkycError
from .models import DocumentArtifact, KycResult

__version__ = "0.1.0"

_TERMINAL_STATUSES = {"VERIFIED", "REJECTED", "REVIEW", "EXPIRED"}


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
        self._http = http_client or httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            headers={"User-Agent": f"ittech-ekyc-sdk/{__version__}"},
        )
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

    # -- platform ----------------------------------------------------------- #
    def health(self) -> dict[str, Any]:
        """Unauthenticated liveness/config probe (status, environment, flows)."""
        response = self._http.get("/health")
        return _json_or_raise(response, "Health check failed")

    # -- KYC sessions ------------------------------------------------------- #
    def create_session(
        self,
        *,
        customer_reference: str,
        flow: str,
        metadata: dict[str, Any] | None = None,
        jurisdiction: str | None = None,
    ) -> dict[str, Any]:
        """Create a session; returns the payload including ``verification_url``.

        ``jurisdiction`` asserts the *regulatory context* of the operation
        (e.g. ``"CI"``, ``"EU"``, ``"GLOBAL"``) — it is NOT the identity
        document's country. It drives storage vault routing, retention and the
        required trust services. Falls back to the tenant's default
        jurisdiction, then the platform default.
        """
        body: dict[str, Any] = {"customer_reference": customer_reference, "flow": flow}
        if metadata:
            body["metadata"] = metadata
        if jurisdiction:
            body["jurisdiction"] = jurisdiction
        response = self._http.post("/v1/kyc/sessions", json=body, headers=self._auth_headers())
        return _json_or_raise(response, "Session creation failed")

    def get_result(self, session_id: str) -> KycResult:
        response = self._http.get(f"/v1/kyc/sessions/{session_id}", headers=self._auth_headers())
        data = _json_or_raise(response, "Fetching session failed")
        return KycResult(
            session_id=data.get("session_id", session_id),
            status=data.get("status", "UNKNOWN"),
            flow=data.get("flow"),
            jurisdiction=data.get("jurisdiction"),
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

    def get_audit_export(self, session_id: str) -> dict[str, Any]:
        """Return the chained audit trail plus its integrity verification."""
        response = self._http.get(
            f"/v1/kyc/sessions/{session_id}/audit", headers=self._auth_headers()
        )
        return _json_or_raise(response, "Audit export failed")

    # -- evidence ----------------------------------------------------------- #
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

    def download_signed_document(
        self, session_id: str, signed_document_id: str
    ) -> DocumentArtifact:
        """Download a sealed document PDF with its integrity metadata.

        ``sha256`` is the digest of the *source* document (before the proof
        metadata was embedded), so it will not match the downloaded bytes —
        it attests the archived original.
        """
        response = self._http.get(
            f"/v1/kyc/sessions/{session_id}/documents/{signed_document_id}",
            headers=self._auth_headers(),
        )
        if response.status_code >= 400:
            raise EkycError(f"Document download failed: {response.status_code} {response.text}")
        return _artifact(response)

    def download_certificate(self, session_id: str) -> DocumentArtifact:
        """Download the KYC certificate PDF (signed + timestamped by the platform)."""
        response = self._http.get(
            f"/v1/kyc/sessions/{session_id}/certificate", headers=self._auth_headers()
        )
        if response.status_code >= 400:
            raise EkycError(f"Certificate download failed: {response.status_code} {response.text}")
        return _artifact(response)


def _json_or_raise(response: httpx.Response, message: str) -> dict[str, Any]:
    if response.status_code >= 400:
        raise EkycError(f"{message}: {response.status_code} {response.text}")
    return response.json()


def _artifact(response: httpx.Response) -> DocumentArtifact:
    headers = response.headers
    qualified = headers.get("X-EKYC-Timestamp-Qualified", "")
    return DocumentArtifact(
        content=response.content,
        sha256=headers.get("X-EKYC-Document-Sha256"),
        signature_algorithm=headers.get("X-EKYC-Signature-Algorithm"),
        timestamp_authority=headers.get("X-EKYC-Timestamp-Authority") or None,
        timestamp_qualified=(qualified.lower() == "true") if qualified else None,
        filename=_filename(headers.get("Content-Disposition", "")),
    )


def _filename(content_disposition: str) -> str | None:
    for part in content_disposition.split(";"):
        part = part.strip()
        if part.lower().startswith("filename="):
            return part.split("=", 1)[1].strip('"')
    return None
