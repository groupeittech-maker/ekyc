"""Generic SDK (clients.ekyc) end-to-end coverage through the ASGI app."""

from __future__ import annotations

import hashlib
import time

import pytest
from fastapi.testclient import TestClient

from app.core.security import sign_webhook
from app.main import app
from app.services.pdf import render_contract
from clients.ekyc import EkycClient, WebhookVerificationError, verify_webhook


@pytest.fixture
def sdk(tenant_credentials: dict) -> EkycClient:
    # Starlette's TestClient is an httpx.Client subclass with a synchronous ASGI
    # transport, so it plugs straight into the SDK for in-process testing.
    http = TestClient(app)
    client = EkycClient(
        base_url="http://testserver",
        client_id=tenant_credentials["client_id"],
        client_secret=tenant_credentials["client_secret"],
        http_client=http,
    )
    yield client
    client.close()


def test_sdk_health_is_public(sdk: EkycClient) -> None:
    health = sdk.health()
    assert health["status"] == "ok"
    assert "TRAVEL_INSURANCE" in health["flows"]


def test_sdk_audit_export_verifies_chain(sdk: EkycClient) -> None:
    session = sdk.create_session(customer_reference="APP-1", flow="TRAVEL_INSURANCE")
    audit = sdk.get_audit_export(session["session_id"])

    assert audit["session_id"] == session["session_id"]
    assert audit["integrity"]["valid"] is True
    assert len(audit["events"]) >= 1


def test_sdk_seals_and_downloads_a_document(sdk: EkycClient) -> None:
    session = sdk.create_session(customer_reference="APP-2", flow="TRAVEL_INSURANCE")
    pdf_bytes = render_contract(
        title="Contract",
        session_id=session["session_id"],
        tenant_name="SDK Test",
        body=[("field", "value")],
        issued_at="2026-10-15T00:00:00",
    )

    sealed = sdk.seal_document(
        session["session_id"],
        document_reference="CONTRACT-1",
        pdf_bytes=pdf_bytes,
    )
    # sha256 attests the integrity of the source document, before the proof
    # metadata is embedded into the sealed PDF.
    assert sealed["sha256"] == hashlib.sha256(pdf_bytes).hexdigest()

    artifact = sdk.download_signed_document(session["session_id"], sealed["signed_document_id"])
    assert artifact.content.startswith(b"%PDF")
    assert artifact.sha256 == sealed["sha256"]


def test_sdk_downloads_the_kyc_certificate(sdk: EkycClient) -> None:
    session = sdk.create_session(customer_reference="APP-3", flow="TRAVEL_INSURANCE")
    cert = sdk.download_certificate(session["session_id"])

    assert cert.content.startswith(b"%PDF")
    assert cert.sha256
    assert cert.signature_algorithm
    assert cert.filename and cert.filename.endswith(".pdf")


def test_verify_webhook_accepts_a_valid_signature() -> None:
    secret = "whsec_example"
    body = b'{"event":"KYC_VERIFIED","session_id":"KYC-1","customer_reference":"APP-1"}'
    ts = str(int(time.time()))
    header = f"sha256={sign_webhook(secret, ts, body)}"

    payload = verify_webhook(secret, body, header, ts)
    assert payload["event"] == "KYC_VERIFIED"


def test_verify_webhook_rejects_tampering_and_replays() -> None:
    secret = "whsec_example"
    body = b'{"event":"KYC_VERIFIED"}'
    ts = str(int(time.time()))
    header = f"sha256={sign_webhook(secret, ts, body)}"

    with pytest.raises(WebhookVerificationError):
        verify_webhook(secret, b'{"event":"KYC_REJECTED"}', header, ts)

    old_ts = str(int(time.time()) - 10_000)
    old_header = f"sha256={sign_webhook(secret, old_ts, body)}"
    with pytest.raises(WebhookVerificationError):
        verify_webhook(secret, body, old_header, old_ts)
