from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from app.core.security import sign_webhook
from app.main import app
from clients.mhc import EkycClient, WebhookVerificationError, verify_webhook


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


def test_sdk_creates_session_and_reads_result(sdk: EkycClient) -> None:
    session = sdk.create_session(customer_reference="MHC-123456", flow="TRAVEL_INSURANCE")

    assert session["session_id"].startswith("KYC-")
    assert session["verification_url"].startswith("http")

    result = sdk.get_result(session["session_id"])
    assert result.session_id == session["session_id"]
    assert result.is_terminal is False  # nothing submitted yet


def test_sdk_caches_the_access_token(sdk: EkycClient) -> None:
    first = sdk._access_token()
    second = sdk._access_token()
    assert first == second


def test_verify_webhook_accepts_a_valid_signature() -> None:
    secret = "whsec_example"
    body = b'{"event":"KYC_VERIFIED","session_id":"KYC-1","customer_reference":"MHC-1"}'
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
