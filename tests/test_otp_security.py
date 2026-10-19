"""R5 — OTP security: consent gate, atomic send limits, delivery failures."""

from __future__ import annotations

import logging
import threading
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.security import hash_secret
from app.db.session import SessionLocal
from app.engines import ratelimit
from app.models.otp import OtpChallenge
from tests.conftest import CapturingOtpSender

_ADMIN = {"X-Admin-Key": "test-admin-key"}


@pytest.fixture(autouse=True)
def _reset_limiter() -> None:
    ratelimit._reset_mem()


@pytest.fixture
def send_ctx(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> dict:
    """Session with consent given, ready for OTP; sender captured."""
    monkeypatch.setattr(settings, "otp_send_cooldown_seconds", 0)
    sender = CapturingOtpSender()
    monkeypatch.setattr("app.engines.providers.get_otp_sender", lambda: sender)
    creds = client.post(
        "/v1/admin/tenants",
        headers=_ADMIN,
        json={"name": "OtpT", "allowed_flows": ["TRAVEL_INSURANCE"]},
    ).json()
    token = client.post(
        "/v1/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        },
    ).json()["access_token"]

    def make_session() -> tuple[str, dict]:
        session = client.post(
            "/v1/kyc/sessions",
            headers={"authorization": f"Bearer {token}"},
            json={"customer_reference": "OTP-1", "flow": "TRAVEL_INSURANCE"},
        ).json()
        vtoken = parse_qs(urlparse(session["verification_url"]).query)["token"][0]
        vh = {"authorization": f"Bearer {vtoken}"}
        client.post(
            f"/v1/verification/{session['session_id']}/consent",
            headers=vh,
            json={"accepted": True},
        )
        return session["session_id"], vh

    return {"sender": sender, "make_session": make_session}


def _send(client: TestClient, sid: str, headers: dict, dest: str = "+33611112222"):
    return client.post(
        f"/v1/verification/{sid}/otp/send",
        headers=headers,
        json={"channel": "SMS", "destination": dest},
    )


# --------------------------------------------------------------------------- #
# Consent gating (both emission and verification)
# --------------------------------------------------------------------------- #
def test_send_and_verify_require_consent(client: TestClient) -> None:
    creds = client.post(
        "/v1/admin/tenants",
        headers=_ADMIN,
        json={"name": "OtpC", "allowed_flows": ["TRAVEL_INSURANCE"]},
    ).json()
    token = client.post(
        "/v1/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        },
    ).json()["access_token"]
    session = client.post(
        "/v1/kyc/sessions",
        headers={"authorization": f"Bearer {token}"},
        json={"customer_reference": "OTP-C", "flow": "TRAVEL_INSURANCE"},
    ).json()
    sid = session["session_id"]
    vtoken = parse_qs(urlparse(session["verification_url"]).query)["token"][0]
    vh = {"authorization": f"Bearer {vtoken}"}

    resp = _send(client, sid, vh)
    assert resp.status_code == 409 and resp.json()["detail"] == "CONSENT_REQUIRED"
    resp = client.post(f"/v1/verification/{sid}/otp/verify", headers=vh, json={"code": "000000"})
    assert resp.status_code == 409 and resp.json()["detail"] == "CONSENT_REQUIRED"


# --------------------------------------------------------------------------- #
# Send limits
# --------------------------------------------------------------------------- #
def test_resend_within_cooldown_rejected(
    client: TestClient, send_ctx: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "otp_send_cooldown_seconds", 120)
    sid, vh = send_ctx["make_session"]()
    assert _send(client, sid, vh).status_code == 200
    resp = _send(client, sid, vh)
    assert resp.status_code == 429 and resp.json()["detail"] == "OTP_RATE_LIMITED"


def test_max_sends_per_session(
    client: TestClient, send_ctx: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "otp_max_sends_per_session", 2)
    sid, vh = send_ctx["make_session"]()
    assert _send(client, sid, vh).status_code == 200
    assert _send(client, sid, vh).status_code == 200
    assert _send(client, sid, vh).status_code == 429


def test_destination_cap_survives_session_recreation(
    client: TestClient, send_ctx: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Recreating sessions must not bypass the per-destination limit."""
    monkeypatch.setattr(settings, "otp_max_sends_per_destination", 2)
    sid1, vh1 = send_ctx["make_session"]()
    assert _send(client, sid1, vh1).status_code == 200
    assert _send(client, sid1, vh1).status_code == 200
    sid2, vh2 = send_ctx["make_session"]()
    resp = _send(client, sid2, vh2)  # different session, same phone number
    assert resp.status_code == 429


def test_concurrent_sends_cannot_bypass_limit(
    client: TestClient, send_ctx: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "otp_max_sends_per_session", 1)
    sid, vh = send_ctx["make_session"]()
    results: list[int] = []
    barrier = threading.Barrier(2)

    def attempt() -> None:
        barrier.wait()
        results.append(_send(client, sid, vh).status_code)

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert sorted(results) == [200, 429]


# --------------------------------------------------------------------------- #
# Code lifecycle
# --------------------------------------------------------------------------- #
def test_new_send_invalidates_previous_code(client: TestClient, send_ctx: dict) -> None:
    sid, vh = send_ctx["make_session"]()
    _send(client, sid, vh)
    first = send_ctx["sender"].codes[-1]
    _send(client, sid, vh)
    second = send_ctx["sender"].codes[-1]

    resp = client.post(f"/v1/verification/{sid}/otp/verify", headers=vh, json={"code": first})
    assert resp.json()["verified"] is False  # superseded code no longer verifies
    resp = client.post(f"/v1/verification/{sid}/otp/verify", headers=vh, json={"code": second})
    assert resp.json()["verified"] is True


def test_expired_code_rejected(client: TestClient, send_ctx: dict) -> None:
    from datetime import timedelta

    from app.db.base import utcnow

    sid, vh = send_ctx["make_session"]()
    _send(client, sid, vh)
    with SessionLocal() as db:
        challenge = db.scalars(select(OtpChallenge).where(OtpChallenge.session_id == sid)).one()
        challenge.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    resp = client.post(
        f"/v1/verification/{sid}/otp/verify",
        headers=vh,
        json={"code": send_ctx["sender"].codes[-1]},
    )
    assert resp.status_code == 400


def test_max_attempts_marks_check_failed(
    client: TestClient, send_ctx: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "otp_max_attempts", 2)
    sid, vh = send_ctx["make_session"]()
    _send(client, sid, vh)
    for _ in range(2):
        client.post(f"/v1/verification/{sid}/otp/verify", headers=vh, json={"code": "000000"})
    resp = client.post(f"/v1/verification/{sid}/otp/verify", headers=vh, json={"code": "000000"})
    assert resp.status_code == 400
    with SessionLocal() as db:
        from app.models.session import KycSession

        assert db.get(KycSession, sid).checks["OTP"] == "FAILED"


# --------------------------------------------------------------------------- #
# Delivery failure & confidentiality
# --------------------------------------------------------------------------- #
def test_gateway_down_returns_503_without_challenge(
    client: TestClient, send_ctx: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    class DownSender(CapturingOtpSender):
        def send(self, channel: str, destination: str, code: str) -> None:
            raise ConnectionError("gateway down")

    monkeypatch.setattr("app.engines.providers.get_otp_sender", lambda: DownSender())
    sid, vh = send_ctx["make_session"]()
    resp = _send(client, sid, vh)
    assert resp.status_code == 503
    with SessionLocal() as db:
        assert db.scalars(select(OtpChallenge).where(OtpChallenge.session_id == sid)).all() == []


def test_otp_code_never_logged(
    client: TestClient, send_ctx: dict, caplog: pytest.LogCaptureFixture
) -> None:
    sid, vh = send_ctx["make_session"]()
    with caplog.at_level(logging.DEBUG):
        _send(client, sid, vh)
    code = send_ctx["sender"].codes[-1]
    assert code not in caplog.text
    assert hash_secret(code) not in caplog.text
