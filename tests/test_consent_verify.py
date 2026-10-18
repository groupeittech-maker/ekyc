"""Consent evidence + public proof verification (GET /v1/verify/{sha256})."""

from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.services.pdf import render_contract
from tests.conftest import PASSPORT_MRZ

_ADMIN = {"X-Admin-Key": "test-admin-key"}


@pytest.fixture
def tenant(client: TestClient) -> dict:
    creds = client.post(
        "/v1/admin/tenants",
        headers=_ADMIN,
        json={"name": "Consent Tenant", "allowed_flows": ["TRAVEL_INSURANCE"]},
    ).json()
    token = client.post(
        "/v1/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        },
    ).json()["access_token"]
    return {"headers": {"authorization": f"Bearer {token}"}}


@pytest.fixture
def session(client: TestClient, tenant: dict) -> dict:
    created = client.post(
        "/v1/kyc/sessions",
        headers=tenant["headers"],
        json={"customer_reference": "C-1", "flow": "TRAVEL_INSURANCE"},
    ).json()
    token = parse_qs(urlparse(created["verification_url"]).query)["token"][0]
    return {
        "id": created["session_id"],
        "headers": {"authorization": f"Bearer {token}"},
        "base": f"/v1/verification/{created['session_id']}",
    }


# --------------------------------------------------------------------------- #
# Consent
# --------------------------------------------------------------------------- #
def test_context_exposes_consent_requirement(client: TestClient, session: dict) -> None:
    context = client.get(f"{session['base']}/context", headers=session["headers"]).json()
    assert context["consent"] == {
        "required": True,
        "given": False,
        "policy_version": None,
    }


def test_capture_is_blocked_until_consent(client: TestClient, session: dict) -> None:
    blocked = client.post(
        f"{session['base']}/document",
        headers=session["headers"],
        files={"file": ("passport.txt", PASSPORT_MRZ.encode(), "text/plain")},
        data={"document_type": "PASSPORT"},
    )
    assert blocked.status_code == 409
    assert blocked.json()["detail"] == "CONSENT_REQUIRED"

    blocked_selfie = client.post(
        f"{session['base']}/selfie",
        headers=session["headers"],
        files={"file": ("s.jpg", b"img", "image/jpeg")},
    )
    assert blocked_selfie.status_code == 409

    blocked_otp = client.post(
        f"{session['base']}/otp/send",
        headers=session["headers"],
        json={"channel": "SMS", "destination": "+242060000000"},
    )
    assert blocked_otp.status_code == 409


def test_consent_then_capture_is_allowed_and_audited(
    client: TestClient, session: dict, tenant: dict
) -> None:
    granted = client.post(
        f"{session['base']}/consent",
        headers=session["headers"],
        json={"accepted": True, "policy_version": "v2"},
    )
    assert granted.status_code == 200 and granted.json()["accepted"] is True

    context = client.get(f"{session['base']}/context", headers=session["headers"]).json()
    assert context["consent"]["given"] is True
    assert context["consent"]["policy_version"] == "v2"

    uploaded = client.post(
        f"{session['base']}/document",
        headers=session["headers"],
        files={"file": ("passport.txt", PASSPORT_MRZ.encode(), "text/plain")},
        data={"document_type": "PASSPORT"},
    )
    assert uploaded.status_code == 202

    audit = client.get(f"/v1/kyc/sessions/{session['id']}/audit", headers=tenant["headers"]).json()
    types = [e["event_type"] for e in audit["events"]]
    assert "CONSENT_GIVEN" in types
    assert types.index("CONSENT_GIVEN") < types.index("DOCUMENT_UPLOADED")


def test_consent_declined_is_recorded_and_blocks(
    client: TestClient, session: dict, tenant: dict
) -> None:
    declined = client.post(
        f"{session['base']}/consent",
        headers=session["headers"],
        json={"accepted": False},
    )
    assert declined.status_code == 409

    audit = client.get(f"/v1/kyc/sessions/{session['id']}/audit", headers=tenant["headers"]).json()
    assert "CONSENT_DECLINED" in [e["event_type"] for e in audit["events"]]


# --------------------------------------------------------------------------- #
# Public verification by hash
# --------------------------------------------------------------------------- #
def test_verify_endpoint_reports_trust_metadata(
    client: TestClient, session: dict, tenant: dict
) -> None:
    client.post(
        f"{session['base']}/consent",
        headers=session["headers"],
        json={"accepted": True},
    )
    pdf = render_contract(
        title="C",
        session_id=session["id"],
        tenant_name="T",
        body=[("a", "1")],
        issued_at="2026-10-18T00:00:00",
    )
    sealed = client.post(
        f"/v1/kyc/sessions/{session['id']}/documents",
        headers=tenant["headers"],
        json={
            "document_reference": "VER-1",
            "pdf_base64": base64.b64encode(pdf).decode(),
        },
    ).json()

    # No auth header — the endpoint is public for third parties.
    result = client.get(f"/v1/verify/{sealed['sha256']}").json()
    assert result["found"] is True
    assert result["sha256"] == sealed["sha256"]
    assert result["signature"]["algorithm"] == "RSASSA-PKCS1-v1_5-SHA256"
    assert result["signature"]["verified"] is True
    assert result["timestamp"]["provider"] == "internal"
    assert result["timestamp"]["qualified"] is False
    ts_verif = result["timestamp"]["verification"]
    assert ts_verif["type"] == "internal-soft-timestamp"
    assert ts_verif["signature_verified"] is True
    # No tenant/session/identity data leaks to third parties.
    assert "tenant" not in str(result).lower()
    assert "session" not in str(result).lower()


def test_verify_unknown_hash_returns_not_found(client: TestClient) -> None:
    result = client.get(f"/v1/verify/{'f' * 64}").json()
    assert result == {"found": False, "sha256": "f" * 64}
