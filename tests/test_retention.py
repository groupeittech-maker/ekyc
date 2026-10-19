"""Retention purge: personal data deleted, proofs kept."""

from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.document import Artifact, Document
from app.models.enums import SessionStatus
from app.models.session import KycSession
from app.services.pdf import render_contract
from app.services.storage import get_vault
from tests.conftest import PASSPORT_MRZ

_ADMIN = {"X-Admin-Key": "test-admin-key"}


@pytest.fixture
def fast_retention(monkeypatch: pytest.MonkeyPatch) -> None:
    """Jurisdiction FAST with retention_days=0 → immediately purgeable."""
    monkeypatch.setattr(
        settings,
        "jurisdictions_json",
        json.dumps(
            {
                "FAST": {
                    "retention_days": 0,
                    "vault_profile": "default",
                    "tsa_policy": "internal",
                    "signature_level": "platform",
                }
            }
        ),
    )


@pytest.fixture
def expired_session(client: TestClient, fast_retention: None) -> dict:
    creds = client.post(
        "/v1/admin/tenants",
        headers=_ADMIN,
        json={"name": "Ret", "allowed_flows": ["TRAVEL_INSURANCE"]},
    ).json()
    token = client.post(
        "/v1/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        },
    ).json()["access_token"]
    headers = {"authorization": f"Bearer {token}"}
    session = client.post(
        "/v1/kyc/sessions",
        headers=headers,
        json={"customer_reference": "RET-1", "flow": "TRAVEL_INSURANCE", "jurisdiction": "FAST"},
    ).json()
    sid = session["session_id"]

    # consent + document upload + sealed document → artifacts + PII on disk
    vtoken = parse_qs(urlparse(session["verification_url"]).query)["token"][0]
    vh = {"authorization": f"Bearer {vtoken}"}
    base = f"/v1/verification/{sid}"
    client.post(f"{base}/consent", headers=vh, json={"accepted": True})
    client.post(
        f"{base}/document",
        headers=vh,
        files={"file": ("passport.txt", PASSPORT_MRZ.encode(), "text/plain")},
        data={"document_type": "PASSPORT"},
    )
    pdf = render_contract(
        title="R",
        session_id=sid,
        tenant_name="T",
        body=[("a", "1")],
        issued_at="2026-10-19T00:00:00",
    )
    sealed = client.post(
        f"/v1/kyc/sessions/{sid}/documents",
        headers=headers,
        json={"document_reference": "RET-DOC", "pdf_base64": base64.b64encode(pdf).decode()},
    ).json()

    # mark terminal → eligible for purge (retention_days=0)
    with SessionLocal() as db:
        s = db.get(KycSession, sid)
        s.status = SessionStatus.VERIFIED
        db.commit()
    return {"id": sid, "headers": headers, "sha256": sealed["sha256"]}


def test_purge_deletes_blobs_wipes_pii_keeps_proofs(
    client: TestClient, expired_session: dict
) -> None:
    sid = expired_session["id"]

    # sanity: blobs + PII exist before purge
    with SessionLocal() as db:
        artifacts = db.query(Artifact).filter_by(session_id=sid).all()
        assert artifacts and all(
            get_vault(a.vault_profile).exists(a.storage_key) for a in artifacts
        )
        doc = db.query(Document).filter_by(session_id=sid).first()
        assert doc.ocr, "expected OCR payload before purge"

    report = client.post("/v1/admin/purge", headers=_ADMIN).json()
    assert report["sessions_purged"] >= 1
    assert report["artifacts_failed"] == 0
    assert sid in report["session_ids"]

    with SessionLocal() as db:
        session = db.get(KycSession, sid)
        assert session.purged_at is not None
        assert session.identity == {} and session.internal == {}
        assert session.metadata_ == {}
        assert "ip" not in session.consent and "user_agent" not in session.consent
        assert session.consent["accepted"] is True  # proof of consent survives

        for a in db.query(Artifact).filter_by(session_id=sid).all():
            assert a.purged_at is not None
            assert not get_vault(a.vault_profile).exists(a.storage_key)

        doc = db.query(Document).filter_by(session_id=sid).first()
        assert doc.ocr == {} and doc.verification == {}

    # audit chain intact + checkpoint recorded
    audit = client.get(f"/v1/kyc/sessions/{sid}/audit", headers=expired_session["headers"]).json()
    assert audit["integrity"]["valid"] is True
    purge_event = next(e for e in audit["events"] if e["event_type"] == "DATA_PURGED")
    assert expired_session["sha256"] in purge_event["payload"]["artifact_sha256"]

    # blob downloads are gone but the proof still verifies
    with SessionLocal() as db:
        from app.models.signature import SignedDocument

        signed = db.query(SignedDocument).filter_by(session_id=sid).first()
        resp = client.get(
            f"/v1/kyc/sessions/{sid}/documents/{signed.id}",
            headers=expired_session["headers"],
        )
        assert resp.status_code == 410

    check = client.get(f"/v1/verify/{expired_session['sha256']}").json()
    assert check["found"] is True and check["purged"] is True
    assert check["signature"]["verified"] is True


def test_purge_is_idempotent(client: TestClient, expired_session: dict) -> None:
    client.post("/v1/admin/purge", headers=_ADMIN)
    second = client.post("/v1/admin/purge", headers=_ADMIN).json()
    assert expired_session["id"] not in second["session_ids"]


def test_open_session_is_never_purged(client: TestClient, fast_retention: None) -> None:
    creds = client.post(
        "/v1/admin/tenants",
        headers=_ADMIN,
        json={"name": "Open", "allowed_flows": ["TRAVEL_INSURANCE"]},
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
        json={"customer_reference": "OPEN-1", "flow": "TRAVEL_INSURANCE", "jurisdiction": "FAST"},
    ).json()

    report = client.post("/v1/admin/purge", headers=_ADMIN).json()
    assert session["session_id"] not in report["session_ids"]
