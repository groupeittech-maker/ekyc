from __future__ import annotations

import base64
import io

from fastapi.testclient import TestClient
from pypdf import PdfReader

from app.core.hashing import sha256_bytes
from app.engines.signature import verify_signature
from app.services.pdf import render_contract
from tests.conftest import CapturingOtpSender
from tests.test_kyc_flow import run_full_flow


def test_contract_is_hashed_signed_timestamped_and_archived(
    client: TestClient, tenant_token: str, otp_sender: CapturingOtpSender
) -> None:
    session = run_full_flow(client, tenant_token, otp_sender)
    auth = {"Authorization": f"Bearer {tenant_token}"}

    sealed = client.post(
        f"/v1/kyc/sessions/{session['session_id']}/documents",
        headers=auth,
        json={
            "document_reference": "POLICY-2026-0001",
            "title": "Contrat d'assurance voyage",
            "fields": {"prime": "45000 XAF", "duree": "30 jours"},
        },
    )
    assert sealed.status_code == 201, sealed.text
    body = sealed.json()
    assert body["signature_algorithm"] == "RSASSA-PKCS1-v1_5-SHA256"
    assert body["timestamp_qualified"] is False  # no TSA configured in tests

    download = client.get(body["download_url"], headers=auth)
    assert download.status_code == 200
    assert download.headers["X-EKYC-Document-SHA256"] == body["sha256"]
    assert download.content.startswith(b"%PDF")

    audit = client.get(f"/v1/kyc/sessions/{session['session_id']}/audit", headers=auth).json()
    event_types = [event["event_type"] for event in audit["events"]]
    assert event_types[-5:] == [
        "CONTRACT_GENERATED",
        "HASH_GENERATED",
        "DOCUMENT_SIGNED",
        "TIMESTAMPED",
        "DOCUMENT_ARCHIVED",
    ]
    assert audit["integrity"]["valid"] is True


def test_certificate_is_sealed_and_stable(
    client: TestClient, tenant_token: str, otp_sender: CapturingOtpSender
) -> None:
    session = run_full_flow(client, tenant_token, otp_sender)
    auth = {"Authorization": f"Bearer {tenant_token}"}

    first = client.get(f"/v1/kyc/sessions/{session['session_id']}/certificate", headers=auth)
    assert first.status_code == 200, first.text
    assert first.content.startswith(b"%PDF")
    digest = first.headers["X-EKYC-Document-Sha256"]
    assert first.headers["X-EKYC-Signature-Algorithm"] == "RSASSA-PKCS1-v1_5-SHA256"
    assert first.headers["X-EKYC-Timestamp-Qualified"] == "False"  # no TSA configured in tests

    metadata = PdfReader(io.BytesIO(first.content)).metadata or {}
    assert metadata["/DocumentSha256"] == digest
    assert verify_signature(bytes.fromhex(digest), base64.b64decode(metadata["/Signature"]))

    # The certificate is sealed once, then served from the archive.
    second = client.get(f"/v1/kyc/sessions/{session['session_id']}/certificate", headers=auth)
    assert second.headers["X-EKYC-Document-Sha256"] == digest
    assert second.content == first.content


def test_uploaded_pdf_signature_matches_its_digest(
    client: TestClient, tenant_token: str, otp_sender: CapturingOtpSender, db
) -> None:
    from app.models.signature import SignedDocument

    session = run_full_flow(client, tenant_token, otp_sender)
    pdf = render_contract(
        title="Contrat fourni par le client",
        session_id=session["session_id"],
        tenant_name="MHC",
        body=[("Prime", "45000 XAF")],
        issued_at="2026-01-01T00:00:00",
    )

    response = client.post(
        f"/v1/kyc/sessions/{session['session_id']}/documents",
        headers={"Authorization": f"Bearer {tenant_token}"},
        json={"pdf_base64": base64.b64encode(pdf).decode(), "document_reference": "RAW"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["sha256"] == sha256_bytes(pdf)

    signed = db.get(SignedDocument, body["signed_document_id"])
    assert verify_signature(bytes.fromhex(signed.sha256), base64.b64decode(signed.signature))
