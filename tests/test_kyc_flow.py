from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from tests.conftest import PASSPORT_MRZ, CapturingOtpSender


def create_session(client: TestClient, token: str, flow: str = "TRAVEL_INSURANCE") -> dict:
    response = client.post(
        "/v1/kyc/sessions",
        headers={"Authorization": f"Bearer {token}"},
        json={"flow": flow, "customer_reference": "MHC-123456"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def session_headers(verification_url: str) -> dict[str, str]:
    query = parse_qs(urlparse(verification_url).query)
    return {"Authorization": f"Bearer {query['token'][0]}"}


def run_full_flow(
    client: TestClient,
    tenant_token: str,
    otp_sender: CapturingOtpSender,
    *,
    selfie: bytes = b"selfie-image-bytes",
) -> dict:
    session = create_session(client, tenant_token)
    headers = session_headers(session["verification_url"])
    base = f"/v1/verification/{session['session_id']}"

    client.post(
        f"{base}/document",
        headers=headers,
        files={"file": ("passport.txt", PASSPORT_MRZ.encode(), "text/plain")},
        data={"document_type": "PASSPORT"},
    )
    client.post(
        f"{base}/selfie", headers=headers, files={"file": ("selfie.jpg", selfie, "image/jpeg")}
    )
    client.post(
        f"{base}/otp/send", headers=headers, json={"channel": "SMS", "destination": "+242060000000"}
    )
    client.post(f"{base}/otp/verify", headers=headers, json={"code": otp_sender.codes[-1]})
    return session


def test_tenant_receives_only_minimised_result(
    client: TestClient, tenant_token: str, otp_sender: CapturingOtpSender
) -> None:
    session = run_full_flow(client, tenant_token, otp_sender)

    result = client.get(
        f"/v1/kyc/sessions/{session['session_id']}",
        headers={"Authorization": f"Bearer {tenant_token}"},
    ).json()

    assert result["status"] == "VERIFIED"
    assert result["checks"] == {
        "DOCUMENT_VERIFICATION": "PASSED",
        "LIVENESS": "PASSED",
        "FACE_MATCH": "PASSED",
        "OTP": "PASSED",
    }
    assert result["identity"] == {
        "first_name": "JOHN",
        "last_name": "DOE",
        "date_of_birth": "1990-05-15",
        "nationality": "CGO",
        "document_type": "PASSPORT",
    }
    # Raw scores and document numbers stay inside the platform.
    assert "document_number" not in result["identity"]
    assert "score" not in str(result)


def test_ocr_parses_mrz_and_audit_chain_is_verifiable(
    client: TestClient, tenant_token: str, otp_sender: CapturingOtpSender
) -> None:
    session = run_full_flow(client, tenant_token, otp_sender)

    audit = client.get(
        f"/v1/kyc/sessions/{session['session_id']}/audit",
        headers={"Authorization": f"Bearer {tenant_token}"},
    ).json()

    assert audit["integrity"]["valid"] is True
    event_types = [event["event_type"] for event in audit["events"]]
    assert event_types[:4] == [
        "KYC_SESSION_CREATED",
        "DOCUMENT_UPLOADED",
        "OCR_COMPLETED",
        "DOCUMENT_VERIFIED",
    ]
    assert "KYC_DECISION" in event_types
    assert audit["events"][1]["previous_event_hash"] == audit["events"][0]["event_hash"]


def test_failed_liveness_rejects_the_session(
    client: TestClient, tenant_token: str, otp_sender: CapturingOtpSender
) -> None:
    session = create_session(client, tenant_token)
    headers = session_headers(session["verification_url"])
    base = f"/v1/verification/{session['session_id']}"

    client.post(
        f"{base}/document",
        headers=headers,
        files={"file": ("passport.txt", PASSPORT_MRZ.encode(), "text/plain")},
        data={"document_type": "PASSPORT"},
    )
    response = client.post(
        f"{base}/selfie",
        headers=headers,
        files={"file": ("selfie.txt", b"LIVENESS_FAIL", "text/plain")},
    )
    assert response.status_code == 202

    result = client.get(
        f"/v1/kyc/sessions/{session['session_id']}",
        headers={"Authorization": f"Bearer {tenant_token}"},
    ).json()
    assert result["status"] == "REJECTED"
    assert result["identity"] is None
    assert result["reasons"] == ["LIVENESS_FAILED"]


def test_face_match_failure_goes_to_review(
    client: TestClient, tenant_token: str, otp_sender: CapturingOtpSender
) -> None:
    session = run_full_flow(client, tenant_token, otp_sender, selfie=b"FACE_MATCH_FAIL")

    result = client.get(
        f"/v1/kyc/sessions/{session['session_id']}",
        headers={"Authorization": f"Bearer {tenant_token}"},
    ).json()
    assert result["status"] == "REVIEW"
    assert result["reasons"] == ["FACE_MATCH_REVIEW"]


def test_session_token_is_scoped_to_its_session(client: TestClient, tenant_token: str) -> None:
    first = create_session(client, tenant_token)
    second = create_session(client, tenant_token)

    response = client.get(
        f"/v1/verification/{second['session_id']}/context",
        headers=session_headers(first["verification_url"]),
    )
    assert response.status_code == 401


def test_flow_not_enabled_for_tenant_is_refused(client: TestClient, tenant_token: str) -> None:
    response = client.post(
        "/v1/kyc/sessions",
        headers={"Authorization": f"Bearer {tenant_token}"},
        json={"flow": "BANK_ACCOUNT"},
    )
    assert response.status_code == 403
