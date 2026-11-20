"""Recapture (RETRY), TD1 cards, cross-device transfer, OTP binding, NFC PKI."""

from __future__ import annotations

import base64
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.db.base import utcnow
from app.engines.asn1 import (
    encode_integer,
    encode_null,
    encode_octet_string,
    encode_oid,
    encode_sequence,
)
from app.engines.providers.mrz import check_digit, find_mrz, parse_mrz
from tests.conftest import PASSPORT_MRZ, CapturingOtpSender
from tests.test_kyc_flow import create_session, give_consent, session_headers


def _create_tenant(client: TestClient, flows: list[str]) -> dict:
    response = client.post(
        "/v1/admin/tenants",
        headers={"X-Admin-Key": "test-admin-key"},
        json={"name": "CIV tenant", "allowed_flows": flows},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _tenant_token(client: TestClient, credentials: dict) -> str:
    response = client.post(
        "/v1/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": credentials["client_id"],
            "client_secret": credentials["client_secret"],
        },
    )
    return response.json()["access_token"]


# --------------------------------------------------------------------------- #
# Document recapture
# --------------------------------------------------------------------------- #
def test_unreadable_document_asks_for_recapture_then_reviews(
    client: TestClient, tenant_token: str, otp_sender: CapturingOtpSender
) -> None:
    session = create_session(client, tenant_token)
    headers = session_headers(session["verification_url"])
    base = f"/v1/verification/{session['session_id']}"
    give_consent(client, headers, base)

    for attempt in range(settings.document_max_attempts):
        response = client.post(
            f"{base}/document",
            headers=headers,
            files={"file": ("passport.txt", b"DOC_FAIL unreadable", "text/plain")},
            data={"document_type": "PASSPORT"},
        )
        assert response.status_code == 202
        state = response.json()
        if attempt < settings.document_max_attempts - 1:
            assert state["checks"]["DOCUMENT_VERIFICATION"] == "RETRY"
            assert state["status"] == "IN_PROGRESS"
        else:
            assert state["checks"]["DOCUMENT_VERIFICATION"] == "FAILED"

    # Once every required step is decided, the failed-but-reviewable document
    # lands the session in REVIEW — recapture got its chances, no auto-reject.
    client.post(
        f"{base}/selfie", headers=headers, files={"file": ("s.jpg", b"selfie", "image/jpeg")}
    )
    client.post(
        f"{base}/otp/send",
        headers=headers,
        json={"channel": "SMS", "destination": "+2250707070707"},
    )
    client.post(f"{base}/otp/verify", headers=headers, json={"code": otp_sender.codes[-1]})

    result = client.get(
        f"/v1/kyc/sessions/{session['session_id']}",
        headers={"Authorization": f"Bearer {tenant_token}"},
    ).json()
    assert result["status"] == "REVIEW"


# --------------------------------------------------------------------------- #
# TD1 national ID card
# --------------------------------------------------------------------------- #
def build_td1_mrz(
    *,
    surname: str = "DOE",
    given: str = "JOHN",
    document_number: str = "12CIV0001",
    nationality: str = "CIV",
    birth: str = "900515",
    sex: str = "M",
    expiry: str = "300515",
) -> str:
    doc9 = document_number.ljust(9, "<")[:9]
    line1 = f"ID{nationality}{doc9}{check_digit(doc9)}{'<' * 15}"[:30].ljust(30, "<")
    body2 = f"{birth}{check_digit(birth)}{sex}{expiry}{check_digit(expiry)}{nationality}{'<' * 11}"
    composite = check_digit(line1[5:30] + body2[0:7] + body2[8:15] + body2[18:29])
    line2 = (body2 + composite)[:30]
    line3 = f"{surname}<<{given}".ljust(30, "<")
    return f"{line1}\n{line2}\n{line3}\n"


def test_td1_mrz_is_detected_and_validated() -> None:
    mrz = find_mrz(build_td1_mrz())
    assert mrz is not None and mrz.format == "TD1"
    fields = parse_mrz(mrz)
    assert fields["checks_passed"] is True
    assert fields["document_number"] == "12CIV0001"
    assert fields["nationality"] == "CIV"
    assert fields["last_name"] == "DOE"


def test_national_id_card_verifies_via_td1(
    client: TestClient, otp_sender: CapturingOtpSender
) -> None:
    tenant = _create_tenant(client, ["CITIZEN"])
    token = _tenant_token(client, tenant)
    session = create_session(client, token, flow="CITIZEN")
    headers = session_headers(session["verification_url"])
    base = f"/v1/verification/{session['session_id']}"
    give_consent(client, headers, base)

    uploaded = client.post(
        f"{base}/document",
        headers=headers,
        files={
            "file": ("card-back.txt", build_td1_mrz().encode(), "text/plain"),
            "file_verso": ("card-front.txt", b"portrait side", "text/plain"),
        },
        data={"document_type": "NATIONAL_ID"},
    )
    assert uploaded.status_code == 202

    client.post(
        f"{base}/otp/send",
        headers=headers,
        json={"channel": "SMS", "destination": "+2250707070707"},
    )
    client.post(
        f"{base}/otp/verify", headers=headers, json={"code": otp_sender.codes[-1]}
    )

    result = client.get(
        f"/v1/kyc/sessions/{session['session_id']}",
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    assert result["status"] == "VERIFIED"
    assert result["identity"]["last_name"] == "DOE"
    assert result["identity"]["first_name"] == "JOHN"


# --------------------------------------------------------------------------- #
# Fraud engine — duplicate signals
# --------------------------------------------------------------------------- #
def test_same_document_on_two_sessions_forces_review(
    client: TestClient, tenant_token: str, otp_sender: CapturingOtpSender
) -> None:
    """The same document number verified twice under one tenant is a strong
    signal — the second dossier goes to REVIEW instead of VERIFIED."""
    from tests.test_kyc_flow import run_full_flow

    first = run_full_flow(client, tenant_token, otp_sender)
    first_result = client.get(
        f"/v1/kyc/sessions/{first['session_id']}",
        headers={"Authorization": f"Bearer {tenant_token}"},
    ).json()
    assert first_result["status"] == "VERIFIED"

    second = run_full_flow(client, tenant_token, otp_sender)
    second_result = client.get(
        f"/v1/kyc/sessions/{second['session_id']}",
        headers={"Authorization": f"Bearer {tenant_token}"},
    ).json()
    assert second_result["status"] == "REVIEW"
    assert any(r.startswith("FRAUD_SIGNAL:DUPLICATE_DOCUMENT") for r in second_result["reasons"])


def test_viz_crosscheck_flags_missing_printed_name() -> None:
    pytest.importorskip("numpy")  # provider module imports numpy transitively
    from app.engines.providers.base import OcrResult
    from app.engines.providers.inhouse import InHouseOcrProvider

    fields = {"last_name": "DOE", "document_number": "AB1234567", "checks_passed": True}
    consistent = InHouseOcrProvider._viz_signals(
        OcrResult(fields=fields, raw_text="SURNAME DOE\nDOC AB1234567", provider="t")
    )
    assert consistent == {"viz_surname_present": True, "viz_doc_number_present": True}
    forged = InHouseOcrProvider._viz_signals(
        OcrResult(fields=fields, raw_text="SOMEONE ELSE\nNO NUMBER", provider="t")
    )
    assert forged["viz_surname_present"] is False


# --------------------------------------------------------------------------- #
# OTP destination declared by the tenant
# --------------------------------------------------------------------------- #
def test_otp_destination_is_bound_to_the_tenant_declared_number(
    client: TestClient,
    tenant_token: str,
    otp_sender: CapturingOtpSender,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "otp_send_cooldown_seconds", 0)
    response = client.post(
        "/v1/kyc/sessions",
        headers={"Authorization": f"Bearer {tenant_token}"},
        json={
            "flow": "TRAVEL_INSURANCE",
            "customer_reference": "MHC-1",
            "otp_destination": "+225 07 07 07 07 07",
        },
    )
    session = response.json()
    headers = session_headers(session["verification_url"])
    base = f"/v1/verification/{session['session_id']}"
    give_consent(client, headers, base)

    context = client.get(f"{base}/context", headers=headers).json()
    assert context["otp_destination"] == "*********0707"

    mismatch = client.post(
        f"{base}/otp/send",
        headers=headers,
        json={"channel": "SMS", "destination": "+242060000000"},
    )
    assert mismatch.status_code == 400
    assert mismatch.json()["detail"] == "OTP_DESTINATION_MISMATCH"

    # Tolerant compare: the same number with a different layout is accepted.
    sent = client.post(
        f"{base}/otp/send",
        headers=headers,
        json={"channel": "SMS", "destination": "+2250707070707"},
    )
    assert sent.status_code == 200

    # The verify UI echoes back the masked destination it was shown — same
    # destination, not a substitution.
    masked = client.post(
        f"{base}/otp/send",
        headers=headers,
        json={"channel": "SMS", "destination": "*********0707"},
    )
    assert masked.status_code == 200

    # No destination at all: the declared one is used.
    empty = client.post(f"{base}/otp/send", headers=headers, json={})
    assert empty.status_code == 200
    assert empty.json()["destination"] == "*********0707"


def test_otp_declared_email_routes_to_the_email_channel(
    client: TestClient, tenant_token: str, otp_sender: CapturingOtpSender
) -> None:
    response = client.post(
        "/v1/kyc/sessions",
        headers={"Authorization": f"Bearer {tenant_token}"},
        json={
            "flow": "TRAVEL_INSURANCE",
            "customer_reference": "MHC-2",
            "otp_destination": "jmartin@yahoo.fr",
        },
    )
    session = response.json()
    headers = session_headers(session["verification_url"])
    base = f"/v1/verification/{session['session_id']}"
    give_consent(client, headers, base)

    context = client.get(f"{base}/context", headers=headers).json()
    masked = context["otp_destination"]
    assert masked.endswith("@yahoo.fr")
    assert masked.startswith("jm")

    # The masked echo shown in the UI is accepted and the channel is derived
    # from the declared destination — not trusted from the client.
    sent = client.post(
        f"{base}/otp/send",
        headers=headers,
        json={"channel": "SMS", "destination": masked},
    )
    assert sent.status_code == 200
    body = sent.json()
    assert body["channel"] == "EMAIL"
    assert body["destination"] == masked


# --------------------------------------------------------------------------- #
# Cross-device transfer
# --------------------------------------------------------------------------- #
def test_transfer_code_exchanges_once_for_a_scoped_token(
    client: TestClient, tenant_token: str
) -> None:
    session = create_session(client, tenant_token)
    headers = session_headers(session["verification_url"])
    base = f"/v1/verification/{session['session_id']}"

    created = client.post(f"{base}/transfer", headers=headers)
    assert created.status_code == 200
    body = created.json()
    code = parse_qs(urlparse(body["transfer_url"]).query)["transfer"][0]

    exchanged = client.post(f"{base}/transfer/exchange", json={"code": code})
    assert exchanged.status_code == 200
    device_headers = {"Authorization": f"Bearer {exchanged.json()['token']}"}

    # The minted device token works; the original token still works too.
    assert client.get(f"{base}/context", headers=device_headers).status_code == 200
    assert client.get(f"{base}/context", headers=headers).status_code == 200

    # Single use: replaying the code is refused.
    replay = client.post(f"{base}/transfer/exchange", json={"code": code})
    assert replay.status_code == 401


def test_transfer_code_expires(
    client: TestClient, tenant_token: str, db
) -> None:
    from app.models.session import KycSession

    session = create_session(client, tenant_token)
    headers = session_headers(session["verification_url"])
    base = f"/v1/verification/{session['session_id']}"
    created = client.post(f"{base}/transfer", headers=headers).json()
    code = parse_qs(urlparse(created["transfer_url"]).query)["transfer"][0]

    row = db.get(KycSession, session["session_id"])
    row.transfer_expires_at = utcnow() - timedelta(seconds=1)
    db.commit()

    response = client.post(f"{base}/transfer/exchange", json={"code": code})
    assert response.status_code == 401


# --------------------------------------------------------------------------- #
# NFC passive authentication
# --------------------------------------------------------------------------- #
def _tlv(tag: bytes, content: bytes) -> bytes:
    size = len(content)
    if size < 0x80:
        length = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return tag + length + content


def _build_ef_com() -> bytes:
    # EF.COM tag list uses the real DG tag values: 0x61 = DG1, 0x75 = DG2.
    return _tlv(0x60.to_bytes(1, "big"), _tlv(b"\x5f\x01", b"0108") + _tlv(b"\x5c", b"\x61\x75"))


def _build_sod(dg1: bytes, dg2: bytes, tmp_path) -> tuple[bytes, bytes]:
    """A SOD signed by a DSC chained to a CSCA cert placed in the trust store."""
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
    from cryptography.x509.oid import NameOID

    def _cert(subject_cn, issuer_name=None, issuer_key=None, ca=False):
        key = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer_name or name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(utcnow() - timedelta(days=1))
            .not_valid_after(utcnow() + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        )
        cert = builder.sign(issuer_key or key, hashes.SHA256())
        return cert, key

    csca, csca_key = _cert("TEST CSCA", ca=True)
    dsc, dsc_key = _cert("TEST DSC", issuer_name=csca.subject, issuer_key=csca_key)
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "test-csca.pem").write_bytes(
        csca.public_bytes(serialization.Encoding.PEM)
    )

    sha256_oid = (2, 16, 840, 1, 101, 3, 4, 2, 1)
    dg_hashes = encode_sequence(
        *[
            encode_sequence(encode_integer(number), encode_octet_string(hashlib.sha256(dg).digest()))
            for number, dg in ((1, dg1), (2, dg2))
        ]
    )
    econtent = encode_sequence(
        encode_integer(0),
        encode_sequence(encode_oid(sha256_oid), encode_null()),
        dg_hashes,
    )
    sod = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(econtent)
        .add_signer(dsc, dsc_key, hashes.SHA256())
        .sign(Encoding.DER, [])
    )
    return _build_ef_com(), sod


def _nfc_payload(ef_com: bytes, sod: bytes, dg1: bytes, dg2: bytes) -> dict:
    b64 = lambda data: base64.b64encode(data).decode()  # noqa: E731
    return {"ef_com": b64(ef_com), "ef_sod": b64(sod), "dg1": b64(dg1), "dg2": b64(dg2)}


def test_nfc_passive_authentication_valid(
    client: TestClient, tenant_token: str, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "csca_dir", str(tmp_path))
    dg1, dg2 = b"fake-dg1-bytes", b"fake-dg2-bytes"
    ef_com, sod = _build_sod(dg1, dg2, tmp_path)

    session = create_session(client, tenant_token)
    headers = session_headers(session["verification_url"])
    base = f"/v1/verification/{session['session_id']}"
    give_consent(client, headers, base)

    response = client.post(
        f"{base}/nfc", headers=headers, json=_nfc_payload(ef_com, sod, dg1, dg2)
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["nfc_status"] == "VALID"
    assert body["checks"]["NFC"] == "PASSED"


def test_nfc_tampered_datagroup_rejects(
    client: TestClient, tenant_token: str, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "csca_dir", str(tmp_path))
    dg1, dg2 = b"real-dg1", b"real-dg2"
    ef_com, sod = _build_sod(dg1, dg2, tmp_path)

    session = create_session(client, tenant_token)
    headers = session_headers(session["verification_url"])
    base = f"/v1/verification/{session['session_id']}"
    give_consent(client, headers, base)

    response = client.post(
        f"{base}/nfc",
        headers=headers,
        json=_nfc_payload(ef_com, sod, b"FORGED-dg1", dg2),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["nfc_status"] == "INVALID"
    assert body["checks"]["NFC"] == "FAILED"
    assert body["status"] == "REJECTED"  # a forged chip is fraud evidence


def test_nfc_unknown_csca_is_indeterminate_not_forged(
    client: TestClient, tenant_token: str, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The SOD is signed by a DSC chained to a CSCA that exists nowhere in the
    # trust store (the cert file is written to a directory we do NOT load).
    monkeypatch.setattr(settings, "csca_dir", str(tmp_path / "empty-store"))
    dg1, dg2 = b"dg1", b"dg2"
    ef_com, sod = _build_sod(dg1, dg2, tmp_path / "elsewhere")

    session = create_session(client, tenant_token)
    headers = session_headers(session["verification_url"])
    base = f"/v1/verification/{session['session_id']}"
    give_consent(client, headers, base)

    response = client.post(
        f"{base}/nfc", headers=headers, json=_nfc_payload(ef_com, sod, dg1, dg2)
    )
    body = response.json()
    assert body["nfc_status"] == "INDETERMINATE"
    assert body["checks"]["NFC"] == "REVIEW"
    # Other steps are still pending — the session stays open, but once they
    # complete the indeterminate chip puts the dossier in REVIEW, never REJECT.
    assert body["status"] == "IN_PROGRESS"


# --------------------------------------------------------------------------- #
# Tenant return_url + evidence bundle
# --------------------------------------------------------------------------- #
def test_return_url_is_exposed_in_context_and_evidence_lists_artifacts(
    client: TestClient, tenant_token: str, otp_sender: CapturingOtpSender
) -> None:
    response = client.post(
        "/v1/kyc/sessions",
        headers={"Authorization": f"Bearer {tenant_token}"},
        json={
            "flow": "TRAVEL_INSURANCE",
            "customer_reference": "MHC-3",
            "otp_destination": "jmartin@yahoo.fr",
            "return_url": "https://mymhc.example/ekyc-return.html",
        },
    )
    session = response.json()
    headers = session_headers(session["verification_url"])
    base = f"/v1/verification/{session['session_id']}"
    give_consent(client, headers, base)

    context = client.get(f"{base}/context", headers=headers).json()
    assert context["return_url"] == "https://mymhc.example/ekyc-return.html"

    # The tenant fetches the evidence bundle for its own review.
    bearer = {"Authorization": f"Bearer {tenant_token}"}
    evidence = client.get(
        f"/v1/kyc/sessions/{session['session_id']}/evidence", headers=bearer
    )
    assert evidence.status_code == 200
    body = evidence.json()
    assert body["session_id"] == session["session_id"]
    assert "artifacts" in body and "check_details" in body

    # A document upload lands in the artifact list and is downloadable.
    client.post(
        f"{base}/document",
        headers=headers,
        files={"file": ("passport.txt", PASSPORT_MRZ.encode(), "text/plain")},
        data={"document_type": "PASSPORT"},
    )
    evidence = client.get(
        f"/v1/kyc/sessions/{session['session_id']}/evidence", headers=bearer
    ).json()
    assert len(evidence["artifacts"]) >= 1
    first = evidence["artifacts"][0]
    assert first["kind"] and first["sha256"] and first["purged"] is False

    blob = client.get(
        f"/v1/kyc/sessions/{session['session_id']}/artifacts/{first['artifact_id']}",
        headers=bearer,
    )
    assert blob.status_code == 200
    assert len(blob.content) == first["size_bytes"]

    # Another tenant's artifact id is rejected.
    other = client.get(
        "/v1/kyc/sessions/NONEXISTENT/artifacts/x", headers=bearer
    )
    assert other.status_code in (404, 401)


def test_return_url_rejects_non_http() -> None:
    from pydantic import ValidationError

    from app.schemas import SessionCreateRequest

    with pytest.raises(ValidationError):
        SessionCreateRequest(flow="TRAVEL_INSURANCE", return_url="javascript:alert(1)")
