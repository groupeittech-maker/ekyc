"""Trust services: TSA Manager + Electronic Signature Manager."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.engines import signature_manager, tsa
from app.services.pdf import render_contract

_ADMIN = {"X-Admin-Key": "test-admin-key"}
_DIGEST = hashlib.sha256(b"payload").hexdigest()


# --------------------------------------------------------------------------- #
# Minimal DER encoder for fabricating RFC 3161 test tokens
# --------------------------------------------------------------------------- #
def _tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 128:
        hdr = bytes([n])
    else:
        hdr = bytes([0x81, n])
    return bytes([tag]) + hdr + content


def _seq(c: bytes) -> bytes:
    return _tlv(0x30, c)


def _ctx0(c: bytes) -> bytes:
    return _tlv(0xA0, c)


_OID_SIGNED_DATA = bytes.fromhex("2A864886F70D010702")
_OID_TST_INFO = bytes.fromhex("2A864886F70D0109100104")
_OID_SHA256 = bytes.fromhex("608648016503040201")
_OID_POLICY = bytes.fromhex("2A864886F70D0109100308")


def _fake_tsa_response(digest_bytes: bytes) -> bytes:
    tst_info = _seq(
        _tlv(0x02, b"\x01")
        + _oid(_OID_POLICY)
        + _seq(_oid(_OID_SHA256) + _tlv(0x04, digest_bytes))
        + _tlv(0x02, b"\x2a")
        + _tlv(0x18, b"20261018120000Z")
    )
    eci = _seq(_oid(_OID_TST_INFO) + _ctx0(_tlv(0x04, tst_info)))
    signed_data = _seq(_tlv(0x02, b"\x01") + _tlv(0x31, b"") + eci)
    return _seq(_seq(_tlv(0x02, b"\x00")) + _seq(_oid(_OID_SIGNED_DATA) + _ctx0(signed_data)))


def _oid(content: bytes) -> bytes:
    return _tlv(0x06, content)


# --------------------------------------------------------------------------- #
# TSA Manager — provider resolution
# --------------------------------------------------------------------------- #
def test_resolve_internal_and_qualified_fallback() -> None:
    assert tsa.resolve_policy("internal").mode == "internal"
    # No external TSA configured in tests: "qualified" degrades honestly.
    assert tsa.resolve_policy("qualified").name == "internal"


def test_resolve_named_provider_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        settings,
        "tsas_json",
        json.dumps(
            {
                "digisign": {
                    "endpoint": "https://tsa.digisign.example",
                    "qualified": True,
                    "timeout_s": 5,
                }
            }
        ),
    )
    provider = tsa.resolve_policy("digisign")
    assert provider.mode == "external" and provider.qualified
    # "qualified" now picks the named provider.
    assert tsa.resolve_policy("qualified").name == "digisign"


def test_resolve_unknown_provider_raises() -> None:
    with pytest.raises(tsa.UnknownTsaProviderError):
        tsa.resolve_policy("acme-tsa")


# --------------------------------------------------------------------------- #
# TSA Manager — timestamp + verification
# --------------------------------------------------------------------------- #
def test_internal_timestamp_and_verify() -> None:
    token = tsa.timestamp(_DIGEST, "internal")
    assert token.qualified is False and token.provider == "internal"
    result = tsa.verify_token(token.token, _DIGEST, issued_at=token.issued_at)
    assert result["signature_verified"] is True
    assert result["imprint_matches"] is True


def test_internal_token_tamper_detected() -> None:
    token = tsa.timestamp(_DIGEST, "internal")
    other = hashlib.sha256(b"other").hexdigest()
    result = tsa.verify_token(token.token, other, issued_at=token.issued_at)
    assert result["signature_verified"] is False


def test_internal_verify_without_issued_at_is_honest() -> None:
    token = tsa.timestamp(_DIGEST, "internal")
    result = tsa.verify_token(token.token, _DIGEST)
    assert result["signature_verified"] is None


def test_rfc3161_structural_verification() -> None:
    blob = _fake_tsa_response(bytes.fromhex(_DIGEST))
    result = tsa.verify_token(blob, _DIGEST)
    assert result["structural_ok"] is True
    assert result["granted"] is True
    assert result["imprint_matches"] is True
    assert result["gen_time"] == "20261018120000Z"


def test_rfc3161_imprint_mismatch_detected() -> None:
    blob = _fake_tsa_response(hashlib.sha256(b"different").digest())
    result = tsa.verify_token(blob, _DIGEST)
    assert result["imprint_matches"] is False


def test_garbage_blob_fails_cleanly() -> None:
    result = tsa.verify_token(b"\x00\x01\x02", _DIGEST)
    assert result["structural_ok"] is False


# --------------------------------------------------------------------------- #
# Signature Manager
# --------------------------------------------------------------------------- #
def test_sign_and_verify_roundtrip() -> None:
    sig = signature_manager.sign(bytes.fromhex(_DIGEST), "platform")
    assert sig.provider == "localkey"
    assert signature_manager.verify(bytes.fromhex(_DIGEST), sig.value) is True
    assert signature_manager.verify(b"tampered", sig.value) is False


def test_verify_with_embedded_public_key() -> None:
    from app.engines.signature import get_signer

    sig = signature_manager.sign(bytes.fromhex(_DIGEST))
    ok = signature_manager.verify(
        bytes.fromhex(_DIGEST), sig.value, public_key_pem=get_signer().public_key_pem()
    )
    assert ok is True


def test_provider_info_reports_cert_lifecycle() -> None:
    info = signature_manager.provider_info("platform")
    assert info.algorithm == "RSASSA-PKCS1-v1_5-SHA256"
    assert info.days_to_expiry is not None and info.days_to_expiry > 0


def test_unknown_signature_level_raises() -> None:
    with pytest.raises(signature_manager.UnknownSignerError):
        signature_manager.resolve("some-external-dss")


# --------------------------------------------------------------------------- #
# End-to-end: the session's trust services are routed through the managers
# --------------------------------------------------------------------------- #
def _client_session(client: TestClient, jurisdiction: str | None = None) -> tuple[dict, str]:
    creds = client.post(
        "/v1/admin/tenants",
        headers=_ADMIN,
        json={"name": "TS Tenant", "allowed_flows": ["TRAVEL_INSURANCE"]},
    ).json()
    token = client.post(
        "/v1/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        },
    ).json()["access_token"]
    body = {"customer_reference": "TS-1", "flow": "TRAVEL_INSURANCE"}
    if jurisdiction:
        body["jurisdiction"] = jurisdiction
    session = client.post(
        "/v1/kyc/sessions", headers={"authorization": f"Bearer {token}"}, json=body
    ).json()
    return {"authorization": f"Bearer {token}"}, session["session_id"]


def test_seal_records_trust_providers(client: TestClient) -> None:
    headers, sid = _client_session(client)
    pdf = render_contract(
        title="T",
        session_id=sid,
        tenant_name="T",
        body=[("a", "1")],
        issued_at="2026-10-18T00:00:00",
    )
    client.post(
        f"/v1/kyc/sessions/{sid}/documents",
        headers=headers,
        json={"document_reference": "TS-DOC", "pdf_base64": base64.b64encode(pdf).decode()},
    )
    audit = client.get(f"/v1/kyc/sessions/{sid}/audit", headers=headers).json()
    signed_event = next(e for e in audit["events"] if e["event_type"] == "DOCUMENT_SIGNED")
    ts_event = next(e for e in audit["events"] if e["event_type"] == "TIMESTAMPED")
    assert signed_event["payload"]["provider"] == "localkey"
    assert ts_event["payload"]["provider"] == "internal"
    assert ts_event["payload"]["qualified"] is False


def test_session_with_unknown_named_tsa_is_400(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        settings, "jurisdictions_json", '{"CI": {"tsa_policy": "unconfigured-tsa"}}'
    )
    creds = client.post(
        "/v1/admin/tenants",
        headers=_ADMIN,
        json={"name": "T", "allowed_flows": ["TRAVEL_INSURANCE"], "default_jurisdiction": "CI"},
    ).json()
    token = client.post(
        "/v1/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        },
    ).json()["access_token"]
    resp = client.post(
        "/v1/kyc/sessions",
        headers={"authorization": f"Bearer {token}"},
        json={"customer_reference": "X", "flow": "TRAVEL_INSURANCE"},
    )
    assert resp.status_code == 400
