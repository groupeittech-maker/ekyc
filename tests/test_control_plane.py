"""End-to-end Central↔National: enroll → attest → verify on the national side."""

from __future__ import annotations

import base64
import json
import time
import uuid

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi.testclient import TestClient

from apps.control_plane.app import app
from apps.control_plane.config import settings as cs


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(cs, "bootstrap_key", "boot-123")
    monkeypatch.setattr(cs, "admin_key", "admin-123")
    monkeypatch.setattr(cs, "private_key_path", str(tmp_path / "central.pem"))
    import apps.control_plane.crypto as crypto

    crypto._key = None  # fresh key per test
    with TestClient(app) as c:
        yield c


def _instance_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _pub_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()


def _instance_jwt(key: Ed25519PrivateKey, sub: str) -> str:
    return pyjwt.encode(
        {
            "typ": "instance",
            "sub": sub,
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "jti": str(uuid.uuid4()),
        },
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        algorithm="EdDSA",
    )


def _enroll(client: TestClient) -> tuple[str, Ed25519PrivateKey, str]:
    key = _instance_key()
    r = client.post(
        "/v1/instances",
        headers={"X-Bootstrap-Key": "boot-123"},
        json={
            "instance_public_key": _pub_b64(key),
            "country_code": "CI",
            "software_version": "0.1.0",
            "capabilities": ["ocr", "mrz", "nfc"],
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    return body["instance_id"], key, body["central_public_key"]


def test_enroll_requires_bootstrap_key(client):
    r = client.post(
        "/v1/instances",
        json={
            "instance_public_key": _pub_b64(_instance_key()),
            "country_code": "CI",
        },
    )
    assert r.status_code == 403


def test_full_cycle_attestation_verifies_on_national_side(client, tmp_path):
    from app.core import country_profile as cp

    instance_id, _key, central_pub = _enroll(client)

    r = client.post(
        f"/v1/instances/{instance_id}/attestations",
        headers={"X-Admin-Key": "admin-123"},
        json={
            "legal_review": True,
            "hosting_approved": True,
            "trust_services_validated": True,
        },
    )
    assert r.status_code == 201, r.text
    att = r.json()["activation_attestation"]

    # The national side must accept exactly this document.
    profile = {
        "country_code": "CI",
        "deployment_mode": "national",
        "environment": "production",
        "activation": {
            "legal_review": True,
            "hosting_approved": True,
            "trust_services_validated": True,
        },
        "activation_attestation": att,
    }
    f = tmp_path / "CI.json"
    f.write_text(json.dumps(profile))
    import app.core.country_profile as mod

    orig_profile, orig_key = cp.settings.country_profile, cp.settings.central_public_key
    mod.settings.country_profile, mod.settings.central_public_key = str(f), central_pub
    try:
        loaded = cp.enforce_country_profile()
        assert loaded.country_code == "CI"
    finally:
        mod.settings.country_profile, mod.settings.central_public_key = (
            orig_profile,
            orig_key,
        )


def test_heartbeat_authenticated(client):
    instance_id, key, _ = _enroll(client)
    token = _instance_jwt(key, instance_id)
    r = client.post(
        f"/v1/instances/{instance_id}/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "version": "0.1.0",
            "counters": {"sessions": {"VERIFIED": 3}},
            "health": {"db": True},
        },
    )
    assert r.status_code == 200


def test_heartbeat_rejects_unknown_instance(client):
    r = client.post(
        "/v1/instances/nope/heartbeat",
        headers={"Authorization": "Bearer x"},
        json={},
    )
    assert r.status_code == 401


def test_manifest_signed_and_retrieved(client):
    instance_id, key, _ = _enroll(client)
    client.post(
        f"/v1/instances/{instance_id}/manifest",
        headers={"X-Admin-Key": "admin-123"},
        json={"version": "0.2.0", "config_overlay": {"EKYC_RISK_ACCEPT_THRESHOLD": "82"}},
    )
    token = _instance_jwt(key, instance_id)
    r = client.get(
        f"/v1/instances/{instance_id}/manifest",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == "0.2.0"
    assert body["signature"]


def test_jti_replay_rejected(client):
    """F3: replaying the same jti is refused — and persists beyond a restart
    since the ledger lives in the database, not in memory."""
    instance_id, key, _ = _enroll(client)
    token = _instance_jwt(key, instance_id)
    # same jti twice: rebuild identical token
    import jwt as _jwt

    claims = {"typ": "instance", "sub": instance_id,
              "iat": int(time.time()), "exp": int(time.time()) + 300,
              "jti": str(uuid.uuid4())}
    fixed = _jwt.encode(
        claims,
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
        algorithm="EdDSA",
    )
    r1 = client.post(
        f"/v1/instances/{instance_id}/heartbeat",
        headers={"Authorization": f"Bearer {fixed}"},
        json={"version": "0.1.0"},
    )
    r2 = client.post(
        f"/v1/instances/{instance_id}/heartbeat",
        headers={"Authorization": f"Bearer {fixed}"},
        json={"version": "0.1.0"},
    )
    assert r1.status_code == 200
    assert r2.status_code == 401


def test_revoke_attestation(client):
    instance_id, _k, _p = _enroll(client)
    client.post(
        f"/v1/instances/{instance_id}/attestations",
        headers={"X-Admin-Key": "admin-123"},
        json={"legal_review": True, "hosting_approved": True,
              "trust_services_validated": True},
    )
    r = client.delete(
        f"/v1/instances/{instance_id}/attestations",
        headers={"X-Admin-Key": "admin-123"},
    )
    assert r.status_code == 200
    lst = client.get("/v1/instances", headers={"X-Admin-Key": "admin-123"}).json()
    row = next(i for i in lst if i["instance_id"] == instance_id)
    assert row["status"] == "revoked"
    assert row["activated"] is False
