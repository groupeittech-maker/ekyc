"""Lot A residual — heartbeat client and manifest-sync network paths,
plus the fundamental autonomy rule: a dead Central never breaks a
national instance."""

from __future__ import annotations

import base64
import time
import uuid

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from app.services import heartbeat as hb
from app.services import manifest as mf


def _instance_key(tmp_path):
    key = Ed25519PrivateKey.generate()
    kp = tmp_path / "instance.pem"
    kp.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    return key, kp


class _Session:
    """Minimal SessionLocal stub returning empty result sets."""
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def execute(self, q):
        class R:
            def all(self):
                return []
        return R()


@pytest.fixture()
def central_config(tmp_path, monkeypatch):
    key, kp = _instance_key(tmp_path)
    for mod in (hb.settings, mf.settings):
        monkeypatch.setattr(mod, "central_url", "http://central.test")
        monkeypatch.setattr(mod, "instance_id", "inst-1")
        monkeypatch.setattr(mod, "instance_key_path", str(kp))
    return key


def test_jwt_structure(central_config):
    tok = hb._instance_jwt()
    claims = pyjwt.decode(tok, options={"verify_signature": False})
    assert claims["typ"] == "instance"
    assert claims["sub"] == "inst-1"
    assert claims["exp"] - claims["iat"] == 300
    assert claims["jti"]


def test_not_configured_returns_none(monkeypatch):
    monkeypatch.setattr(hb.settings, "central_url", "")
    assert hb._instance_jwt() is None


def test_heartbeat_aggregates_and_posts(central_config, monkeypatch):
    monkeypatch.setattr(hb, "SessionLocal", lambda: _Session())

    calls = {}

    class FakeResp:
        status_code = 200
        def raise_for_status(self): ...
        def json(self):
            return {"status": "ack"}

    def fake_post(url, json=None, headers=None, timeout=None):
        calls["url"] = url
        calls["payload"] = json
        calls["auth"] = headers["Authorization"]
        return FakeResp()

    monkeypatch.setattr(hb.httpx, "post", fake_post)
    out = hb.send_heartbeat()
    assert out == {"status": "ack"}
    assert calls["url"].endswith("/v1/instances/inst-1/heartbeat")
    assert calls["auth"].startswith("Bearer ")
    # Contract: aggregated counters only — no identity fields
    assert set(calls["payload"]) <= {"version", "counters", "health", "profile"}


def test_central_down_is_autonomy_not_failure(central_config, monkeypatch):
    """FUNDAMENTAL RULE: unreachable Central → warning + None, never an
    exception that could break verification."""
    def boom(*a, **kw):
        raise hb.httpx.ConnectError("dead")
    monkeypatch.setattr(hb, "SessionLocal", lambda: _Session())
    monkeypatch.setattr(hb.httpx, "post", boom)
    assert hb.send_heartbeat() is None


def test_manifest_not_yet_effective(central_config, tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.serialization import PublicFormat

    pub = base64.b64encode(
        central_config.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    monkeypatch.setattr(mf.settings, "central_public_key", pub)
    monkeypatch.setattr(mf.settings, "overrides_path", str(tmp_path / "ov.json"))

    import json as _json
    overlay = {"EKYC_RISK_ACCEPT_THRESHOLD": "82"}
    canonical = _json.dumps(
        {"version": "9.9.9", "not_before": "2999-01-01T00:00:00+00:00",
         "config_overlay": overlay, "artifacts": []},
        sort_keys=True, separators=(",", ":")).encode()

    class FakeResp:
        status_code = 200
        def raise_for_status(self): ...
        def json(self):
            return {
                "version": "9.9.9",
                "not_before": "2999-01-01T00:00:00+00:00",
                "config_overlay": overlay,
                "artifacts": [],
                "signature": base64.b64encode(
                    central_config.sign(canonical)
                ).decode(),
            }

    monkeypatch.setattr(mf.httpx, "get", lambda *a, **kw: FakeResp())
    out = mf.sync_manifest()
    assert out["status"] == "not-yet-effective"


def test_manifest_unreachable_is_autonomy(central_config, monkeypatch):
    def boom(*a, **kw):
        raise mf.httpx.ConnectError("dead")
    monkeypatch.setattr(mf.httpx, "get", boom)
    assert mf.sync_manifest()["status"] == "unreachable"


def test_manifest_no_manifest_returns_none_published(central_config, monkeypatch):
    class R404:
        status_code = 404
        def raise_for_status(self):
            raise AssertionError("not reached")
    monkeypatch.setattr(mf.httpx, "get", lambda *a, **kw: R404())
    assert mf.sync_manifest()["status"] == "none-published"
