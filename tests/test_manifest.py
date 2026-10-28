"""Signed-manifest sync on the national side — F4 coverage."""

from __future__ import annotations

import base64
import json
import time
import uuid

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from app.core import runtime_config
from app.services import manifest as mf


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(mf.settings, "overrides_path", str(tmp_path / "overrides.json"))
    monkeypatch.setattr(runtime_config.settings, "overrides_path", str(tmp_path / "overrides.json"))
    runtime_config._cache_mtime = -1.0
    runtime_config._cache = {}
    yield tmp_path


def _canonical(version: str, not_before: str, overlay: dict, artifacts: list) -> bytes:
    return json.dumps(
        {
            "version": version,
            "not_before": not_before,
            "config_overlay": overlay,
            "artifacts": artifacts,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _manifest(key: Ed25519PrivateKey, **kw) -> dict:
    body = {
        "version": kw.get("version", "0.2.0"),
        "not_before": kw.get(
            "not_before", "2000-01-01T00:00:00+00:00"
        ),
        "config_overlay": kw.get("config_overlay", {}),
        "artifacts": kw.get("artifacts", []),
    }
    body["signature"] = base64.b64encode(
        key.sign(_canonical(body["version"], body["not_before"], body["config_overlay"], body["artifacts"]))
    ).decode()
    return body


def test_verify_valid_manifest(env, monkeypatch):
    key = Ed25519PrivateKey.generate()
    pub = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    monkeypatch.setattr(mf.settings, "central_public_key", pub)
    m = _manifest(key, config_overlay={"EKYC_RISK_ACCEPT_THRESHOLD": "82"})
    assert mf._verify(m) is None


def test_verify_rejects_tampered_overlay(env, monkeypatch):
    key = Ed25519PrivateKey.generate()
    pub = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    monkeypatch.setattr(mf.settings, "central_public_key", pub)
    m = _manifest(key, config_overlay={"EKYC_RISK_ACCEPT_THRESHOLD": "82"})
    m["config_overlay"]["EKYC_RISK_ACCEPT_THRESHOLD"] = "10"  # tamper after sign
    assert mf._verify(m) == "manifest signature invalid"


def test_verify_rejects_wrong_key(env, monkeypatch):
    key = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    pub = base64.b64encode(other.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    monkeypatch.setattr(mf.settings, "central_public_key", pub)
    m = _manifest(key)
    assert mf._verify(m) == "manifest signature invalid"


def test_apply_overlay_whitelist_only(env, monkeypatch):
    """Only whitelisted keys land in runtime config — a manifest can never
    turn off encryption or swap providers."""
    applied = runtime_config.apply_overlay(
        {
            "EKYC_RISK_ACCEPT_THRESHOLD": "82",
            "EKYC_STORAGE_ENCRYPTION": "false",
            "EKYC_OTP_PROVIDER": "stub",
        }
    )
    assert applied == {"risk_accept_threshold": "82"}
    assert runtime_config.get("risk_accept_threshold") == "82"
    # Non-whitelisted keys fall back to the env setting unchanged —
    # and never land in the overrides file.
    from app.core.config import settings as _s

    assert runtime_config.get("storage_encryption") == _s.storage_encryption
    assert runtime_config.get("otp_provider") == _s.otp_provider
    stored = json.loads((env / "overrides.json").read_text())
    assert "storage_encryption" not in stored
    assert "otp_provider" not in stored


def test_state_records_applied_version(env, tmp_path):
    state = tmp_path / "manifest_state.json"
    state.write_text(json.dumps({"version": "0.2.0"}))
    assert mf._load_state()["version"] == "0.2.0"
