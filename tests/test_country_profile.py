"""Country profile schema + attested activation gate."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat

from app.core import country_profile as cp
from app.core.config import InsecureConfigError, Settings


def _profile(**activation) -> dict:
    return {
        "country_code": "CI",
        "deployment_mode": "national",
        "environment": "production",
        "activation": {
            "legal_review": activation.get("legal", False),
            "hosting_approved": activation.get("hosting", False),
            "trust_services_validated": activation.get("trust", False),
        },
    }


def _sign_attestation(key: Ed25519PrivateKey, *, country="CI", not_after=None) -> dict:
    not_after = not_after or datetime.now(timezone.utc) + timedelta(days=365)
    att = cp.ActivationAttestation(
        country=country,
        legal_review=True,
        hosting_approved=True,
        trust_services_validated=True,
        issued_at=datetime.now(timezone.utc) - timedelta(days=1),
        not_after=not_after,
        signature="",
    )
    att.signature = base64.b64encode(key.sign(att.canonical_payload())).decode()
    return att.model_dump(mode="json")


def _pub_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def _cfg(monkeypatch, profile: dict, tmp_path, pubkey: str = ""):
    f = tmp_path / "profile.json"
    f.write_text(json.dumps(profile))
    monkeypatch.setattr(cp.settings, "country_profile", str(f))
    monkeypatch.setattr(cp.settings, "central_public_key", pubkey)


def test_activation_requires_all_flags(tmp_path, monkeypatch):
    _cfg(monkeypatch, _profile(legal=True, hosting=True), tmp_path)
    with pytest.raises(InsecureConfigError, match="not activated"):
        cp.enforce_country_profile()


def test_activation_requires_attestation(tmp_path, monkeypatch):
    _cfg(monkeypatch, _profile(legal=True, hosting=True, trust=True), tmp_path)
    with pytest.raises(InsecureConfigError, match="attestation"):
        cp.enforce_country_profile()


def test_valid_signed_attestation_passes(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    profile = _profile(legal=True, hosting=True, trust=True)
    profile["activation_attestation"] = _sign_attestation(key)
    _cfg(monkeypatch, profile, tmp_path, pubkey=_pub_b64(key))
    result = cp.enforce_country_profile()
    assert result.country_code == "CI"


def test_wrong_key_rejected(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    profile = _profile(legal=True, hosting=True, trust=True)
    profile["activation_attestation"] = _sign_attestation(key)
    _cfg(monkeypatch, profile, tmp_path, pubkey=_pub_b64(other))
    with pytest.raises(InsecureConfigError, match="signature invalid"):
        cp.enforce_country_profile()


def test_expired_attestation_rejected(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    profile = _profile(legal=True, hosting=True, trust=True)
    profile["activation_attestation"] = _sign_attestation(
        key, not_after=datetime.now(timezone.utc) - timedelta(days=1)
    )
    _cfg(monkeypatch, profile, tmp_path, pubkey=_pub_b64(key))
    with pytest.raises(InsecureConfigError, match="expired"):
        cp.enforce_country_profile()


def test_editing_flags_without_resigning_fails(tmp_path, monkeypatch):
    """The plan's core rule: a plain config edit cannot unlock the instance —
    the attestation no longer matches the file's flags."""
    key = Ed25519PrivateKey.generate()
    profile = _profile(legal=True, hosting=True, trust=True)
    profile["activation_attestation"] = _sign_attestation(key)
    # Attacker edits the attestation's flags down — signature still valid
    # over the old payload but flags no longer all true.
    profile["activation_attestation"]["legal_review"] = False
    _cfg(monkeypatch, profile, tmp_path, pubkey=_pub_b64(key))
    with pytest.raises(InsecureConfigError):
        cp.enforce_country_profile()


def test_no_profile_configured_is_noop(monkeypatch):
    monkeypatch.setattr(cp.settings, "country_profile", "")
    assert cp.enforce_country_profile() is None


def test_schema_rejects_unknown_fields(tmp_path):
    bad = _profile()
    bad["rogue_field"] = True
    f = tmp_path / "p.json"
    f.write_text(json.dumps(bad))
    with pytest.raises(Exception):
        cp.load_profile(f)


def test_attestation_for_other_country_rejected(tmp_path, monkeypatch):
    """F1: a signed attestation for country CG must not activate profile CI —
    attestations are non-transferable."""
    key = Ed25519PrivateKey.generate()
    profile = _profile(legal=True, hosting=True, trust=True)
    profile["activation_attestation"] = _sign_attestation(key, country="CG")
    _cfg(monkeypatch, profile, tmp_path, pubkey=_pub_b64(key))
    with pytest.raises(InsecureConfigError, match="non-transferable"):
        cp.enforce_country_profile()


def test_profile_flags_must_match_signed_flags(tmp_path, monkeypatch):
    """File says 'activated' but the signed attestation says otherwise —
    tampering with the file flags is caught even with a valid signature."""
    key = Ed25519PrivateKey.generate()
    profile = _profile(legal=True, hosting=True, trust=True)
    att = _sign_attestation(key)
    att["legal_review"] = False
    # Re-sign so the signature is VALID over the modified payload — the gate
    # must still catch the divergence between file flags and signed flags.
    obj = cp.ActivationAttestation(**att)
    obj.signature = base64.b64encode(key.sign(obj.canonical_payload())).decode()
    profile["activation_attestation"] = obj.model_dump(mode="json")
    _cfg(monkeypatch, profile, tmp_path, pubkey=_pub_b64(key))
    with pytest.raises(InsecureConfigError, match="tampered"):
        cp.enforce_country_profile()


def test_require_profile_blocks_unset(monkeypatch):
    """F2: with EKYC_REQUIRE_COUNTRY_PROFILE the gate cannot be disarmed by
    simply unsetting the profile path."""
    from app.core.config import validate_production_settings

    cfg = Settings(
        environment="production",
        admin_api_key="k" * 40,
        jwt_secret="s" * 40,
        kek="a" * 64,
        ocr_provider="inhouse",
        face_provider="inhouse",
        otp_provider="http",
        otp_http_url="https://gw",
        signing_dev_self_signed_cert=False,
        require_country_profile=True,
        country_profile="",
    )
    with pytest.raises(InsecureConfigError, match="EKYC_COUNTRY_PROFILE is required"):
        validate_production_settings(cfg)


def test_production_gate_invoked():
    """validate_production_settings must call the gate when a profile is set —
    smoke check that the wiring exists (settings fixture is production-less)."""
    src = open("app/core/config.py").read()
    assert "enforce_country_profile()" in src
