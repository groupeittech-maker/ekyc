"""Country-profile trust connectors drive instance defaults (client-brought
trust services: TSA + signature provider)."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import Column, String

from app.core import country_profile as cp
from app.engines import orchestrator


class _Tenant:
    default_jurisdiction = None


def _write_profile(tmp_path, monkeypatch, **trust):
    profile = {
        "country_code": "CI",
        "deployment_mode": "national",
        "environment": "production",
        "trust": trust,
    }
    f = tmp_path / "P.json"
    f.write_text(json.dumps(profile))
    monkeypatch.setattr(cp.settings, "country_profile", str(f))
    cp._active_cache.clear()


def test_profile_trust_overrides_jurisdiction_defaults(tmp_path, monkeypatch):
    _write_profile(
        tmp_path, monkeypatch,
        tsa_provider="digisign",
        signature_provider="local",
    )
    p = orchestrator.resolve(_Tenant(), "GLOBAL")
    assert p.tsa_policy == "digisign"          # client's named TSA wins
    assert p.signature_level == "local"


def test_null_trust_falls_back_to_jurisdiction(tmp_path, monkeypatch):
    _write_profile(tmp_path, monkeypatch, tsa_provider=None, signature_provider=None)
    p = orchestrator.resolve(_Tenant(), "GLOBAL")
    assert p.tsa_policy == "internal"          # GLOBAL rule default
    assert p.signature_level == "platform"


def test_no_profile_uses_jurisdiction_only(monkeypatch):
    monkeypatch.setattr(cp.settings, "country_profile", "")
    cp._active_cache.clear()
    p = orchestrator.resolve(_Tenant(), "FR")
    assert p.tsa_policy == "qualified"         # FR rule
    assert p.signature_level == "platform"


def test_client_tsa_name_must_exist(tmp_path, monkeypatch):
    """A profile declaring a provider name that isn't configured must fail
    at use, not silently degrade — the connector can't be bluffed."""
    from app.engines import tsa

    _write_profile(tmp_path, monkeypatch, tsa_provider="nonexistent-tsa")
    p = orchestrator.resolve(_Tenant(), "GLOBAL")
    assert p.tsa_policy == "nonexistent-tsa"
    with pytest.raises(tsa.UnknownTsaProviderError):
        tsa.resolve_policy(p.tsa_policy)
