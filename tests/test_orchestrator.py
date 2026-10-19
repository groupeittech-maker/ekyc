"""Regulatory orchestrator: jurisdiction resolution and vault routing."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.engines import orchestrator
from app.services import storage
from app.services.pdf import render_contract

_ADMIN = {"X-Admin-Key": "test-admin-key"}


@pytest.fixture
def vault_ci(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """A second vault (CI jurisdiction) rooted in a temp dir."""
    root = str(tmp_path / "vault-ci").replace("\\", "/")
    monkeypatch.setattr(
        settings,
        "vaults_json",
        json.dumps({"ci-vault": {"backend": "local", "root": root}}),
    )
    monkeypatch.setattr(
        settings,
        "jurisdictions_json",
        '{"CI": {"vault_profile": "ci-vault", "retention_days": 1800,'
        ' "tsa_policy": "internal", "signature_level": "platform"}}',
    )
    storage._vaults.clear()
    yield root
    storage._vaults.clear()


def _tenant(client: TestClient, **overrides) -> dict:
    body = {"name": "Orchestrated Tenant", "allowed_flows": ["TRAVEL_INSURANCE"], **overrides}
    resp = client.post("/v1/admin/tenants", headers=_ADMIN, json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _headers(client: TestClient, creds: dict) -> dict[str, str]:
    token = client.post(
        "/v1/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": creds["client_id"],
            "client_secret": creds["client_secret"],
        },
    ).json()["access_token"]
    return {"authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------- #
# Unit: resolution order
# --------------------------------------------------------------------------- #
def test_resolve_prefers_request_over_tenant_and_default() -> None:
    tenant = SimpleNamespace(default_jurisdiction="FR")
    assert orchestrator.resolve(tenant, "eu").jurisdiction == "EU"
    assert orchestrator.resolve(tenant, "eu").source == "request"
    assert orchestrator.resolve(tenant, None).source == "tenant_default"
    assert orchestrator.resolve(SimpleNamespace(default_jurisdiction=None), None).source == (
        "platform_default"
    )
    assert orchestrator.resolve(SimpleNamespace(), None).jurisdiction == "GLOBAL"


def test_resolve_rejects_unknown_jurisdiction() -> None:
    with pytest.raises(orchestrator.UnknownJurisdictionError):
        orchestrator.resolve(SimpleNamespace(), "ATLANTIS")


# --------------------------------------------------------------------------- #
# API: jurisdiction on session create
# --------------------------------------------------------------------------- #
def test_session_snapshots_jurisdiction(vault_ci: str, client: TestClient) -> None:
    creds = _tenant(client)
    headers = _headers(client, creds)
    resp = client.post(
        "/v1/kyc/sessions",
        headers=headers,
        json={"customer_reference": "ORC-1", "flow": "TRAVEL_INSURANCE", "jurisdiction": "ci"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["jurisdiction"] == "CI"

    result = client.get(f"/v1/kyc/sessions/{body['session_id']}", headers=headers).json()
    assert result["jurisdiction"] == "CI"

    audit = client.get(f"/v1/kyc/sessions/{body['session_id']}/audit", headers=headers).json()
    created = audit["events"][0]["payload"]
    assert created["jurisdiction"] == "CI"
    assert created["jurisdiction_source"] == "request"
    assert created["vault_profile"] == "ci-vault"
    assert created["retention_days"] == 1800


def test_tenant_default_jurisdiction_is_used(vault_ci: str, client: TestClient) -> None:
    creds = _tenant(client, default_jurisdiction="CI")
    headers = _headers(client, creds)
    resp = client.post(
        "/v1/kyc/sessions",
        headers=headers,
        json={"customer_reference": "ORC-2", "flow": "TRAVEL_INSURANCE"},
    )
    assert resp.status_code == 201
    assert resp.json()["jurisdiction"] == "CI"


def test_unknown_jurisdiction_is_400(client: TestClient) -> None:
    creds = _tenant(client)
    headers = _headers(client, creds)
    resp = client.post(
        "/v1/kyc/sessions",
        headers=headers,
        json={"customer_reference": "ORC-3", "flow": "TRAVEL_INSURANCE", "jurisdiction": "XX"},
    )
    assert resp.status_code == 400


def test_jurisdiction_with_unconfigured_vault_is_400(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        settings, "jurisdictions_json", '{"XY": {"vault_profile": "missing-vault"}}'
    )
    creds = _tenant(client)
    headers = _headers(client, creds)
    resp = client.post(
        "/v1/kyc/sessions",
        headers=headers,
        json={"customer_reference": "ORC-4", "flow": "TRAVEL_INSURANCE", "jurisdiction": "XY"},
    )
    assert resp.status_code == 400


# --------------------------------------------------------------------------- #
# Routing: artifacts land in the resolved vault
# --------------------------------------------------------------------------- #
def test_artifacts_are_routed_to_the_session_vault(vault_ci: str, client: TestClient) -> None:
    creds = _tenant(client)
    headers = _headers(client, creds)
    session = client.post(
        "/v1/kyc/sessions",
        headers=headers,
        json={"customer_reference": "ORC-5", "flow": "TRAVEL_INSURANCE", "jurisdiction": "CI"},
    ).json()
    sid = session["session_id"]

    pdf = render_contract(
        title="Routed",
        session_id=sid,
        tenant_name="T",
        body=[("a", "1")],
        issued_at="2026-10-18T00:00:00",
    )
    sealed = client.post(
        f"/v1/kyc/sessions/{sid}/documents",
        headers=headers,
        json={
            "document_reference": "ROUTED-1",
            "pdf_base64": base64.b64encode(pdf).decode(),
        },
    )
    assert sealed.status_code == 201, sealed.text

    # The blob must exist under the CI vault root, not the default one.
    from pathlib import Path

    ci_files = list(Path(vault_ci).rglob("*.pdf"))
    assert ci_files, "no artifact written to the CI vault"
    # ...and the default vault holds nothing for this session.
    default_root = Path(settings.storage_root)
    leaked = list(default_root.rglob(f"*{sid}*"))
    assert not leaked, "artifact leaked to the default vault"

    # Reading back goes through the session's vault too.
    downloaded = client.get(
        f"/v1/kyc/sessions/{sid}/documents/{sealed.json()['signed_document_id']}",
        headers=headers,
    )
    assert downloaded.status_code == 200
    assert downloaded.content.startswith(b"%PDF")


def test_session_without_jurisdiction_stays_on_default_vault(client: TestClient) -> None:
    creds = _tenant(client)
    headers = _headers(client, creds)
    resp = client.post(
        "/v1/kyc/sessions",
        headers=headers,
        json={"customer_reference": "ORC-6", "flow": "TRAVEL_INSURANCE"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["jurisdiction"] == "GLOBAL"


# --------------------------------------------------------------------------- #
# Admin storage monitoring: GET /v1/admin/storage
# --------------------------------------------------------------------------- #
def test_admin_storage_reports_per_vault_and_tenant(vault_ci: str, client: TestClient) -> None:
    creds = _tenant(client)
    headers = _headers(client, creds)
    session = client.post(
        "/v1/kyc/sessions",
        headers=headers,
        json={"customer_reference": "ORC-7", "flow": "TRAVEL_INSURANCE", "jurisdiction": "CI"},
    ).json()
    pdf = render_contract(
        title="M",
        session_id=session["session_id"],
        tenant_name="T",
        body=[("a", "1")],
        issued_at="2026-10-18T00:00:00",
    )
    client.post(
        f"/v1/kyc/sessions/{session['session_id']}/documents",
        headers=headers,
        json={
            "document_reference": "MON-1",
            "pdf_base64": base64.b64encode(pdf).decode(),
        },
    )

    report = client.get("/v1/admin/storage", headers=_ADMIN).json()
    assert report["totals"]["artifacts"] >= 3  # source + token + sealed
    assert report["vaults"]["ci-vault"]["artifacts"] >= 3
    # Configured vaults appear even before use; local ones carry disk stats.
    assert "default" in report["vaults"]
    assert report["vaults"]["ci-vault"]["disk"]["root"] == vault_ci
    entry = next(t for t in report["tenants"] if t["tenant_id"] == creds["tenant_id"])
    assert entry["by_vault"]["ci-vault"]["artifacts"] >= 3


def test_admin_storage_requires_admin_key(client: TestClient) -> None:
    assert client.get("/v1/admin/storage").status_code == 401
