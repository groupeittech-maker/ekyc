"""LOT B — internal security checks: OAuth brute-force throttle,
production docs disabled."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_oauth_token_is_rate_limited(client: TestClient) -> None:
    """11th request inside the window → 429 regardless of credentials."""
    hits = [
        client.post(
            "/v1/oauth/token",
            json={"client_id": "spray-cid", "client_secret": "bad"},
        )
        for _ in range(11)
    ]
    assert hits[-1].status_code == 429
    assert all(r.status_code in {401, 429} for r in hits)


def test_oauth_ip_cap_blocks_cid_spray(client: TestClient) -> None:
    """Rotating client_id values still hit the per-IP cap (50/10min)."""
    for i in range(51):
        resp = client.post(
            "/v1/oauth/token",
            json={"client_id": f"cid-{i}", "client_secret": "bad"},
        )
        if resp.status_code == 429:
            break
    assert resp.status_code == 429


def test_docs_disabled_in_production(monkeypatch) -> None:
    """_docs_enabled() is the gate — the wiring is trivial by design."""
    import app.main as m

    monkeypatch.setattr(m.settings, "environment", "production")
    assert m._docs_enabled() is False
    monkeypatch.setattr(m.settings, "environment", "development")
    assert m._docs_enabled() is True


def test_verification_error_leaks_nothing_sensitive(client: TestClient) -> None:
    """Auth-failure responses must not reveal whether the resource exists,
    paths, or internals."""
    resp = client.get("/v1/verification/nonexistent-token/context")
    assert resp.status_code in {401, 404}
    body = resp.text.lower()
    for leak in ("traceback", ".py", "sqlite", "postgres", "c:\\", "/srv/"):
        assert leak not in body
