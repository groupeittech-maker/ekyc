"""National-side signed manifest sync (control-plane contract §3.4).

Fetches the instance's manifest from Central, verifies the Ed25519 signature
against ``EKYC_CENTRAL_PUBLIC_KEY``, applies the whitelisted config overlay
atomically, and records the applied version. A manifest is applied when:

- signature is valid over the canonical payload,
- ``not_before`` has been reached,
- version differs from the last applied (idempotent),
- signature check happens BEFORE any overlay touches runtime config.

Autonomy rule (§5): if Central is unreachable the last applied manifest
keeps governing — sync failures never break verification.
"""

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import httpx

from app.core.config import settings
from app.core import runtime_config
from app.services.heartbeat import _instance_jwt

logger = logging.getLogger(__name__)


def _state_path() -> Path:
    return Path(settings.overrides_path).expanduser().parent / "manifest_state.json"


def _load_state() -> dict:
    try:
        return json.loads(_state_path().read_text())
    except (OSError, ValueError):
        return {}


def _canonical(manifest: dict) -> bytes:
    """Same canonicalization as apps.control_plane.crypto.sign_manifest —
    changing either side breaks signature verification by design."""
    return json.dumps(
        {
            "version": manifest["version"],
            "not_before": manifest["not_before"],
            "config_overlay": manifest["config_overlay"],
            "artifacts": manifest["artifacts"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _verify(manifest: dict) -> str | None:
    """None = valid, else a reason label."""
    if not settings.central_public_key:
        return "EKYC_CENTRAL_PUBLIC_KEY not configured"
    try:
        from app.core.country_profile import _load_public_key

        key = _load_public_key(settings.central_public_key)
        key.verify(base64.b64decode(manifest["signature"]), _canonical(manifest))
    except Exception:
        return "manifest signature invalid"
    return None


def sync_manifest() -> dict:
    """Fetch + verify + apply. Returns a status dict (also useful in tests)."""
    if not settings.central_url or not settings.instance_id:
        return {"status": "disabled"}
    token = _instance_jwt()
    if token is None:
        return {"status": "no-identity"}
    try:
        resp = httpx.get(
            f"{settings.central_url.rstrip('/')}/v1/instances/{settings.instance_id}/manifest",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )
        if resp.status_code == 404:
            return {"status": "none-published"}
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("manifest sync unreachable (autonomy): %s", type(exc).__name__)
        return {"status": "unreachable", "error": type(exc).__name__}

    manifest = resp.json()
    reason = _verify(manifest)
    if reason is not None:
        logger.error("manifest rejected: %s", reason)
        return {"status": "rejected", "reason": reason}

    not_before = datetime.fromisoformat(manifest["not_before"])
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_before > datetime.now(timezone.utc):
        return {"status": "not-yet-effective", "version": manifest["version"]}

    state = _load_state()
    if state.get("version") == manifest["version"]:
        return {"status": "already-applied", "version": manifest["version"]}

    applied = runtime_config.apply_overlay(manifest.get("config_overlay", {}))
    _state_path().write_text(
        json.dumps(
            {
                "version": manifest["version"],
                "applied_at": datetime.now(timezone.utc).isoformat(),
                "applied_keys": sorted(applied),
            },
            indent=2,
        )
    )
    logger.info(
        "manifest %s applied: %d config key(s) updated",
        manifest["version"],
        len(applied),
    )
    return {"status": "applied", "version": manifest["version"], "applied": applied}
