"""Runtime configuration overrides distributed via signed Central manifests.

Only whitelisted keys can be overridden remotely — a manifest may tune
thresholds but can never disable encryption, switch providers, or change
endpoints. Overrides persist in ``EKYC_OVERRIDES_PATH`` (JSON); they survive
restarts and roll back by pushing the previous values in a new manifest.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger(__name__)

# Remote-tunable keys only — secrets, providers, URLs and toggles are never
# in this list by design.
_OVERRIDABLE = {
    "risk_accept_threshold",
    "risk_review_threshold",
    "face_match_threshold",
    "liveness_threshold",
    "document_review_threshold",
}

_cache: dict = {}
_cache_mtime: float = -1.0


def _path() -> Path:
    return Path(settings.overrides_path).expanduser()


def _load() -> dict:
    global _cache, _cache_mtime
    p = _path()
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return _cache
    if mtime != _cache_mtime:
        try:
            _cache = json.loads(p.read_text())
            _cache_mtime = mtime
        except (ValueError, OSError):
            logger.warning("overrides file unreadable — keeping previous values")
    return _cache


def get(name: str):
    """Return the manifest-applied value for ``name``, else the env setting."""
    overrides = _load()
    if name in overrides:
        return overrides[name]
    return getattr(settings, name)


def apply_overlay(overlay: dict) -> dict:
    """Apply a signed manifest's ``config_overlay`` — EKYC_-prefixed keys are
    normalized, non-whitelisted keys are ignored (and reported). Returns the
    map actually applied."""
    applied: dict = {}
    ignored: list[str] = []
    for raw_key, value in overlay.items():
        key = raw_key.removeprefix("EKYC_").lower()
        if key in _OVERRIDABLE:
            applied[key] = value
        else:
            ignored.append(raw_key)
    if ignored:
        logger.warning("manifest overlay keys ignored (not overridable): %s", ignored)
    overrides = _load() | applied
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(overrides, indent=2))
    os.replace(tmp, p)  # atomic apply — no half-written overrides
    global _cache_mtime
    _cache_mtime = -1.0
    return applied
