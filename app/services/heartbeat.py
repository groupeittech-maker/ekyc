"""Trusdy National → Central heartbeat client (control-plane contract v1).

Sends aggregated technical counters every ``heartbeat_interval`` seconds —
never identities, scores, artifacts or OTP destinations. Offline-safe by
contract: when Central is unreachable the instance keeps working; failures
are logged as warnings only.
"""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path

from collections import Counter

import httpx
import jwt
from sqlalchemy import func, select

from app.core.config import settings
from app.db.session import SessionLocal
from app.models.session import KycSession

logger = logging.getLogger(__name__)

_INSTANCE_KEY_PATH = "/srv/ekyc/var/keys/instance_ed25519.pem"


def _instance_jwt() -> str | None:
    if not settings.central_url or not settings.instance_id:
        return None
    key_path = Path(settings.instance_key_path or _INSTANCE_KEY_PATH)
    if not key_path.exists():
        logger.warning("heartbeat: instance key missing at %s", key_path)
        return None
    now = int(time.time())
    return jwt.encode(
        {
            "typ": "instance",
            "sub": settings.instance_id,
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
        },
        key_path.read_bytes(),
        algorithm="EdDSA",
    )


def _counters() -> dict:
    """Aggregated counts only — checks live in the session's JSON map, so we
    fold them in Python (no per-session identifiers leave the instance)."""
    with SessionLocal() as s:
        sessions = dict(
            s.execute(
                select(KycSession.status, func.count()).group_by(KycSession.status)
            ).all()
        )
        check_counter: Counter[str] = Counter()
        for (checks,) in s.execute(select(KycSession.checks)).all():
            for name, status in (checks or {}).items():
                check_counter[f"{name}:{status}"] += 1
    return {"sessions": sessions, "checks": dict(check_counter)}


def _health() -> dict:
    from redis import Redis

    try:
        with SessionLocal() as s:
            s.execute(select(1))
        db_ok = True
    except Exception:
        db_ok = False
    try:
        redis_ok = bool(Redis.from_url(settings.redis_url).ping())
    except Exception:
        redis_ok = False
    model_dir = Path(settings.biometrics_model_dir)
    models_ok = (
        model_dir.exists()
        and (model_dir / settings.antispoof_model).exists()
    )
    return {"db": db_ok, "redis": redis_ok, "models": models_ok}


def _profile_summary() -> dict:
    if not settings.country_profile:
        return {}
    try:
        from app.core.country_profile import load_profile

        p = load_profile(settings.country_profile)
        return {
            "country_code": p.country_code,
            "activated": bool(p.activation_attestation),
        }
    except Exception:
        return {"country_code": "unknown", "activated": False}


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("ittech-ekyc")
    except Exception:
        return "unknown"


def send_heartbeat() -> dict | None:
    """POST counters to Central. Returns the ack payload or None on failure —
    autonomy rule: a dead centre must never break a national instance."""
    token = _instance_jwt()
    if token is None:
        return None
    payload = {
        "version": _version(),
        "counters": _counters(),
        "health": _health(),
        "profile": _profile_summary(),
    }
    try:
        resp = httpx.post(
            f"{settings.central_url.rstrip('/')}/v1/instances/{settings.instance_id}/heartbeat",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("heartbeat unreachable (autonomy mode): %s", type(exc).__name__)
        return None
