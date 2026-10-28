"""Trusdy Central — control-plane API (contract trusdy-control-plane.v1)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from apps.control_plane import crypto
from apps.control_plane.auth import current_instance
from apps.control_plane.config import settings
from apps.control_plane.db import init_db, session_scope
from apps.control_plane.models import Attestation, Instance, Manifest


def _admin(x_admin_key: str = Header(default="")) -> None:
    if x_admin_key != settings.admin_key:
        raise HTTPException(403, "invalid admin key")


app = FastAPI(title="Trusdy Central", version="1.0.0")


@app.on_event("startup")
def _startup() -> None:
    init_db()
    crypto.central_key()  # generate on first boot


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {"status": "ok", "service": "trusdy-central"}


# ---------------------------------------------------------------------------
# Enrollment — POST /v1/instances  (X-Bootstrap-Key, one-shot operator key)
# ---------------------------------------------------------------------------

class EnrollRequest(BaseModel):
    instance_public_key: str
    country_code: str = Field(min_length=2, max_length=3)
    deployment_mode: str = "national"
    software_version: str = ""
    capabilities: list[str] = []


@app.post("/v1/instances", status_code=201, tags=["registry"])
def enroll(req: EnrollRequest, x_bootstrap_key: str = Header(default="")) -> dict:
    if x_bootstrap_key != settings.bootstrap_key:
        raise HTTPException(403, "invalid bootstrap key")
    with session_scope() as s:
        inst = Instance(
            country_code=req.country_code.upper(),
            instance_public_key=req.instance_public_key,
            software_version=req.software_version,
            capabilities=req.capabilities,
        )
        s.add(inst)
        s.flush()
        return {
            "instance_id": inst.id,
            "central_public_key": crypto.public_key_b64(),
        }


@app.get("/v1/instances", tags=["registry"])
def list_instances(_: None = Depends(_admin)) -> list[dict]:
    with session_scope() as s:
        return [
            {
                "instance_id": i.id,
                "country_code": i.country_code,
                "status": i.status,
                "activated": i.activated,
                "software_version": i.software_version,
                "last_heartbeat_at": i.last_heartbeat_at.isoformat()
                if i.last_heartbeat_at
                else None,
            }
            for i in s.query(Instance).all()
        ]


# ---------------------------------------------------------------------------
# Heartbeat — POST /v1/instances/{id}/heartbeat  (instance JWT)
# ---------------------------------------------------------------------------

class HeartbeatRequest(BaseModel):
    version: str = ""
    counters: dict = {}
    health: dict = {}
    profile: dict = {}


@app.post("/v1/instances/{instance_id}/heartbeat", tags=["telemetry"])
def heartbeat(
    instance_id: str,
    req: HeartbeatRequest,
    inst: Instance = Depends(current_instance),
) -> dict:
    if inst.id != instance_id:
        raise HTTPException(403, "instance mismatch")
    with session_scope() as s:
        row = s.get(Instance, inst.id)
        row.last_heartbeat_at = datetime.now(timezone.utc)
        row.heartbeat_payload = req.model_dump()
        row.software_version = req.version or row.software_version
        return {"status": "ack"}


# ---------------------------------------------------------------------------
# Attestations — issued by the operator (X-Admin-Key) after offline checks
# ---------------------------------------------------------------------------

class AttestRequest(BaseModel):
    legal_review: bool = False
    hosting_approved: bool = False
    trust_services_validated: bool = False
    validity_days: int | None = None


@app.post("/v1/instances/{instance_id}/attestations", status_code=201, tags=["attestations"])
def issue_attestation(
    instance_id: str,
    req: AttestRequest,
    _: None = Depends(_admin),
) -> dict:
    with session_scope() as s:
        inst = s.get(Instance, instance_id)
        if inst is None:
            raise HTTPException(404, "instance not found")
        issued = datetime.now(timezone.utc)
        expires = issued + timedelta(
            days=req.validity_days or settings.attestation_validity_days
        )
        payload = crypto.canonical_attestation_payload(
            inst.country_code,
            req.legal_review,
            req.hosting_approved,
            req.trust_services_validated,
            issued.isoformat(),
            expires.isoformat(),
        )
        att = Attestation(
            instance_id=inst.id,
            country=inst.country_code,
            legal_review=req.legal_review,
            hosting_approved=req.hosting_approved,
            trust_services_validated=req.trust_services_validated,
            issued_at=issued,
            not_after=expires,
            signature=crypto.sign_attestation(payload),
        )
        s.add(att)
        inst.activated = req.legal_review and req.hosting_approved and req.trust_services_validated
        inst.status = "activated" if inst.activated else inst.status
        s.flush()
        return {
            "activation_attestation": {
                "country": att.country,
                "legal_review": att.legal_review,
                "hosting_approved": att.hosting_approved,
                "trust_services_validated": att.trust_services_validated,
                "issued_at": att.issued_at.isoformat(),
                "not_after": att.not_after.isoformat(),
                "signature": att.signature,
            }
        }


@app.delete("/v1/instances/{instance_id}/attestations", tags=["attestations"])
def revoke_attestation(instance_id: str, _: None = Depends(_admin)) -> dict:
    with session_scope() as s:
        inst = s.get(Instance, instance_id)
        if inst is None:
            raise HTTPException(404, "instance not found")
        for att in s.query(Attestation).filter_by(instance_id=instance_id, revoked=False):
            att.revoked = True
            att.revoked_at = datetime.now(timezone.utc)
        inst.activated = False
        inst.status = "revoked"
        return {"status": "revoked"}


# ---------------------------------------------------------------------------
# Manifest — signed config/software distribution
# ---------------------------------------------------------------------------

class ManifestRequest(BaseModel):
    version: str
    not_before: datetime | None = None
    config_overlay: dict = {}
    artifacts: list = []


@app.post("/v1/instances/{instance_id}/manifest", status_code=201, tags=["manifest"])
def publish_manifest(
    instance_id: str,
    req: ManifestRequest,
    _: None = Depends(_admin),
) -> dict:
    with session_scope() as s:
        inst = s.get(Instance, instance_id)
        if inst is None:
            raise HTTPException(404, "instance not found")
        nb = req.not_before or datetime.now(timezone.utc)
        m = Manifest(
            instance_id=instance_id,
            version=req.version,
            not_before=nb,
            config_overlay=req.config_overlay,
            artifacts=req.artifacts,
            signature=crypto.sign_manifest(
                req.version, nb.isoformat(), req.config_overlay, req.artifacts
            ),
        )
        s.add(m)
        s.flush()
        return {"manifest_id": m.id}


@app.get("/v1/instances/{instance_id}/manifest", tags=["manifest"])
def get_manifest(
    instance_id: str,
    inst: Instance = Depends(current_instance),
) -> dict:
    if inst.id != instance_id:
        raise HTTPException(403, "instance mismatch")
    with session_scope() as s:
        m = (
            s.query(Manifest)
            .filter_by(instance_id=instance_id)
            .order_by(Manifest.id.desc())
            .first()
        )
        if m is None:
            raise HTTPException(404, "no manifest")
        # SQLite strips tzinfo — the signature was computed over the
        # timezone-aware ISO string, so re-attach it before returning.
        nb = m.not_before
        if nb.tzinfo is None:
            nb = nb.replace(tzinfo=timezone.utc)
        return {
            "version": m.version,
            "not_before": nb.isoformat(),
            "config_overlay": m.config_overlay,
            "artifacts": m.artifacts,
            "signature": m.signature,
        }
