"""Admin operations: tenant provisioning + platform storage monitoring."""

from __future__ import annotations

import shutil
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from app.api.deps import DbSession, require_admin
from app.core.config import settings
from app.db.base import utcnow
from app.models.document import Artifact
from app.models.tenant import Tenant
from app.services.retention import purge_expired_sessions
from app.services.storage import vault_configs

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])


def _local_vault_root(profile: str) -> str | None:
    """Filesystem root for local vaults — for free-space reporting."""
    if profile == "default":
        return settings.storage_root if settings.storage_backend == "local" else None
    cfg = vault_configs().get(profile)
    if cfg and cfg.get("backend", "local") == "local":
        return cfg.get("root")
    return None


@router.post("/purge")
def purge_now(db: DbSession) -> dict[str, Any]:
    """Manually trigger the retention purge (the Celery beat job runs it
    nightly). Returns the deletion report; blob failures surface in
    ``artifacts_failed`` and stay eligible for the next run."""
    report = purge_expired_sessions(db)
    db.commit()
    return report


@router.get("/storage")
def storage_report(db: DbSession) -> dict[str, Any]:
    """Archive usage per vault and per tenant — the ops view of vault routing.

    Counts/bytes come from the artifacts table (authoritative registry);
    local vaults additionally report filesystem free space.
    """
    rows = db.execute(
        select(
            Artifact.vault_profile,
            Artifact.kind,
            Artifact.tenant_id,
            func.count(),
            func.coalesce(func.sum(Artifact.size_bytes), 0),
        ).group_by(Artifact.vault_profile, Artifact.kind, Artifact.tenant_id)
    ).all()

    vaults: dict[str, dict[str, Any]] = {}
    tenants: dict[str, dict[str, Any]] = {}
    for profile, kind, tenant_id, count, size in rows:
        v = vaults.setdefault(profile, {"artifacts": 0, "bytes": 0, "kinds": {}})
        v["artifacts"] += count
        v["bytes"] += size
        v["kinds"][kind] = v["kinds"].get(kind, 0) + count
        t = tenants.setdefault(tenant_id, {"artifacts": 0, "bytes": 0, "by_vault": {}})
        t["artifacts"] += count
        t["bytes"] += size
        tv = t["by_vault"].setdefault(profile, {"artifacts": 0, "bytes": 0})
        tv["artifacts"] += count
        tv["bytes"] += size

    # Configured vaults report even with zero artifacts; local ones get disk stats.
    for name in ["default", *sorted(vault_configs())]:
        vaults.setdefault(name, {"artifacts": 0, "bytes": 0, "kinds": {}})
        root = _local_vault_root(name)
        if root:
            try:
                usage = shutil.disk_usage(root)
                vaults[name]["disk"] = {
                    "root": root,
                    "free_bytes": usage.free,
                    "total_bytes": usage.total,
                }
            except OSError:
                vaults[name]["disk"] = {"root": root, "error": "not reachable"}

    names = {
        t.id: t.name
        for t in db.scalars(select(Tenant).where(Tenant.id.in_(list(tenants) or ["_"]))).all()
    }
    tenant_list = [
        {"tenant_id": tid, "tenant_name": names.get(tid), **stats} for tid, stats in tenants.items()
    ]
    return {
        "checked_at": utcnow().isoformat(),
        "totals": {
            "artifacts": sum(v["artifacts"] for v in vaults.values()),
            "bytes": sum(v["bytes"] for v in vaults.values()),
        },
        "vaults": vaults,
        "tenants": sorted(tenant_list, key=lambda t: -t["bytes"]),
    }
