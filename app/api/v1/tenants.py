from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import DbSession, require_admin
from app.core.ids import new_client_id, new_secret
from app.core.security import hash_secret
from app.engines.policy import FLOWS
from app.models.tenant import Tenant
from app.schemas import TenantCreateRequest, TenantCredentialsResponse

router = APIRouter(prefix="/admin/tenants", tags=["admin"], dependencies=[Depends(require_admin)])


@router.post("", response_model=TenantCredentialsResponse, status_code=status.HTTP_201_CREATED)
def create_tenant(payload: TenantCreateRequest, db: DbSession) -> TenantCredentialsResponse:
    unknown = [flow for flow in payload.allowed_flows if flow not in FLOWS]
    if unknown:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown flows: {', '.join(unknown)}")

    client_id = new_client_id()
    client_secret = new_secret("sk")
    webhook_secret = new_secret("whsec") if payload.webhook_url else None

    tenant = Tenant(
        name=payload.name,
        client_id=client_id,
        client_secret_hash=hash_secret(client_secret),
        webhook_url=payload.webhook_url,
        webhook_secret=webhook_secret,
        allowed_flows=payload.allowed_flows,
        branding=payload.branding,
        retention_days=payload.retention_days,
    )
    db.add(tenant)
    db.commit()

    # Secrets are returned once, at creation: only their hash is stored.
    return TenantCredentialsResponse(
        tenant_id=tenant.id,
        name=tenant.name,
        client_id=client_id,
        client_secret=client_secret,
        webhook_secret=webhook_secret,
    )
