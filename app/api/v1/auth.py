from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.api.deps import DbSession
from app.core.security import create_access_token, verify_secret
from app.models.tenant import Tenant
from app.schemas import TokenRequest, TokenResponse

router = APIRouter(prefix="/oauth", tags=["auth"])


@router.post("/token", response_model=TokenResponse)
def issue_token(payload: TokenRequest, db: DbSession) -> TokenResponse:
    tenant = db.scalars(select(Tenant).where(Tenant.client_id == payload.client_id)).first()
    if (
        tenant is None
        or not tenant.active
        or not verify_secret(payload.client_secret, tenant.client_secret_hash)
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid client credentials")

    token, ttl = create_access_token(tenant.id)
    return TokenResponse(access_token=token, expires_in=ttl)
