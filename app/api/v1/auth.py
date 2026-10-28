from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app.api.deps import DbSession, client_ip
from app.core.security import create_access_token, verify_secret
from app.engines import ratelimit
from app.models.tenant import Tenant
from app.schemas import TokenRequest, TokenResponse

router = APIRouter(prefix="/oauth", tags=["auth"])

_OAUTH_WINDOW_S = 600  # 10 min sliding window
_OAUTH_MAX_FAILS = 10


def _deny_too_many(client_id: str, ip: str | None) -> None:
    """Brute-force guard on token issuance: 10 requests / 10 min per
    client_id, 50 / 10 min per source IP (a rotating client_id spray hits
    the IP cap). Each call counts — a legit client fetches a token roughly
    once per 30 min."""
    if ratelimit.hit(f"oauth:fail:cid:{client_id}", _OAUTH_WINDOW_S) > _OAUTH_MAX_FAILS:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts")
    if ip and ratelimit.hit(f"oauth:fail:ip:{ip}", _OAUTH_WINDOW_S) > _OAUTH_MAX_FAILS * 5:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts")


@router.post("/token", response_model=TokenResponse)
def issue_token(payload: TokenRequest, request: Request, db: DbSession) -> TokenResponse:
    _deny_too_many(payload.client_id, client_ip(request))
    tenant = db.scalars(select(Tenant).where(Tenant.client_id == payload.client_id)).first()
    if (
        tenant is None
        or not tenant.active
        or not verify_secret(payload.client_secret, tenant.client_secret_hash)
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid client credentials")

    token, ttl = create_access_token(tenant.id)
    return TokenResponse(access_token=token, expires_in=ttl)
