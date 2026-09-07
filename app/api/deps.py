from __future__ import annotations

from typing import Annotated

import jwt
from fastapi import Depends, Header, HTTPException, Path, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import decode_access_token, verify_secret
from app.db.session import get_db
from app.models.session import KycSession
from app.models.tenant import Tenant
from app.services import kyc

DbSession = Annotated[Session, Depends(get_db)]


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    return authorization.split(" ", 1)[1].strip()


def get_current_tenant(
    db: DbSession, authorization: Annotated[str | None, Header()] = None
) -> Tenant:
    token = _bearer(authorization)
    try:
        claims = decode_access_token(token)
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token") from exc

    tenant = db.get(Tenant, claims.get("sub", ""))
    if tenant is None or not tenant.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown tenant")
    return tenant


CurrentTenant = Annotated[Tenant, Depends(get_current_tenant)]


def require_admin(x_admin_key: Annotated[str | None, Header()] = None) -> None:
    if x_admin_key != settings.admin_api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid admin key")


def get_tenant_session(session_id: Annotated[str, Path()], db: DbSession, tenant: CurrentTenant):
    session = db.get(KycSession, session_id)
    if session is None or session.tenant_id != tenant.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    return session


def get_verification_session(
    session_id: Annotated[str, Path()],
    db: DbSession,
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> KycSession:
    """Session-scoped auth for the end-user verification UI."""
    token = _bearer(authorization)
    session = db.get(KycSession, session_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found")
    if not verify_secret(token, session.access_token_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid session token")
    request.state.session_id = session.id
    return session


def require_open(session: KycSession) -> None:
    """Guard for steps that mutate a session; reading its state stays allowed."""
    try:
        kyc.ensure_active(session)
    except kyc.SessionExpiredError as exc:
        raise HTTPException(status.HTTP_410_GONE, "Session expired") from exc
    except kyc.SessionClosedError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


def client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None
