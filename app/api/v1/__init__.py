from fastapi import APIRouter

from app.api.v1 import auth, sessions, tenants, verification

api_router = APIRouter(prefix="/v1")
api_router.include_router(auth.router)
api_router.include_router(tenants.router)
api_router.include_router(sessions.router)
api_router.include_router(verification.router)

__all__ = ["api_router"]
