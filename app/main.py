from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.api.v1 import api_router
from app.core.config import settings
from app.db.base import Base
from app.db.session import engine
from app.engines.policy import FLOWS

logging.basicConfig(level=logging.INFO)
templates = Jinja2Templates(directory="app/web/templates")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    import app.models  # noqa: F401 - register the mappers before create_all

    if settings.environment != "production":
        # Production schema changes go through Alembic migrations.
        Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="IT-TECH eKYC",
    description="Plateforme de confiance numerique: eKYC, signature electronique, preuve.",
    version="0.1.0",
    lifespan=lifespan,
)
app.include_router(api_router)


@app.get("/health", tags=["ops"])
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "environment": settings.environment,
        "flows": sorted(FLOWS),
    }


@app.get("/verify/{session_id}", response_class=HTMLResponse, tags=["verification"])
def verification_ui(request: Request, session_id: str, token: str = "") -> HTMLResponse:
    """Hosted verification interface opened by the end-user."""
    return templates.TemplateResponse(
        request=request,
        name="verify.html",
        context={"session_id": session_id, "token": token},
    )
