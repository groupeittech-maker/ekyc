from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.api.v1 import api_router
from app.core.config import settings
from app.db.base import Base
from app.db.session import engine
from app.engines.policy import FLOWS

logging.basicConfig(level=logging.INFO)
templates = Jinja2Templates(directory="app/web/templates")


def _production_readiness_checks() -> None:
    """Boot-time fail-closed checks that need runtime resources (models, keys).

    The in-house face provider degrading to heuristic liveness would silently
    weaken spoof resistance — production refuses to boot without the
    anti-spoofing model.
    """
    if settings.face_provider == "inhouse":
        from app.engines.providers.antispoof import AntiSpoofProvider

        AntiSpoofProvider()  # raises if the model is missing or fails integrity


@asynccontextmanager
async def lifespan(_app: FastAPI):
    import app.models  # noqa: F401 - register the mappers before create_all
    from app.core.config import validate_production_settings

    validate_production_settings()  # fail fast on dev-grade secrets in prod
    if settings.environment == "production":
        _production_readiness_checks()
    else:
        # Production schema changes go through Alembic migrations.
        Base.metadata.create_all(bind=engine)
    yield


def _docs_enabled() -> bool:
    """Swagger/OpenAPI schema is dev tooling — in production it would hand
    the full API surface (endpoints, payloads, admin hints) to anyone."""
    return settings.environment != "production"


app = FastAPI(
    title="Trusdy eKYC",
    description="Plateforme de confiance numerique: eKYC, signature electronique, preuve.",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if _docs_enabled() else None,
)
app.include_router(api_router)


@app.get("/", include_in_schema=False)
def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/docs" if _docs_enabled() else "/health", status_code=302)


@app.get("/health", tags=["ops"])
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "environment": settings.environment,
        "flows": sorted(FLOWS),
    }


@app.get("/verify/{session_id}", response_class=HTMLResponse, tags=["verification"])
def verification_ui(
    request: Request, session_id: str, token: str = "", transfer: str = ""
) -> HTMLResponse:
    """Hosted verification interface opened by the end-user.

    ``token`` is the session bearer (scrubbed from the URL client-side);
    ``transfer`` is a one-time handoff code exchanged for a fresh bearer.
    """
    return templates.TemplateResponse(
        request=request,
        name="verify.html",
        context={"session_id": session_id, "token": token, "transfer": transfer},
    )
