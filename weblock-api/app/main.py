"""WebLock API - Phase 0 modular monolith (FastAPI + SQLAlchemy 2.x)."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.api.v1 import admin, auth, correlations, endpoints, events, health, incidents, login, risk, rules, telemetry
from app.core.config import settings

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("weblock")


@asynccontextmanager
async def lifespan(application: FastAPI):
    for problem in settings.validate_secrets():
        logger.warning("config: %s", problem)
    yield


def create_app() -> FastAPI:
    application = FastAPI(
        title="WebLock API",
        version=settings.APP_VERSION,
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url=None,
    )

    @application.exception_handler(Exception)
    async def unhandled(request, exc):  # noqa: ANN001, ANN202
        # Safe error responses: never leak stack traces to clients.
        logger.exception("unhandled error: %s", exc)
        return JSONResponse(status_code=500, content={"detail": "Internal error"})

    application.include_router(health.router, prefix="/v1")
    application.include_router(auth.router, prefix="/v1")
    application.include_router(login.router, prefix="/v1")
    application.include_router(admin.router, prefix="/v1")
    application.include_router(endpoints.router, prefix="/v1")
    application.include_router(telemetry.router, prefix="/v1")
    application.include_router(events.router, prefix="/v1")
    application.include_router(rules.router, prefix="/v1")
    application.include_router(correlations.router, prefix="/v1")
    application.include_router(risk.router, prefix="/v1")
    application.include_router(incidents.router, prefix="/v1")

    @application.get("/")
    def root():
        return {"status": "WebLock API Running", "version": settings.APP_VERSION}

    return application


app = create_app()
