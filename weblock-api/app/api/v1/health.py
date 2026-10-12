"""GET /v1/health - no secrets, DB ping with latency."""
import logging
import time

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import get_db
from app.schemas.common import HealthOut

logger = logging.getLogger("weblock.health")
router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthOut)
def health(db: Session = Depends(get_db)):
    started = time.perf_counter()
    try:
        db.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception:
        logger.exception("health db ping failed")
        db_status = "error"
    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    return HealthOut(
        application="weblock-api",
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        database=db_status,
        database_latency_ms=latency_ms,
    )
