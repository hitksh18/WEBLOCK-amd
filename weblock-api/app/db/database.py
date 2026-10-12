"""SQLAlchemy 2.x declarative base + engine/session. Single DB architecture."""
import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings

logger = logging.getLogger("weblock.db")


class Base(DeclarativeBase):
    pass


def _engine_kwargs() -> dict:
    # Never echo SQL in production (would leak parameters into logs).
    return {"echo": not settings.is_production and settings.LOG_LEVEL == "DEBUG"}


engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True, **_engine_kwargs())
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
