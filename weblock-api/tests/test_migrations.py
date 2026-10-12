"""Migration drift guard: alembic head on a scratch DB must match models.

Catches exactly the class of bug where a migration creates a column name
that differs from the SQLAlchemy model (e.g. meta_data vs metadata).
"""
import os

import psycopg
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect
from sqlalchemy.pool import NullPool

from app.db.database import Base
import app.db.models  # noqa: F401  (register tables)

SCRATCH_DB = "weblock_migcheck"
ADMIN_CONN = "host=localhost dbname=postgres user=postgres password=18022005"
SCRATCH_URL = ("postgresql+psycopg://postgres:18022005"
               "@localhost:5432/weblock_migcheck")


def _alembic_cfg(url: str) -> Config:
    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    cfg.set_main_option("script_location",
                        os.path.join(os.path.dirname(__file__), "..", "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_migrations_match_models():
    with psycopg.connect(ADMIN_CONN, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {SCRATCH_DB}")
        conn.execute(f"CREATE DATABASE {SCRATCH_DB}")
    try:
        command.upgrade(_alembic_cfg(SCRATCH_URL), "head")
        eng = create_engine(SCRATCH_URL, poolclass=NullPool)
        try:
            insp = inspect(eng)
            problems: list[str] = []
            for table in Base.metadata.sorted_tables:
                if table.name == "alembic_version":
                    continue
                db_cols = {c["name"] for c in insp.get_columns(table.name)}
                model_cols = set(table.c.keys())
                if db_cols != model_cols:
                    problems.append(
                        f"{table.name}: db={sorted(db_cols)} model={sorted(model_cols)}")
            assert not problems, problems
        finally:
            eng.dispose()
    finally:
        with psycopg.connect(ADMIN_CONN, autocommit=True) as conn:
            conn.execute(f"DROP DATABASE IF EXISTS {SCRATCH_DB}")
