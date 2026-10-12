"""Phase 0 test harness: isolated Postgres test DB (weblock_test).

Run:  pytest -q   (from weblock-api/, with .env DATABASE_URL pointing anywhere;
       conftest overrides it to weblock_test)
"""
import os

os.environ["APP_ENV"] = "test"
os.environ["JWT_SECRET_KEY"] = "test-access-secret-0123456789abcdef"
os.environ["JWT_REFRESH_SECRET_KEY"] = "test-refresh-secret-0123456789abcdef"
os.environ["DATABASE_URL"] = "postgresql+psycopg://postgres:18022005@localhost:5432/weblock_test"
os.environ["LOGIN_RATE_LIMIT_MAX_ATTEMPTS"] = "100"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

TEST_DB_URL = os.environ["DATABASE_URL"]

import app.db.database as database  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.database import Base, get_db  # noqa: E402
from app.db.models import Organization, OrgPolicy, User  # noqa: E402
from app.main import create_app  # noqa: E402

TEST_ROLES = {
    "test_day": {
        "allowed_hours": {"start": "00:00", "end": "23:59"},
        "allowed_ip_ranges": ["0.0.0.0/0"],
        "require_registered_device": True,
    },
    "strict_day": {
        "allowed_hours": {"start": "08:00", "end": "20:00"},
        "allowed_ip_ranges": ["10.0.0.0/8"],
        "require_registered_device": True,
    },
}


def _make_org(db, slug: str, name: str) -> Organization:
    org = Organization(name=name, slug=slug)
    db.add(org)
    db.flush()
    db.add(
        OrgPolicy(
            org_id=org.id,
            allowed_countries=["India"],
            risk_threshold=75,
            roles=dict(TEST_ROLES),
            user_overrides={},
        )
    )
    db.flush()
    return org


def _make_user(db, org_id: int, email: str, role: str,
               policy_role: str = "test_day") -> User:
    user = User(
        org_id=org_id,
        email=email.lower(),
        password_hash=hash_password("Password123!"),
        role=role,
        baseline_mac="AA:BB:CC:DD:EE:01",
        baseline_country="India",
    )
    db.add(user)
    db.flush()
    pol = db.query(OrgPolicy).filter(OrgPolicy.org_id == org_id).first()
    overrides = dict(pol.user_overrides or {})
    overrides[str(user.id)] = {"role": policy_role}
    pol.user_overrides = dict(overrides)
    db.flush()
    return user


@pytest.fixture(scope="session")
def engine():
    # Ensure test database exists.
    import psycopg

    admin_url = "host=localhost dbname=postgres user=postgres password=18022005"
    with psycopg.connect(admin_url, autocommit=True) as conn:
        try:
            conn.execute("CREATE DATABASE weblock_test")
        except Exception:
            pass  # already exists
    eng = create_engine(TEST_DB_URL)
    Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def db(engine):
    connection = engine.connect()
    transaction = connection.begin()
    testing_session = sessionmaker(bind=connection)
    session = testing_session()
    try:
        yield session
    finally:
        session.close()
        try:
            transaction.rollback()
        except Exception:
            pass
        # Service code calls db.commit() inside requests, which persists past
        # the outer transaction. Truncate everything so tests stay isolated.
        with engine.begin() as conn:
            for table in reversed(Base.metadata.sorted_tables):
                conn.execute(table.delete())
        connection.close()


@pytest.fixture()
def client(db):
    application = create_app()

    def _override():
        try:
            yield db
        finally:
            pass

    application.dependency_overrides[get_db] = _override
    with TestClient(application, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture()
def org_a(db):
    org = _make_org(db, "org-a", "Org A")
    admin = _make_user(db, org.id, "admin@a.weblock.io", "admin")
    analyst = _make_user(db, org.id, "analyst@a.weblock.io", "analyst")
    viewer = _make_user(db, org.id, "viewer@a.weblock.io", "viewer")
    employee = _make_user(db, org.id, "employee@a.weblock.io", "viewer")
    db.commit()
    return {"org": org, "admin": admin, "analyst": analyst,
            "viewer": viewer, "employee": employee}


@pytest.fixture()
def org_b(db):
    org = _make_org(db, "org-b", "Org B")
    admin = _make_user(db, org.id, "admin@b.weblock.io", "admin")
    db.commit()
    return {"org": org, "admin": admin}


def login(client: TestClient, email: str, password: str = "Password123!") -> dict:
    resp = client.post("/v1/auth/login",
                       json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
