# WebLock API — Phase 1 (Foundation + Endpoint Telemetry)

Modular FastAPI monolith. PostgreSQL + SQLAlchemy 2.x + Alembic.

## Implemented (Phase 0)

- `GET /v1/health` — app + DB status (no secrets)
- `POST /v1/auth/login` — JWT access + refresh, rate-limited, blocked-check
- `POST /v1/auth/refresh` — rotation (old token revoked)
- `POST /v1/auth/logout` — refresh revocation
- `POST /v1/analyze-login` — policy + behavioral risk → event, assessment,
  incident + evidence when Suspicious/Intruder (temporary adapter; becomes
  telemetry adapter in Phase 2)
- `GET /v1/incidents`, `GET /v1/incidents/{id}`, `POST /v1/incidents/{id}/status`
- `GET /v1/admin/metrics`, `POST /v1/admin/unblock-user/{id}`, `GET /v1/admin/audit`
- RBAC (admin/analyst/investigator/viewer), org isolation (`org_id` on every
  tenant row), audit logs, SHA-256 evidence, login rate limiting

## Implemented (Phase 1 — NEW)

- `POST /v1/admin/enrollment-tokens` (admin) — mint one-time `wle_…` token
  (24h expiry, single-use, sha256-only storage)
- `POST /v1/endpoints/enroll` — bootstrap endpoint → `agent_id` + `wlk_…`
  API key shown ONCE
- `POST /v1/endpoints/{id}/heartbeat` (agent key; path id must match key)
- `GET /v1/endpoints/{id}/config` (agent key; server→agent config pull)
- `GET /v1/endpoints`, `GET /v1/endpoints/{id}` (user JWT, org-scoped,
  computed `presence`: healthy/offline/never-seen/isolated/revoked)
- `PUT /v1/admin/endpoints/{id}/config` (validated keys only, audited)
- `POST /v1/admin/endpoints/{id}/revoke` (revokes key, status=revoked, audited)
- `POST /v1/telemetry/batch` (agent key) — envelope validation, 500-event /
  2MB caps, per-event reject list, `(endpoint,event)` dedup, canonical
  event hash → `telemetry_events`
- Timezone-safe datetimes (`app/core/timeutil.as_utc` — fixed IST relabel bug)

## Planned (NOT built yet)

Detection rules, correlation, AI analyst, response actions, dashboard,
Docker. Agent: `weblock-agent/README.md`. See root README roadmap.

## Setup

```powershell
# 1. PostgreSQL running, database exists:
psql -U postgres -c "CREATE DATABASE weblock;"

# 2. Env (never commit .env):
copy .env.example .env
# fill DATABASE_URL, JWT_SECRET_KEY (32+ chars), JWT_REFRESH_SECRET_KEY

# 3. Install + migrate + seed (from weblock-api/):
D:\weblock\venv\Scripts\python.exe -m pip install -r requirements.txt
D:\weblock\venv\Scripts\python.exe -m alembic upgrade head
D:\weblock\venv\Scripts\python.exe -m app.seed --admin-email admin@abccorp.com

# 4. Run:
D:\weblock\venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
# docs: http://localhost:8000/docs
```

## Tests

```powershell
D:\weblock\venv\Scripts\python.exe -m pytest tests/   # uses weblock_test DB
```

## Security notes

- Secrets only from env (`app/core/config.py`). Leaked Phase-(-1) values
  (old SECRET_KEY, Gmail app-password in git history) are revoked/rotated;
  revoke the Gmail app-password in Google Account settings.
- App never returns password hashes, secrets, or tracebacks.
- Rate limit defaults: 10 attempts / 5 min per (IP, email).
