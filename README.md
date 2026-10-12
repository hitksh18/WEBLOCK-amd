# WebLock — Adaptive Cyber Defense & Digital Forensics Platform

Enterprise-oriented security platform: endpoint telemetry → detection →
correlation → risk → incidents → forensics → AI-assisted analysis →
controlled response → SOC control center.

## Status: Phase 0 complete (backend foundation)

| Area | State |
|---|---|
| Backend API (`weblock-api/app`, `/v1`) | **Implemented + tested (20 tests)** |
| PostgreSQL + Alembic (`0001_phase0_baseline`) | **Implemented** |
| Auth (JWT access/refresh, RBAC, org isolation) | **Implemented** |
| Login risk → incidents → evidence → audit | **Implemented** |
| Windows agent (`weblock-agent/`) | Planned — Phase 1 |
| Telemetry pipeline | Planned — Phase 2 |
| Detection / correlation / adaptive risk | Planned — Phases 3–5 |
| Forensics reports, MITRE, AI analyst, response | Planned — Phases 6–10 |
| Dashboard (`weblock-dashboard/`) | Planned — Phases 12–15 (empty scaffold today) |
| `weblock-ai/`, `weblock-forensics/`, `weblock-compliance/`, `weblock-sdk/` | Empty scaffolds, planned Phases 7–9 |

No fake features: anything marked Planned does not exist yet.

## Quick start (Phase 0)

See `weblock-api/README.md`. In short:

```powershell
psql -U postgres -c "CREATE DATABASE weblock;"
copy weblock-api\.env.example weblock-api\.env   # then fill secrets
D:\weblock\venv\Scripts\python.exe -m pip install -r weblock-api\requirements.txt
D:\weblock\venv\Scripts\python.exe -m alembic upgrade head      # run in weblock-api/
D:\weblock\venv\Scripts\python.exe -m app.seed --admin-email admin@abccorp.com
D:\weblock\venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
D:\weblock\venv\Scripts\python.exe -m pytest tests/
```

## Roadmap

Phase 0 foundation → 1 agent → 2 telemetry → 3 detection → 4 correlation →
5 risk → 6 incidents → 7 forensics → 8 ATT&CK → 9 AI → 10 response →
11 endpoints → 12–15 dashboard/admin → 16 reports → 17 hardening →
18 perf → 19 tests → 20 demo → 21 deploy → 22 docs → 23 YUKTI readiness.

## Known limitations (honest)

- Single-server monolith; in-memory login rate limiter (Redis needed to scale).
- Login-centric until telemetry pipeline lands (Phase 2).
- Notifications stubbed; no real EDR/driver claims.
- Previous leaked secrets rotated; old values must be treated as compromised.
