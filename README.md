# WebLock — Adaptive Cyber Defense & Digital Forensics Platform

Enterprise-oriented security platform: endpoint telemetry → detection →
correlation → risk → incidents → forensics → AI-assisted analysis →
controlled response → SOC control center.

## Status: Phase 2 complete (normalization + detection foundation)

| Area | State |
|---|---|
| Backend API (`weblock-api/app`, `/v1`) | **Implemented + tested (105 tests)** |
| PostgreSQL + Alembic (`0006_contextual_risk`) | **Implemented (21 tables)** |
| Auth (JWT access/refresh, RBAC, org isolation) | **Implemented** |
| Login risk → incidents → evidence → audit | **Implemented** |
| Windows agent (`weblock-agent/`, 18 tests, live-verified) | **Implemented — Phase 1** |
| Telemetry pipeline + normalization + dispatcher | **Implemented — Phase 2** |
| Production detection (8 rules, admin control, lifecycle) | **Implemented — Phase 3** |
| Event correlation (clusters, score, timeline) | **Implemented — Phase 4** |
| Contextual risk (0–100, factors, history) | **Implemented — Phase 5** |
| Adaptive risk + incidents planned — Phases 5–6 | Incidents planned — Phase 6 |
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
- Detection registry empty until Phase 3 (dispatcher + tables ready, no fake threats).
- Notifications stubbed; no real EDR/driver claims.
- Previous leaked secrets rotated; old values must be treated as compromised.
