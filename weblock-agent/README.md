# WebLock Windows Endpoint Agent — Phase 1

Real telemetry collection. **No response actions, no process killing, no drivers.**
Production target is Windows; collectors degrade gracefully elsewhere.

## What it does

1. **Enroll** once with a one-time token → persistent `agent_id` + API key
   (DPAPI-encrypted at rest on Windows).
2. **Collect** every cycle: identity, processes, network connections, Windows
   Security events (4624/4625/4634…), system health, USB volumes.
3. **Queue** every event in local SQLite outbox (survives offline/restart).
4. **Upload** batches to `POST /v1/telemetry/batch` with retry + server dedup.
5. **Heartbeat** `POST /v1/endpoints/{id}/heartbeat`; pull server config
   `GET …/config` (intervals, collector toggles, log level, retention).

## Install

```powershell
D:\weblock\venv\Scripts\python.exe -m pip install -r requirements.txt
$env:PYTHONPATH = "D:\weblock\weblock-agent"   # or pip install -e .
```

## Enroll + run (needs API at --server)

```powershell
# 1. Admin mints a one-time token (24h, single-use):
#    POST /v1/admin/enrollment-tokens {"label":"pc-01"}  (admin JWT)

# 2. Enroll + single cycle (lab):
python -m weblock_agent.main --server http://localhost:8000 `
  --workdir "$env:USERPROFILE\.weblock-agent" --enroll wle_... --once

# 3. Continuous (60s default, configurable by server):
python -m weblock_agent.main --server http://localhost:8000 --once:$false
```

`--no-verify` is **dev-only** (plain-http lab). Production requires HTTPS;
the agent never disables cert validation by default.

## Windows service (elevated PowerShell)

```powershell
setx WEBLOCK_SERVER "https://weblock.local:8000"
setx WEBLOCK_ENROLL_TOKEN "wle_..."   # first run only; then delete it
python -m weblock_agent.service --startup auto install
python -m weblock_agent.service start
# logs: Windows Event Viewer → Application, or console when run manually
```

Service stop is graceful (finishes the current cycle, keeps the outbox).

## Windows limitations (honest)

- **Security event log needs elevation**: reading `Security` requires
  SeSecurityPrivilege. Unelevated, the collector emits a `collector_status`
  error event — never fabricated logons. Run elevated for 4624/4625/4634.
- USB is poll-based snapshots; insert/remove between polls can be missed.
- Credential store is DPAPI user-scope: re-enroll if the agent user profile
  changes. File-permission fallback (with warning) on non-Windows lab hosts.

## Files

`weblock_agent/{main,config,identity,outbox,client}.py`,
`collectors/{identity,processes,network,windows_events,system,usb}.py`,
`models/telemetry.py` (envelope v1.0), `security/store.py` (DPAPI),
`service.py`. Tests: `tests/test_agent.py` (18 tests, live-Windows verified).

## Troubleshooting

- `Not enrolled` → pass `--enroll` once; check token unused/unexpired.
- `401` on upload → endpoint revoked (admin) — re-enroll with a new token.
- `pending` grows → server down; outbox drains automatically on reconnect.
- No `eventlog` events → run elevated; check `eventlog.bookmark` in workdir.
