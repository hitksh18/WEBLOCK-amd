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

## Implemented (Phase 2 — NEW)

- **Pipeline**: `POST /v1/telemetry/batch` now runs
  RECEIVE→AUTH→VALIDATE→DEDUP→PERSIST RAW→NORMALIZE→CLASSIFY→DISPATCH→STATUS
  (`app/services/ingest.py`). Response contract unchanged from Phase 1.
- **Raw preservation**: `telemetry_events` gains processing metadata
  (`processing_status` RECEIVED|NORMALIZED|PROCESSED|FAILED, `event_category`,
  `normalization_version`, `processing_error`, `normalized_at`); payloads never mutated.
- **Normalized events** (`security_events`): category/subtype/severity_hint,
  actor/host/process/network facets + attributes JSON + `telemetry_ref` FK.
  Taxonomy: AUTHENTICATION (LOGON_SUCCESS/FAILURE/LOGOFF/PRIVILEGED_LOGON/
  SESSION_SNAPSHOT), IDENTITY (ACCOUNT_CREATED), PROCESS (SNAPSHOT), NETWORK
  (CONNECTION_ROLLUP), SYSTEM (STATUS/SERVICE_SNAPSHOT), USB
  (VOLUME_SNAPSHOT/DEVICE_CHANGE), AGENT (HEARTBEAT/COLLECTOR_STATUS).
- **Detection foundation**: `DetectionRule`/`Detection` tables, rule Protocol +
  `dispatch_event()` dispatcher (idempotent via unique constraint),
  `reprocess_failed()` retry. Production registry intentionally empty until
  Phase 3; `TEST-MARKER` is test-only, never seeded in production.
- **Login adapter** (`app/services/login_adapter.py`): normalized auth events →
  risk-engine input shape; `/v1/analyze-login` retained unchanged as
  compatibility endpoint (Phase 0 scores untouched).
- **Query APIs**: `GET /v1/events` (endpoint/category/type/severity/actor/time/
  search + pagination), `GET /v1/endpoints/{id}/events` (chronological timeline),
  `GET /v1/detections` — all org-scoped.
- **Retention**: `python -m app.retention --days N [--apply]` (dry-run default,
  refuses <7d, never touches evidence/incidents/audit).

## Implemented (Phase 3 — NEW)

- **Production rules** (`app/services/rules.py`, 8 seeded globally via
  `python -m app.seed_rules`): AUTH-01 brute-force (HIGH, T1110),
  AUTH-02 off-hours (MEDIUM), DEV-01 first-auth-from-endpoint (MEDIUM),
  PROC-01 suspicious PowerShell (HIGH, T1059.001), PROC-02 Office→shell
  (HIGH, T1059), NET-01 external sensitive-port (MEDIUM), SYS-01 privileged
  logon 4672 (MEDIUM), USB-01 new device (LOW). No MITRE where unjustified.
- **Rule admin**: `GET /v1/rules` (any user), `PUT /v1/admin/rules/{id}`
  (admin only, org-override rows, param-type validation, audited).
- **Detection lifecycle**: `POST /v1/detections/{id}/status`
  (open/acknowledged/resolved/false_positive; analyst+; audited).
- **Detection filters**: severity/status/rule/endpoint/time-range/category;
  output includes explanation, confidence, mitre, event references.
- Migration `0004_fix_detections_meta`; drift-guard test
  (`test_migrations.py`) compares migrated schema vs models on scratch DB.

## Implemented (Phase 4 — NEW)

- **Correlation engine** (`app/services/correlate.py`): `process_detection()`
  hooked from detection dispatch (same transaction, failure-isolated).
  No cluster for isolated/single-family detections; new cluster when ≥2
  detections across ≥2 rule families share endpoint + 30-min window
  (`CORRELATION_WINDOW_SECONDS`, bidirectional for backfill).
- **Score/severity** (deterministic, documented in code): 20 + 15/family
  (max +60) + severity weight + proximity + actor bonus, clamped 0–100;
  CRITICAL iff ≥3 families with HIGH+, else HIGH/MEDIUM/LOW table.
- **Explanations** use "observed sequence" wording; timeline有序 via members.
- **APIs**: `GET /v1/correlations` (endpoint/severity/status/family/time),
  `GET /v1/correlations/{id}` (metadata + chronological timeline with
  detection→event→telemetry refs), `POST …/close` (analyst+, audited),
  `POST /v1/admin/correlations/expire` (admin, >2 windows stale).
- Migration `0005_correlation` (`correlation_clusters` + members table).

## Implemented (Phase 6 — NEW)

- **Incident engine** (`app/services/incidents.py`): auto-incident from OPEN
  HIGH/CRITICAL clusters with endpoint risk ≥ `INCIDENT_MIN_RISK` (60);
  manual analyst creation from any open cluster; idempotent per cluster
  (app check + partial unique index); incidents re-sync title/summary/risk
  as their cluster grows; shared `next_incident_key()` (INC-YYYY-NNNN).
- **APIs**: `POST /v1/correlations/{id}/incident` (analyst+), incident list
  += severity/endpoint/pagination filters, detail += correlation block
  (cluster + ordered detections + event refs) and risk block (snapshot).
  user_id stays NULL (no identity binding yet — documented).
- Migration `0007_incident_engine` (correlation_id/risk_snapshot_id FKs).

## Implemented (Phase 7 — NEW)

- **Hash chain**: `telemetry_events` gains `prev_hash`/`chain_seq` (unique per
  endpoint) + `hash_algorithm`. New rows: `sha256-canonical-v1` (server
  UTC-canonical, fully recomputable); pre-Phase-7 rows: `sha256-received-v1`
  (linkage-only, labeled LEGACY). Backfilled per endpoint by migration.
- **Verification**: `POST /v1/endpoints/{id}/integrity/verify` (7-day window
  cap) and `GET /v1/incidents/{id}/integrity`; detects payload/hash edits,
  prev-link breaks, sequence gaps; read-only; "cryptographic integrity
  verification" (no tamper-proof/legal claims).
- **Evidence**: extended table (nullable incident, correlation ref, source
  types TELEMETRY/SECURITY/DETECTION/CORRELATION/INCIDENT/LOGIN only),
  collect/verify endpoints, integrity statuses, audited views/exports.
- **Custody**: hash-chained COLLECTED/STORED/VIEWED/VERIFIED/EXPORTED/
  UPDATED_METADATA records (DB CHECK), chain verify endpoint.
- **Snapshots**: immutable incident reference-graph snapshots (hash).
- **Timeline**: `GET /v1/incidents/{id}/timeline` (telemetry→custody,
  deterministic order, paginated).
- **Reports**: versioned JSON + PDF (reportlab) with SHA-256, immutable files
  under `reports/`, download + verify endpoints. Migration `0008_forensics`.

## Implemented (Phase 8 — NEW)

- **Response engine** (`app/services/response.py` + `response_policy.py`):
  allowlisted actions (ISOLATE/RESTORE/TERMINATE/BLOCK/UNBLOCK/DISABLE/
  COLLECT), SIMULATION (explicit, never touches endpoint) vs LIVE,
  deterministic RBAC policy matrix (admin all; analyst all-but-disable;
  investigator COLLECT-only live; viewer read-only), target validation
  (PID/IP/port/collection enums; loopback rejected), idempotency keys,
  attempt budgets, TTLs, expire sweeper. Fail-closed everywhere.
- **Command plane** (existing agent trust channel, no second channel):
  heartbeat piggybacks peek-only pending list; explicit pull marks
  DELIVERED/ACCEPTED; result posts close the loop; DELIVERED re-delivery
  + agent ledger prevent duplicates and strand-recovery.
- **APIs**: request/list/get/cancel/retry response actions, capabilities,
  pending pull, result post. Isolation state syncs to endpoint.status.
  Response lifecycle appears in the forensic timeline (audit-backed).
- Agent 1.1.0 executes terminate/block/isolate/collect for real
  (elevation-gated firewall work; DISABLE_SESSION honestly NOT_AVAILABLE).
  Migration `0009_response`. NO arbitrary remote execution exists.

## Implemented (Phase 9 — NEW)

- **AI analyst** (`services/ai_providers.py` + `ai_context.py` +
  `ai_analysis.py`): provider abstraction (OpenAI-compatible HTTPS, no new
  deps; MockProvider test-only), deterministic bounded incident context
  (detections/events/evidence/integrity/response/timeline, truncation
  flagged, SHA-256 context hash, zero secrets), strict output schema
  (facts/inferences/recommendations/unknowns + MITRE), reference validation
  against live org records (hallucinated IDs reject the analysis),
  versioned immutable `ai_analyses`, rate limits (quota/refresh/output),
  honest AI_UNAVAILABLE when unconfigured. Prompt structure separates
  trusted instructions from untrusted data (injection documented, not
  claimed solved). AI advises only — zero execution path to Phase 8.
- **APIs**: request/list/get/refresh analyses, ai-context preview; timeline
  carries AI_ANALYSIS_* events. Migration `0010_ai_analyses`.

## Implemented (Phase 5 — NEW)

- **Contextual risk** (`app/services/risk.py`): endpoint score 0–100 from
  open clusters + 24h detections + endpoint novelty. Factor budget:
  correlation (strongest conf×0.4 ≤32, +4/extra ≤8), HIGH×9 (≤18),
  families 5extra (≤10), recency 10/7/4/2, volume 0/3/5/7, repeat +5,
  novel +4. Severity LOW<30/MEDIUM<60/HIGH<80/CRITICAL. No ML, no user
  profiling (no identity binding yet — documented).
- **APIs**: `GET /v1/endpoints/{id}/risk` (compute + snapshot-on-change),
  `GET …/risk/history`. Migration `0006_contextual_risk` (`risk_snapshots`).

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
