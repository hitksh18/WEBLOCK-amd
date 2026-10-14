# WebLock SOC Dashboard (Phase 10)

React 18 + TypeScript + Vite. **No fabricated security data**: every number
comes from the backend; empty API responses render as explicit empty states.

## Develop

```powershell
copy .env.example .env   # VITE_API_BASE_URL=http://localhost:8000
npm install
npm run dev              # http://localhost:5173
```

Backend needs `CORS_ORIGINS=http://localhost:5173` (see `weblock-api/.env.example`).

## Build / test

```powershell
npm run build    # tsc + vite build -> dist/
npm test         # vitest (mocked fetch; mocks live ONLY in tests)
```

## Architecture

- `src/api.ts` — sole API layer (base URL, JWT, timeout, typed endpoints).
- `src/auth.tsx` — session (JWT in sessionStorage), role helpers.
  Frontend RBAC is UX-only; the backend remains authoritative.
- `src/ui.tsx` — shell, badges, loading/error/empty states, `useApi` hook
  (independent per-widget loading; 60s visibility-aware polling on Overview).
- `src/pages/` — Overview, Incidents, IncidentDetail (9 tabs), Detections,
  Correlations, Endpoints (+detail), Response, AI, Reports, Audit.
- AI output is untrusted: rendered as plain text only, never HTML.
- PDF downloads use authenticated fetch→blob (the backend requires JWT).

## Deployment

Serve `dist/` statically; set `VITE_API_BASE_URL` at build time to the API
origin and add the dashboard origin to backend `CORS_ORIGINS`. No secrets
in the bundle (only the API base URL).

## Limitations

- No WebSocket/SSE in the backend → polling for overview freshness.
- Incident list is capped at 100 (backend default); severity distribution
  is labeled with its scope.
- Detection-rules administration has no UI yet (backend API exists).
- Correlations link outward to incidents; no standalone correlation detail
  page (backend detail endpoint exists and is used via incident views).
