import React, { useCallback, useEffect, useRef, useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { ApiError, api } from "./api";
import { isAdmin, useAuth } from "./auth";

/* ---------------- data hook: independent loading per widget ---------------- */

export interface ApiState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

export function useApi<T>(fn: () => Promise<T>, deps: unknown[] = []): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [nonce, setNonce] = useState(0);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const reload = useCallback(() => setNonce((n) => n + 1), []);
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fn()
      .then((result) => {
        if (!cancelled && alive.current) {
          setData(result);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled && alive.current) {
          setError(err instanceof ApiError ? err.detail : "Unexpected error");
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce, ...deps]);
  return { data, error, loading, reload };
}

/** Polling wrapper: refreshes on an interval, pauses when tab hidden. */
export function usePolling(reload: () => void, intervalMs: number): void {
  useEffect(() => {
    if (intervalMs <= 0) return;
    const tick = (): void => {
      if (document.visibilityState === "visible") reload();
    };
    const id = setInterval(tick, intervalMs);
    const onVis = (): void => {
      if (document.visibilityState === "visible") reload();
    };
    document.addEventListener("visibilitychange", onVis);
    return () => {
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [reload, intervalMs]);
}

/* ---------------- badges ---------------- */

const SEVERITY_CLASS: Record<string, string> = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
};

export function SeverityBadge({ value }: { value: string | null | undefined }): React.JSX.Element {
  const key = (value ?? "unknown").toLowerCase();
  return (
    <span className={`badge ${SEVERITY_CLASS[key] ?? "sev-unknown"}`} aria-label={`severity ${key}`}>
      {(value ?? "UNKNOWN").toUpperCase()}
    </span>
  );
}

export function StatusBadge({ value }: { value: string | null | undefined }): React.JSX.Element {
  const key = (value ?? "unknown").toLowerCase().replace(/[^a-z]/g, "-");
  return (
    <span className={`badge status-${key}`} aria-label={`status ${value ?? "unknown"}`}>
      {(value ?? "UNKNOWN").toUpperCase().replace(/_/g, " ")}
    </span>
  );
}

export function ModeBadge({ mode }: { mode: string }): React.JSX.Element {
  const live = mode === "LIVE";
  return (
    <span className={`badge ${live ? "mode-live" : "mode-sim"}`} title={live ? "Actual endpoint action requested/executed" : "Simulation only: no endpoint action was executed"}>
      {mode}
    </span>
  );
}

/* ---------------- states ---------------- */

export function Loading({ label }: { label: string }): React.JSX.Element {
  return (
    <div className="state" role="status" aria-live="polite">
      <div className="skeleton-line" style={{ width: "40%" }} />
      <div className="skeleton-line" style={{ width: "70%" }} />
      <span className="sr-only">{label}…</span>
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }): React.JSX.Element {
  return (
    <div className="state state-error" role="alert">
      <strong>Couldn’t load this section.</strong>
      <p>{message}</p>
      {onRetry ? (
        <button type="button" className="btn btn-secondary" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint?: string }): React.JSX.Element {
  return (
    <div className="state" role="status">
      <strong>{title}</strong>
      {hint ? <p className="muted">{hint}</p> : null}
    </div>
  );
}

export function Section({
  title,
  action,
  children,
}: {
  title: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}): React.JSX.Element {
  return (
    <section className="panel" aria-label={title}>
      <div className="panel-head">
        <h2>{title}</h2>
        {action}
      </div>
      <div className="panel-body">{children}</div>
    </section>
  );
}

export function QueryView<T>({
  state,
  emptyTitle,
  emptyHint,
  children,
}: {
  state: ApiState<T>;
  emptyTitle: string;
  emptyHint?: string;
  children: (data: T) => React.ReactNode;
}): React.JSX.Element {
  if (state.loading && state.data === null) return <Loading label="Loading" />;
  if (state.error && state.data === null)
    return <ErrorState message={state.error} onRetry={state.reload} />;
  if (state.data === null) return <EmptyState title={emptyTitle} hint={emptyHint} />;
  return <>{children(state.data)}</>;
}

/* ---------------- shell ---------------- */

const NAV: Array<{ to: string; label: string; adminOnly?: boolean }> = [
  { to: "/", label: "Overview" },
  { to: "/incidents", label: "Incidents" },
  { to: "/detections", label: "Detections" },
  { to: "/correlations", label: "Correlations" },
  { to: "/endpoints", label: "Endpoints" },
  { to: "/response", label: "Response" },
  { to: "/ai", label: "AI Analyst" },
  { to: "/reports", label: "Reports" },
  { to: "/audit", label: "Audit", adminOnly: true },
];

export function Shell({ children }: { children: React.ReactNode }): React.JSX.Element {
  const { session, logout } = useAuth();
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);
  const health = useApi(() => api.health(), []);
  usePolling(health.reload, 60000);

  const onLogout = (): void => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="app">
      <button
        type="button"
        className="menu-toggle"
        aria-label={menuOpen ? "Close navigation" : "Open navigation"}
        aria-expanded={menuOpen}
        onClick={() => setMenuOpen((v) => !v)}
      >
        ☰
      </button>
      <aside className={`sidebar${menuOpen ? " open" : ""}`} aria-label="Primary">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">◈</span>
          <span className="brand-name">WebLock</span>
          <span className="brand-sub">SOC</span>
        </div>
        <nav>
          <ul>
            {NAV.filter((item) => !item.adminOnly || isAdmin(session?.role)).map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  end={item.to === "/"}
                  className={({ isActive }) => (isActive ? "active" : "")}
                  onClick={() => setMenuOpen(false)}
                >
                  {item.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <div className="sidebar-foot">
          <div className="api-status" role="status">
            <span
              className={`dot ${health.data?.database === "ok" ? "dot-ok" : "dot-bad"}`}
              aria-hidden="true"
            />
            {health.data ? `API ${health.data.database}` : health.error ? "API unreachable" : "API…"}
          </div>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="topbar-user">
            <span>{session?.email}</span>
            <span className="badge role">{session?.role?.toUpperCase()}</span>
          </div>
          <button type="button" className="btn btn-secondary" onClick={onLogout}>
            Sign out
          </button>
        </header>
        <main className="content">{children}</main>
      </div>
    </div>
  );
}
