import React from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { QueryView, Section, SeverityBadge, StatusBadge, useApi } from "../ui";
import { timeAgo } from "./Overview";

export function IncidentsPage(): React.JSX.Element {
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "";
  const severity = params.get("severity") ?? "";
  const state = useApi(
    () => api.incidents({ status: status || undefined, severity: severity || undefined, limit: 100 }),
    [status, severity],
  );

  const set = (key: string, value: string): void => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };

  return (
    <div>
      <h1>Incidents</h1>
      <p className="page-sub">Every row is a real backend incident. Filters map to API query parameters.</p>
      <Section
        title="Filter"
        action={
          <div className="form-row" role="search">
            <div className="field">
              <label htmlFor="f-status">Status</label>
              <select id="f-status" value={status} onChange={(e) => set("status", e.target.value)}>
                <option value="">All</option>
                {["open", "investigating", "contained", "resolved", "closed"].map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="f-sev">Severity</label>
              <select id="f-sev" value={severity} onChange={(e) => set("severity", e.target.value)}>
                <option value="">All</option>
                {["critical", "high", "medium", "low"].map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
          </div>
        }
      >
        <QueryView state={state} emptyTitle="No incidents" emptyHint="No incidents match your filters.">
          {(list) => list.length === 0 ? (
            <p className="muted">No incidents match your filters.</p>
          ) : (
            <div className="table-scroll">
              <table className="grid-table">
                <thead>
                  <tr><th>Key</th><th>Title</th><th>Severity</th><th>Risk</th><th>Status</th><th>Created</th></tr>
                </thead>
                <tbody>
                  {list.map((i) => (
                    <tr key={i.id}>
                      <td className="mono"><Link to={`/incidents/${i.id}`}>{i.incident_key}</Link></td>
                      <td>{i.title}</td>
                      <td><SeverityBadge value={i.severity} /></td>
                      <td className="mono">{i.risk_score}</td>
                      <td><StatusBadge value={i.status} /></td>
                      <td className="small muted">{timeAgo(i.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </QueryView>
      </Section>
    </div>
  );
}
