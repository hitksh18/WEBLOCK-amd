import React from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { ErrorState, QueryView, Section, SeverityBadge, StatusBadge, useApi, usePolling } from "../ui";

function timeAgo(iso: string | null): string {
  if (!iso) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function OverviewPage(): React.JSX.Element {
  const incidents = useApi(() => api.incidents({ limit: 100 }), []);
  const detections = useApi(() => api.detections({ limit: 100 }), []);
  const endpoints = useApi(() => api.endpoints(), []);
  const correlations = useApi(() => api.correlations({ limit: 100 }), []);
  usePolling(incidents.reload, 60000);
  usePolling(detections.reload, 60000);
  usePolling(endpoints.reload, 60000);

  const incidentList = incidents.data ?? [];
  const openIncidents = incidentList.filter((i) => i.status === "open" || i.status === "investigating");
  const critical = incidentList.filter((i) => i.severity === "critical" && i.status !== "closed" && i.status !== "resolved");
  const epList = endpoints.data ?? [];
  const offline = epList.filter((e) => e.presence === "offline" || e.status === "isolated" || e.status === "revoked");
  const sevCounts = ["critical", "high", "medium", "low"].map((sev) => ({
    sev,
    count: incidentList.filter((i) => i.severity === sev).length,
  }));
  const maxSev = Math.max(1, ...sevCounts.map((s) => s.count));

  return (
    <div>
      <h1>Overview</h1>
      <p className="page-sub">Live organization state, derived from backend APIs. Zero means zero.</p>

      <div className="grid grid-4">
        <div className="panel"><div className="panel-body">
          <div className="stat-label">Open incidents</div>
          {incidents.loading && !incidents.data ? <div className="stat">…</div> :
            incidents.error ? <div className="stat">—</div> :
            <div className="stat"><Link to="/incidents">{openIncidents.length}</Link></div>}
        </div></div>
        <div className="panel"><div className="panel-body">
          <div className="stat-label">Critical (unresolved)</div>
          {incidents.loading && !incidents.data ? <div className="stat">…</div> :
            <div className="stat"><Link to="/incidents?severity=critical">{critical.length}</Link></div>}
        </div></div>
        <div className="panel"><div className="panel-body">
          <div className="stat-label">Protected endpoints</div>
          {endpoints.loading && !endpoints.data ? <div className="stat">…</div> :
            endpoints.error ? <div className="stat">—</div> :
            <div className="stat"><Link to="/endpoints">{epList.length}</Link></div>}
        </div></div>
        <div className="panel"><div className="panel-body">
          <div className="stat-label">Endpoints needing attention</div>
          {endpoints.loading && !endpoints.data ? <div className="stat">…</div> :
            <div className="stat"><Link to="/endpoints">{offline.length}</Link></div>}
        </div></div>
      </div>

      <div className="grid grid-2">
        <Section title="Recent incidents">
          <QueryView state={incidents} emptyTitle="No incidents" emptyHint="No incidents exist in this organization.">
            {(list) => list.length === 0 ? <p className="muted">No incidents.</p> : (
              <div className="table-scroll"><table className="grid-table">
                <thead><tr><th>Key</th><th>Title</th><th>Severity</th><th>Risk</th><th>Status</th></tr></thead>
                <tbody>
                  {list.slice(0, 8).map((i) => (
                    <tr key={i.id}>
                      <td className="mono"><Link to={`/incidents/${i.id}`}>{i.incident_key}</Link></td>
                      <td>{i.title}</td>
                      <td><SeverityBadge value={i.severity} /></td>
                      <td className="mono">{i.risk_score}</td>
                      <td><StatusBadge value={i.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            )}
          </QueryView>
        </Section>

        <Section title="Recent detections">
          <QueryView state={detections} emptyTitle="No detections" emptyHint="No detections match.">
            {(res) => res.detections.length === 0 ? <p className="muted">No detections.</p> : (
              <div className="table-scroll"><table className="grid-table">
                <thead><tr><th>Rule</th><th>Title</th><th>Severity</th><th>MITRE</th></tr></thead>
                <tbody>
                  {res.detections.slice(0, 8).map((d) => (
                    <tr key={d.id}>
                      <td className="mono">{d.rule_id}</td>
                      <td>{d.title}</td>
                      <td><SeverityBadge value={d.severity} /></td>
                      <td className="mono">{(d.mitre ?? []).join(", ") || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            )}
          </QueryView>
        </Section>
      </div>

      <div className="grid grid-2">
        <Section title="Incident severity (first 100)">
          {incidents.error ? <ErrorState message={incidents.error} onRetry={incidents.reload} /> : (
            <ul className="factor-list">
              {sevCounts.map((s) => (
                <li key={s.sev}>
                  <span><SeverityBadge value={s.sev} /></span>
                  <span className="mono">{s.count}</span>
                  <span style={{ flex: 1, background: "#1c2635", borderRadius: 3, height: 8, alignSelf: "center" }}>
                    <span style={{ display: "block", width: `${(s.count / maxSev) * 100}%`, height: "100%", background: "var(--accent)", borderRadius: 3 }} />
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Endpoint health">
          <QueryView state={endpoints} emptyTitle="No endpoints enrolled" emptyHint="Enroll an agent to begin monitoring.">
            {(list) => list.length === 0 ? <p className="muted">No endpoints enrolled.</p> : (
              <div className="table-scroll"><table className="grid-table">
                <thead><tr><th>Hostname</th><th>Presence</th><th>Last seen</th></tr></thead>
                <tbody>
                  {list.slice(0, 8).map((e) => (
                    <tr key={e.id}>
                      <td><Link to={`/endpoints/${e.id}`}>{e.hostname || e.agent_id}</Link></td>
                      <td><StatusBadge value={e.presence} /></td>
                      <td className="small muted">{timeAgo(e.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            )}
          </QueryView>
        </Section>
      </div>

      <Section title="Open correlations">
        <QueryView state={correlations} emptyTitle="No correlations" emptyHint="Correlated multi-stage behavior will appear here.">
          {(res) => res.total === 0 ? <p className="muted">No correlations.</p> : (
            <p>{res.total} correlation cluster(s) in scope. <Link to="/correlations">Open correlations →</Link></p>
          )}
        </QueryView>
      </Section>
    </div>
  );
}

export { timeAgo };
