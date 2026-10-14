import React from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { EmptyState, ErrorState, Loading, QueryView, Section, SeverityBadge, StatusBadge, useApi } from "../ui";
import { timeAgo } from "./Overview";

export function EndpointsPage(): React.JSX.Element {
  const state = useApi(() => api.endpoints(), []);
  return (
    <div>
      <h1>Endpoints</h1>
      <p className="page-sub">Enrolled agents. Capabilities reflect real agent advertisements.</p>
      <Section title="Endpoints">
        <QueryView state={state} emptyTitle="No endpoints enrolled" emptyHint="Enroll an agent to begin monitoring.">
          {(list) => list.length === 0 ? (
            <EmptyState title="No endpoints enrolled" hint="Enroll an agent to begin monitoring." />
          ) : (
            <div className="table-scroll"><table className="grid-table">
              <thead><tr><th>Hostname</th><th>OS</th><th>Agent</th><th>Presence</th><th>Status</th><th>Last seen</th></tr></thead>
              <tbody>
                {list.map((e) => (
                  <tr key={e.id}>
                    <td><Link to={`/endpoints/${e.id}`}>{e.hostname || e.agent_id}</Link></td>
                    <td className="small">{e.os ?? "—"}</td>
                    <td className="mono small">{e.agent_version ?? "—"}</td>
                    <td><StatusBadge value={e.presence} /></td>
                    <td><StatusBadge value={e.status} /></td>
                    <td className="small muted">{timeAgo(e.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
        </QueryView>
      </Section>
    </div>
  );
}

const CAPABILITY_LABELS: Record<string, string> = {
  isolate_endpoint: "Isolate",
  restore_isolation: "Restore isolation",
  terminate_process: "Terminate process",
  block_network_destination: "Block destination",
  disable_session: "Disable session",
  collect_evidence: "Collect evidence",
};

export function EndpointDetailPage(): React.JSX.Element {
  const { id } = useParams();
  const endpointId = Number(id);
  const state = useApi(() => api.endpoint(endpointId), [endpointId]);
  const risk = useApi(() => api.endpointRisk(endpointId), [endpointId]);
  const dets = useApi(() => api.endpointDetections(endpointId), [endpointId]);
  const incs = useApi(() => api.endpointIncidents(endpointId), [endpointId]);

  return (
    <div>
      <p className="page-sub"><Link to="/endpoints">← Endpoints</Link></p>
      <QueryView state={state} emptyTitle="Endpoint not found">
        {(e) => (
          <>
            <h1>{e.hostname || e.agent_id}</h1>
            <p className="page-sub mono small">{e.agent_id}</p>
            <div className="rowline" style={{ marginBottom: 12 }}>
              <StatusBadge value={e.presence} />
              <StatusBadge value={e.status} />
            </div>
            <Section title="Identity & agent">
              <ul className="kv-list">
                <li><span>Hostname</span><span>{e.hostname || "—"}</span></li>
                <li><span>OS</span><span>{e.os ?? "—"}</span></li>
                <li><span>IP</span><span className="mono">{e.ip ?? "—"}</span></li>
                <li><span>Agent version</span><span className="mono">{e.agent_version ?? "—"}</span></li>
                <li><span>Last seen</span><span className="small">{e.last_seen ?? "never"}</span></li>
                <li><span>Risk score</span><span className="mono">{e.risk_score}</span></li>
              </ul>
            </Section>
            <Section title="Current risk (deterministic engine)">
              {risk.loading ? <Loading label="Risk" /> :
                risk.error ? <ErrorState message={risk.error} onRetry={risk.reload} /> :
                !risk.data ? <EmptyState title="No risk data" /> : (
                  <>
                    <p><span className="stat">{risk.data.score}</span> <SeverityBadge value={risk.data.severity} /></p>
                    <ul className="factor-list">
                      {risk.data.factors.map((f, i) => (
                        <li key={i}><span>{f.label}</span><span className="points">+{f.points}</span></li>
                      ))}
                    </ul>
                    <p className="small muted">{risk.data.explanation}</p>
                  </>
                )}
            </Section>
            <Section title="Response capabilities (as advertised by the agent)">
              {Object.keys(e.capabilities ?? {}).length === 0 ? (
                <p className="muted">No capabilities reported (agent older than 1.1.0 or never heartbeated with capabilities).</p>
              ) : (
                <ul className="kv-list">
                  {Object.entries(e.capabilities).filter(([k]) => k in CAPABILITY_LABELS).map(([k, v]) => (
                    <li key={k}>
                      <span>{CAPABILITY_LABELS[k]}</span>
                      <span>{v === true ? "AVAILABLE" : v === false ? "NOT AVAILABLE" : String(v)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Section>
            <Section title="Recent detections">
              {dets.loading ? <Loading label="Detections" /> :
                dets.error ? <ErrorState message={dets.error} onRetry={dets.reload} /> :
                (dets.data?.detections.length ?? 0) === 0 ? <EmptyState title="No detections for this endpoint" /> : (
                  <ul className="kv-list">
                    {(dets.data?.detections ?? []).slice(0, 10).map((d) => (
                      <li key={d.id}><span className="mono">DET-{d.id} {d.rule_id}</span><span><SeverityBadge value={d.severity} /></span></li>
                    ))}
                  </ul>
                )}
            </Section>
            <Section title="Recent incidents">
              {incs.loading ? <Loading label="Incidents" /> :
                incs.error ? <ErrorState message={incs.error} onRetry={incs.reload} /> :
                (incs.data?.length ?? 0) === 0 ? <EmptyState title="No incidents for this endpoint" /> : (
                  <ul className="kv-list">
                    {(incs.data ?? []).slice(0, 10).map((i) => (
                      <li key={i.id}>
                        <span><Link to={`/incidents/${i.id}`}>{i.incident_key}</Link> {i.title}</span>
                        <span><SeverityBadge value={i.severity} /></span>
                      </li>
                    ))}
                  </ul>
                )}
            </Section>
          </>
        )}
      </QueryView>
    </div>
  );
}
