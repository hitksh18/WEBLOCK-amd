import React from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { QueryView, Section, SeverityBadge, useApi } from "../ui";

export function DetectionsPage(): React.JSX.Element {
  const [params, setParams] = useSearchParams();
  const severity = params.get("severity") ?? "";
  const rule = params.get("rule") ?? "";
  const state = useApi(
    () => api.detections({ severity: severity || undefined, rule_id: rule || undefined, limit: 100 }),
    [severity, rule],
  );
  const set = (key: string, value: string): void => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };
  return (
    <div>
      <h1>Detections</h1>
      <p className="page-sub">Rule matches from the detection engine. No match is ever fabricated.</p>
      <Section
        title="Filter"
        action={
          <div className="form-row" role="search">
            <div className="field">
              <label htmlFor="d-sev">Severity</label>
              <select id="d-sev" value={severity} onChange={(e) => set("severity", e.target.value)}>
                <option value="">All</option>
                {["critical", "high", "medium", "low", "info"].map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="d-rule">Rule contains</label>
              <input id="d-rule" value={rule} placeholder="AUTH-01" onChange={(e) => set("rule", e.target.value)} />
            </div>
          </div>
        }
      >
        <QueryView state={state} emptyTitle="No detections" emptyHint="No detections match your filters.">
          {(res) => res.detections.length === 0 ? (
            <p className="muted">No detections match your filters.</p>
          ) : (
            <>
              <p className="small muted">{res.total} total (showing {res.detections.length})</p>
              <div className="table-scroll"><table className="grid-table">
                <thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Confidence</th><th>Title</th><th>MITRE</th><th>Status</th></tr></thead>
                <tbody>
                  {res.detections.map((d) => (
                    <tr key={d.id}>
                      <td className="mono">DET-{d.id}</td>
                      <td className="mono">{d.rule_id}</td>
                      <td><SeverityBadge value={d.severity} /></td>
                      <td className="mono">{d.confidence}</td>
                      <td>{d.title}</td>
                      <td className="mono">{(d.mitre ?? []).join(", ") || "—"}</td>
                      <td className="small">{d.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            </>
          )}
        </QueryView>
      </Section>
    </div>
  );
}

export function CorrelationsPage(): React.JSX.Element {
  const [params, setParams] = useSearchParams();
  const severity = params.get("severity") ?? "";
  const state = useApi(
    () => api.correlations({ severity: severity || undefined, limit: 100 }),
    [severity],
  );
  return (
    <div>
      <h1>Correlations</h1>
      <p className="page-sub">Multi-stage behavior clusters. A cluster needs ≥2 detections across ≥2 rule families.</p>
      <Section
        title="Filter"
        action={
          <div className="field">
            <label htmlFor="c-sev">Severity</label>
            <select id="c-sev" value={severity} onChange={(e) => {
              const next = new URLSearchParams(params);
              if (e.target.value) next.set("severity", e.target.value);
              else next.delete("severity");
              setParams(next, { replace: true });
            }}>
              <option value="">All</option>
              {["critical", "high", "medium", "low"].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
        }
      >
        <QueryView state={state} emptyTitle="No correlations" emptyHint="Correlated multi-stage behavior will appear here.">
          {(res) => res.total === 0 ? (
            <p className="muted">No correlations.</p>
          ) : (
            <div className="table-scroll"><table className="grid-table">
              <thead><tr><th>ID</th><th>Severity</th><th>Score</th><th>Families</th><th>Detections</th><th>Explanation</th></tr></thead>
              <tbody>
                {res.clusters.map((c) => (
                  <tr key={c.id}>
                    <td className="mono">CORR-{c.id}</td>
                    <td><SeverityBadge value={c.severity} /></td>
                    <td className="mono">{c.confidence}</td>
                    <td className="small">{(c.families ?? []).join(", ")}</td>
                    <td className="mono">{c.detection_count}</td>
                    <td className="small">{c.explanation}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
        </QueryView>
      </Section>
      <p className="small muted">Correlations gain incident links in the incident views. <Link to="/incidents">Open incidents →</Link></p>
    </div>
  );
}
