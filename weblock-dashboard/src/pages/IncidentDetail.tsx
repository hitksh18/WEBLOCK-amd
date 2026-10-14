import React, { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, API_BASE, api, type IncidentDetail, type ResponseActionItem, type Session } from "../api";
import { canRespond, canWrite, useAuth } from "../auth";
import {
  EmptyState,
  ErrorState,
  Loading,
  ModeBadge,
  QueryView,
  Section,
  SeverityBadge,
  StatusBadge,
  useApi,
} from "../ui";

const TABS = [
  "Summary",
  "Risk",
  "Detections",
  "Timeline",
  "Evidence",
  "Integrity",
  "Reports",
  "AI Analyst",
  "Response",
] as const;

type Tab = (typeof TABS)[number];

function useIncident(id: number) {
  return useApi(() => api.incident(id), [id]);
}

export function IncidentDetailPage(): React.JSX.Element {
  const { id } = useParams();
  const incidentId = Number(id);
  const [tab, setTab] = useState<Tab>("Summary");
  const state = useIncident(Number.isFinite(incidentId) ? incidentId : -1);

  return (
    <div>
      <p className="page-sub">
        <Link to="/incidents">← Incidents</Link>
      </p>
      <QueryView state={state} emptyTitle="Incident not found" emptyHint="It may belong to another organization.">
        {(incident) => (
          <>
            <h1 className="mono">{incident.incident_key}</h1>
            <p className="page-sub">{incident.title}</p>
            <div className="rowline" style={{ marginBottom: 12 }}>
              <SeverityBadge value={incident.severity} />
              <span className="mono">Risk {incident.risk_score}</span>
              <StatusBadge value={incident.status} />
              <IncidentStatusChanger incident={incident} onChanged={state.reload} />
            </div>
            <div className="tabs" role="tablist" aria-label="Incident sections">
              {TABS.map((t) => (
                <button
                  key={t}
                  role="tab"
                  aria-selected={tab === t}
                  onClick={() => setTab(t)}
                >
                  {t}
                </button>
              ))}
            </div>
            <div role="tabpanel">
              {tab === "Summary" && <SummaryTab incident={incident} />}
              {tab === "Risk" && <RiskTab incident={incident} />}
              {tab === "Detections" && <DetectionsTab incident={incident} />}
              {tab === "Timeline" && <TimelineTab incidentId={incident.id} />}
              {tab === "Evidence" && <EvidenceTab incident={incident} />}
              {tab === "Integrity" && <IntegrityTab incidentId={incident.id} />}
              {tab === "Reports" && <ReportsTab incidentId={incident.id} />}
              {tab === "AI Analyst" && <AIAnalystTab incidentId={incident.id} />}
              {tab === "Response" && <ResponseTab incident={incident} onChanged={state.reload} />}
            </div>
          </>
        )}
      </QueryView>
    </div>
  );
}

function IncidentStatusChanger({
  incident,
  onChanged,
}: {
  incident: IncidentDetail;
  onChanged: () => void;
}): React.JSX.Element | null {
  const { session } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!canWrite(session?.role)) return null;
  const change = async (status: string): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      await api.incidentStatus(incident.id, status);
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : "Failed");
    } finally {
      setBusy(false);
    }
  };
  return (
    <span className="rowline">
      <label className="small muted" htmlFor="incident-status">Set status</label>
      <select
        id="incident-status"
        disabled={busy}
        value={incident.status}
        onChange={(e) => void change(e.target.value)}
      >
        {["open", "investigating", "contained", "resolved", "closed"].map((s) => (
          <option key={s} value={s}>{s}</option>
        ))}
      </select>
      {error ? <span className="small" role="alert">{error}</span> : null}
    </span>
  );
}

function SummaryTab({ incident }: { incident: IncidentDetail }): React.JSX.Element {
  return (
    <Section title="Summary">
      <ul className="kv-list">
        <li><span>Title</span><span>{incident.title}</span></li>
        <li><span>Endpoint</span><span>{incident.endpoint_id ? <Link to={`/endpoints/${incident.endpoint_id}`}>endpoint #{incident.endpoint_id}</Link> : "—"}</span></li>
        <li><span>User</span><span>{incident.user_id ? `user #${incident.user_id}` : "User attribution unavailable"}</span></li>
        <li><span>Correlation</span><span>{incident.correlation_id ? `cluster #${incident.correlation_id}` : "—"}</span></li>
        <li><span>Created</span><span className="small">{incident.created_at ?? "—"}</span></li>
      </ul>
      {incident.summary ? (
        <div style={{ marginTop: 10 }}>
          <h3 className="small muted">Summary</h3>
          <p>{incident.summary}</p>
        </div>
      ) : null}
      {incident.correlation ? (
        <div style={{ marginTop: 10 }}>
          <h3 className="small muted">Correlation explanation</h3>
          <p>{incident.correlation.explanation}</p>
          <p className="small muted">
            Score {incident.correlation.confidence} · Families {(incident.correlation.families ?? []).join(", ") || "—"}
          </p>
        </div>
      ) : null}
    </Section>
  );
}

function RiskTab({ incident }: { incident: IncidentDetail }): React.JSX.Element {
  const risk = incident.risk;
  return (
    <Section title="Risk — WebLock Risk Engine (deterministic, not an AI score)">
      {!risk ? (
        <EmptyState title="No risk snapshot" hint="Risk is computed when detections correlate on this endpoint." />
      ) : (
        <>
          <p><span className="stat">{risk.score}</span> <SeverityBadge value={risk.severity} /></p>
          <ul className="factor-list">
            {risk.factors.map((f, i) => (
              <li key={i}><span>{f.label}</span><span className="points">+{f.points}</span></li>
            ))}
          </ul>
          <p className="small muted">Snapshot #{risk.id} · {risk.created_at ?? "—"}</p>
          {incident.endpoint_id ? <EndpointRiskHistory endpointId={incident.endpoint_id} /> : null}
        </>
      )}
    </Section>
  );
}

function EndpointRiskHistory({ endpointId }: { endpointId: number }): React.JSX.Element {
  const state = useApi(() => api.endpointRiskHistory(endpointId), [endpointId]);
  if (state.loading) return <Loading label="Risk history" />;
  if (state.error || !state.data || state.data.total === 0)
    return <p className="muted small">No risk history.</p>;
  return (
    <ul className="factor-list">
      {state.data.snapshots.map((s) => (
        <li key={s.id}>
          <span>{s.created_at ?? `#${s.id}`}</span>
          <span><SeverityBadge value={s.severity} /> <span className="points mono">{s.score}</span></span>
        </li>
      ))}
    </ul>
  );
}

function DetectionsTab({ incident }: { incident: IncidentDetail }): React.JSX.Element {
  const dets = incident.correlation?.detections ?? [];
  return (
    <Section title={`Detections (${dets.length})`}>
      {dets.length === 0 ? (
        <EmptyState title="No detections linked" hint="Detections appear here when correlation links them." />
      ) : (
        <div className="table-scroll"><table className="grid-table">
          <thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Confidence</th><th>Explanation</th><th>MITRE</th><th>Occurred</th></tr></thead>
          <tbody>
            {dets.map((d) => (
              <tr key={d.id}>
                <td className="mono">DET-{d.id}</td>
                <td className="mono">{d.rule_id}</td>
                <td><SeverityBadge value={d.severity} /></td>
                <td className="mono">{d.confidence}</td>
                <td>{d.explanation}</td>
                <td className="mono">{(d.mitre ?? []).join(", ") || "—"}</td>
                <td className="small muted">{d.occurred_at ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}
    </Section>
  );
}

function TimelineTab({ incidentId }: { incidentId: number }): React.JSX.Element {
  const state = useApi(() => api.incidentTimeline(incidentId, 200), [incidentId]);
  if (state.loading) return <Loading label="Timeline" />;
  if (state.error) return <ErrorState message={state.error} onRetry={state.reload} />;
  const items = state.data?.timeline ?? [];
  if (items.length === 0) return <EmptyState title="Empty timeline" />;
  return (
    <Section title={`Timeline (${state.data?.total ?? items.length} events)`}>
      <ul className="timeline">
        {items.map((t, i) => (
          <li key={i}>
            <time>{t.timestamp ?? "—"}</time>
            <span className="kind">{t.kind}</span>
            <span>{t.title}{t.severity ? <> <SeverityBadge value={t.severity} /></> : null}</span>
          </li>
        ))}
      </ul>
    </Section>
  );
}

function EvidenceTab({ incident }: { incident: IncidentDetail }): React.JSX.Element {
  const state = useApi(() => api.incidentEvidence(incident.id), [incident.id]);
  const { session } = useAuth();
  const [verifying, setVerifying] = useState<number | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const verify = async (id: number): Promise<void> => {
    setVerifying(id);
    setMessage(null);
    try {
      const res = await api.evidenceVerify(id);
      setMessage(`Evidence #${id}: ${res.integrity_status}`);
      state.reload();
    } catch (err) {
      setMessage(err instanceof ApiError ? err.detail : "Verification failed");
    } finally {
      setVerifying(null);
    }
  };
  const [custodyId, setCustodyId] = useState<number | null>(null);
  const custody = useApi(
    () => (custodyId === null ? Promise.resolve(null) : api.evidenceCustody(custodyId)),
    [custodyId],
  );
  return (
    <Section title="Evidence">
      {message ? <p role="status">{message}</p> : null}
      {state.loading ? <Loading label="Evidence" /> :
        state.error ? <ErrorState message={state.error} onRetry={state.reload} /> :
        (state.data?.evidence.length ?? 0) === 0 ? (
          <EmptyState title="No evidence collected for this incident" />
        ) : (
          <div className="table-scroll"><table className="grid-table">
            <thead><tr><th>ID</th><th>Source</th><th>SHA-256</th><th>Integrity</th><th>Collected</th><th>Actions</th></tr></thead>
            <tbody>
              {(state.data?.evidence ?? []).map((e) => (
                <tr key={e.id}>
                  <td className="mono">EVD-{e.id}</td>
                  <td className="mono">{e.source_type}{e.source_id ? ` #${e.source_id}` : ""}</td>
                  <td className="mono small">{e.sha256.slice(0, 16)}…</td>
                  <td><StatusBadge value={e.integrity_status} /></td>
                  <td className="small muted">{e.collected_at ?? "—"}</td>
                  <td>
                    <div className="rowline">
                      <button type="button" className="btn btn-secondary" onClick={() => setCustodyId(e.id)}>
                        Custody
                      </button>
                      {canWrite(session?.role) ? (
                        <button type="button" className="btn btn-secondary" disabled={verifying === e.id} onClick={() => void verify(e.id)}>
                          {verifying === e.id ? "Verifying…" : "Verify"}
                        </button>
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      {custodyId !== null ? (
        <div style={{ marginTop: 12 }}>
          <h3>Custody chain — EVD-{custodyId}</h3>
          {custody.loading ? <Loading label="Custody" /> :
            custody.error ? <ErrorState message={custody.error} onRetry={custody.reload} /> :
            custody.data ? (
              <>
                <p>Chain valid: <strong>{custody.data.chain_valid ? "yes" : "NO — see problems"}</strong></p>
                <ul className="timeline">
                  {custody.data.records.map((r) => (
                    <li key={r.id}>
                      <time>{r.created_at ?? "—"}</time>
                      <span className="kind">{r.action}</span>
                      <span className="mono small">{r.record_hash.slice(0, 16)}…</span>
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
        </div>
      ) : null}
    </Section>
  );
}

function IntegrityTab({ incidentId }: { incidentId: number }): React.JSX.Element {
  const state = useApi(() => api.incidentIntegrity(incidentId), [incidentId]);
  if (state.loading) return <Loading label="Integrity" />;
  if (state.error) return <ErrorState message={state.error} onRetry={state.reload} />;
  const data = state.data as { valid?: boolean; events_checked?: number; violations?: Array<Record<string, unknown>>; scope?: string; detail?: string } | null;
  if (!data || data.scope === "none") return <EmptyState title="No telemetry scope" hint={typeof data?.detail === "string" ? data.detail : undefined} />;
  const violations = (data.violations ?? []) as Array<{ type?: string; event_id?: string; detail?: string; severity?: string }>;
  return (
    <Section title={`Telemetry chain: ${data.valid ? "VALID" : "INVALID"}`}>
      <p>Events checked: <span className="mono">{data.events_checked ?? 0}</span></p>
      {violations.length === 0 ? (
        <p>No violations detected. This is cryptographic integrity verification of recorded telemetry — not a tamper-proof guarantee.</p>
      ) : (
        <div className="table-scroll"><table className="grid-table">
          <thead><tr><th>Type</th><th>Event</th><th>Detail</th><th>Severity</th></tr></thead>
          <tbody>
            {violations.map((v, i) => (
              <tr key={i}>
                <td className="mono">{String(v.type ?? "?")}</td>
                <td className="mono small">{String(v.event_id ?? "—")}</td>
                <td>{String(v.detail ?? "")}</td>
                <td><SeverityBadge value={typeof v.severity === "string" ? v.severity : "unknown"} /></td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}
    </Section>
  );
}

function ReportsTab({ incidentId }: { incidentId: number }): React.JSX.Element {
  const { session } = useAuth();
  const [busy, setBusy] = useState<"json" | "pdf" | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const latest = useApi(() => api.reportLatest(incidentId).catch((err: unknown) => {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }), [incidentId, nonce]);

  const exportReport = async (format: "json" | "pdf"): Promise<void> => {
    setBusy(format);
    setMessage(null);
    try {
      const meta = await api.reportsExport(incidentId, format);
      setMessage(`Report v${meta.version} generated (SHA-256 ${meta.sha256.slice(0, 16)}…).`);
      setNonce((n) => n + 1);
    } catch (err) {
      setMessage(err instanceof ApiError ? err.detail : "Export failed");
    } finally {
      setBusy(null);
    }
  };

  const download = async (): Promise<void> => {
    const meta = latest.data;
    if (!meta || meta.format !== "pdf") return;
    const token = sessionStorage.getItem("weblock.session");
    let access = "";
    try {
      access = token ? (JSON.parse(token) as { accessToken: string }).accessToken : "";
    } catch { /* ignore */ }
    const resp = await fetch(`${API_BASE}/v1/reports/${meta.id}/download`, {
      headers: access ? { Authorization: `Bearer ${access}` } : {},
    });
    if (!resp.ok) {
      setMessage("Download failed");
      return;
    }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `weblock-incident-${incidentId}-v${meta.version}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <Section title="Forensic reports">
      {message ? <p role="status">{message}</p> : null}
      {latest.loading ? <Loading label="Reports" /> :
        latest.error ? <ErrorState message={latest.error} onRetry={latest.reload} /> :
        !latest.data ? <EmptyState title="No reports yet" hint="Generate one below. Reports are immutable versions." /> : (
          <ul className="kv-list">
            <li><span>Latest</span><span>v{latest.data.version} ({latest.data.format.toUpperCase()})</span></li>
            <li><span>SHA-256</span><span className="mono small">{latest.data.sha256}</span></li>
            <li><span>Generated</span><span className="small">{latest.data.generated_at ?? "—"}</span></li>
            {latest.data.format === "pdf" ? (
              <li><span>File</span><span><button type="button" className="btn btn-secondary" onClick={() => void download()}>Download PDF</button></span></li>
            ) : null}
          </ul>
        )}
      {canWrite(session?.role) ? (
        <div className="rowline" style={{ marginTop: 10 }}>
          <button type="button" className="btn btn-secondary" disabled={busy !== null} onClick={() => void exportReport("json")}>
            {busy === "json" ? "Generating…" : "Generate JSON report"}
          </button>
          <button type="button" className="btn btn-secondary" disabled={busy !== null} onClick={() => void exportReport("pdf")}>
            {busy === "pdf" ? "Generating…" : "Generate PDF report"}
          </button>
        </div>
      ) : null}
    </Section>
  );
}

function AIAnalystTab({ incidentId }: { incidentId: number }): React.JSX.Element {
  const { session } = useAuth();
  const [nonce, setNonce] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const request = async (): Promise<void> => {
    setBusy(true);
    setMessage(null);
    try {
      const row = await api.aiRequest(incidentId);
      setMessage(`Analysis v${row.version}: ${row.status}${row.error_code ? ` (${row.error_code})` : ""}`);
      if (row.status === "SUCCEEDED") setSelected(row.id);
      setNonce((n) => n + 1);
    } catch (err) {
      setMessage(err instanceof ApiError ? err.detail : "Request failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section
      title="AI Analyst (advisory only — never executes response)"
      action={canWrite(session?.role) ? (
        <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void request()}>
          {busy ? "Analyzing…" : "Request analysis"}
        </button>
      ) : undefined}
    >
      {message ? <p role="status">{message}</p> : null}
      <AnalystVersions
        incidentId={incidentId}
        nonce={nonce}
        selected={selected}
        setSelected={setSelected}
      />
    </Section>
  );
}

function AnalystVersions({
  incidentId,
  nonce,
  selected,
  setSelected,
}: {
  incidentId: number;
  nonce: number;
  selected: number | null;
  setSelected: (id: number) => void;
}): React.JSX.Element {
  const list = useApi(() => api.aiAnalyses(incidentId), [incidentId, nonce]);
  if (list.loading) return <Loading label="Analyses" />;
  if (list.error) return <ErrorState message={list.error} onRetry={list.reload} />;
  const data = list.data;
  if (!data || data.total === 0) {
    return (
      <EmptyState title="No AI analyses yet" hint="Request one to get an evidence-grounded assessment. If the provider is unconfigured you will see AI_UNAVAILABLE — never a fabricated analysis." />
    );
  }
  const current = selected ?? data.analyses[0].id;
  return (
    <>
      <div className="rowline" style={{ marginBottom: 8 }}>
        <label className="small muted" htmlFor="ai-version">Version</label>
        <select id="ai-version" value={current} onChange={(e) => setSelected(Number(e.target.value))}>
          {data.analyses.map((a) => (
            <option key={a.id} value={a.id}>v{a.version} — {a.status} ({a.created_at ?? "—"})</option>
          ))}
        </select>
      </div>
      <AnalysisView analysisId={current} />
    </>
  );
}

export function AnalysisView({ analysisId }: { analysisId: number }): React.JSX.Element {
  const state = useApi(() => api.aiAnalysis(analysisId), [analysisId]);
  if (state.loading) return <Loading label="Analysis" />;
  if (state.error || !state.data) return <ErrorState message={state.error ?? "Not found"} onRetry={state.reload} />;
  const analysis = state.data;
  if (analysis.status !== "SUCCEEDED") {
    return (
      <div className="state" role="status">
        <strong>Analysis {analysis.status}</strong>
        <p>{analysis.error_code ? `${analysis.error_code}: ${analysis.error_message}` : "No result."}</p>
        {analysis.status === "AI_UNAVAILABLE" ? (
          <p className="muted">AI Analyst unavailable: the provider is not configured. Detections, correlation, risk, and response remain fully functional.</p>
        ) : null}
      </div>
    );
  }
  const a = analysis.analysis;
  const ref = (r: string, i: number): React.JSX.Element => (
    <span key={`${r}-${i}`} className="ref-link">{r} </span>
  );
  return (
    <div>
      <p><strong>Assessment:</strong> {a.assessment}</p>
      <p><strong>Confidence:</strong> <StatusBadge value={a.confidence} /> <span className="muted small">{a.confidence_reason}</span></p>
      <h3>Observed facts (WebLock evidence)</h3>
      {(a.observed_facts ?? []).map((f, i) => (
        <div key={i} className="ai-fact"><p>{f.statement}</p><p>{(f.references ?? []).map(ref)}</p></div>
      ))}
      <h3>Inferences (AI interpretation)</h3>
      {(a.inferences ?? []).map((f, i) => (
        <div key={i} className="ai-inference"><p>{f.statement} <StatusBadge value={f.confidence} /></p><p>{(f.references ?? []).map(ref)}</p></div>
      ))}
      <h3>Recommendations (require human approval — never auto-executed)</h3>
      {(a.recommendations ?? []).map((f, i) => (
        <div key={i} className="ai-recommendation">
          <p><span className="mono">{f.action}</span> — {f.reason}</p>
          <p>{(f.references ?? []).map(ref)}</p>
        </div>
      ))}
      <h3>Unknown / missing information</h3>
      {(a.unknowns ?? []).map((f, i) => (
        <div key={i} className="ai-unknown"><p>{f.statement}</p><p className="muted small">{f.why_unknown}</p></div>
      ))}
      {(a.mitre_assessment ?? []).length > 0 ? (
        <><h3>MITRE assessment</h3>
        <ul>{(a.mitre_assessment ?? []).map((m, i) => (
          <li key={i}><span className="mono">{m.technique}</span> {m.observed ? "(observed)" : "(inferred)"} — {m.reason}</li>
        ))}</ul></>
      ) : null}
      {(a.limitations ?? []).length > 0 ? (
        <><h3>Limitations</h3><ul>{(a.limitations ?? []).map((l, i) => <li key={i}>{l}</li>)}</ul></>
      ) : null}
      <p className="small muted">Context hash <span className="mono">{analysis.context_hash.slice(0, 16)}…</span> · validation {analysis.validation_status}</p>
    </div>
  );
}

function ResponseTab({ incident, onChanged }: { incident: IncidentDetail; onChanged: () => void }): React.JSX.Element {
  const { session } = useAuth();
  const actions = useApi(() => api.responseActions(incident.id), [incident.id]);
  const [form, setForm] = useState({ action_type: "COLLECT_EVIDENCE", targetText: '{"collection_type":"SYSTEM_INFO"}', reason: "", mode: "SIMULATION" });
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const submit = async (): Promise<void> => {
    setBusy(true);
    setMessage(null);
    try {
      const target = JSON.parse(form.targetText) as Record<string, unknown>;
      await api.requestAction(incident.id, incident.endpoint_id ?? 0, {
        action_type: form.action_type,
        target,
        reason: form.reason,
        execution_mode: form.mode,
      });
      setConfirming(false);
      actions.reload();
      onChanged();
    } catch (err) {
      setMessage(err instanceof ApiError ? err.detail : "Request failed (invalid JSON target?)");
    } finally {
      setBusy(false);
    }
  };

  const retry = async (action: ResponseActionItem): Promise<void> => {
    try {
      await api.retryAction(action.id);
      actions.reload();
    } catch (err) {
      setMessage(err instanceof ApiError ? err.detail : "Retry failed");
    }
  };

  return (
    <Section title="Response actions">
      {message ? <p role="status">{message}</p> : null}
      <ActionsBody
        actions={actions}
        session={session}
        retry={retry}
      />
      {canRespond(session?.role) ? (
        <RequestForm
          incident={incident}
          form={form}
          setForm={setForm}
          confirming={confirming}
          setConfirming={setConfirming}
          busy={busy}
          submit={submit}
        />
      ) : null}
    </Section>
  );
}

function ActionsBody({
  actions,
  session,
  retry,
}: {
  actions: import("../ui").ApiState<{ total: number; actions: ResponseActionItem[] }>;
  session: Session | null;
  retry: (action: ResponseActionItem) => Promise<void>;
}): React.JSX.Element {
  if (actions.loading) return <Loading label="Response actions" />;
  if (actions.error) return <ErrorState message={actions.error} onRetry={actions.reload} />;
  const data = actions.data;
  if (!data || data.total === 0)
    return <EmptyState title="No response actions" hint="Request one below. Simulations never touch the endpoint." />;
  return (
    <div className="table-scroll"><table className="grid-table">
      <thead><tr><th>ID</th><th>Action</th><th>Mode</th><th>Status</th><th>Result / error</th><th>Actions</th></tr></thead>
      <tbody>
        {data.actions.map((a) => (
                <tr key={a.id}>
                  <td className="mono">RESP-{a.id}</td>
                  <td className="mono">{a.action_type}</td>
                  <td><ModeBadge mode={a.execution_mode} /></td>
                  <td><StatusBadge value={a.status} /></td>
                  <td className="small">
                    {a.status === "SUCCEEDED" && a.execution_mode === "SIMULATION" ? "Simulated — no endpoint action executed." : null}
                    {a.error_code ? <span className="mono">{a.error_code}</span> : null}
                    {a.error_message ? ` ${a.error_message}` : ""}
                    {a.status === "SUCCEEDED" && a.execution_mode === "LIVE" ? " Endpoint reported success." : ""}
                  </td>
                  <td>
                    {canRespond(session?.role) && (a.status === "FAILED" || a.status === "EXPIRED") ? (
                      <button type="button" className="btn btn-secondary" onClick={() => void retry(a)}>Retry</button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table></div>
  );
}

interface ResponseForm {
  action_type: string;
  targetText: string;
  reason: string;
  mode: string;
}

function RequestForm({
  incident,
  form,
  setForm,
  confirming,
  setConfirming,
  busy,
  submit,
}: {
  incident: IncidentDetail;
  form: ResponseForm;
  setForm: (form: ResponseForm) => void;
  confirming: boolean;
  setConfirming: (value: boolean) => void;
  busy: boolean;
  submit: () => Promise<void>;
}): React.JSX.Element | null {
  const { session } = useAuth();
  if (!canRespond(session?.role)) return null;
  return (
        <div style={{ marginTop: 12 }}>
          <h3>Request action</h3>
          {!incident.endpoint_id ? <p className="muted">This incident has no linked endpoint; response requires one.</p> : (
            <>
              <div className="form-row">
                <div className="field">
                  <label htmlFor="resp-action">Action</label>
                  <select id="resp-action" value={form.action_type} onChange={(e) => setForm({ ...form, action_type: e.target.value })}>
                    {["COLLECT_EVIDENCE", "ISOLATE_ENDPOINT", "RESTORE_ISOLATION", "TERMINATE_PROCESS", "BLOCK_NETWORK_DESTINATION", "UNBLOCK_NETWORK_DESTINATION"].map((a) => (
                      <option key={a} value={a}>{a}</option>
                    ))}
                  </select>
                </div>
                <div className="field">
                  <label htmlFor="resp-mode">Mode</label>
                  <select id="resp-mode" value={form.mode} onChange={(e) => setForm({ ...form, mode: e.target.value })}>
                    <option value="SIMULATION">SIMULATION (safe)</option>
                    <option value="LIVE">LIVE (real endpoint action)</option>
                  </select>
                </div>
              </div>
              <div className="field">
                <label htmlFor="resp-target">Target (JSON — must match backend schema, e.g. {"{"}"pid": 1234{"}"})</label>
                <textarea id="resp-target" rows={2} value={form.targetText} onChange={(e) => setForm({ ...form, targetText: e.target.value })} />
              </div>
              <div className="field">
                <label htmlFor="resp-reason">Reason</label>
                <input id="resp-reason" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
              </div>
              {!confirming ? (
                <button type="button" className="btn btn-primary" onClick={() => setConfirming(true)}>Review</button>
              ) : (
                <div className="confirm-box" role="alertdialog" aria-label="Confirm response action">
                  <p><strong>Confirm {form.mode} action</strong></p>
                  <ul className="kv-list">
                    <li><span>Action</span><span className="mono">{form.action_type}</span></li>
                    <li><span>Target</span><span className="mono small">{form.targetText}</span></li>
                    <li><span>Incident</span><span className="mono">{incident.incident_key}</span></li>
                    <li><span>Endpoint</span><span className="mono">#{incident.endpoint_id}</span></li>
                    <li><span>Mode</span><span><ModeBadge mode={form.mode} /></span></li>
                  </ul>
                  {form.mode === "LIVE" ? <p><strong>This will execute a real action on the endpoint subject to server policy.</strong></p> : null}
                  <div className="rowline">
                    <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void submit()}>
                      {busy ? "Submitting…" : `Submit ${form.mode}`}
                    </button>
                    <button type="button" className="btn btn-secondary" onClick={() => setConfirming(false)}>Back</button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
  );
}
