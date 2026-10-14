import React, { useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api, type IncidentListItem } from "../api";
import { canWrite, useAuth } from "../auth";
import { EmptyState, ErrorState, Loading, QueryView, Section, useApi } from "../ui";
import { AnalysisView } from "./IncidentDetail";

export function AIPage(): React.JSX.Element {
  const { session } = useAuth();
  const incidents = useApi(() => api.incidents({ limit: 100 }), []);
  const [selected, setSelected] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const analyses = useApi(
    () => (selected === null
      ? Promise.resolve({ total: 0, analyses: [] })
      : api.aiAnalyses(selected)),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [selected, nonce],
  );
  const [versionId, setVersionId] = useState<number | null>(null);

  const request = async (): Promise<void> => {
    if (selected === null) return;
    setBusy(true);
    setMessage(null);
    try {
      const row = await api.aiRequest(selected);
      setMessage(`Analysis v${row.version}: ${row.status}${row.error_code ? ` (${row.error_code})` : ""}`);
      if (row.status === "SUCCEEDED") setVersionId(row.id);
      setNonce((n) => n + 1);
    } catch (err) {
      setMessage(err instanceof ApiError ? err.detail : "Request failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1>AI Analyst</h1>
      <p className="page-sub">
        Advisory only: evidence-grounded assessments. Facts, inferences, recommendations,
        and unknowns are always separated. The AI never executes response actions.
      </p>
      <Section title="Select incident">
        <QueryView state={incidents} emptyTitle="No incidents" emptyHint="AI analysis is per-incident.">
          {(list: IncidentListItem[]) => list.length === 0 ? (
            <EmptyState title="No incidents" hint="AI analysis is per-incident." />
          ) : (
            <div className="field">
              <label htmlFor="ai-incident">Incident</label>
              <select
                id="ai-incident"
                value={selected ?? ""}
                onChange={(e) => {
                  setSelected(e.target.value ? Number(e.target.value) : null);
                  setVersionId(null);
                }}
              >
                <option value="">— choose —</option>
                {list.map((i) => (
                  <option key={i.id} value={i.id}>
                    {i.incident_key} — {i.title}
                  </option>
                ))}
              </select>
            </div>
          )}
        </QueryView>
      </Section>
      {selected === null ? null : (
        <Section
          title="Analyses"
          action={canWrite(session?.role) ? (
            <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void request()}>
              {busy ? "Analyzing…" : "Request analysis"}
            </button>
          ) : undefined}
        >
          {message ? <p role="status">{message}</p> : null}
          <AnalysesBody
            analyses={analyses}
            versionId={versionId}
            setVersionId={setVersionId}
          />
        </Section>
      )}
      <p className="small muted">
        Full investigation views live on the <Link to="/incidents">incident detail page</Link>.
      </p>
    </div>
  );
}

function AnalysesBody({
  analyses,
  versionId,
  setVersionId,
}: {
  analyses: import("../ui").ApiState<{ total: number; analyses: import("../api").AIAnalysisItem[] }>;
  versionId: number | null;
  setVersionId: (id: number) => void;
}): React.JSX.Element {
  if (analyses.loading) return <Loading label="Analyses" />;
  if (analyses.error) return <ErrorState message={analyses.error} onRetry={analyses.reload} />;
  const data = analyses.data;
  if (!data || data.total === 0) {
    return (
      <EmptyState
        title="No AI analyses yet"
        hint="If the provider is unconfigured, requesting returns AI_UNAVAILABLE — never a fabricated analysis."
      />
    );
  }
  const current = versionId ?? data.analyses[0].id;
  return (
    <>
      <div className="rowline" style={{ marginBottom: 8 }}>
        <label className="small muted" htmlFor="ai-version">Version</label>
        <select
          id="ai-version"
          value={current}
          onChange={(e) => setVersionId(Number(e.target.value))}
        >
          {data.analyses.map((a) => (
            <option key={a.id} value={a.id}>v{a.version} — {a.status}</option>
          ))}
        </select>
      </div>
      <AnalysisView analysisId={current} />
    </>
  );
}
