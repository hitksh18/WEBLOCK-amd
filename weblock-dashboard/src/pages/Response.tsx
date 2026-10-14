import React, { useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api, type IncidentListItem } from "../api";
import { canRespond, useAuth } from "../auth";
import { EmptyState, ErrorState, Loading, ModeBadge, QueryView, Section, StatusBadge, useApi } from "../ui";

export function ResponsePage(): React.JSX.Element {
  const { session } = useAuth();
  const incidents = useApi(() => api.incidents({ limit: 100 }), []);
  const [selected, setSelected] = useState<number | null>(null);

  return (
    <div>
      <h1>Response Center</h1>
      <p className="page-sub">
        Policy-gated containment. <ModeBadge mode="SIMULATION" /> never touches the endpoint;{" "}
        <ModeBadge mode="LIVE" /> executes real actions subject to server policy.
      </p>
      <Section title="Select incident">
        <QueryView state={incidents} emptyTitle="No incidents" emptyHint="Response actions belong to incidents.">
          {(list: IncidentListItem[]) => list.length === 0 ? (
            <EmptyState title="No incidents" hint="Response actions belong to incidents." />
          ) : (
            <div className="field">
              <label htmlFor="resp-incident">Incident</label>
              <select
                id="resp-incident"
                value={selected ?? ""}
                onChange={(e) => setSelected(e.target.value ? Number(e.target.value) : null)}
              >
                <option value="">— choose —</option>
                {list.map((i) => (
                  <option key={i.id} value={i.id}>
                    {i.incident_key} — {i.title} [{i.status}]
                  </option>
                ))}
              </select>
            </div>
          )}
        </QueryView>
      </Section>
      {selected !== null ? <IncidentActions incidentId={selected} /> : null}
      {!canRespond(session?.role) ? (
        <p className="muted">Your role ({session?.role}) is read-only for response. Actions are requested from the incident page by authorized roles.</p>
      ) : (
        <p className="muted">Request and manage actions from the <Link to="/incidents">incident detail → Response tab</Link>, where targets and confirmation are handled.</p>
      )}
    </div>
  );
}

function IncidentActions({ incidentId }: { incidentId: number }): React.JSX.Element {
  const [nonce, setNonce] = useState(0);
  const state = useApi(() => api.responseActions(incidentId), [incidentId, nonce]);
  const [message, setMessage] = useState<string | null>(null);

  const retry = async (actionId: number): Promise<void> => {
    setMessage(null);
    try {
      await api.retryAction(actionId);
      setNonce((n) => n + 1);
    } catch (err) {
      setMessage(err instanceof ApiError ? err.detail : "Retry failed");
    }
  };

  if (state.loading) return <Loading label="Response actions" />;
  if (state.error) return <ErrorState message={state.error} onRetry={state.reload} />;
  const data = state.data;
  if (!data || data.total === 0)
    return <EmptyState title="No response actions for this incident" />;
  return (
    <Section title={`Actions (${data.total})`}>
      {message ? <p role="status">{message}</p> : null}
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
              </td>
              <td>
                {(a.status === "FAILED" || a.status === "EXPIRED") ? (
                  <button type="button" className="btn btn-secondary" onClick={() => void retry(a.id)}>Retry</button>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table></div>
    </Section>
  );
}
