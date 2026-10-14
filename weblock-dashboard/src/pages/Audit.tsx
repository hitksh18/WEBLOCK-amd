import React from "react";
import { api } from "../api";
import { EmptyState, ErrorState, Loading, Section, useApi } from "../ui";

export function AuditPage(): React.JSX.Element {
  const state = useApi(() => api.audit(100), []);
  return (
    <div>
      <h1>Audit log</h1>
      <p className="page-sub">Administrator only. Identifiers and metadata — never secrets or payloads.</p>
      <Section title="Recent audit entries">
        {state.loading ? <Loading label="Audit" /> :
          state.error ? (
            state.error.includes("403") || state.error.includes("Not authorized") || state.error.includes("Forbidden") ? (
              <EmptyState title="Not authorized" hint="Audit visibility requires the administrator role." />
            ) : (
              <ErrorState message={state.error} onRetry={state.reload} />
            )
          ) : (state.data?.length ?? 0) === 0 ? (
            <EmptyState title="No audit entries" />
          ) : (
            <div className="table-scroll"><table className="grid-table">
              <thead><tr><th>ID</th><th>Action</th><th>Actor</th><th>Target</th><th>Time</th></tr></thead>
              <tbody>
                {(state.data ?? []).map((a) => (
                  <tr key={a.id}>
                    <td className="mono">{a.id}</td>
                    <td className="mono small">{a.action}</td>
                    <td className="mono">{a.actor_id ?? "—"}</td>
                    <td className="small">{a.target ?? "—"}</td>
                    <td className="small muted">{a.created_at ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}
      </Section>
    </div>
  );
}
