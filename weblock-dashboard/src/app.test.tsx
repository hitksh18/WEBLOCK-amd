/**
 * Frontend tests. fetch is mocked per test — mocks live ONLY in tests,
 * never in production code (production has zero fallback data).
 */
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "./auth";
import { OverviewPage } from "./pages/Overview";
import { IncidentsPage } from "./pages/Incidents";
import { IncidentDetailPage } from "./pages/IncidentDetail";
import { AIPage } from "./pages/AI";

function mockFetch(routes: Record<string, { status?: number; body?: unknown }>): void {
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    const path = url.replace("http://localhost:8000", "");
    const prefix = Object.keys(routes)
      .filter((k) => k !== path && path.startsWith(k))
      .sort((a, b) => b.length - a.length)[0];
    const route = routes[path] ?? (prefix ? routes[prefix] : undefined);
    if (!route) {
      return new Response(JSON.stringify({ detail: "not mocked" }), { status: 500 });
    }
    return new Response(JSON.stringify(route.body ?? {}), {
      status: route.status ?? 200,
    });
  }) as unknown as typeof fetch;
}

function renderWithAuth(path: string, element: React.ReactNode, routePath?: string): void {
  sessionStorage.clear();
  render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<div>login page</div>} />
          <Route path={routePath ?? path} element={element} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
}

const INCIDENTS = [
  {
    id: 1, incident_key: "INC-2026-0001", title: "Correlated threat",
    severity: "critical", risk_score: 86, status: "open", user_id: null,
    endpoint_id: 2, correlation_id: 1, created_at: "2026-10-14T00:00:00+00:00",
  },
];

beforeEach(() => {
  sessionStorage.clear();
  vi.restoreAllMocks();
});

describe("overview", () => {
  it("shows real zeros when APIs return empty", async () => {
    mockFetch({
      "/v1/incidents": { body: [] },
      "/v1/detections": { body: { total: 0, detections: [] } },
      "/v1/endpoints": { body: [] },
      "/v1/correlations": { body: { total: 0, clusters: [] } },
      "/v1/health": { body: { application: "x", version: "1", environment: "t", database: "ok" } },
    });
    renderWithAuth("/", <OverviewPage />);
    await waitFor(() => expect(screen.getByText("No incidents.")).toBeInTheDocument());
    expect(screen.getByText("No detections.")).toBeInTheDocument();
    expect(screen.getByText("No endpoints enrolled.")).toBeInTheDocument();
    // No fabricated numbers anywhere.
    expect(screen.queryByText(/threats blocked/i)).not.toBeInTheDocument();
  });

  it("shows API error state instead of fake fallback", async () => {
    mockFetch({
      "/v1/incidents": { status: 500, body: { detail: "boom" } },
      "/v1/detections": { body: { total: 0, detections: [] } },
      "/v1/endpoints": { body: [] },
      "/v1/correlations": { body: { total: 0, clusters: [] } },
      "/v1/health": { body: { application: "x", version: "1", environment: "t", database: "ok" } },
    });
    renderWithAuth("/", <OverviewPage />);
    await waitFor(() =>
      expect(screen.getAllByText("boom").length).toBeGreaterThanOrEqual(1),
    );
  });

  it("renders incident counts from the API", async () => {
    mockFetch({
      "/v1/incidents": { body: INCIDENTS },
      "/v1/detections": { body: { total: 0, detections: [] } },
      "/v1/endpoints": { body: [] },
      "/v1/correlations": { body: { total: 0, clusters: [] } },
      "/v1/health": { body: { application: "x", version: "1", environment: "t", database: "ok" } },
    });
    renderWithAuth("/", <OverviewPage />);
    await waitFor(() => expect(screen.getByText("INC-2026-0001")).toBeInTheDocument());
  });
});

describe("incidents", () => {
  it("renders rows with severity and links", async () => {
    mockFetch({ "/v1/incidents": { body: INCIDENTS } });
    renderWithAuth("/incidents", <IncidentsPage />);
    await waitFor(() => expect(screen.getByText("INC-2026-0001")).toBeInTheDocument());
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
  });
});

describe("incident detail", () => {
  const detail = {
    ...INCIDENTS[0],
    summary: "s",
    event: null,
    assessment: null,
    evidence: [],
    correlation: {
      id: 1, status: "open", severity: "critical", confidence: 80,
      families: ["AUTHENTICATION"], first_seen: null, last_seen: null,
      explanation: "e",
      detections: [
        {
          id: 5, rule_id: "AUTH-01", severity: "high", confidence: 0.9,
          status: "open", title: "t", explanation: "e", mitre: ["T1110"],
          occurred_at: null, event_id: "x", security_event_id: 1, actor: "u",
        },
      ],
    },
    risk: { id: 1, score: 86, severity: "critical", factors: [], created_at: null },
  };
  it("shows tabs and user-attribution honesty", async () => {
    mockFetch({
      "/v1/incidents/1": { body: detail },
      "/v1/endpoints/2/risk/history": { body: { total: 0, snapshots: [] } },
    });
    renderWithAuth("/incidents/1", <IncidentDetailPage />, "/incidents/:id");
    await waitFor(() => expect(screen.getByText("INC-2026-0001")).toBeInTheDocument());
    expect(screen.getByText("User attribution unavailable")).toBeInTheDocument();
    for (const tab of ["Summary", "Risk", "Detections", "Timeline", "Evidence", "Integrity", "Reports", "AI Analyst", "Response"]) {
      expect(screen.getByRole("tab", { name: tab })).toBeInTheDocument();
    }
  });
});

describe("AI page", () => {
  it("shows unavailable honestly and separates categories", async () => {
    const analysis = {
      id: 9, incident_id: 1, version: 1, provider: "", model: "",
      context_hash: "abc", status: "AI_UNAVAILABLE", validation_status: "NOT_RUN",
      error_code: "AI_UNAVAILABLE", error_message: "no key",
      created_at: null, completed_at: null, analysis: {},
    };
    mockFetch({
      "/v1/incidents": { body: INCIDENTS },
      "/v1/incidents/1/ai-analyses": {
        body: { total: 1, analyses: [analysis] },
      },
      "/v1/ai-analyses/9": { body: analysis },
    });
    renderWithAuth("/ai", <AIPage />);
    await userEvent.selectOptions(await screen.findByLabelText("Incident"), "1");
    await waitFor(() =>
      expect(screen.getAllByText(/AI_UNAVAILABLE/).length).toBeGreaterThanOrEqual(1),
    );
    expect(screen.queryByText(/sample|demo analysis/i)).not.toBeInTheDocument();
  });
});
