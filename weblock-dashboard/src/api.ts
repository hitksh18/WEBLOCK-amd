/**
 * WebLock typed API client. Single place for base URL, auth, errors.
 * Every number shown in the UI originates from these calls — no fallbacks.
 */

export const API_BASE =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ??
  "http://localhost:8000";

export type Role = "admin" | "analyst" | "investigator" | "viewer";

export interface Session {
  accessToken: string;
  refreshToken: string;
  role: Role;
  orgId: number;
  email: string;
}

export class ApiError extends Error {
  status: number;
  detail: string;
  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

let tokenGetter: () => string | null = () => null;
let onUnauthorized: () => void = () => {};

export function configureApi(
  getToken: () => string | null,
  handleUnauthorized: () => void,
): void {
  tokenGetter = getToken;
  onUnauthorized = handleUnauthorized;
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  timeoutMs = 15000,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    const token = tokenGetter();
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const resp = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: { ...headers, ...(options.headers as Record<string, string> ?? {}) },
      signal: controller.signal,
    });
    if (resp.status === 401) {
      onUnauthorized();
      throw new ApiError(401, "Session expired. Please sign in again.");
    }
    if (!resp.ok) {
      let detail = `Request failed (${resp.status})`;
      try {
        const body = await resp.json();
        if (typeof body?.detail === "string") detail = body.detail;
      } catch {
        /* keep default */
      }
      throw new ApiError(resp.status, detail);
    }
    if (resp.status === 204) return undefined as T;
    return (await resp.json()) as T;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if ((err as Error).name === "AbortError") {
      throw new ApiError(0, "Request timed out. Is the API reachable?");
    }
    throw new ApiError(0, "API unreachable. Is the backend running?");
  } finally {
    clearTimeout(timer);
  }
}

export const get = <T,>(path: string): Promise<T> =>
  request<T>(path, { method: "GET" });
export const post = <T,>(path: string, body?: unknown): Promise<T> =>
  request<T>(path, { method: "POST", body: JSON.stringify(body ?? {}) });
export const put = <T,>(path: string, body?: unknown): Promise<T> =>
  request<T>(path, { method: "PUT", body: JSON.stringify(body ?? {}) });

/* ---------------- Backend-derived types (mirror Pydantic schemas) -------- */

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  role: Role;
  org_id: number;
}

export interface IncidentListItem {
  id: number;
  incident_key: string;
  title: string;
  severity: string;
  risk_score: number;
  status: string;
  user_id: number | null;
  endpoint_id: number | null;
  correlation_id: number | null;
  created_at: string | null;
}

export interface DetectionListItem {
  id: number;
  rule_id: string;
  rule_version: string;
  severity: string;
  confidence: number;
  status: string;
  title: string;
  explanation: string;
  mitre: string[];
  endpoint_id: number;
  primary_event_id: number;
  related_event_ids: number[];
  detected_at: string | null;
}

export interface CorrelationListItem {
  id: number;
  correlation_key: string;
  endpoint_id: number;
  status: string;
  severity: string;
  confidence: number;
  detection_count: number;
  distinct_family_count: number;
  families: string[];
  primary_detection_id: number | null;
  first_seen: string | null;
  last_seen: string | null;
  explanation: string;
}

export interface EndpointListItem {
  id: number;
  agent_id: string;
  name: string;
  hostname: string;
  os: string | null;
  ip: string | null;
  agent_version: string | null;
  status: string;
  presence: string;
  risk_score: number;
  capabilities: Record<string, boolean | string>;
  last_seen: string | null;
}

export interface IncidentDetail extends IncidentListItem {
  summary: string | null;
  event: { id: number; ip_address: string; classification: string } | null;
  assessment: { explanation: string; factors: string[] } | null;
  evidence: Array<{
    id: number;
    sha256: string;
    source: string;
    collected_at: string | null;
  }>;
  correlation: {
    id: number;
    status: string;
    severity: string;
    confidence: number;
    families: string[];
    first_seen: string | null;
    last_seen: string | null;
    explanation: string;
    detections: Array<{
      id: number;
      rule_id: string;
      severity: string;
      confidence: number;
      status: string;
      title: string;
      explanation: string;
      mitre: string[];
      occurred_at: string | null;
      event_id: string | null;
      security_event_id: number | null;
      actor: string;
    }>;
  } | null;
  risk: {
    id: number;
    score: number;
    severity: string;
    factors: Array<{ label: string; points: number }>;
    created_at: string | null;
  } | null;
}

export interface TimelineItem {
  timestamp: string | null;
  kind: string;
  title: string;
  severity: string | null;
  refs: Record<string, unknown>;
}

export interface EvidenceItem {
  id: number;
  incident_id: number | null;
  correlation_id: number | null;
  source: string;
  source_type: string;
  source_id: number | null;
  sha256: string;
  integrity_status: string;
  collector: string;
  collected_by: string;
  collected_at: string | null;
  description: string;
  content: Record<string, unknown>;
}

export interface CustodyRecord {
  id: number;
  action: string;
  actor_user_id: number | null;
  created_at: string | null;
  reason: string;
  prev_hash: string;
  record_hash: string;
}

export interface ResponseActionItem {
  id: number;
  incident_id: number;
  endpoint_id: number;
  action_type: string;
  target: Record<string, unknown>;
  execution_mode: "SIMULATION" | "LIVE";
  status: string;
  policy_decision: { allowed: boolean; checks: Array<{ name: string; ok: boolean; code: string }> };
  attempt: number;
  result: Record<string, unknown>;
  error_code: string;
  error_message: string;
  requested_by: number | null;
  requested_at: string | null;
  expires_at: string | null;
}

export interface AIAnalysisItem {
  id: number;
  incident_id: number;
  version: number;
  provider: string;
  model: string;
  context_hash: string;
  status: string;
  validation_status: string;
  error_code: string;
  error_message: string;
  created_at: string | null;
  completed_at: string | null;
  analysis: {
    assessment?: string;
    confidence?: string;
    confidence_reason?: string;
    observed_facts?: Array<{ statement: string; references: string[] }>;
    inferences?: Array<{ statement: string; confidence: string; references: string[] }>;
    recommendations?: Array<{
      action: string;
      reason: string;
      references: string[];
      urgency: string;
      requires_human_approval: boolean;
    }>;
    unknowns?: Array<{ statement: string; why_unknown: string }>;
    mitre_assessment?: Array<{ technique: string; observed: boolean; reason: string }>;
    limitations?: string[];
  };
}

export interface ReportMeta {
  id: number;
  incident_id: number;
  version: number;
  format: string;
  sha256: string;
  size_bytes: number;
  generated_at: string | null;
  content?: Record<string, unknown>;
  download?: string;
}

export interface AuditEntry {
  id: number;
  action: string;
  actor_id: number | null;
  target: string | null;
  metadata: Record<string, unknown>;
  created_at: string | null;
}

/* ---------------- Endpoint functions ------------------------------------- */

const q = (params: Record<string, string | number | undefined>): string => {
  const parts = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== "")
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  return parts.length ? `?${parts.join("&")}` : "";
};

export const api = {
  login: (email: string, password: string): Promise<LoginResponse> =>
    post("/v1/auth/login", { email, password }),
  logout: (refreshToken: string): Promise<void> =>
    post("/v1/auth/logout", { refresh_token: refreshToken }).then(
      () => {},
      () => {},
    ),

  health: (): Promise<{
    application: string;
    version: string;
    environment: string;
    database: string;
  }> => get("/v1/health"),

  incidents: (filters?: {
    status?: string;
    severity?: string;
    endpoint_id?: number;
    limit?: number;
    offset?: number;
  }): Promise<IncidentListItem[]> =>
    get(`/v1/incidents${q({ ...(filters as Record<string, number | string | undefined>) })}`),
  incident: (id: number): Promise<IncidentDetail> => get(`/v1/incidents/${id}`),
  incidentStatus: (id: number, status: string): Promise<unknown> =>
    post(`/v1/incidents/${id}/status`, { status }),
  incidentTimeline: (id: number, limit = 200): Promise<{ total: number; timeline: TimelineItem[] }> =>
    get(`/v1/incidents/${id}/timeline${q({ limit })}`),
  incidentEvidence: (id: number): Promise<{ total: number; evidence: EvidenceItem[] }> =>
    get(`/v1/incidents/${id}/evidence${q({ limit: 200 })}`),
  incidentIntegrity: (id: number): Promise<{
    valid: boolean;
    events_checked: number;
    violations: Array<Record<string, unknown>>;
  }> => get(`/v1/incidents/${id}/integrity`),

  detections: (filters?: Record<string, string | number | undefined>): Promise<{
    total: number;
    detections: DetectionListItem[];
  }> => get(`/v1/detections${q({ limit: 100, ...(filters ?? {}) })}`),
  detectionStatus: (id: number, status: string): Promise<unknown> =>
    post(`/v1/detections/${id}/status`, { status }),

  correlations: (filters?: Record<string, string | number | undefined>): Promise<{
    total: number;
    clusters: CorrelationListItem[];
  }> => get(`/v1/correlations${q({ limit: 100, ...(filters ?? {}) })}`),
  correlation: (id: number): Promise<CorrelationListItem & { timeline: Array<Record<string, unknown>> }> =>
    get(`/v1/correlations/${id}`),

  endpoints: (): Promise<EndpointListItem[]> => get("/v1/endpoints"),
  endpoint: (id: number): Promise<EndpointListItem> => get(`/v1/endpoints/${id}`),
  endpointRisk: (id: number): Promise<{
    endpoint_id: number;
    score: number;
    severity: string;
    factors: Array<{ label: string; points: number }>;
    explanation: string;
  }> => get(`/v1/endpoints/${id}/risk`),
  endpointRiskHistory: (id: number): Promise<{
    total: number;
    snapshots: Array<{ id: number; score: number; severity: string; created_at: string | null }>;
  }> => get(`/v1/endpoints/${id}/risk/history${q({ limit: 20 })}`),
  endpointDetections: (endpointId: number): Promise<{ total: number; detections: DetectionListItem[] }> =>
    get(`/v1/detections${q({ endpoint_id: endpointId, limit: 50 })}`),
  endpointIncidents: (endpointId: number): Promise<IncidentListItem[]> =>
    get(`/v1/incidents${q({ endpoint_id: endpointId, limit: 50 })}`),

  evidenceDetail: (id: number): Promise<EvidenceItem> => get(`/v1/evidence/${id}`),
  evidenceVerify: (id: number): Promise<{ id: number; integrity_status: string; valid: boolean }> =>
    post(`/v1/evidence/${id}/verify`),
  evidenceCustody: (id: number): Promise<{
    evidence_id: number;
    chain_valid: boolean;
    problems: Array<Record<string, unknown>>;
    records: CustodyRecord[];
  }> => get(`/v1/evidence/${id}/custody`),
  evidenceCollect: (incidentId: number, sourceType: string, sourceId: number): Promise<EvidenceItem> =>
    post(`/v1/incidents/${incidentId}/evidence/collect`, {
      source_type: sourceType,
      source_id: sourceId,
    }),
  snapshot: (incidentId: number): Promise<unknown> =>
    post(`/v1/incidents/${incidentId}/snapshot`),

  responseActions: (incidentId: number): Promise<{ total: number; actions: ResponseActionItem[] }> =>
    get(`/v1/incidents/${incidentId}/response-actions${q({ limit: 100 })}`),
  requestAction: (
    incidentId: number,
    endpointId: number,
    body: { action_type: string; target: Record<string, unknown>; reason: string; execution_mode: string },
  ): Promise<ResponseActionItem> =>
    post(`/v1/incidents/${incidentId}/response-actions?endpoint_id=${endpointId}`, body),
  retryAction: (actionId: number): Promise<ResponseActionItem> =>
    post(`/v1/response-actions/${actionId}/retry`),

  aiContext: (incidentId: number): Promise<Record<string, unknown>> =>
    get(`/v1/incidents/${incidentId}/ai-context`),
  aiAnalyses: (incidentId: number): Promise<{ total: number; analyses: AIAnalysisItem[] }> =>
    get(`/v1/incidents/${incidentId}/ai-analyses${q({ limit: 20 })}`),
  aiAnalysis: (analysisId: number): Promise<AIAnalysisItem> =>
    get(`/v1/ai-analyses/${analysisId}`),
  aiRequest: (incidentId: number): Promise<AIAnalysisItem> =>
    post(`/v1/incidents/${incidentId}/ai-analysis`),

  reportsExport: (incidentId: number, format: "json" | "pdf"): Promise<ReportMeta> =>
    post(`/v1/incidents/${incidentId}/report/export`, { format }),
  reportLatest: (incidentId: number): Promise<ReportMeta> =>
    get(`/v1/incidents/${incidentId}/report`),
  reportDownloadUrl: (reportId: number): string =>
    `${API_BASE}/v1/reports/${reportId}/download`,

  audit: (limit = 100): Promise<AuditEntry[]> =>
    get(`/v1/admin/audit${q({ limit })}`),
};
