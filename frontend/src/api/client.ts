/**
 * DFIR-Nexus Portal API client.
 * 
 * All endpoints are under /portal/api/* and return JSON.
 * The Vite dev server proxies these to the Starlette backend on :4508.
 */

const BASE = "/portal/api";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public detail?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiError(
      res.status,
      (body as { error?: string }).error || res.statusText,
      body,
    );
  }
  return body as T;
}

function post<T>(path: string, data?: unknown): Promise<T> {
  return request<T>(path, {
    method: "POST",
    body: data ? JSON.stringify(data) : undefined,
  });
}

// --- Types ---

export interface CaseInfo {
  case_id: string;
  case_name: string;
  status?: string;
  examiner?: string;
}

export interface Finding {
  id: string;
  case_id: string;
  status: "DRAFT" | "APPROVED" | "REJECTED";
  title: string;
  observation: string;
  interpretation: string;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  confidence_justification?: string;
  type?: string;
  host?: string;
  audit_ids: string[];
  evidence?: Array<{ audit_id: string; path: string; note?: string }>;
  approved_by?: string;
  approved_at?: string;
  examiner_selected?: boolean;
  created_at: string;
  modified_at: string;
}

export interface ChatEntry {
  role: string;
  action: string;
  text: string;
  meta?: Record<string, unknown>;
  timestamp?: string;
}

export interface ExploreHit {
  audit_id: string;
  family: string;
  host: string;
  timestamp: string;
  line: string;
  path: string;
  line_no?: number;
}

export interface SearchResponse {
  hits: ExploreHit[];
  total: number;
  offset: number;
  limit: number;
}

export interface AggregateBucket {
  key: string;
  count: number;
}

export interface AggregateResponse {
  field: string;
  buckets: AggregateBucket[];
}

export interface HistogramBucket {
  hour: string;
  count: number;
  family: string;
}

export interface TimelineLane {
  family: string;
  buckets: Array<{ hour: string; count: number }>;
}

export interface EntityResult {
  type: "user" | "ip" | "process" | "path";
  value: string;
  count: number;
}

export interface WorkbenchItem {
  id: string;
  hit: ExploreHit;
  added_at: string;
}

export interface ChallengeResponse {
  challenge_id: string;
  nonce: string;
  salt: string;
  iterations: number;
  hash_algorithm: string;
}

// --- API ---

export const api = {
  // Case management
  cases: () => request<CaseInfo[]>("/cases"),
  activateCase: (caseId: string) =>
    post<{ status: string; case_id: string }>("/case/activate", { case_id: caseId }),

  // Findings & evidence
  findings: () => request<Finding[]>("/findings"),
  evidence: () => request<unknown[]>("/evidence"),
  iocs: () => request<unknown[]>("/iocs"),
  todos: () => request<unknown[]>("/todos"),
  summary: () => request<Record<string, unknown>>("/summary"),
  transparency: () => request<unknown[]>("/transparency"),
  auditForFinding: (findingId: string) =>
    request<unknown[]>(`/audit/${findingId}`),

  // Mode 1
  ask: (question: string, needles?: string[]) =>
    post<{ reply: string; needles?: string[]; hits?: ExploreHit[] }>("/mode1/ask", {
      question,
      needles,
    }),
  select: (hitIds: number[], title: string, observation?: string) =>
    post<{ status: string; finding_id: string }>("/mode1/select", {
      hit_ids: hitIds,
      title,
      observation,
    }),

  // Explore
  search: (params: {
    needles?: string;
    family?: string;
    host?: string;
    limit?: number;
    offset?: number;
  }) => post<SearchResponse>("/explore/search", params),
  aggregate: (field: string) =>
    post<AggregateResponse>("/explore/aggregate", { field }),
  histogram: (params: { family?: string; hours?: number }) =>
    post<{ buckets: HistogramBucket[] }>("/explore/histogram", params),

  // Workbench
  workbench: () => request<WorkbenchItem[]>("/workbench"),
  workbenchAdd: (hit: ExploreHit) => post("/workbench/add", { hit }),
  workbenchRemove: (id: string) => post("/workbench/remove", { id }),
  workbenchClear: () => post("/workbench/clear"),
  workbenchPromote: (params: {
    title: string;
    observation: string;
    interpretation?: string;
    confidence?: string;
    confidence_justification?: string;
  }) => post<{ status: string; finding_id: string }>("/workbench/promote", params),

  // Chat
  chat: (limit?: number) =>
    request<ChatEntry[]>(`/chat${limit ? `?limit=${limit}` : ""}`),
  chatPost: (text: string) => post<{ reply: string; action: string }>("/chat", { text }),
  chatClear: () => post<{ status: string }>("/chat/clear"),

  // Timeline
  timelineLanes: (params?: { family?: string; hours?: number }) =>
    post<TimelineLane[]>("/timeline/lanes", params || {}),

  // Entities
  entities: (params: { needles?: string; family?: string; type?: string }) =>
    post<EntityResult[]>("/entities", params),

  // Mode 2
  mode2Iterate: (params: { question: string; max_iterations?: number }) =>
    post<{
      iterations: number;
      total_hits: number;
      proposed_needles: string[];
      hits: ExploreHit[];
      chat_entries: ChatEntry[];
    }>("/mode2/iterate", params),
  mode2Corroborate: (params: { finding_id?: string; family?: string }) =>
    post<{
      corroboration: Array<{ family: string; count: number; confidence: string }>;
      suggestions: string[];
    }>("/mode2/corroborate", params),
  mode2ProposeDraft: (params: {
    title: string;
    observation: string;
    interpretation?: string;
    confidence?: string;
    confidence_justification?: string;
    audit_ids?: string[];
  }) => post<{ status: string; finding_id: string }>("/mode2/propose-draft", params),

  // Mode 3
  mode3Plan: (params: { question?: string }) =>
    post<{
      extras: string[];
      skips: string[];
      queries: string[];
      rationale: string;
    }>("/mode3/plan", params),
  mode3Execute: (params: {
    extras?: string[];
    queries?: string[];
    approval_token?: string;
  }) =>
    post<{
      status: string;
      extras_persisted: number;
      queries_run: number;
      results: unknown[];
    }>("/mode3/execute", params),
  mode3Seal: (params: {
    challenge_id: string;
    response: string;
    examiner: string;
  }) => post<{ status: string; sealed: boolean; hmac: string }>("/mode3/seal", params),

  // Approval
  getChallenge: () => request<ChallengeResponse>("/commit/challenge"),
  commit: (params: {
    finding_ids: string[];
    challenge_id: string;
    response: string;
    examiner: string;
  }) =>
    post<{
      approved: string[];
      errors: Array<{ finding_id: string; error: string }>;
    }>("/commit", params),
};
