/**
 * DFIR-Nexus Portal API client.
 *
 * All endpoints are under /portal/api/* and return JSON.
 * The Vite dev server proxies these to the Starlette backend on :4508.
 * In production, Starlette serves both the SPA and the API on the same port.
 */

const BASE = "/portal/api";

/**
 * Phase 4e: explicit case identity for every request.
 *
 * The cockpit always tells the server which case it means — the active-case
 * pointer is only a fallback for CLI/MCP/legacy consumers. CaseContext owns
 * this value; pages never set it directly.
 */
let requestCaseId = "";

/** Set (or clear) the case id attached to every API request. */
export function setRequestCaseId(caseId: string): void {
  requestCaseId = caseId || "";
}

function caseHeaders(): Record<string, string> {
  return requestCaseId ? { "X-Nexus-Case": requestCaseId } : {};
}

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
    headers: { "Content-Type": "application/json", ...caseHeaders(), ...options.headers },
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

// --- Types (matched against actual backend handler responses) ---

/** GET /cases → {cases: string[], active: string, details: Record<string, CaseSummary>} */
export interface CaseSummary {
  case_id: string;
  name: string;
  status: string;
  mode: string;
  evidence_count?: number;
  findings_count?: number;
  approved_count?: number;
  pipeline_complete?: boolean;
  report_exists?: boolean;
  /** Seeded demo case — mock evidence, no parsers ran. */
  synthetic?: boolean;
}
export interface CasesResponse {
  cases: string[];
  active: string;
  details?: Record<string, CaseSummary>;
}

/** POST /case/activate → {ok: bool, active: string} or {ok: false, error} */
export interface ActivateCaseResponse {
  ok: boolean;
  active?: string;
  error?: string;
}

export interface Finding {
  id: string;
  case_id?: string;
  status: "DRAFT" | "APPROVED" | "REJECTED";
  title: string;
  observation: string;
  interpretation: string;
  confidence: "LOW" | "MEDIUM" | "HIGH" | "SPECULATIVE";
  confidence_justification?: string;
  type?: string;
  host?: string;
  audit_ids: string[];
  evidence?: Array<{ source: string; path: string; note?: string }>;
  iocs?: Array<{ type: string; value: string }>;
  approved_by?: string;
  approved_at?: string;
  examiner_selected?: boolean;
  created_at?: string;
  modified_at?: string;
}

/** GET /findings → {findings: Finding[], total: number} */
export interface FindingsResponse {
  findings: Finding[];
  total: number;
}

/** GET /evidence → {evidence: dict[], total: number} */
export interface EvidenceResponse {
  evidence: Record<string, unknown>[];
  total: number;
}

/** GET /iocs → IOCs extracted from findings */
export interface Ioc {
  type?: string;
  value?: string;
  finding_title?: string;
  finding_status?: string;
  [key: string]: unknown;
}
export interface IocsResponse {
  iocs: Ioc[];
  total: number;
}

/** GET /todos → TODO list */
export interface Todo {
  todo_id?: string;
  id?: string;
  description: string;
  status?: string;
  priority?: string;
  assignee?: string;
  [key: string]: unknown;
}
export interface TodosResponse {
  todos: Todo[];
  total: number;
}

/** GET /summary → nested counts */
export interface SummaryResponse {
  findings: { total: number; draft: number; approved: number; rejected: number };
  timeline: number;
  evidence: number;
  todos: { total: number; open: number };
}

/** GET /transparency → transparency_verify result */
export type TransparencyResponse = Record<string, unknown>;

/** GET /audit/{finding_id} → audit entries */
export type AuditResponse = Record<string, unknown>[];

/** N4 hit shape (from query_pack) — fields/host added by WP 4d.1 */
export interface N4Hit {
  family: string;
  file: string;
  line: string | number;
  terms: string;
  text: string;
  fields?: Record<string, string>;
  host?: string;
}

/** WP 4j.1 — POST /hit/interpret → what a hit means + what to check next. */
export interface HitLearn {
  headline: string;
  why_matters: string[];
  technique: { id: string; name: string; caveat: string }[];
  watch_out: string[];
  sources: string[];
}
export interface HitInterpretation {
  meaning: string;
  /** WP 4j.4 — plain-language "why this matters" teaching block. */
  learn?: HitLearn;
  skills: {
    name: string;
    title: string;
    description?: string;
    mitre: string[];
    /** WP 4j.2 — why this skill matched the alert (technique/keyword/family). */
    why?: string[];
    /** WP 4j.2 — high/medium/low confidence rules for this skill. */
    confidence?: Record<string, string>;
    /** WP 4j.2 — steps that would confirm the alert (query + what to look for). */
    confirm?: { query: string; look_for: string; corroborate: string }[];
    /** WP 4j.2 — what absence of the procedure would mean. */
    refute?: string;
    matched_steps: {
      name: string;
      query: string;
      look_for: string;
      corroborate: string;
      pivot: string;
    }[];
  }[];
  techniques: string[];
  look_for: string[];
  corroborate: string[];
  next_queries: string[];
  pivots: string[];
  negative: string[];
  caveats: string[];
  confidence_rules: Record<string, string>;
  methodology?: string;
  sources: string[];
  error?: string;
}

/** POST /mode1/ask → {needles, window, hits, count, backend} or {needles: [], window, error} */
export interface AskResponse {
  needles: string[];
  window: string;
  hits?: N4Hit[];
  count?: number;
  backend?: string;
  error?: string;
}

// WP 4b.12: SelectResponse removed with api.select (see api.select note).

/** POST /explore/search */
export interface SearchResponse {
  hits: N4Hit[];
  count: number;
  total_before_family_filter: number;
  backend: string;
  families: string[];
  needles: string[];
  query: string;
  offset: number;
}

/** POST /explore/aggregate → n4_aggregate result */
export interface AggregateResponse {
  group_by: string;
  buckets: Record<string, number>;
  total?: number;
  error?: string;
}

/** POST /explore/histogram → {buckets: Record<string, number>, count} */
export interface HistogramResponse {
  buckets: Record<string, number>;
  count: number;
}

/** Bookmark shape (from workbench.py) */
export interface Bookmark {
  id: string;
  family: string;
  file: string;
  line: string;
  time: string;
  text: string;
  note: string;
  bookmarked_at: string;
}

/** GET /workbench → {bookmarks: Bookmark[], total} */
export interface WorkbenchResponse {
  bookmarks: Bookmark[];
  total: number;
}

/** POST /workbench/add → {status, bookmark_id, total} */
export interface WorkbenchAddResponse {
  status: string;
  bookmark_id?: string;
  total: number;
  error?: string;
}

/** POST /workbench/remove → {status, total} */
export interface WorkbenchRemoveResponse {
  status: string;
  total: number;
}

/** POST /workbench/clear → {status} */
export interface WorkbenchClearResponse {
  status: string;
}

/** POST /workbench/promote → {finding_id, status, title, bookmark_count} or {error} */
export interface WorkbenchPromoteResponse {
  finding_id?: string;
  status?: string;
  title?: string;
  bookmark_count?: number;
  error?: string | string[];
}

/** Chat entry shape (from chat.py) — data.hits added by WP 4d.3 */
export interface ChatEntry {
  ts: string;
  role: string;
  action: string;
  text: string;
  meta?: Record<string, string>;
  data?: { hits?: N4Hit[] };
}

/** GET /chat → {messages: ChatEntry[], total} */
export interface ChatResponse {
  messages: ChatEntry[];
  total: number;
}

/** POST /chat → {reply, needles, window, hits, count, backend} or {reply, needles: [], count: 0} */
export interface ChatPostResponse {
  reply: string;
  needles: string[];
  window?: string;
  hits?: N4Hit[];
  count?: number;
  backend?: string;
}

/** POST /timeline/lanes → {families: [{family, buckets}], total, bucket} */
export interface TimelineLaneEntry {
  family: string;
  buckets: Record<string, number>;
}
export interface TimelineLanesResponse {
  families: TimelineLaneEntry[];
  total: number;
  bucket: string;
}

/** POST /entities → {entities: {ips, users, processes, paths}, total} */
export interface EntitiesResponse {
  entities: {
    ips: Record<string, number>;
    users: Record<string, number>;
    processes: Record<string, number>;
    paths: Record<string, number>;
  };
  total: number;
}

/** POST /mode2/iterate → {question, iterations, total_hits, needles_run, capped} */
export interface Mode2Iteration {
  iteration: number;
  action: string;
  backend?: string;
  needles?: string[];
  rationale?: string;
  source?: string;
  hits?: number;
  new_families?: string[];
}
export interface Mode2IterateResponse {
  question: string;
  iterations: Mode2Iteration[];
  total_hits: number;
  needles_run: string[];
  capped: boolean;
  error?: string;
}

/** POST /mode2/corroborate → {families, distinct_families, confidence, ok, problems, suggested_queries} */
export interface CorroborationResponse {
  families: string[];
  distinct_families: number;
  confidence: string;
  ok: boolean;
  problems: string[];
  suggested_queries: string[];
}

/** POST /mode2/propose-draft → {finding_id, status, corroboration} or {error} */
export interface ProposeDraftResponse {
  finding_id?: string;
  status?: string;
  corroboration?: CorroborationResponse;
  error?: string | string[];
}

/** POST /mode3/plan → {items, queries, rationale, created_at, lane_complete} */
export interface Mode3PlanItem {
  type: string;
  key?: string;
  tool?: string;
  purpose: string;
}
export interface Mode3PlanResponse {
  items: Mode3PlanItem[];
  queries: string[];
  rationale: string;
  created_at: string;
  lane_complete: boolean;
}

/** POST /mode3/execute → {status, extras_persisted, query_results, note} or {error} */
export interface Mode3ExecuteResponse {
  status: string;
  extras_persisted: string[];
  query_results: Array<{ query: string; count: number; error?: string }>;
  note: string;
  error?: string;
}

/** POST /mode3/seal → {status: "SEALED", case_id, examiner} or {error} */
export interface Mode3SealResponse {
  status: string;
  case_id?: string;
  examiner?: string;
  error?: string;
}

/** GET /commit/challenge → {challenge_id, nonce, salt, iterations, hash_algorithm} */
export interface ChallengeResponse {
  challenge_id: string;
  nonce: string;
  salt: string;
  iterations: number;
  hash_algorithm: string;
}

/** POST /commit → {status, approved, errors, examiner} */
export interface CommitResponse {
  status: string;
  approved: string[];
  errors: Array<{ id: string; error: string }>;
  examiner: string;
}

// --- Phase 4b: Workflow-driven cockpit types ---

/** POST /case/create → {ok, case_id, name, active} */
export interface CaseCreateResponse {
  ok: boolean;
  case_id: string;
  name: string;
  active: string;
  error?: string;
}

/** GET /case/details → case metadata + counts */
export interface CaseDetailsResponse {
  case_id: string;
  name?: string;
  description?: string;
  status?: string;
  investigation_mode?: string;
  evidence_count?: number;
  findings_count?: number;
  approved_count?: number;
  report_exists?: boolean;
  pipeline_complete?: boolean;
  /** Seeded demo case — mock evidence, no parsers ran. */
  synthetic?: boolean;
  error?: string;
}

/** POST /pipeline/run → {run_id, case_id, mode, status} */
export interface PipelineRunResponse {
  run_id: string;
  case_id: string;
  mode: string;
  status: string;
  error?: string;
}

/** GET /pipeline/status → {run_id, case_id, mode, status, ...} */
export interface PipelineStatusResponse {
  run_id: string;
  case_id: string;
  mode: string;
  status: string;
  started_at?: string;
  completed_at?: string;
  error?: string;
  stages?: string[];
}

/** GET /pipeline/ledger → tool-lane parser run status */
export interface LedgerRow {
  tool?: string;
  host?: string;
  status?: string;
  detail?: string;
  reason?: string;
  purpose?: string;
  argv?: string[];
  timeout?: number;
  audit_id?: string;
  output_saved_to?: string;
  output_files?: Array<{ path?: string; sha256?: string; kind?: string }>;
  [key: string]: unknown;
}
export interface PipelineLedgerResponse {
  run_id: string;
  run_status?: string;
  evidence_paths?: string[];
  ledger: LedgerRow[];
  total: number;
  extractions?: string;
  error?: string;
}

/** GET /case/briefing — WP 4i.1 deterministic case briefing */
export interface BriefingAlert {
  family: string;
  level: string;
  title: string;
  time: string;
  host: string;
  file: string;
  line: string;
  /** WP 4j.1 — interpretation (meaning + what to check next) attached at build. */
  interpret?: HitInterpretation;
}
export interface BriefingNeedle {
  needle: string;
  hits: number;
  source: string;
}
export interface BriefingEntity {
  value: string;
  hits: number;
  families?: string[];
}
export interface BriefingDirection {
  title: string;
  why: string;
  needles: string[];
  family: string;
}
/** WP 4j.3 — one step of the deterministic guided first pass. */
export interface BriefingWalkthroughStep {
  order: number;
  key: string;
  title: string;
  why: string;
  count: number;
  actions: {
    label: string;
    needle: string;
    family?: string;
    hits?: number;
    level?: string;
    host?: string;
    source?: string;
    etype?: string;
  }[];
  /** WP 4j.4 — why this step matters (learning layer). */
  learn?: { headline: string; why_matters: string[]; sources: string[] };
}
export interface BriefingResponse {
  inventory: Record<string, { files: number; rows: number; capped?: boolean }>;
  families: string[];
  total_files: number;
  total_rows: number;
  ledger: { run_id: string; entries: { tool: string; status: string; family: string; reason: string }[]; ok: number; skip: number; fail: number };
  hosts: string[];
  time_range: { start: string; end: string };
  alerts: BriefingAlert[];
  alert_count: number;
  needle_scan: BriefingNeedle[];
  scanned_needles: number;
  entities: Record<string, BriefingEntity[]>;
  intake: Record<string, string>;
  directions?: BriefingDirection[];
  walkthrough?: BriefingWalkthroughStep[];
  backend: string;
  hits_examined: number;
  error?: string;
}

/** GET /fs/list → directory listing for the evidence picker */
export interface FsEntry {
  name: string;
  path: string;
  is_dir: boolean;
  size: number | null;
}
export interface FsListResponse {
  path: string;
  parent: string;
  drives: boolean;
  entries: FsEntry[];
  is_file?: boolean;
  file_entry?: FsEntry;
  error?: string;
}

/** GET /playbook/needles → {suggestions: [...], total} */
export interface PlaybookSuggestion {
  playbook: string;
  slug: string;
  needles: string[];
  strong_needles?: string[];
  caveats: string[];
  triggers: string[];
  /** "playbook" (YAML) | "mitre" | "sigma" | "overlay". */
  source?: string;
}
export interface PlaybookNeedlesResponse {
  suggestions: PlaybookSuggestion[];
  total: number;
}

/** POST/GET /case/mode → {ok, mode} or {mode} */
export interface CaseModeResponse {
  ok?: boolean;
  mode: string;
  error?: string;
}

/** GET /system/health → cheap backend/ES/RAG/LLM/parser status */
export interface SystemHealthResponse {
  backend: string;
  es?: { configured?: boolean; reachable?: boolean; url?: string };
  rag?: { configured?: boolean };
  llm?: { configured?: boolean; model?: string };
  parser?: string;
}

// --- API ---

export const api = {
  // Case management
  cases: () => request<CasesResponse>("/cases"),
  activateCase: (caseId: string) =>
    post<ActivateCaseResponse>("/case/activate", { case_id: caseId }),
  deactivateCase: () => post<{ ok: boolean; active: string }>("/case/deactivate"),
  reopenCase: (caseId?: string) =>
    post<{ ok: boolean; status?: string; note?: string; error?: string }>("/case/reopen", {
      case_id: caseId,
    }),
  caseCreate: (params: {
    name: string;
    description?: string;
    examiner?: string;
    mode?: string;
    activate?: boolean;
  }) => post<CaseCreateResponse>("/case/create", params),
  registerEvidence: (path: string, caseId?: string, description?: string) =>
    post<{
      ok: boolean;
      case_id?: string;
      sha256?: string;
      files?: number;
      total_bytes?: number;
      error?: string;
    }>("/evidence", { path, case_id: caseId, description }),

  // Findings & evidence
  findings: (status?: string, limit?: number) => {
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    if (limit) params.set("limit", String(limit));
    const qs = params.toString();
    return request<FindingsResponse>(`/findings${qs ? `?${qs}` : ""}`);
  },
  evidence: () => request<EvidenceResponse>("/evidence"),
  iocs: () => request<IocsResponse>("/iocs"),
  todos: (status?: string) =>
    request<TodosResponse>(`/todos${status ? `?status=${status}` : ""}`),
  summary: () => request<SummaryResponse>("/summary"),
  transparency: () => request<TransparencyResponse>("/transparency"),
  auditForFinding: (findingId: string) =>
    request<AuditResponse>(`/audit/${findingId}`),

  // Mode 1
  ask: (question: string, limit?: number) =>
    post<AskResponse>("/mode1/ask", { question, limit }),
  // WP 4b.12: api.select removed — Mode 1 selection flows through the
  // Workbench (bookmark → promote); the legacy /mode1/select endpoint
  // remains available to the legacy HTML pages only.

  // Explore
  search: (params: {
    query?: string;
    needles?: string;
    family?: string;
    host?: string;
    start?: string;
    end?: string;
    limit?: number;
    offset?: number;
  }) => post<SearchResponse>("/explore/search", params),
  aggregate: (params: { query?: string; group_by: string }) =>
    post<AggregateResponse>("/explore/aggregate", params),
  histogram: (params: {
    needles?: string;
    family?: string;
    start?: string;
    end?: string;
    bucket?: number;
  }) => post<HistogramResponse>("/explore/histogram", params),
  // WP 4j.1: hit interpretation — what the row means + what to check next
  hitInterpret: (hit: N4Hit, rag = true) =>
    post<HitInterpretation>("/hit/interpret", { hit, rag }),

  // Workbench
  workbench: () => request<WorkbenchResponse>("/workbench"),
  workbenchAdd: (hit: N4Hit, note?: string) =>
    post<WorkbenchAddResponse>("/workbench/add", { hit, note }),
  workbenchRemove: (bookmarkId: string) =>
    post<WorkbenchRemoveResponse>("/workbench/remove", { bookmark_id: bookmarkId }),
  workbenchClear: () => post<WorkbenchClearResponse>("/workbench/clear"),
  workbenchPromote: (params: {
    bookmark_ids: string[];
    title: string;
    scribe?: boolean;
    interpretation?: string;
  }) => post<WorkbenchPromoteResponse>("/workbench/promote", params),

  // Chat
  chat: (limit?: number) =>
    request<ChatResponse>(`/chat${limit ? `?limit=${limit}` : ""}`),
  chatPost: (message: string) => post<ChatPostResponse>("/chat", { message }),
  chatClear: () => post<{ status: string }>("/chat/clear"),

  // Timeline
  timelineLanes: (params?: {
    query?: string;
    needles?: string;
    family?: string;
    start?: string;
    end?: string;
    bucket?: string;
  }) => post<TimelineLanesResponse>("/timeline/lanes", params || {}),

  // Entities
  entities: (params: { query?: string; needles?: string }) =>
    post<EntitiesResponse>("/entities", params),

  // Mode 2
  mode2Iterate: (params: { question: string; max_iterations?: number }) =>
    post<Mode2IterateResponse>("/mode2/iterate", params),
  mode2Corroborate: (params: { finding_id?: string }) =>
    post<CorroborationResponse>("/mode2/corroborate", params),
  mode2ProposeDraft: (params: { title: string; hits?: N4Hit[]; query?: string }) =>
    post<ProposeDraftResponse>("/mode2/propose-draft", params),

  // Mode 3
  mode3Plan: (params?: { question?: string }) =>
    post<Mode3PlanResponse>("/mode3/plan", params || {}),
  mode3Execute: (params: { extras?: string[]; queries?: string[] }) =>
    post<Mode3ExecuteResponse>("/mode3/execute", params),
  mode3Seal: (params: {
    challenge_id: string;
    response: string;
    examiner?: string;
  }) => post<Mode3SealResponse>("/mode3/seal", params),

  // Approval & Rejection
  getChallenge: () => request<ChallengeResponse>("/commit/challenge"),
  commit: (params: {
    finding_ids: string[];
    challenge_id: string;
    response: string;
    examiner?: string;
  }) => post<CommitResponse>("/commit", params),
  rejectFindings: (params: {
    finding_ids: string[];
    reason: string;
    examiner?: string;
  }) => post<{ ok: boolean; rejected: string[]; error?: string }>("/findings/reject", params),

  // Phase 4b/4c/4d: Workflow-driven cockpit
  seedDemo: (params?: { name?: string; activate?: boolean }) =>
    post<{
      ok: boolean;
      case_id: string;
      evidence_count: number;
      findings_count: number;
      active: string;
      error?: string;
    }>("/case/seed-demo", params || {}),
  caseDetails: (caseId?: string) =>
    request<CaseDetailsResponse>(`/case/details${caseId ? `?case_id=${caseId}` : ""}`),
  pipelineRun: (params: { mode: string; case_id?: string }) =>
    post<PipelineRunResponse>("/pipeline/run", params),
  pipelineStatus: (runId: string) =>
    request<PipelineStatusResponse>(`/pipeline/status?run_id=${runId}`),
  pipelineLedger: (caseId?: string) =>
    request<PipelineLedgerResponse>(
      `/pipeline/ledger${caseId ? `?case_id=${encodeURIComponent(caseId)}` : ""}`,
    ),
  caseBriefing: () => request<BriefingResponse>("/case/briefing"),
  fsList: (path?: string) =>
    request<FsListResponse>(`/fs/list${path ? `?path=${encodeURIComponent(path)}` : ""}`),
  playbookNeedles: (families?: string) =>
    request<PlaybookNeedlesResponse>(`/playbook/needles${families ? `?families=${families}` : ""}`),
  needleFeedback: (params: {
    needles: string[];
    family?: string;
    source?: string;
    verdict: "accept" | "reject" | "promote";
  }) =>
    post<{ ok: boolean; verdict: string; promoted?: Record<string, unknown>; error?: string }>(
      "/needles/feedback",
      params,
    ),
  setCaseMode: (mode: string, caseId?: string) =>
    post<CaseModeResponse>("/case/mode", { mode, case_id: caseId }),
  getCaseMode: (caseId?: string) =>
    request<CaseModeResponse>(`/case/mode${caseId ? `?case_id=${caseId}` : ""}`),
  systemHealth: () => request<SystemHealthResponse>("/system/health"),

  // Report & Evidence Verification
  reportGenerate: (params?: { profile?: string }) =>
    post<{ ok: boolean; report_path: string; findings_count: number; error?: string }>("/report/generate", params || {}),
  reportView: () =>
    request<{ ok: boolean; markdown: string; title?: string; error?: string }>("/report/view"),
  evidenceVerify: () =>
    post<{ ok: boolean; results: Array<{ name: string; file_path: string; valid: boolean; error?: string }> }>("/evidence/verify", {}),
};

// --- WP 4d.3: live steer-chat stream (SSE over fetch) ---

export type ChatStreamEvent =
  | { event: "status"; data: { stage: string; detail?: string; needles?: string[] } }
  | { event: "iteration"; data: Record<string, unknown> }
  | { event: "hits"; data: { hits: N4Hit[]; count?: number } }
  | { event: "done"; data: { reply: string; needles: string[]; count: number; backend?: string; hits?: N4Hit[] } }
  | { event: "error"; data: { error: string } };

/**
 * Stream a steer-chat turn via POST /chat/stream (SSE).
 * Calls onEvent for each server event; resolves when the stream ends.
 */
export async function chatStream(
  body: { message: string; mode: "mode1" | "mode2"; max_iterations?: number },
  onEvent: (evt: { event: string; data: Record<string, unknown> }) => void,
  signal?: AbortSignal,
): Promise<void> {
  const res = await fetch(`${BASE}/chat/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...caseHeaders() },
    body: JSON.stringify(body),
    signal,
  });
  if (!res.ok || !res.body) {
    let detail = res.statusText;
    try {
      const b = await res.json();
      detail = (b as { error?: string }).error || detail;
    } catch {
      // keep statusText
    }
    throw new ApiError(res.status, detail);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (value) {
      buf += decoder.decode(value, { stream: true });
      let idx: number;
      while ((idx = buf.indexOf("\n\n")) >= 0) {
        const raw = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        let event = "message";
        const dataLines: string[] = [];
        for (const line of raw.split("\n")) {
          if (line.startsWith("event: ")) event = line.slice(7).trim();
          else if (line.startsWith("data: ")) dataLines.push(line.slice(6));
        }
        if (event === "ping") continue;
        let parsed: Record<string, unknown> = {};
        try {
          parsed = JSON.parse(dataLines.join("\n")) as Record<string, unknown>;
        } catch {
          parsed = {};
        }
        onEvent({ event, data: parsed });
      }
    }
    if (done) break;
  }
}
