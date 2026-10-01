import { BASE, ApiError, caseHeaders } from "./transport";

export { BASE, ApiError, request, post, caseHeaders, setRequestCaseId } from "./transport";

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
  /** Detection severity propagated from parser levels (critical..informational). */
  severity?: string;
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
  /** Approval-desk L1 verdict (WO-2) — attached to DRAFT rows only. */
  l1?: {
    verdict: string;
    counts: Record<string, number>;
    failing_checks: Array<{ id: string; detail: string }>;
  };
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

/** Evidence-gate state (hard rule, 2026-09-29): while any artifact is
 *  unprocessed the analysis stages answer 409; the banner surfaces it. */
export interface LaneGateItem {
  tool?: string;
  purpose?: string;
  reason?: string;
}
export interface LaneGateSkip {
  examiner?: string;
  tool?: string;
  purpose?: string;
  reason?: string;
  ts?: string;
}
export interface LaneGate {
  status?: "blocked" | "clear" | string;
  run_id?: string;
  blocked_count?: number;
  unprocessed?: LaneGateItem[];
  examiner_skips?: LaneGateSkip[];
  ts?: string;
}
/** N1-N8 stage state as served by the gate's lane_stages(). */
export interface NStage {
  stage: string;
  status?: string;
  detail?: string;
}

/** GET /summary → nested counts */
export interface SummaryResponse {
  findings: { total: number; draft: number; approved: number; rejected: number };
  timeline: number;
  evidence: number;
  todos: { total: number; open: number };
  /** Evidence gate + N1-N8 stages (present when a case is active). */
  lane_gate?: LaneGate;
  n_stages?: NStage[];
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
  /** Structured matched needles — a comma needle must not re-split (EH-8). */
  terms_list?: string[];
  text: string;
  fields?: Record<string, string>;
  host?: string;
  /** EH-7 provenance (present on imported/derived rows). */
  ts_synthesized?: boolean;
  ts_year_assumed?: boolean;
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
  /** WP 9.7 — detection-dictionary annotations (ICS/cloud/kernel/maldev). */
  det?: { id: string; name: string; platform: string; techniques: string[] }[];
  methodology?: string;
  sources: string[];
  error?: string;
}

/** POST /mode1/ask → {needles, window, hits, count, backend} or {needles: [], window, error} */
export interface AskResponse {
  needles: string[];
  window: string;
  /** WP 4j.11 — the structured query the LLM emitted (verbatim, validated). */
  query?: string;
  dsl?: boolean;
  dsl_fallback?: boolean;
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
  /** True when a cap was hit — ``count`` is a LOWER BOUND (EH-1). */
  count_lower_bound?: boolean;
  count_exact?: boolean;
  capped_reasons?: string[];
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

/** POST /workbench/add_many → {added, skipped, matched, truncated, total} */
export interface WorkbenchAddManyResponse {
  status: string;
  added: number;
  skipped: number;
  matched: number;
  truncated?: boolean;
  total: number;
  error?: string;
}

/** POST/GET /mode1/full-run[/status] → tracked run record (202 on start) */
export interface Mode1FullRunResponse {
  status: string; // running | complete | error | interrupted | never_run
  run_id?: string;
  stage?: string;
  current?: string;
  started_at?: number;
  updated_at?: number;
  completed_at?: number;
  needles_done?: number;
  needles_total?: number;
  needles_scanned: number;
  needles_hit_total?: number;
  needles_hit?: number;
  needles_capped?: number;
  scan_truncated?: boolean;
  bookmarks_added: number;
  drafts: { finding_id?: string; title: string; hits: number; families: string[]; confidence_adjusted?: string[] }[];
  drafts_staged?: number;
  superseded?: { needle: string; finding_id: string; replaced_by?: string }[];
  revised_approved?: { needle: string; finding_id?: string; prior_approved_ids: string[] }[];
  reprocess?: boolean;
  skipped: { needle?: string; reason: string }[];
  next?: string;
  error?: string;
  thread_alive?: boolean;
}

/** GET /commit/status → {examiner, password_configured, setup_hint} */
export interface CommitStatusResponse {
  examiner: string | null;
  password_configured: boolean;
  setup_hint: string | null;
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
  /** FD-006/007 auto-cap note — set when the draft's confidence was
      lowered to LOW because corroboration requirements weren't met. */
  confidence_adjusted?: string[];
  error?: string | string[];
}

/** Chat entry shape (from chat.py) — data.hits added by WP 4d.3 */
export interface ChatEntry {
  ts: string;
  role: string;
  action: string;
  text: string;
  meta?: Record<string, string>;
  data?: {
    hits?: N4Hit[];
    queries?: { tool: string; dsl: string; why?: string; hits: number; audit_id?: string }[];
    aggregations?: { field: string; distinct: number; top?: { value: string; count: number }[] }[];
    followups?: { label: string; question: string }[];
    /** WP 10.53: true when the turn returned rows on budget expiry. */
    partial?: boolean;
    /** Slim tool-call chain (tool/why/audit_id/summary counters). */
    tool_calls?: { tool: string; why?: string; audit_id?: string; elapsed_ms?: number }[];
    /** Set on `answer_saved` entries: the assistant message they refer to. */
    entry_ts?: string;
  };
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

/** POST /timeline/lanes → {families: [{family, buckets, buckets_sev}], total, bucket} */
export interface TimelineLaneEntry {
  family: string;
  buckets: Record<string, number>;
  /** WP — max detection severity per bucket (critical|high|medium|low|informational). */
  buckets_sev?: Record<string, string>;
}
export interface TimelineLanesResponse {
  families: TimelineLaneEntry[];
  total: number;
  bucket: string;
  /** Needles auto-injected when the query was empty (0 = explicit query). */
  default_needles?: number;
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
export interface Mode1Iteration {
  iteration: number;
  action: string;
  backend?: string;
  needles?: string[];
  rationale?: string;
  source?: string;
  hits?: number;
  new_families?: string[];
  /** WP 4j.10 — per-query detail (the structured queries actually executed) */
  query?: string;
  dsl?: boolean;
  fallback?: boolean;
  queries?: { query: string; dsl?: boolean; fallback?: boolean; hits?: number; audit_id?: string }[];
  /** WP 4j.12 — aggregations proposed + run through the backbone */
  aggregations?: { dsl?: string; field?: string; why?: string; distinct?: number; rows_scanned?: number; top?: { value: string; count: number }[]; audit_id?: string }[];
}
export interface Mode1IterateResponse {
  question: string;
  iterations: Mode1Iteration[];
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
  /** FD-006/007 auto-cap note — set when confidence was lowered to LOW. */
  confidence_adjusted?: string[];
  error?: string | string[];
}

/** POST /mode2/suggestions → suggested examiner questions for the chat */
export interface Mode1SuggestionsResponse {
  suggestions: { text: string; source: string }[];
  generated_by: string;
  cached?: boolean;
}

/** POST /mode2/save-answer → bookmark an answer's rows + record it for the report */
export interface Mode1SaveAnswerResponse {
  saved?: boolean;
  entry_ts?: string;
  bookmarked?: number;
  existed?: number;
  total?: number;
  saved_answers?: number;
  error?: string | string[];
}

/** POST /mode3/plan → {items, queries, rationale, created_at, lane_complete} */
export interface Mode2PlanItem {
  type: string;
  key?: string;
  tool?: string;
  purpose: string;
}
export interface Mode2PlanResponse {
  items: Mode2PlanItem[];
  queries: string[];
  rationale: string;
  created_at: string;
  lane_complete: boolean;
}

/** POST /mode3/execute → {status, extras_persisted, query_results, note} or {error} */
export interface Mode2ExecuteResponse {
  status: string;
  extras_persisted: string[];
  query_results: Array<{ query: string; count: number; error?: string }>;
  note: string;
  error?: string;
}

/* ── Mode 3 supervised agent run (M6) ─────────────────────────────────── */

export interface WorkOrderSkillRef {
  skill: string;
  title?: string;
  version?: string;
  score?: number;
  why?: string[];
  citations?: string[];
  mitre?: string[];
}

export interface WorkOrder {
  order_id: string;
  role: string;
  task: string;
  family?: string;
  why?: string;
  priority_tools?: string[];
  acceptance?: string;
  negative_evidence_rule?: string;
  skill_refs?: WorkOrderSkillRef[];
  status?: string;
}

export interface RunBudget {
  rounds: number;
  calls: number;
  seconds: number;
}

/** One observable agent-run event (never hidden reasoning). */
export interface AgentRunEvent {
  event_id: string;
  ts: string;
  run_id: string;
  event_type: string;
  actor: string;
  agent_id?: string;
  tool?: string;
  why?: string;
  audit_id?: string;
  status?: string;
  detail?: string;
  data?: Record<string, unknown>;
}

export interface CandidateFinding {
  title?: string;
  observation?: string;
  interpretation?: string;
  confidence?: string;
  confidence_justification?: string;
  audit_ids?: string[];
  attack_ids?: string[];
  itm_stage?: string;
  itm_objects?: string;
}

export interface Verdict {
  title?: string;
  class?: string;
  basis?: string;
  audit_ids?: string[];
}

export interface Mode2RunStatusResponse {
  run_id: string;
  status?: string;
  stop_reason?: string;
  pause_requested?: boolean;
  stop_requested?: boolean;
  question?: string;
  orders?: number;
  order_index?: number;
  followup_rounds?: number;
  results?: number;
  candidates?: number;
  gaps?: number;
  events?: number;
  last_event?: AgentRunEvent | null;
  verdicts?: Verdict[];
  candidate_findings?: CandidateFinding[];
  narrative?: string;
  created_at?: string;
  completed_at?: string;
  error?: string;
}

export interface Mode2RunPlanResponse {
  run_id: string;
  question: string;
  orders: WorkOrder[];
}

export interface Mode2StageResult {
  run_id: string;
  staged?: { title: string; finding_id?: string; input_call_ids?: string[]; verifier_class?: string }[];
  skipped?: { title: string; reason: string }[];
  staged_count?: number;
  skipped_count?: number;
  error?: string;
}

/** SSE path for a run's event stream (EventSource cannot send case headers). */
export function mode2RunEventsPath(runId: string): string {
  return `${BASE}/mode2/run/events?run_id=${encodeURIComponent(runId)}`;
}

/* ── Mode 3 — Multi-agent concurrent board ───────────────────────────── */

export interface Mode3Claim {
  entity_type?: string;
  entity_value?: string;
  claim_kind?: string;
  polarity?: string;
  value?: string;
  audit_ids?: string[];
  confidence?: string;
  confidence_justification?: string;
}

export interface Mode3BoardEntry {
  entry_id?: string;
  agent_id?: string;
  role?: string;
  family?: string;
  superstep?: number;
  claims?: Mode3Claim[];
  open_questions?: string[];
  note?: string;
}

export interface Mode3Dispute {
  entity_type?: string;
  entity_value?: string;
  claim_kind?: string;
  seats?: string[];
  families?: string[];
  audit_ids?: string[];
}

export interface Mode3Candidate {
  title?: string;
  observation?: string;
  confidence?: string;
  confidence_justification?: string;
  audit_ids?: string[];
  agent_id?: string;
}

export interface Mode3RunStatus {
  run_id: string;
  status?: string;
  stop_reason?: string;
  question?: string;
  superstep?: number;
  board?: number;
  disputes?: number;
  candidates?: number;
  gaps?: string[];
  /** How many agents are working right now (0 once the run settles). */
  agents_running?: number;
  agents_active?: Mode3ActiveSeat[];
  roles?: string[];
  skills_used?: number;
  events?: number;
  error?: string;
}

export interface Mode3ActiveSeat {
  agent_id: string;
  role: string;
  family?: string;
  superstep?: number;
  why?: string;
  started_at?: string;
}

export interface Mode3TimelineRow {
  ts: string;
  event: string;
  actor?: string;
  agent_id?: string;
  detail?: string;
  tool?: string;
  audit_id?: string;
  data?: Record<string, unknown>;
}

export interface Mode3SkillRef {
  skill: string;
  version?: string;
  role?: string;
}

export interface Mode3BoardResponse {
  run_id: string;
  board?: Mode3BoardEntry[];
  disputes?: Mode3Dispute[];
  candidates?: Mode3Candidate[];
  /** Seats started but not yet reported - the agents running right now. */
  active?: Mode3ActiveSeat[];
  /** Ordered log of how the agents interacted, for the board narrative. */
  timeline?: Mode3TimelineRow[];
  /** Which documented procedures this run used, with content versions. */
  skills_used?: Mode3SkillRef[];
}

export interface Mode3StageResult {
  run_id?: string;
  staged?: { title?: string; finding_id?: string; input_call_ids?: string[] }[];
  skipped?: { title?: string; reason?: string }[];
  staged_count?: number;
  skipped_count?: number;
  error?: string;
}

/** SSE path for a multi-agent run's event stream. */
export function mode3RunEventsPath(runId: string): string {
  return `${BASE}/mode3/run/events?run_id=${encodeURIComponent(runId)}`;
}

/** POST /case/seal → {status: "SEALED", case_id, examiner} or {error} */
export interface CaseSealResponse {
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

/** One live-feed line: a pipeline stage or a tool-lane job. */
export interface PipelineStageLine {
  ts?: string;
  /** Pipeline node name ("interpret", "execute_tool_lane", ...). */
  stage?: string;
  /** Tool-lane job fields. */
  tool?: string;
  host?: string;
  status?: string;
  detail?: string;
  /** Granular tool fields (live feed). */
  command?: string;
  purpose?: string;
  reason?: string;
  output?: string;
  duration_s?: number;
  audit_id?: string;
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
  /** True when the run got examiner intake (question/window) — N1 gate. */
  intake?: boolean;
  /** WP 4j.5d — live stage entries: pipeline nodes (stage/status/detail)
   *  merged with per-tool entries (tool/host/status/command/duration) while
   *  running. */
  stages?: PipelineStageLine[];
  /** WP 4j.5d — live counters from _tool_lane_progress.json. */
  progress?: {
    done: number;
    total: number;
    current?: string;
    /** The job currently executing (tool + exact command). */
    running?: { tool: string; host?: string; purpose?: string; command?: string };
  };
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
  /** F1 ubiquity demotion: matches a large share of the case — background,
   *  ranked last, never staged as a finding. */
  ubiquitous?: boolean;
}
/** Insider Threat Matrix coverage: hit counts per relevant needle pack
 *  (0 hits = negative evidence, not absence of risk). */
export interface BriefingItmCoverage {
  itm: string;
  name: string;
  hits: number;
  strong_hits?: number;
  caveat?: string;
}
/** Match-site fact: keyword matched an id/label column (EventId, Provider,
 *  RecordNumber...). A value in the evidence — a pivot, never signal. */
export interface BriefingNeedleFact {
  needle: string;
  hits: number;
  field?: string;
  class?: string;
}
export interface BriefingEntity {
  value: string;
  hits: number;
  families?: string[];
  /** Case-relative evidence file the entity was found in (provenance). */
  source_file?: string;
  source_family?: string;
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
  /** Id/label column matches (EventId, Provider, ...) — facts, not signal. */
  needle_facts?: BriefingNeedleFact[];
  /** Insider Threat Matrix pack coverage for this case (F3). */
  itm_coverage?: BriefingItmCoverage[];
  /** Hit count at/above which a needle is background (F1). */
  ubiquity_floor?: number;
  scanned_needles: number;
  entities: Record<string, BriefingEntity[]>;
  /** Host filesystem paths inside evidence content (NOT evidence files) —
   *  summarized instead of listed as top entities. */
  paths_summary?: { distinct: number; families: string[]; examples: string[] };
  intake: Record<string, string>;
  directions?: BriefingDirection[];
  walkthrough?: BriefingWalkthroughStep[];
  backend: string;
  hits_examined: number;
  /** WP 4j.5 — true when the needle scan hit its cap; chip counts are lower bounds. */
  scan_truncated?: boolean;
  /** Mode 2 — LLM interpretation markdown (verdict + findings + gaps + TI). */
  mode_interpretation?: string;
  /** Mode 2 — deterministic IOC sweep + provider verdicts (markdown). */
  ti_context?: string;
  /** Mode 2 — staged findings summary. */
  findings_summary?: {
    count: number;
    drafts: number;
    top: { id: string; title: string; severity: string; confidence: string }[];
  };
  /** WP 4j.5c — persisted offline copies (absolute paths on the server host). */
  artifacts?: { briefing_md?: string; signal_map_csv?: string };
  /** GATE-A — deterministic Case Digest exists (Mode 2/3). */
  digest_exists?: boolean;
  /** EH-1 — scan coverage accounting (lower-bound reasons when truncated). */
  scan_stats?: {
    terms_requested?: number;
    terms_queried?: number;
    files_total?: number;
    files_scanned?: number;
    truncated?: boolean;
    truncated_reasons?: string[];
    terms_failed?: string[];
    needles_dropped_cap?: string[];
  };
  error?: string;
}

/** GET /case/rounds → GATE-B interpret round log. */
export interface InterpretRound {
  round: number;
  kind: "orient" | "verify" | "notes";
  hypotheses?: { id: string; statement: string; why?: string }[];
  items?: Record<string, unknown>[];
  entries?: {
    kind: string;
    why?: string;
    params?: Record<string, unknown>;
    audit_id?: string;
    error?: string;
    count?: number;
    field?: string;
    distinct?: number;
    hits?: Record<string, unknown>[];
  }[];
  notes?: { hypothesis?: string; status?: string; evidence?: string; family?: string }[];
  next?: Record<string, unknown>[];
}
export interface InterpretRoundsResponse {
  summary: {
    rounds_requested: number;
    rounds_run: number;
    stop_reason: string;
    hypotheses: { id: string; statement: string; why?: string }[];
    notes: { hypothesis?: string; status?: string; evidence?: string }[];
    findings_emitted: number;
    reconciliation: { addressed: number; unaddressed: { kind: string; value: string }[] };
  } | null;
  rounds: InterpretRound[];
  error?: string;
}

/** GET /case/digest → deterministic Case Digest (Mode 2/3). */
export interface CaseDigestResponse {
  digest: {
    case_id: string;
    generated_at: string;
    scope: {
      families_present: Record<string, string[]>;
      evidence_classes_present: string[];
      explicitly_absent: string[];
    };
    inventory: Record<string, { files: number; rows: number; capped?: boolean }>;
    ledger: { ok: number; skip: number; fail: number; entries: unknown[] };
    hosts: string[];
    time_range: { start?: string; end?: string };
    signal_map: {
      scanned: number;
      with_hits: { needle: string; hits: number }[];
      zero_hit: string[];
      /** Needles that were NOT scanned (dropped cap/truncation) — shown so
       *  "scanned" can never be read as full coverage. */
      unscanned?: string[];
    };
    alerts: { level: string; family: string; title: string; host: string; time: string }[];
    entities: Record<string, { value: string; hits: number }[]>;
    entity_spans: Record<string, { value: string; count: number; first_seen?: string; last_seen?: string }[]>;
    timeline: { buckets_per_day: Record<string, number>; source: string };
    ts_coverage?: Record<string, {
      present?: number; missing?: number; synthesized?: number;
      tz_assumed?: number; year_assumed?: number;
    }>;
    backend: string;
    scan_stats?: {
      truncated?: boolean;
      truncated_reasons?: string[];
    };
  };
  markdown: string;
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
  es?: { configured?: boolean; reachable?: boolean; url?: string; note?: string };
  rag?: { configured?: boolean; path?: string };
  llm?: { configured?: boolean; model?: string; base_url?: string };
  parser?: string;
  parser_error?: string;
  /** SIFT lane (operator 2026-09-29): reported only for a case that SELECTS it. */
  sift?: { selected?: boolean; reachable?: boolean | null; message?: string };
  fixes?: Record<string, string>;
}

/** POST /setup/env → writes allowlisted NEXUS_* keys to .env (secrets masked) */
export interface SetupEnvResponse {
  ok?: boolean;
  applied?: Record<string, string>;
  env_file?: string;
  error?: string;
}

/** POST /setup/rag → starts the RAG index download (202/409) */
export interface SetupTask {
  status: string;
  detail?: string;
  started_at?: string;
  finished_at?: string;
}
export interface SetupStatusResponse {
  tasks: Record<string, SetupTask>;
}

// --- API ---

import { casesApi } from "./domains/cases";
import { evidenceApi } from "./domains/evidence";
import { findingsApi } from "./domains/findings";
import { reportApi } from "./domains/report";
import { runsApi } from "./domains/runs";
import { searchApi } from "./domains/search";
import { systemApi } from "./domains/system";
import { timelineApi } from "./domains/timeline";

/**
 * The API facade (WO-U4): the same members as before, now grouped by domain
 * module behind this one object — callers do not change.
 */
export const api = {
  // WO-A10: namespaced on purpose - a spread would shadow the existing
  // api.histogram/searchApi methods with the timeline's.
  timeline: timelineApi,
  ...casesApi,
  ...evidenceApi,
  ...findingsApi,
  ...searchApi,
  ...runsApi,
  ...reportApi,
  ...systemApi,
};

// --- WP 4d.3: live steer-chat stream (SSE over fetch) ---

export type ChatStreamEvent =
  | { event: "status"; data: { stage: string; detail?: string; needles?: string[] } }
  | { event: "iteration"; data: Record<string, unknown> }
  // WP 10.53/10.54 — live bounded tool loop events.
  | { event: "round"; data: { round: number; max_rounds?: number } }
  | { event: "tool_call"; data: { round?: number; tool: string; args?: Record<string, unknown>; why?: string } }
  | { event: "tool_result"; data: { round?: number; tool: string; why?: string; audit_id?: string; summary?: Record<string, unknown>; error?: string; ms?: number } }
  | { event: "partial"; data: { reason: string; round?: number } }
  | { event: "hits"; data: { hits: N4Hit[]; count?: number } }
  | { event: "done"; data: { reply: string; needles?: string[]; count?: number; backend?: string; hits?: N4Hit[]; queries_executed?: unknown[]; tool_calls?: unknown[]; total_hits?: number; partial?: boolean } }
  | { event: "error"; data: { error: string } };

/**
 * Stream a steer-chat turn via POST /chat/stream (SSE).
 * Calls onEvent for each server event; resolves when the stream ends.
 */
export async function chatStream(
  body: {
    message: string;
    mode: "mode1" | "mode2";
    max_iterations?: number;
    history?: { role: string; text: string }[];
  },
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
