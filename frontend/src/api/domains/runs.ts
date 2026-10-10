/**
 * Runs domain (WO-U4): the pipeline, the Mode 1 conversational surfaces, and
 * the Mode 2/3 agent runtimes with their control verbs.
 */
import { post, request } from "../transport";
import type {
  AskResponse,
  ChatPostResponse,
  ChatResponse,
  CorroborationResponse,
  Mode1IterateResponse,
  Mode1SaveAnswerResponse,
  Mode1SuggestionsResponse,
  Mode2ExecuteResponse,
  Mode2PlanResponse,
  Mode2RunPlanResponse,
  Mode2RunStatusResponse,
  Mode2StageResult,
  Mode3BoardResponse,
  Mode3RunStatus,
  Mode3StageResult,
  N4Hit,
  PipelineLedgerResponse,
  PipelineRunResponse,
  PipelineStatusResponse,
  ProposeDraftResponse,
} from "../client";

/** GET /cross-mode - shared conclusions and contradictions across this case's modes (WO-1C item 5). */
export interface CrossModeReport {
  modes_present?: string[];
  modes_missing?: string[];
  shared?: unknown[];
  contradictions?: unknown[];
  error?: string;
  [key: string]: unknown;
}

export const runsApi = {
  crossMode: () => request<CrossModeReport>("/cross-mode"),

  ask: (question: string, limit?: number) =>
    post<AskResponse>("/mode1/ask", { question, limit }),

  pipelineRun: (params: { mode: string; case_id?: string; question?: string; window?: string; host?: string; notes?: string; interpret_rounds?: number; context_window?: number; context?: "independent" | "informed" }) =>
    post<PipelineRunResponse>("/pipeline/run", params),
  pipelineStatus: (runId: string) =>
    request<PipelineStatusResponse>(`/pipeline/status?run_id=${runId}`),
  /** Re-attach to the newest (or still-running) pipeline run of a case. */
  pipelineActive: (caseId?: string) =>
    request<PipelineStatusResponse>(
      `/pipeline/status${caseId ? `?case_id=${encodeURIComponent(caseId)}` : ""}`,
    ),
  pipelineLedger: (caseId?: string) =>
    request<PipelineLedgerResponse>(
      `/pipeline/ledger${caseId ? `?case_id=${encodeURIComponent(caseId)}` : ""}`,
    ),

  // Steer chat transcript
  chat: (limit?: number) =>
    request<ChatResponse>(`/chat${limit ? `?limit=${limit}` : ""}`),
  chatPost: (message: string) => post<ChatPostResponse>("/chat", { message }),
  chatClear: () => post<{ status: string }>("/chat/clear"),

  // Mode 1 — LLM (ask / guided chat / iterate)
  mode1Iterate: (params: { question: string; max_iterations?: number }) =>
    post<Mode1IterateResponse>("/mode1/iterate", params),
  /** WP 4j.13 — POST /mode1/chat → the conversational evidence agent */
  mode1Chat: (params: { message: string; history?: { role: string; text: string }[] }) =>
    post<{
      reply: string;
      queries_executed: { tool: string; dsl: string; why?: string; hits: number; audit_id?: string }[];
      total_hits: number;
      confidence: string;
      /** WP 4j.33 — per-stage timings in ms (plan/execute/helpers/answer). */
      timings_ms?: Record<string, number>;
      stages?: { stage: string; ms: number; detail?: string }[];
      /** 4j-H.8 — deterministic drill-down chips for the next turn. */
      followups?: { label: string; question: string }[];
      /** Cited rows for bookmarking/explore (top N). */
      hits?: N4Hit[];
      error?: string;
    }>("/mode1/chat", params),
  mode1Corroborate: (params: { finding_id?: string }) =>
    post<CorroborationResponse>("/mode1/corroborate", params),
  mode1ProposeDraft: (params: { title: string; hits?: N4Hit[]; query?: string }) =>
    post<ProposeDraftResponse>("/mode1/propose-draft", params),
  mode1Suggestions: () => post<Mode1SuggestionsResponse>("/mode1/suggestions", {}),
  mode1SaveAnswer: (params: { entry_ts: string; note?: string }) =>
    post<Mode1SaveAnswerResponse>("/mode1/save-answer", params),

  // Mode 2 — legacy plan/execute sliver
  mode2Plan: (params?: { question?: string }) =>
    post<Mode2PlanResponse>("/mode2/plan", params || {}),
  mode2Execute: (params: { extras?: string[]; queries?: string[] }) =>
    post<Mode2ExecuteResponse>("/mode2/execute", params),
  // Mode 2 — Multi-role supervised agent run (M6) — same runtime/event stream as the CLI.
  mode2RunPlan: (params: { question?: string; max_orders?: number }) =>
    post<Mode2RunPlanResponse>("/mode2/run/plan", params),
  // WO-1C item 3: the context policy is decided before the run and recorded on it.
  mode2RunStart: (params: { question?: string; max_orders?: number; run_id?: string; context?: "independent" | "informed" }) =>
    post<{ run_id: string; status: string; question?: string; error?: string }>(
      "/mode2/run",
      params,
    ),
  mode2RunStatus: (runId?: string) =>
    request<Mode2RunStatusResponse>(
      `/mode2/run/status${runId ? `?run_id=${encodeURIComponent(runId)}` : ""}`,
    ),
  mode2RunSteer: (params: { run_id: string; text: string }) =>
    post<{ run_id: string; steering: { ts: string; text: string } }>(
      "/mode2/run/steer",
      params,
    ),
  mode2RunPause: (params: { run_id: string; paused: boolean }) =>
    post<{ run_id: string; paused: boolean }>("/mode2/run/pause", params),
  mode2RunStop: (params: { run_id: string }) =>
    post<{ run_id: string; stop_requested: boolean }>("/mode2/run/stop", params),
  mode2RunResume: (params: { run_id: string }) =>
    post<{ run_id: string; status: string }>("/mode2/run/resume", params),
  mode2RunStage: (params: { run_id: string }) =>
    post<Mode2StageResult>("/mode2/run/stage", params),
  // Mode 3 — Multi-agent concurrent board.
  mode3Run: (params: { question?: string; run_id?: string; context_policy?: "independent" | "informed" }) =>
    post<{ run_id: string; status: string; question?: string; error?: string }>(
      "/mode3/run",
      params,
    ),
  mode3RunStatus: (runId?: string) =>
    request<Mode3RunStatus>(
      `/mode3/run/status${runId ? `?run_id=${encodeURIComponent(runId)}` : ""}`,
    ),
  mode3RunBoard: (runId?: string) =>
    request<Mode3BoardResponse>(
      `/mode3/run/board${runId ? `?run_id=${encodeURIComponent(runId)}` : ""}`,
    ),
  mode3RunSteer: (params: { run_id: string; text: string }) =>
    post<{ run_id: string; steering: { ts: string; text: string } }>(
      "/mode3/run/steer",
      params,
    ),
  mode3RunPause: (params: { run_id: string; paused: boolean }) =>
    post<{ run_id: string; paused: boolean }>("/mode3/run/pause", params),
  mode3RunResume: (params: { run_id: string }) =>
    post<{ run_id: string; status: string }>("/mode3/run/resume", params),
  mode3RunStop: (params: { run_id: string }) =>
    post<{ run_id: string; stop_requested: boolean }>("/mode3/run/stop", params),
  mode3RunStage: (params: { run_id: string }) =>
    post<Mode3StageResult>("/mode3/run/stage", params),
};
