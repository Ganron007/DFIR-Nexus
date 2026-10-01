/**
 * The case status shape (WO-U3) - the one source the stepper, the gate banner
 * and every page header read. Mirrors `GET /portal/api/case/status`; a field
 * added there without adding it here is a bug in one of them, not here.
 */
export interface CaseStatusResponse {
  case_id: string;
  case_dir?: string;
  generated_at?: string;
  requested_case_id?: string;

  stages: { stage: string; status: string; detail: string }[];

  gate: {
    blocked: boolean;
    blocked_count: number;
    message: string;
    items?: { tool: string; purpose: string; reason: string }[];
  };

  index: {
    state: "built" | "unknown";
    docs: number | null;
    capped: boolean | null;
    errors?: number | null;
    index?: string | null;
    generated_at?: string | null;
  };

  runs: {
    pipeline: { state: string; run_id: string; stage: string; error: string };
    mode2: RunSummary;
    mode3: RunSummary;
  };

  findings: { total: number; by_status: Record<string, number> };

  report: {
    state: "present" | "absent";
    files?: string[];
    latest?: string;
    modified_at?: number;
  };

  freshness: {
    state?: string;
    modified?: number;
    missing?: number;
    total?: number;
    error?: string;
    [key: string]: unknown;
  };
}

export interface RunSummary {
  state: string;
  run_id: string;
  reason?: string;
  staged?: number | null;
}

/** The stage list a case has actually reached (derived, never invented). */
export function completedStages(status: CaseStatusResponse | null | undefined): string[] {
  if (!status?.stages) return [];
  return status.stages
    .filter((s) => ["complete", "done", "ok"].includes(String(s.status).toLowerCase()))
    .map((s) => s.stage);
}

/** One label for the case's state - the same words the header and banner use. */
export function caseStateLabel(status: CaseStatusResponse | null | undefined): string {
  if (!status) return "unknown";
  if (status.gate?.blocked) return "evidence gate blocked";
  const pipeline = status.runs?.pipeline?.state ?? "unknown";
  if (["running", "in_progress"].includes(pipeline)) return "running";
  if (status.report?.state === "present") return "report ready";
  if (status.index?.state === "built") return "indexed";
  if (status.findings?.total) return "findings staged";
  return "registered";
}