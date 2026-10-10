/**
 * The analysis picker's run sequence (WO-1C item 5).
 *
 * One case, three modes. The examiner runs one mode, or all three in order (1 -> 2 -> 3).
 * The server runs one analysis run at a time per case, so the sequence starts a mode only
 * after the one before it reached its own terminal status. The sequence never starts a later
 * mode after an earlier one was refused or failed: that is reported, not papered over.
 *
 * Pure logic with an injected adapter, so the same rules are tested without the network.
 */

export type AnalysisMode = "1" | "2" | "3";
export type ContextPolicy = "independent" | "informed";

/** What the adapter does for one mode: start its run, then read its status. */
export interface ModeRunAdapter {
  /** Start the run. Throws with the server's reason when the start is refused. */
  start(mode: AnalysisMode, policy: ContextPolicy): Promise<{ runId: string }>;
  /** The run's current status word, as the server reports it. */
  status(mode: AnalysisMode, runId: string): Promise<string>;
}

export type RowState = "waiting" | "running" | "done" | "failed" | "refused" | "left-running";

export interface ModeRow {
  mode: AnalysisMode;
  state: RowState;
  runId?: string;
  status?: string;
  message?: string;
}

/** The status words each mode's run ends with (the server's own vocabulary). */
const TERMINAL: Record<AnalysisMode, { done: string[]; failed: string[] }> = {
  "1": { done: ["complete"], failed: ["error", "failed", "interrupted"] },
  "2": { done: ["completed"], failed: ["failed", "stopped"] },
  "3": { done: ["completed"], failed: ["failed", "stopped"] },
};

export const MODE_ORDER: AnalysisMode[] = ["1", "2", "3"];

export const MODE_LABEL: Record<AnalysisMode, string> = {
  "1": "Mode 1 — LLM interpretation",
  "2": "Mode 2 — multi-role",
  "3": "Mode 3 — multi-agent",
};

export interface RunSequenceOptions {
  modes: AnalysisMode[];
  policy: ContextPolicy;
  adapter: ModeRunAdapter;
  /** Called with a fresh copy of the rows after every change. */
  onRows: (rows: ModeRow[]) => void;
  /** Wait between status reads. Injected so tests do not sleep. */
  sleep: (ms: number) => Promise<void>;
  pollMs?: number;
  /** Stop following the runs; the server keeps any run it already started. */
  signal?: AbortSignal;
}

/** Run the chosen modes in order and return the final rows. */
export async function runModeSequence(opts: RunSequenceOptions): Promise<ModeRow[]> {
  const chosen = MODE_ORDER.filter((mode) => opts.modes.includes(mode));
  const rows: ModeRow[] = chosen.map((mode) => ({ mode, state: "waiting" }));
  const emit = () => opts.onRows(rows.map((row) => ({ ...row })));
  const pollMs = opts.pollMs ?? 2000;
  emit();

  for (let i = 0; i < rows.length; i += 1) {
    const row = rows[i];
    if (opts.signal?.aborted) {
      row.state = "waiting";
      row.message = "Not started: the sequence was cancelled.";
      emit();
      continue;
    }

    row.state = "running";
    emit();
    let runId: string;
    try {
      ({ runId } = await opts.adapter.start(row.mode, opts.policy));
    } catch (exc) {
      row.state = "refused";
      row.message = exc instanceof Error ? exc.message : String(exc);
      emit();
      stopAfter(rows, i);
      break;
    }
    row.runId = runId;
    emit();

    const terminal = await followRun(row, opts, pollMs);
    emit();
    if (terminal === "done") continue;
    stopAfter(rows, i);
    break;
  }
  emit();
  return rows.map((row) => ({ ...row }));
}

/** Poll one run to its own terminal status. Returns how it ended. */
async function followRun(
  row: ModeRow,
  opts: RunSequenceOptions,
  pollMs: number,
): Promise<"done" | "failed" | "left-running"> {
  const term = TERMINAL[row.mode];
  for (;;) {
    if (opts.signal?.aborted) {
      row.state = "left-running";
      row.message = "Cancelled here. The run keeps going on the server; check its page.";
      return "left-running";
    }
    let status: string;
    try {
      status = await opts.adapter.status(row.mode, row.runId ?? "");
    } catch (exc) {
      row.state = "failed";
      row.message = `Could not read the run's status: ${exc instanceof Error ? exc.message : String(exc)}`;
      return "failed";
    }
    row.status = status;
    if (term.done.includes(status)) {
      row.state = "done";
      return "done";
    }
    if (term.failed.includes(status)) {
      row.state = "failed";
      row.message = `The run ended as "${status}".`;
      return "failed";
    }
    await opts.sleep(pollMs);
  }
}

/** Later modes never start after a refusal or failure; say so on their rows. */
function stopAfter(rows: ModeRow[], index: number): void {
  for (const later of rows.slice(index + 1)) {
    later.state = "waiting";
    later.message = `Not started: ${MODE_LABEL[rows[index].mode]} did not complete.`;
  }
}
