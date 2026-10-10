/**
 * Analysis - the case cockpit's mode picker (WO-1C item 5).
 *
 * One case, three modes. The examiner runs one mode, or all three in order (1 -> 2 -> 3), on the
 * evidence this case already has, and picks the context each run reads: independent (the default)
 * or informed. The server allows one analysis run at a time per case; a busy case says so.
 *
 * The page also shows the cross-mode view inside the case: which modes reached the same
 * conclusions, and where they contradict each other.
 */
import { useCallback, useRef, useState } from "react";

import { ApiError, api } from "../api/client";
import { useCrossMode } from "../api/queries/crossMode";
import type { CrossModeReport } from "../api/domains/runs";
import { useCase } from "../context/CaseContext";
import { Badge, Button, EmptyState, PageHeader, Panel, type SemanticTone } from "@/ui";
import {
  MODE_LABEL,
  MODE_ORDER,
  runModeSequence,
  type AnalysisMode,
  type ContextPolicy,
  type ModeRow,
  type ModeRunAdapter,
} from "./analysis/sequence";
import styles from "./Analysis.module.css";

const STATE_TONE: Record<ModeRow["state"], SemanticTone | undefined> = {
  waiting: undefined,
  running: "sev-info",
  done: "verifier-confirmed",
  failed: "verifier-refuted",
  refused: "verifier-refuted",
  "left-running": "l1-unsupported",
};

const STATE_WORD: Record<ModeRow["state"], string> = {
  waiting: "not started",
  running: "running",
  done: "complete",
  failed: "failed",
  refused: "refused",
  "left-running": "still running",
};

const MODE_HINT: Record<AnalysisMode, string> = {
  "1": "LLM reads the indexed hits and writes DRAFT findings.",
  "2": "Supervised role workers query the index and propose candidates.",
  "3": "Concurrent agents work the leads and a verifier checks each claim.",
};

/** The real adapter: the runs API the other cockpit pages already use. */
function runAdapter(caseId: string): ModeRunAdapter {
  return {
    async start(mode: AnalysisMode, policy: ContextPolicy) {
      if (mode === "1") {
        const r = await api.pipelineRun({ mode: "interpret", case_id: caseId, context: policy });
        if (!r.run_id) throw new Error(r.error || "The server did not start the run.");
        return { runId: r.run_id };
      }
      if (mode === "2") {
        const r = await api.mode2RunStart({ context: policy });
        if (!r.run_id) throw new Error(r.error || "The server did not start the run.");
        return { runId: r.run_id };
      }
      const r = await api.mode3Run({ context_policy: policy });
      if (!r.run_id) throw new Error(r.error || "The server did not start the run.");
      return { runId: r.run_id };
    },
    async status(mode: AnalysisMode, runId: string) {
      if (mode === "1") return (await api.pipelineStatus(runId)).status;
      if (mode === "2") return (await api.mode2RunStatus(runId)).status ?? "";
      return (await api.mode3RunStatus(runId)).status ?? "";
    },
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export default function Analysis() {
  const { activeCase } = useCase();
  const [chosen, setChosen] = useState<AnalysisMode[]>([]);
  const [policy, setPolicy] = useState<ContextPolicy>("independent");
  const [rows, setRows] = useState<ModeRow[]>([]);
  const [running, setRunning] = useState(false);
  const [startError, setStartError] = useState("");
  const controller = useRef<AbortController | null>(null);
  const cross = useCrossMode(activeCase);

  const toggle = (mode: AnalysisMode) =>
    setChosen((prev) => (prev.includes(mode) ? prev.filter((m) => m !== mode) : [...prev, mode]));

  const run = useCallback(async () => {
    if (!activeCase || chosen.length === 0) return;
    setStartError("");
    setRunning(true);
    const ac = new AbortController();
    controller.current = ac;
    try {
      const final = await runModeSequence({
        modes: chosen,
        policy,
        adapter: runAdapter(activeCase),
        onRows: setRows,
        sleep,
        pollMs: 2000,
        signal: ac.signal,
      });
      setRows(final);
    } catch (exc) {
      setStartError(exc instanceof ApiError ? exc.message : String(exc));
    } finally {
      controller.current = null;
      setRunning(false);
    }
  }, [activeCase, chosen, policy]);

  const runLabel =
    chosen.length === MODE_ORDER.length ? "Run all three (1 → 2 → 3)" : chosen.length > 1 ? `Run ${chosen.length} modes` : "Run";

  return (
    <div className={styles.page}>
      <PageHeader
        title="Analysis"
        stageCode="N5"
        subtitle="One case, three modes. Run one mode, or all three in order, on this case's evidence. One analysis run at a time."
      />

      <Panel title="Choose modes">
        <fieldset className={styles.modes}>
          <legend className={styles.legend}>Modes</legend>
          {MODE_ORDER.map((mode) => (
            <label key={mode} className={styles.mode}>
              <input
                type="checkbox"
                name="mode"
                value={mode}
                checked={chosen.includes(mode)}
                disabled={running}
                onChange={() => toggle(mode)}
              />
              <span className={styles.modeName}>{MODE_LABEL[mode]}</span>
              <span className={styles.modeHint}>{MODE_HINT[mode]}</span>
            </label>
          ))}
        </fieldset>

        <fieldset className={styles.modes}>
          <legend className={styles.legend}>Context each run reads</legend>
          <label className={styles.mode}>
            <input
              type="radio"
              name="context"
              value="independent"
              checked={policy === "independent"}
              disabled={running}
              onChange={() => setPolicy("independent")}
            />
            <span className={styles.modeName}>Independent (default)</span>
            <span className={styles.modeHint}>The evidence, the leads and the digest. Never other runs' findings.</span>
          </label>
          <label className={styles.mode}>
            <input
              type="radio"
              name="context"
              value="informed"
              checked={policy === "informed"}
              disabled={running}
              onChange={() => setPolicy("informed")}
            />
            <span className={styles.modeName}>Informed</span>
            <span className={styles.modeHint}>Earlier runs' reports and DRAFT summaries, as labelled context. Every claim still needs this run's own queries.</span>
          </label>
        </fieldset>

        <div className={styles.actions}>
          <Button
            variant="primary"
            onClick={() => void run()}
            disabled={!activeCase || chosen.length === 0 || running}
          >
            {runLabel}
          </Button>
          {running ? (
            <Button variant="secondary" onClick={() => controller.current?.abort()}>
              Stop following
            </Button>
          ) : null}
          {chosen.length === 0 ? <span className={styles.hint}>Choose one mode, or all three.</span> : null}
        </div>
        {startError ? <p role="alert" className={styles.error}>{startError}</p> : null}
      </Panel>

      <Panel title="Runs">
        {rows.length === 0 ? (
          <EmptyState title="No run started from this page yet." hint="Each run gets its own id and record. They appear here as they start." />
        ) : (
          <ol className={styles.rows} aria-label="Analysis runs">
            {rows.map((row) => (
              <li key={row.mode} className={styles.row} data-testid={`analysis-row-${row.mode}`}>
                <span className={styles.rowMode}>{MODE_LABEL[row.mode]}</span>
                <Badge tone={STATE_TONE[row.state]}>{STATE_WORD[row.state]}</Badge>
                {row.runId ? <code className={styles.runId}>{row.runId}</code> : null}
                {row.status ? <span className={styles.rowStatus}>server status: {row.status}</span> : null}
                {row.message ? <span className={styles.rowMessage}>{row.message}</span> : null}
              </li>
            ))}
          </ol>
        )}
      </Panel>

      <Panel title="Cross-mode view">
        {cross.isLoading ? (
          <p className={styles.hint}>Comparing this case's runs…</p>
        ) : cross.error ? (
          <EmptyState tone="error" title="The cross-mode view could not be read." hint={(cross.error as Error).message} />
        ) : (
          <CrossModeSummary report={cross.data} />
        )}
      </Panel>
    </div>
  );
}

function CrossModeSummary({ report }: { report: CrossModeReport | undefined }) {
  if (!report) return <EmptyState title="No comparison yet." />;
  if (report.error) return <EmptyState tone="error" title="The cross-mode view refused." hint={report.error} />;
  const present = report.modes_present ?? [];
  return (
    <div className={styles.cross}>
      <p>
        Modes with runs in this case: {present.length ? present.map((m) => `Mode ${m}`).join(", ") : "none yet"}.
      </p>
      <p>Conclusions more than one mode reached: {(report.shared ?? []).length}.</p>
      <p>Where the modes contradict each other: {(report.contradictions ?? []).length}.</p>
    </div>
  );
}
