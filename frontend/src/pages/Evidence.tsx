/**
 * Evidence registry + N2 lane controls (WP 4b.8 + 4d), migrated to the kit
 * (WO-U8a).
 *
 * Kit: PageHeader + Panel + EmptyState + Badge + StatusPill + Button, plus the
 * two copy primitives the review asked for — CopyablePath for the path,
 * CopyableHash for the SHA-256. Styles in a CSS module; zero inline style
 * objects.
 *
 * Data: four case-scoped queries (registry, parser ledger, timestamp coverage,
 * A5 freshness) and two mutations (register, verify). The old page held 17
 * pieces of component state and re-fetched by calling `load()`, so a
 * registration on one surface left the registry stale everywhere else.
 *
 * Two behaviours kept deliberately:
 * * **Verify is on demand.** It reads every registered file off disk. It must
 *   not fire because a page mounted.
 * * **Registering reports per-path failures.** A batch of ten where the third
 *   fails says so rather than reporting the batch as done.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { api, type PipelineStageLine, type PipelineStatusResponse } from "../api/client";
import {
  useCaseIntake,
  useEvidenceRegistry,
  usePipelineLedger,
  useRegisterEvidence,
  useTsCoverage,
  useVerifyEvidence,
} from "../api/queries/evidence";
import { useEvidenceFreshness } from "../api/queries/summary";
import { useCase } from "../context/CaseContext";
import {
  Badge,
  Button,
  CopyableHash,
  CopyablePath,
  EmptyState,
  PageHeader,
  Panel,
  StatusPill,
  type SemanticTone,
} from "@/ui";
import EvidencePicker from "../components/EvidencePicker";
import LiveRunFeed from "../components/LiveRunFeed";
import styles from "./Evidence.module.css";
import table from "./Page.module.css";

/** WO-A5: the freshness word, from the polled summary — never a re-hash. */
const FRESHNESS_TONES: Record<string, SemanticTone> = {
  ok: "fresh-ok",
  modified: "fresh-modified",
  missing: "fresh-modified",
  unknown: "fresh-stale",
};

const LEDGER_TONES: Record<string, SemanticTone> = {
  OK: "seal-verified",
  SKIP: "l1-unsupported",
  FAIL: "verifier-refuted",
  ERROR: "verifier-refuted",
};

function ledgerTone(status: string | undefined): SemanticTone | undefined {
  return LEDGER_TONES[(status || "").toUpperCase()];
}

export default function Evidence() {
  const { activeCase, refreshStages, mode: caseMode, setMode } = useCase();
  const freshness = useEvidenceFreshness(activeCase);

  const registry = useEvidenceRegistry(activeCase);
  const intake = useCaseIntake(activeCase);
  const ledgerQuery = usePipelineLedger(activeCase);
  const register = useRegisterEvidence(activeCase);
  const verify = useVerifyEvidence(activeCase);

  const [runId, setRunId] = useState("");
  const [runStatus, setRunStatus] = useState("");
  const [runStages, setRunStages] = useState<PipelineStageLine[]>([]);
  const [runProg, setRunProg] = useState<PipelineStatusResponse["progress"] | null>(null);
  const [busy, setBusy] = useState(false);
  const [showPicker, setShowPicker] = useState(false);
  const [dismissVerify, setDismissVerify] = useState(false);
  const [localError, setLocalError] = useState("");

  // Timestamp coverage refreshes after each lane run.
  const [coverageNonce, setCoverageNonce] = useState(0);
  const tsCoverage = useTsCoverage(activeCase, { enabled: coverageNonce >= 0 });

  const evidence = registry.data?.evidence ?? [];
  const ledger = ledgerQuery.data?.ledger ?? [];
  const ledgerEvidence = ledgerQuery.data?.evidence_paths ?? [];
  const coverage = tsCoverage.data ?? {};
  const verifyResult = verify.data ?? null;

  const error =
    localError ||
    (registry.error as Error | null)?.message ||
    (register.error as Error | null)?.message ||
    (verify.error as Error | null)?.message ||
    "";

  // Poll handle, cleared on unmount and before any new poll.
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(
    () => () => {
      if (pollRef.current) clearInterval(pollRef.current);
    },
    [],
  );

  const refreshAll = useCallback(async () => {
    await Promise.all([
      registry.refetch(),
      ledgerQuery.refetch(),
      setCoverageNonce((n) => n + 1),
    ]);
    if (activeCase) await refreshStages(activeCase);
  }, [activeCase, ledgerQuery, refreshStages, registry]);

  const startPolling = useCallback(
    (rid: string) => {
      if (pollRef.current) clearInterval(pollRef.current);
      const poll = setInterval(async () => {
        try {
          const status = await api.pipelineStatus(rid);
          setRunStatus(status.status);
          if (status.stages) setRunStages(status.stages);
          if (status.progress) setRunProg(status.progress);
          if (status.status === "complete" || status.status === "error") {
            clearInterval(poll);
            pollRef.current = null;
            setBusy(false);
            if (status.status === "error") {
              setLocalError(status.error || "Pipeline failed");
            } else {
              await refreshAll();
            }
          }
        } catch {
          // keep polling: a transient failure is not a failed run
        }
      }, 3000);
      pollRef.current = poll;
    },
    [refreshAll],
  );

  // Re-attach to an in-flight run after a reload (the run id was client state).
  useEffect(() => {
    if (!activeCase || runId) return;
    let cancelled = false;
    (async () => {
      try {
        const active = await api.pipelineActive(activeCase).catch(() => null);
        if (cancelled || !active?.run_id || active.status !== "running") return;
        setRunId(active.run_id);
        setRunStatus(active.status);
        if (active.stages) setRunStages(active.stages);
        if (active.progress) setRunProg(active.progress);
        startPolling(active.run_id);
      } catch {
        /* nothing to re-attach */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeCase, runId, startPolling]);

  const registerPaths = useCallback(
    async (paths: string[]) => {
      setLocalError("");
      try {
        await register.mutateAsync(paths);
        await refreshAll();
      } catch {
        // the mutation already carries the per-path failure list
      }
    },
    [refreshAll, register],
  );

  const runN2 = async () => {
    // Mode 2/3 needs the examiner's question: the interpretation reconciles
    // evidence against it, and running the lane without it produces a case
    // that looks processed and is not. Restored after the migration - the
    // guard is behaviour, not decoration.
    if (caseMode !== "1" && !intake.data?.question.trim()) {
      setLocalError(
        "Mode 2/3 needs an examiner question — add it in Case Setup (N1) first; " +
          "the interpretation reconciles evidence against that question.",
      );
      return;
    }
    setBusy(true);
    setLocalError("");
    try {
      const response = await api.pipelineRun({
        mode: "tools",
        case_id: activeCase,
      });
      setRunId(response.run_id);
      setRunStatus("running");
      setRunStages([]);
      setRunProg(null);
      startPolling(response.run_id);
    } catch (exc) {
      setLocalError((exc as Error).message);
      setBusy(false);
    }
  };

  const freshnessResult = freshness.data?.result ?? "unknown";
  const pipelineComplete = Boolean(ledgerQuery.data?.run_status === "complete");

  const headerActions = activeCase ? (
    <div className={styles.actions}>
      <StatusPill
        tone={FRESHNESS_TONES[freshnessResult] ?? "fresh-stale"}
        label={
          freshnessResult === "ok" ? "Evidence verified" : `Evidence ${freshnessResult}`
        }
      />
      <span
        title={pipelineComplete ? "The N2 lane completed" : "The N2 lane has not run"}
      >
        {pipelineComplete ? "✓ N2 lane complete" : "N2 lane not run"}
      </span>
      <span
        title={
          caseMode
            ? `Investigation Mode ${caseMode} — processing runs the matching pipeline`
            : "No investigation mode set for this case: analysis runs the parsing lane only."
        }
      >
        {caseMode ? `Mode ${caseMode}` : "No mode set"}
      </span>
      {!caseMode ? (
        <>
          {(["1", "2", "3"] as const).map((mode) => (
            <Button
              key={mode}
              size="sm"
              onClick={() => {
                setMode(mode).catch((exc) => setLocalError((exc as Error).message));
              }}
            >
              Set Mode {mode}
            </Button>
          ))}
        </>
      ) : null}
      <Button
        size="sm"
        onClick={() => verify.mutate()}
        disabled={verify.isPending || evidence.length === 0}
        title="Cryptographically verify SHA-256 hashes against disk files"
      >
        {verify.isPending ? "Verifying…" : "Verify hashes"}
      </Button>
      <Button size="sm" onClick={() => setShowPicker(true)}>
        + Add evidence
      </Button>
      <Button
        variant="primary"
        size="sm"
        onClick={runN2}
        disabled={busy || runStatus === "running"}
        title={
          caseMode === "2"
            ? "Parse and index. The multi-role run starts on Agent Run, not here."
            : caseMode === "3"
              ? "Parse and index. The multi-agent team starts on Agent Run, not here."
              : "Parse and index. Mode 1 LLM work is Briefing and Steer Chat."
        }
      >
        {busy ? "Starting…" : "▶ Run N2 lane"}
      </Button>
    </div>
  ) : null;

  return (
    <div className={styles.page}>
      <PageHeader
        title="Evidence Registry"
        subtitle={
          registry.isLoading
            ? "Loading…"
            : `${evidence.length} registered item${evidence.length === 1 ? "" : "s"}`
        }
        stageCode="N2"
        actions={headerActions}
      />

      {error ? (
        <div role="alert" className="error-banner">
          {error}
        </div>
      ) : null}

      {verifyResult && !dismissVerify ? (
        <div
          role="status"
          data-testid="evidence-verify-verdict"
          className={
            verifyResult.failed === 0
              ? `${styles.verdict} ${styles.verdictOk}`
              : `${styles.verdict} ${styles.verdictBad}`
          }
        >
          <span>
            {verifyResult.failed === 0
              ? `✓ Integrity verified: all ${verifyResult.valid} registered file${
                  verifyResult.valid === 1 ? "" : "s"
                } match their recorded SHA-256 hashes.`
              : `⚠ Integrity mismatch: ${verifyResult.failed} of ${verifyResult.total} file${
                  verifyResult.total === 1 ? "" : "s"
                } failed hash validation.`}
          </span>
          <Button size="sm" onClick={() => setDismissVerify(true)} aria-label="Dismiss">
            ✕
          </Button>
        </div>
      ) : null}

      {runId ? (
        <Panel className={styles.runLine}>
          Pipeline run <code>{runId}</code> —{" "}
          <StatusPill
            tone={
              runStatus === "complete"
                ? "run-complete"
                : runStatus === "error"
                  ? "run-failed"
                  : "run-running"
            }
            label={runStatus}
          />
          {runStatus === "running" ? " (polling…)" : null}
          {runStatus === "running" ? (
            <div className={styles.runFeed}>
              <LiveRunFeed stages={runStages} progress={runProg ?? undefined} maxHeight={220} />
            </div>
          ) : null}
        </Panel>
      ) : null}

      {activeCase && ledger.length > 0 ? (
        <Panel
          title={`N2 parser lane — ${
            ledger.filter((row) => (row.status || "").toUpperCase() === "OK").length
          }/${ledger.length} OK${
            ledgerQuery.data?.run_id ? ` · run ${ledgerQuery.data.run_id}` : ""
          }${ledgerQuery.data?.run_status ? ` · ${ledgerQuery.data.run_status}` : ""}`}
        >
          {ledgerEvidence.length > 0 ? (
            <div className={styles.evidenceList}>
              <strong>Evidence processed:</strong>
              {ledgerEvidence.map((path) => (
                <div key={path} className={table.mono}>
                  {path}
                </div>
              ))}
            </div>
          ) : null}
          <div className={styles.scrollBox}>
            <table className={table.table}>
              <caption className="visually-hidden">Parser lane ledger</caption>
              <thead>
                <tr>
                  <th scope="col">Tool</th>
                  <th scope="col">Status</th>
                  <th scope="col">Command</th>
                  <th scope="col">Output</th>
                  <th scope="col">Detail / reason</th>
                </tr>
              </thead>
              <tbody>
                {ledger.map((row, index) => (
                  <tr key={`${row.tool}-${index}`}>
                    <td className={table.mono}>{row.tool || "—"}</td>
                    <td>
                      <Badge tone={ledgerTone(row.status)}>{row.status || "—"}</Badge>
                    </td>
                    <td
                      className={`${table.mono} ${styles.truncate}`}
                      title={Array.isArray(row.argv) ? row.argv.join(" ") : ""}
                    >
                      {Array.isArray(row.argv) && row.argv.length
                        ? row.argv.join(" ")
                        : "—"}
                    </td>
                    <td
                      className={`${table.mono} ${styles.truncate}`}
                      title={String(row.output_saved_to || "")}
                    >
                      {row.output_saved_to || "—"}
                    </td>
                    <td className={styles.reason}>{row.reason || row.detail || ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : null}

      {activeCase && Object.keys(coverage).length > 0 ? (
        <Panel title="Timestamp coverage (per family)">
          <div className={styles.coverage}>
            {Object.entries(coverage)
              .filter(
                ([, value]) =>
                  (value.present || 0) +
                    (value.missing || 0) +
                    (value.synthesized || 0) >
                  0,
              )
              .sort((a, b) => (b[1].present || 0) - (a[1].present || 0))
              .map(([family, value]) => {
                const notes: string[] = [];
                if (value.synthesized) notes.push(`${value.synthesized} synthesized`);
                if (value.tz_assumed) notes.push(`${value.tz_assumed} UTC-assumed`);
                if (value.year_assumed) notes.push(`${value.year_assumed} year-assumed`);
                const noTimes = (value.present || 0) === 0;
                return (
                  <div key={family} className={styles.coverageRow}>
                    <code>{family}</code>:{" "}
                    {noTimes ? (
                      <span className={styles.noTimes}>
                        no parsed event timestamps — {value.missing || 0} undated row(s);
                        do not read absence as timeline evidence
                      </span>
                    ) : (
                      <span>
                        {value.present} timestamped / {value.missing || 0} undated
                        {notes.length > 0 ? ` (${notes.join("; ")})` : ""}
                      </span>
                    )}
                  </div>
                );
              })}
          </div>
        </Panel>
      ) : null}

      <EvidencePicker
        open={showPicker}
        onClose={() => setShowPicker(false)}
        onAdd={registerPaths}
      />

      {evidence.length === 0 && !registry.isLoading ? (
        <EmptyState
          title="N2 — no evidence registered"
          hint={
            activeCase
              ? `Case ${activeCase} has no registered evidence yet. Choose "Add evidence" to browse files or folders, or register through the Case Setup wizard.`
              : "No active case. Start at N1 Case Setup to create a case and register evidence."
          }
          action={
            activeCase ? (
              <Button variant="primary" onClick={() => setShowPicker(true)}>
                + Add evidence
              </Button>
            ) : (
              <Link
                to="/case-setup"
                className="nx-button nx-button-primary"
                data-testid="evidence-goto-setup"
              >
                Go to Case Setup (N1)
              </Link>
            )
          }
        />
      ) : evidence.length > 0 ? (
        <Panel>
          <table className={table.table}>
            <caption className="visually-hidden">Registered evidence</caption>
            <thead>
              <tr>
                <th scope="col">Path</th>
                <th scope="col">SHA-256</th>
                <th scope="col">Integrity</th>
                <th scope="col">Description</th>
                <th scope="col">Status</th>
                <th scope="col">Registered</th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((item, index) => {
                const result =
                  verifyResult?.byKey[item.path ?? ""] ||
                  verifyResult?.byKey[item.name ?? ""];
                return (
                  <tr key={`${item.path ?? item.name ?? index}`}>
                    {/* CopyablePath / CopyableHash: an examiner registers an
                        artifact and then needs to paste that exact path and
                        that exact digest into another tool. */}
                    <td>
                      <CopyablePath value={item.path ?? ""} />
                    </td>
                    <td>
                      <CopyableHash value={item.sha256 ?? ""} />
                    </td>
                    <td>
                      {!result ? (
                        <span className={styles.reason}>Unverified</span>
                      ) : result.valid ? (
                        <Badge tone="seal-verified">✓ Intact</Badge>
                      ) : (
                        <span title={result.error}>
                          <Badge tone="verifier-refuted">✗ Failed</Badge>
                        </span>
                      )}
                    </td>
                    <td>{item.description}</td>
                    <td>{item.status}</td>
                    <td>{item.registered_at}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Panel>
      ) : null}
    </div>
  );
}
