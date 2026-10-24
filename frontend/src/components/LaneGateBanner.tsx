/**
 * The evidence gate on screen (hard rule, 2026-09-29): while any artifact is
 * unprocessed the analysis stages answer 409 - the examiner must see why here,
 * not discover it when a mode run refuses. Stages come from the same payload
 * the pipeline-status API serves (`lane_gate` + `n_stages`).
 *
 * Three honest states:
 *   blocked  - unprocessed artifacts are listed with their reasons
 *   clear    - the lane pass processed everything (skips are shown)
 *   not-yet  - no tool-lane pass recorded for this case
 */
import { useEffect, useState } from "react";
import { api, type LaneGate, type NStage } from "../api/client";
import { useCase } from "../context/CaseContext";
import styles from "./LaneGateBanner.module.css";

const STAGE_LABELS: Record<string, string> = {
  N1: "Intake",
  N2: "Process",
  N3: "Index",
  N4: "Query",
  N5: "Interpret",
  N6: "Approve",
  N7: "Timeline",
  N8: "Export",
};

function stageTone(status: string): string {
  if (status === "done") return styles.success;
  if (status === "blocked") return styles.danger;
  return styles.muted;
}

export default function LaneGateBanner() {
  const { activeCase } = useCase();
  const [gate, setGate] = useState<LaneGate | null>(null);
  const [stages, setStages] = useState<NStage[]>([]);
  const blocked = (gate?.status ?? "") === "blocked";
  const clear = (gate?.status ?? "") === "clear";
  const waiting = (gate?.status ?? "") === "waiting";
  const waitingCount = typeof gate?.waiting_count === "number" ? gate.waiting_count : undefined;

  useEffect(() => {
    if (!activeCase) {
      setGate(null);
      setStages([]);
      return;
    }
    let alive = true;
    const load = async () => {
      try {
        const r = await api.summary();
        if (!alive) return;
        setGate(r.lane_gate ?? null);
        setStages(r.n_stages ?? []);
      } catch {
        /* transient - keep the last known state */
      }
    };
    load();
    // Keep checking while lane work is blocked or waiting so a retry or SIFT
    // completion updates the banner without a reload.
    const timer = blocked || waiting ? window.setInterval(load, 30_000) : undefined;
    return () => {
      alive = false;
      if (timer !== undefined) window.clearInterval(timer);
    };
  }, [activeCase, blocked, waiting]);

  if (!activeCase) return null;

  const items = gate?.unprocessed ?? [];
  const notApplicable = gate?.not_applicable ?? [];
  const skips = gate?.examiner_skips ?? [];
  const outstanding = (gate?.jobs ?? []).filter((job) =>
    job.state === "failed" || job.state === "running" || job.state === "unknown",
  );
  const outstandingNames = outstanding
    .map((job) => job.family || job.purpose || job.tool || "")
    .filter(Boolean);
  const tone = blocked ? styles.danger : clear ? styles.success : waiting ? styles.warning : styles.muted;

  return (
    <div
      data-testid="lane-gate-banner"
      data-status={gate?.status ?? "not-yet"}
      className={styles.banner}
    >
      <div className={`${styles.box} ${tone}`}>
        <div className={styles.headline}>
          <strong className={styles.status}>
            {blocked
              ? "EVIDENCE GATE BLOCKED"
              : clear
                ? "Evidence gate: clear"
                : waiting
                  ? "EVIDENCE GATE WAITING"
                  : gate?.status && gate.status !== "absent"
                    ? `Evidence gate: ${gate.status}`
                    : "Evidence gate: no tool-lane pass recorded yet"}
          </strong>
          {blocked && (
            <span>
              {gate?.blocked_count ?? items.length} unprocessed artifact(s) - analysis stages are refused until
              the tools lane re-runs them or an examiner records <code>nexus lane skip</code> (password-verified,
              audited).
            </span>
          )}
          {(waiting || (waitingCount ?? 0) > 0) && (
            <span>
              {waitingCount !== undefined
                ? `${waitingCount} lane job(s) are waiting.`
                : "Lane work is waiting for the remote tool host."}
            </span>
          )}
          {typeof gate?.processed_count === "number" && (
            <span className={styles.meta}>
              {gate.processed_count} item(s) processed
            </span>
          )}
          {clear && skips.length > 0 && (
            <span className={styles.meta}>{skips.length} examiner skip(s) recorded</span>
          )}
          {gate?.run_id && (
            <span className={styles.runId}>run {gate.run_id}</span>
          )}
        </div>

        {outstandingNames.length > 0 && (
          <div data-testid="lane-gate-outstanding">
            Still outstanding: {outstandingNames.slice(0, 8).join(", ")}
            {outstandingNames.length > 8 ? ` +${outstandingNames.length - 8}` : ""}
          </div>
        )}

        {blocked && items.length > 0 && (
          <ul className={styles.list}>
            {items.slice(0, 6).map((it, i) => (
              <li key={`${it.tool}-${i}`} data-testid="lane-gate-item" className={styles.item}>
                <strong>{it.tool || "artifact"}</strong>
                {it.purpose ? ` - ${it.purpose}` : ""}
                {it.reason ? `: ${it.reason}` : ""}
              </li>
            ))}
            {items.length > 6 && <li>+{items.length - 6} more</li>}
          </ul>
        )}

        {notApplicable.length > 0 && (
          <div data-testid="lane-gate-not-applicable" className={styles.notApplicable}>
            <strong>Not applicable:</strong>
            <ul className={styles.listTight}>
              {notApplicable.map((item, i) => (
                <li key={`${item.tool}-${i}`} className={styles.item}>
                  <strong>{item.tool || "artifact"}</strong>
                  {item.purpose ? ` - ${item.purpose}` : ""}
                  {item.reason ? `: ${item.reason}` : ""}
                </li>
              ))}
            </ul>
          </div>
        )}

        {stages.length > 0 && (
          <div className={styles.stages}>
            {stages.map((s) => (
              <span
                key={s.stage}
                data-testid={`nstage-${s.stage}`}
                title={s.detail || `${s.stage}: ${STAGE_LABELS[s.stage] ?? ""}`}
                className={`${styles.stage} ${stageTone(s.status ?? "")}`}
              >
                {s.stage} {STAGE_LABELS[s.stage] ?? ""} · {s.status ?? "?"}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
