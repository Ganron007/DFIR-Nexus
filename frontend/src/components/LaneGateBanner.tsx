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

function stageColor(status: string): string {
  if (status === "done") return "var(--success)";
  if (status === "blocked") return "var(--danger)";
  return "var(--text-muted)";
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
  const tone = blocked ? "danger" : clear ? "success" : waiting ? "warning" : "muted";
  const border = {
    danger: "rgba(248,81,73,0.55)",
    success: "rgba(63,185,80,0.35)",
    warning: "rgba(210,153,34,0.55)",
    muted: "rgba(139,148,158,0.35)",
  }[tone];
  const background = {
    danger: "rgba(248,81,73,0.10)",
    success: "rgba(63,185,80,0.07)",
    warning: "rgba(210,153,34,0.08)",
    muted: "rgba(139,148,158,0.06)",
  }[tone];

  return (
    <div
      data-testid="lane-gate-banner"
      data-status={gate?.status ?? "not-yet"}
      style={{ margin: "8px 16px 0", fontSize: 12 }}
    >
      <div style={{ border: `1px solid ${border}`, background, borderRadius: 6, padding: "8px 12px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <strong
            style={{
              color: blocked
                ? "var(--danger)"
                : clear
                  ? "var(--success)"
                  : waiting
                    ? "#d29922"
                    : "var(--text-muted)",
            }}
          >
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
            <span style={{ color: "var(--text-muted)" }}>
              {gate.processed_count} item(s) processed
            </span>
          )}
          {clear && skips.length > 0 && (
            <span style={{ color: "var(--text-muted)" }}>{skips.length} examiner skip(s) recorded</span>
          )}
          {gate?.run_id && (
            <span style={{ color: "var(--text-muted)", fontSize: 11 }}>run {gate.run_id}</span>
          )}
        </div>

        {outstandingNames.length > 0 && (
          <div data-testid="lane-gate-outstanding">
            Still outstanding: {outstandingNames.slice(0, 8).join(", ")}
            {outstandingNames.length > 8 ? ` +${outstandingNames.length - 8}` : ""}
          </div>
        )}

        {blocked && items.length > 0 && (
          <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
            {items.slice(0, 6).map((it, i) => (
              <li key={`${it.tool}-${i}`} data-testid="lane-gate-item" style={{ lineHeight: 1.5 }}>
                <strong>{it.tool || "artifact"}</strong>
                {it.purpose ? ` - ${it.purpose}` : ""}
                {it.reason ? `: ${it.reason}` : ""}
              </li>
            ))}
            {items.length > 6 && <li>+{items.length - 6} more</li>}
          </ul>
        )}

        {notApplicable.length > 0 && (
          <div data-testid="lane-gate-not-applicable" style={{ marginTop: 6 }}>
            <strong>Not applicable:</strong>
            <ul style={{ margin: "2px 0 0", paddingLeft: 18 }}>
              {notApplicable.map((item, i) => (
                <li key={`${item.tool}-${i}`} style={{ lineHeight: 1.5 }}>
                  <strong>{item.tool || "artifact"}</strong>
                  {item.purpose ? ` - ${item.purpose}` : ""}
                  {item.reason ? `: ${item.reason}` : ""}
                </li>
              ))}
            </ul>
          </div>
        )}

        {stages.length > 0 && (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
            {stages.map((s) => (
              <span
                key={s.stage}
                data-testid={`nstage-${s.stage}`}
                title={s.detail || `${s.stage}: ${STAGE_LABELS[s.stage] ?? ""}`}
                style={{
                  fontFamily: "monospace",
                  fontSize: 10,
                  padding: "1px 6px",
                  borderRadius: 3,
                  border: `1px solid ${stageColor(s.status ?? "")}`,
                  color: stageColor(s.status ?? ""),
                }}
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
