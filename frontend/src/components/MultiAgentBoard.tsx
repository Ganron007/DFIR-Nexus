/**
 * Mode 3 — Multi-agent Investigation Board (runtime mode 3).
 *
 * The concurrent surface: several seats work in the same superstep, publish
 * claims on a shared board, and a join opens disputes / re-dispatches. This is
 * deliberately different from the multi-role Agent Run lanes: the unit here is
 * a *claim*, not a work order.
 *
 * Examiner controls: start, steer, pause/resume, stop, re-attach, stage DRAFTs.
 * Agents never stage or approve.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import styles from "../pages/AgentRun.module.css";
import {
  ApiError,
  api,
  mode3RunEventsPath,
  type AgentRunEvent,
  type Mode3BoardEntry,
  type Mode3BoardResponse,
  type Mode3Candidate,
  type Mode3Dispute,
  type Mode3RunStatus,
  type Mode3StageResult,
} from "../api/client";
import { Field, Select, Textarea } from "../ui/Field";

const TERMINAL = new Set(["completed", "failed", "paused", "stopped", "capped", "interrupted"]);
const MAX_EVENTS = 500;

function fmtTs(ts?: string): string {
  if (!ts) return "";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString([], { hour12: false });
}

function statusColor(status?: string): string {
  const s = (status || "").toLowerCase();
  if (s === "completed") return "var(--success)";
  if (s === "running") return "var(--accent)";
  if (s === "paused" || s === "stopped") return "var(--warning)";
  if (s === "failed") return "var(--danger)";
  return "var(--text-muted)";
}

function claimLine(claim: {
  entity_type?: string; entity_value?: string; claim_kind?: string;
  polarity?: string; value?: string; confidence?: string; audit_ids?: string[];
}): string {
  const head = [claim.entity_type, claim.entity_value, claim.claim_kind]
    .filter(Boolean)
    .join(":");
  const polarity = claim.polarity === "deny" ? "denies" : "affirms";
  return `${head} ${polarity} ${claim.value || ""}`.trim();
}

interface SeatTelemetry {
  agentId: string;
  role: string;
  family: string;
  superstep: number;
  why: string;
  calls: number;
  rounds: number;
  inFlightTool: string;
  lastTool: string;
  lastWhy: string;
  lastAuditId: string;
  state: "running" | "settled";
}

export default function MultiAgentBoard() {
  const [searchParams] = useSearchParams();
  const initialParamRun = (() => {
    const r = searchParams.get("run") || "";
    return r.startsWith("M3-") ? r : "";
  })();
  const [question, setQuestion] = useState("");
  const [contextPolicy, setContextPolicy] = useState<"independent" | "informed">(
    "independent",
  );
  const [runId, setRunId] = useState(initialParamRun);
  const [attachId, setAttachId] = useState(initialParamRun);
  const [status, setStatus] = useState<Mode3RunStatus | null>(null);
  const [boardData, setBoardData] = useState<Mode3BoardResponse | null>(null);
  const [events, setEvents] = useState<AgentRunEvent[]>([]);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [steerText, setSteerText] = useState("");
  const [stageResult, setStageResult] = useState<Mode3StageResult | null>(null);
  // Interaction log, from the board payload; falls back to the SSE stream so the
  // narrative still builds live before the first poll returns a timeline.
  const timeline = useMemo(() => {
    const fromBoard = boardData?.timeline ?? [];
    if (fromBoard.length) return fromBoard;
    return events
      .filter((e) => e.event_type)
      .map((e) => ({
        ts: e.ts || "",
        event: e.event_type,
        actor: e.actor,
        agent_id: e.agent_id,
        detail: e.detail,
        tool: e.tool,
        audit_id: e.audit_id,
      }));
  }, [boardData?.timeline, events]);
  const streamRef = useRef<HTMLDivElement | null>(null);

  const running = !!runId && !TERMINAL.has(status?.status || "");

  const refresh = async (id: string) => {
    try {
      const [s, b] = await Promise.all([
        api.mode3RunStatus(id),
        api.mode3RunBoard(id),
      ]);
      setStatus(s);
      setBoardData(b);
      return s;
    } catch {
      return null;
    }
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        if (initialParamRun) {
          const [s, b] = await Promise.all([
            api.mode3RunStatus(initialParamRun),
            api.mode3RunBoard(initialParamRun),
          ]);
          if (!cancelled) {
            setStatus(s);
            setBoardData(b);
          }
          return;
        }
        const s = await api.mode3RunStatus();
        if (!cancelled) {
          setStatus(s);
          setRunId(s.run_id);
          setAttachId(s.run_id);
          void api.mode3RunBoard(s.run_id).then((b) => !cancelled && setBoardData(b)).catch(() => undefined);
        }
      } catch {
        /* no prior run — start one below */
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!runId) return;
    setEvents([]);
    const source = new EventSource(mode3RunEventsPath(runId));
    const onAgent = (raw: MessageEvent) => {
      try {
        const event = JSON.parse(raw.data) as AgentRunEvent;
        setEvents((prev) => {
          const next = [...prev, event];
          return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next;
        });
      } catch {
        /* malformed frame */
      }
    };
    const onRun = () => {
      void refresh(runId);
      source.close();
    };
    source.addEventListener("agent", onAgent);
    source.addEventListener("run", onRun);
    return () => {
      source.removeEventListener("agent", onAgent);
      source.removeEventListener("run", onRun);
      source.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId]);

  useEffect(() => {
    if (!runId) return;
    const timer = window.setInterval(async () => {
      const s = await refresh(runId);
      if (s && TERMINAL.has(String(s.status || ""))) window.clearInterval(timer);
    }, 5000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId]);

  useEffect(() => {
    if (streamRef.current) {
      streamRef.current.scrollTop = streamRef.current.scrollHeight;
    }
  }, [events]);

  const board = useMemo(() => boardData?.board || [], [boardData]);
  const disputes = useMemo(() => boardData?.disputes || [], [boardData]);
  const candidates = useMemo(() => boardData?.candidates || [], [boardData]);

  const { seatTelemetry, lastSupervisorDetail, lastJoinDetail } = useMemo(() => {
    const map = new Map<string, SeatTelemetry>();
    let supDetail = "";
    let joinDetail = "";
    for (const ev of events) {
      const kind = ev.event_type || "";
      if (kind.startsWith("supervisor.") && ev.detail) {
        supDetail = ev.detail;
      } else if ((kind === "join.decision" || kind === "dispute.opened" || kind === "synthesis.composed") && ev.detail) {
        joinDetail = `${kind}: ${ev.detail}`;
      }
      const id = ev.agent_id || "";
      if (!id) continue;
      const data = (ev.data || {}) as Record<string, unknown>;
      const cur: SeatTelemetry = map.get(id) || {
        agentId: id,
        role: String(data.role || id.split(":")[0] || "seat"),
        family: String(data.family || ""),
        superstep: Number(data.superstep || status?.superstep || 1),
        why: String(data.why || ""),
        calls: 0,
        rounds: 0,
        inFlightTool: "",
        lastTool: "",
        lastWhy: "",
        lastAuditId: "",
        state: "running",
      };
      if (kind === "seat.started") {
        cur.state = "running";
        cur.role = String(data.role || cur.role);
        cur.family = String(data.family || cur.family);
        cur.superstep = Number(data.superstep || cur.superstep);
        cur.why = String(data.why || cur.why);
      } else if (kind === "agent.round") {
        const m = /round\s+(\d+)/i.exec(ev.detail || "");
        if (m) cur.rounds = Math.max(cur.rounds, Number(m[1]) || 0);
      } else if (kind === "tool.call") {
        cur.calls += 1;
        cur.inFlightTool = ev.tool || cur.inFlightTool;
        cur.lastTool = ev.tool || cur.lastTool;
        cur.lastWhy = ev.why || cur.lastWhy;
      } else if (kind === "tool.result") {
        cur.inFlightTool = "";
        if (ev.tool) cur.lastTool = ev.tool;
        if (ev.audit_id) cur.lastAuditId = ev.audit_id;
      } else if (kind === "board.entry") {
        cur.inFlightTool = "";
        cur.state = "settled";
      }
      map.set(id, cur);
    }
    for (const activeSeat of status?.agents_active ?? []) {
      const existing = map.get(activeSeat.agent_id);
      if (!existing) {
        map.set(activeSeat.agent_id, {
          agentId: activeSeat.agent_id,
          role: activeSeat.role || "seat",
          family: activeSeat.family || "",
          superstep: Number(activeSeat.superstep ?? status?.superstep ?? 1),
          why: activeSeat.why || "",
          calls: Number(activeSeat.calls || 0),
          rounds: Number(activeSeat.rounds || 0),
          inFlightTool: activeSeat.last_tool || "",
          lastTool: activeSeat.last_tool || "",
          lastWhy: activeSeat.last_why || "",
          lastAuditId: "",
          state: "running",
        });
      }
    }
    return {
      seatTelemetry: Array.from(map.values()),
      lastSupervisorDetail: supDetail,
      lastJoinDetail: joinDetail,
    };
  }, [events, status?.agents_active, status?.superstep]);

  const handleStart = async () => {
    setBusy("run");
    setError("");
    setStageResult(null);
    try {
      const r = await api.mode3Run({
        question: question.trim() || undefined,
        context_policy: contextPolicy,
      });
      setRunId(r.run_id);
      setAttachId(r.run_id);
      setEvents([]);
      void refresh(r.run_id);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Start failed");
    } finally {
      setBusy("");
    }
  };

  const handlePauseToggle = async () => {
    if (!runId) return;
    setBusy("pause");
    try {
      if (status?.status === "paused" || status?.status === "interrupted") {
        await api.mode3RunResume({ run_id: runId });
      } else {
        await api.mode3RunPause({ run_id: runId, paused: true });
      }
      await refresh(runId);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Pause/resume failed");
    } finally {
      setBusy("");
    }
  };

  const handleStop = async () => {
    if (!runId) return;
    setBusy("stop");
    try {
      await api.mode3RunStop({ run_id: runId });
      await refresh(runId);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Stop failed");
    } finally {
      setBusy("");
    }
  };

  const handleSteer = async () => {
    if (!runId || !steerText.trim()) return;
    setBusy("steer");
    try {
      await api.mode3RunSteer({ run_id: runId, text: steerText.trim() });
      setSteerText("");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Steering failed");
    } finally {
      setBusy("");
    }
  };

  const handleStage = async () => {
    if (!runId) return;
    setBusy("stage");
    try {
      const r = await api.mode3RunStage({ run_id: runId });
      setStageResult(r);
      await refresh(runId);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Staging failed");
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="agent-run">
      <div className="card" style={{ marginBottom: 12 }}>
        <div className="card-header">
          <span className="card-title">Investigation Board — Mode 3 Multi-agent</span>
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
            Concurrent seats · shared claim board · disputes · read-only audited tools · DRAFT-only
          </span>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <Field label="Examiner objective" hint="Blank uses the case intake question">
            {({ id, describedBy }) => (
              <Textarea
                id={id}
                aria-describedby={describedBy}
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                placeholder="Examiner objective (blank uses the case intake question)"
                rows={2}
              />
            )}
          </Field>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <Field label="Context policy" hint="independent = evidence, leads and digest only. informed = also passes prior reports and DRAFT summaries as labelled examiner context, never as evidence.">
              {({ id, describedBy }) => (
                <Select
                  id={id}
                  aria-describedby={describedBy}
                  data-testid="context-policy"
                  value={contextPolicy}
                  onChange={(e) =>
                    setContextPolicy(e.target.value as "independent" | "informed")
                  }
                >
                  <option value="independent">independent (evidence only)</option>
                  <option value="informed">informed (+ prior findings)</option>
                </Select>
              )}
            </Field>
            <button className="btn btn-sm btn-primary" onClick={handleStart} disabled={!!busy}>
              {busy === "run" ? "Spawning…" : "Start multi-agent run"}
            </button>
            <span style={{ flex: 1 }} />
            <input
              value={attachId}
              onChange={(e) => setAttachId(e.target.value)}
              placeholder="M3-…"
              style={{
                width: 200, background: "var(--bg-tertiary)", color: "var(--text-primary)",
                border: "1px solid var(--border)", borderRadius: 4,
                padding: "3px 6px", fontSize: 11, fontFamily: "monospace",
              }}
            />
            <button
              className="btn btn-sm"
              disabled={!attachId.trim()}
              onClick={() => {
                setRunId(attachId.trim());
                void refresh(attachId.trim());
              }}
            >
              Attach
            </button>
          </div>
          {error && <div style={{ color: "var(--danger)", fontSize: 12 }}>{error}</div>}
        </div>
      </div>

      {runId && (
        <div className="card" style={{ marginBottom: 12 }}>
          <div className="card-header">
            <span className="card-title" style={{ fontFamily: "monospace" }}>{runId}</span>
            <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span className="badge" style={{ color: statusColor(status?.status), borderColor: statusColor(status?.status) }}>
                {status?.status || "attached"}
              </span>
              {status?.stop_reason && (
                <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                  stop: {status.stop_reason}
                </span>
              )}
            </span>
          </div>
          <div className="agent-meters">
            <span>superstep <strong>{status?.superstep ?? 0}</strong></span>
            <span>board <strong>{status?.board ?? board.length}</strong></span>
            <span>disputes <strong>{status?.disputes ?? disputes.length}</strong></span>
            <span>candidates <strong>{status?.candidates ?? candidates.length}</strong></span>
            <span>events <strong>{events.length}</strong></span>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginTop: 8 }}>
            <button
              className="btn btn-sm"
              onClick={handlePauseToggle}
              disabled={!!busy || (!running && status?.status !== "paused" && status?.status !== "interrupted")}
            >
              {status?.status === "paused" || status?.status === "interrupted" ? "Resume" : "Pause"}
            </button>
            <button className="btn btn-sm btn-danger" onClick={handleStop} disabled={!!busy || !running}>
              {busy === "stop" ? "Stopping…" : "Stop"}
            </button>
            <input
              value={steerText}
              onChange={(e) => setSteerText(e.target.value)}
              placeholder="Steer the next superstep (e.g. 'chase host WS01')"
              onKeyDown={(e) => e.key === "Enter" && void handleSteer()}
              style={{
                flex: 1, minWidth: 220, background: "var(--bg-tertiary)",
                color: "var(--text-primary)", border: "1px solid var(--border)",
                borderRadius: 4, padding: "5px 8px", fontSize: 12,
              }}
            />
            <button className="btn btn-sm" onClick={handleSteer} disabled={!steerText.trim() || !!busy}>
              Steer
            </button>
            <button
              className="btn btn-sm btn-primary"
              onClick={handleStage}
              disabled={!!busy || candidates.length === 0}
              title="Stage settled, audit-backed claims as DRAFT findings (examiner action)"
            >
              {busy === "stage" ? "Staging…" : "Stage DRAFTs"}
            </button>
          </div>
          {stageResult && (
            <div style={{ marginTop: 8, fontSize: 12 }}>
              <div style={{ color: "var(--success)" }}>
                Staged {stageResult.staged_count ?? 0} DRAFT finding(s); skipped{" "}
                {stageResult.skipped_count ?? 0}.
              </div>
              {(stageResult.staged || []).map((s) => (
                <div key={s.finding_id || s.title} style={{ color: "var(--text-muted)" }}>
                  {s.finding_id} — {s.title}
                </div>
              ))}
              {(stageResult.skipped || []).map((s) => (
                <div key={s.title} style={{ color: "var(--warning)" }}>
                  skipped {s.title}: {s.reason}
                </div>
              ))}
              <div style={{ color: "var(--text-muted)" }}>DRAFT only — approve in the Approve desk.</div>
            </div>
          )}
        </div>
      )}

      {runId && (
        <div className={`card ${styles.topoCard}`} data-testid="orchestrator-topology">
          <div className="card-header">
            <span className="card-title">Orchestrator topology</span>
            <span className={styles.s3}>
              supervisor → concurrent seats → join &amp; verifier
            </span>
          </div>
          <div className={styles.topoFlow}>
            <div className={styles.topoNode}>
              <div className={styles.topoNodeHeader}>
                <span>
                  <strong>Supervisor</strong> · superstep {status?.superstep ?? 0}
                </span>
                <span className={styles.s3}>
                  {lastSupervisorDetail || status?.question || "coordinating seat dispatch"}
                </span>
              </div>
            </div>
            <div className={styles.topoConnector}>↓ parallel dispatch ({seatTelemetry.length} seat(s))</div>
            {seatTelemetry.length > 0 && (
              <div className={styles.topoSeatsGrid}>
                {seatTelemetry.map((s) => (
                  <div
                    key={s.agentId}
                    className={`${styles.topoSeatCard} ${s.state === "running" ? styles.topoSeatActive : ""}`}
                  >
                    <div className={styles.topoSeatHeader}>
                      <span className="badge">{`seat:${s.role}`}</span>
                      {s.family && <span className={styles.s11}>{s.family}</span>}
                      <span className={s.state === "running" ? styles.typeTool : styles.statusOk}>
                        {s.state === "running" ? "in-flight" : "settled"}
                      </span>
                    </div>
                    <div className={styles.topoMeta}>
                      step {s.superstep} · rounds {s.rounds} · calls {s.calls}
                    </div>
                    {(s.inFlightTool || s.lastTool) && (
                      <div className={styles.topoToolLine}>
                        {s.inFlightTool ? `running ${s.inFlightTool}` : `last ${s.lastTool}`}
                        {s.lastWhy ? ` · ${s.lastWhy}` : ""}
                        {s.lastAuditId ? ` [${s.lastAuditId}]` : ""}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
            <div className={styles.topoConnector}>↓ board claim join &amp; adversarial verifier</div>
            <div className={styles.topoNode}>
              <div className={styles.topoNodeHeader}>
                <span>
                  <strong>Join &amp; Verifier</strong> · disputes {status?.disputes ?? disputes.length} · candidates {status?.candidates ?? candidates.length}
                </span>
                <span className={styles.s3}>
                  {lastJoinDetail || (status?.status ? `run status: ${status.status}` : "awaiting seat reports")}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="agent-run-grid">
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              Agents running{" "}
              <span
                data-testid="agents-running"
                style={{
                  color: (status?.agents_running ?? 0) > 0 ? "var(--accent)" : "var(--text-muted)",
                }}
              >
                {status?.agents_running ?? 0}
              </span>
              {status?.agents_active?.length ? " of " : " · "}
              {(status?.roles ?? []).join(" / ") || "no seats dispatched yet"}
            </span>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              {status?.skills_used ?? 0} procedure(s) applied
            </span>
          </div>
          {(status?.agents_active ?? []).length === 0 ? (
            <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
              {status?.status && TERMINAL.has(String(status.status))
                ? "No agents in flight — the run has settled."
                : "No seat has started yet."}
            </div>
          ) : (
            <div className="agent-lanes">
              {(status?.agents_active ?? []).map((seat) => {
                const live = seatTelemetry.find((s) => s.agentId === seat.agent_id);
                const calls = live?.calls || seat.calls || 0;
                const rounds = live?.rounds || seat.rounds || 0;
                const activeTool = live?.inFlightTool || live?.lastTool || seat.last_tool || "";
                return (
                  <div key={seat.agent_id} className="agent-lane">
                    <div className={styles.s6}>
                      <span className="badge draft">{(seat.role || "seat").toUpperCase()}</span>
                      {seat.family && <span className="badge">{seat.family}</span>}
                      <span className={styles.s11}>
                        {seat.agent_id}
                      </span>
                      {seat.superstep != null && (
                        <span className={styles.s3}>
                          superstep {seat.superstep}
                        </span>
                      )}
                      {rounds > 0 && <span className={styles.s3}>round {rounds}</span>}
                      {calls > 0 && <span className={styles.s3}>calls {calls}</span>}
                      <span className={styles.s31}>working…</span>
                    </div>
                    {activeTool && (
                      <div className={styles.topoToolLine}>
                        tool: {activeTool}
                        {(live?.lastWhy || seat.last_why) ? ` · ${live?.lastWhy || seat.last_why}` : ""}
                      </div>
                    )}
                    {seat.why && (
                      <div className={styles.s14}>
                        spawned because: {seat.why}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
          {Boolean(timeline.length) && (
            <div style={{ marginTop: 10 }}>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                Interaction log ({timeline.length})
              </div>
              <div style={{ maxHeight: 180, overflowY: "auto" }}>
                {timeline.slice(-40).map((row, i) => (
                  <div
                    key={`${row.event}-${row.ts}-${i}`}
                    style={{ fontSize: 11, fontFamily: "monospace", color: "var(--text-muted)" }}
                  >
                    {row.event} {row.actor ? `· ${row.actor}` : ""}
                    {row.agent_id ? ` › ${row.agent_id}` : ""}
                    {row.detail ? ` · ${row.detail}` : ""}
                    {row.tool ? ` · tool=${row.tool}` : ""}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">Board — {board.length} seat entr{board.length === 1 ? "y" : "ies"}</span>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              claims carry audit IDs; disputes are gaps, not findings
            </span>
          </div>
          {board.length === 0 && (
            <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
              No board entries yet. Start a run to spawn seats.
            </div>
          )}
          <div className="agent-lanes">
            {board.map((entry: Mode3BoardEntry) => (
              <div key={entry.entry_id || entry.agent_id} className="agent-lane">
                <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <span className="badge draft">{(entry.role || "seat").toUpperCase()}</span>
                  {entry.family && <span className="badge">{entry.family}</span>}
                  <span style={{ fontFamily: "monospace", fontSize: 10, color: "var(--text-muted)" }}>
                    {entry.agent_id}
                  </span>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    superstep {entry.superstep}
                  </span>
                </div>
                {(entry.claims || []).map((claim, i) => (
                  <div key={`${entry.entry_id}-${i}`} style={{ fontSize: 12, marginTop: 4 }}>
                    <span style={{ color: claim.polarity === "deny" ? "var(--warning)" : "var(--success)" }}>
                      {claim.polarity === "deny" ? "DENY" : "AFFIRM"}
                    </span>{" "}
                    {claimLine(claim)}
                    {claim.confidence && (
                      <span style={{ color: "var(--text-muted)" }}> [{claim.confidence}]</span>
                    )}
                    {(claim.audit_ids || []).length > 0 && (
                      <div style={{ fontFamily: "monospace", fontSize: 10, color: "var(--accent)" }}>
                        {(claim.audit_ids || []).join(", ")}
                      </div>
                    )}
                  </div>
                ))}
                {(entry.open_questions || []).length > 0 && (
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 3 }}>
                    open: {(entry.open_questions || []).join(" · ")}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">Live event stream</span>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              supervisor.spawn · board.entry · join.decision · dispute.opened
            </span>
          </div>
          <div className="agent-stream" ref={streamRef}>
            {events.length === 0 && (
              <div style={{ color: "var(--text-muted)", fontSize: 12 }}>Waiting for events…</div>
            )}
            {events.map((e) => (
              <div key={e.event_id} className="agent-stream-line">
                <span className={styles.s21}>{fmtTs(e.ts)}</span>{" "}
                <strong>{e.event_type}</strong>{" "}
                {e.agent_id && <span className={styles.s21}>{e.agent_id}</span>}{" "}
                {e.tool && <span>{e.tool}</span>}{" "}
                {e.why && <span className={styles.s21}>· {e.why}</span>}{" "}
                {e.audit_id && (
                  <span className={styles.s31}>
                    audit={e.audit_id}
                  </span>
                )}{" "}
                {e.detail && <span>— {e.detail}</span>}
                {e.status && e.status !== "ok" && (
                  <span className={styles.s22}> [{e.status}]</span>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">Disputes &amp; DRAFT candidates</span>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              unresolved disputes stay gaps
            </span>
          </div>
          {disputes.length > 0 && (
            <div style={{ marginBottom: 10 }}>
              {disputes.map((d: Mode3Dispute, i) => (
                <div key={`${d.entity_value}-${d.claim_kind}-${i}`} style={{ fontSize: 12, marginBottom: 4 }}>
                  <span style={{ color: "var(--warning)", fontWeight: 600 }}>DISPUTE</span>{" "}
                  <strong>{d.entity_type}:{d.entity_value}</strong>{" "}
                  <span style={{ color: "var(--text-muted)" }}>
                    ({d.claim_kind}) seats: {(d.seats || []).join(", ") || "—"}
                  </span>
                </div>
              ))}
            </div>
          )}
          {candidates.length === 0 && disputes.length === 0 && (
            <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
              No settled candidates yet. They appear after the join settles.
            </div>
          )}
          {candidates.map((c: Mode3Candidate, i) => (
            <div key={`${c.title}-${i}`} className="agent-candidate">
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <strong style={{ fontSize: 12 }}>{c.title}</strong>
                <span className={`badge ${(c.confidence || "low").toLowerCase()}`}>
                  {c.confidence || "LOW"}
                </span>
              </div>
              {c.observation && <div style={{ fontSize: 12, marginTop: 3 }}>{c.observation}</div>}
              {(c.audit_ids || []).length > 0 && (
                <div style={{ fontFamily: "monospace", fontSize: 10, color: "var(--accent)", marginTop: 4 }}>
                  lineage: {(c.audit_ids || []).join(", ")}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
