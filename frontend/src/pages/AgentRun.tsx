/**
 * Mode 3 — Agent Run view (M6).
 *
 * One enterprise surface for the supervised agent investigation:
 *   - plan preview + approve-and-run (the examination gate before agents act)
 *   - live agent/task board with budget meters
 *   - live event stream (SSE) with why/audit_id and filters
 *   - hypothesis board (verifier verdicts) + DRAFT candidate findings
 *   - controls: pause/resume, steering, examiner-gated DRAFT staging
 *
 * It consumes the same run API and event envelope as `nexus mode3`; the CLI
 * and this page are two surfaces over one runtime.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  ApiError,
  api,
  mode3RunEventsPath,
  type Mode3Budget,
  type Mode3CandidateFinding,
  type Mode3RunEvent,
  type Mode3RunStatusResponse,
  type Mode3StageResult,
  type Mode3WorkOrder,
  type Mode3Verdict,
} from "../api/client";

const TERMINAL = new Set(["completed", "failed", "paused", "stopped"]);
const MAX_EVENTS = 800;

function fmtTs(ts?: string): string {
  if (!ts) return "";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString([], { hour12: false });
}

function num(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : 0;
}

function statusColor(status?: string): string {
  const s = (status || "").toLowerCase();
  if (s === "completed" || s === "ok") return "var(--success)";
  if (s === "running" || s === "fallback" || s === "paused") return "var(--warning)";
  if (s === "failed" || s === "error" || s === "unparsed") return "var(--danger)";
  return "var(--text-muted)";
}

function verdictColor(cls?: string): string {
  const c = (cls || "").toLowerCase();
  if (c === "confirmed") return "var(--success)";
  if (c === "inferred") return "var(--warning)";
  if (c === "refuted") return "var(--danger)";
  return "var(--text-muted)";
}

interface Lane {
  agentId: string;
  role: string;
  orderId: string;
  family: string;
  status: string;
  rounds: number;
  maxRounds: number;
  calls: number;
  rows: number;
  partial: boolean;
  skills: string[];
  budget?: Mode3Budget;
  lastDetail: string;
}

function buildLanes(events: Mode3RunEvent[]): Lane[] {
  const lanes = new Map<string, Lane>();
  const ensure = (e: Mode3RunEvent): Lane => {
    const id = e.agent_id || "unknown";
    let lane = lanes.get(id);
    if (!lane) {
      lane = {
        agentId: id,
        role: "",
        orderId: "",
        family: "",
        status: "running",
        rounds: 0,
        maxRounds: 0,
        calls: 0,
        rows: 0,
        partial: false,
        skills: [],
        lastDetail: "",
      };
      lanes.set(id, lane);
    }
    return lane;
  };
  for (const e of events) {
    if (!e.agent_id) continue;
    const lane = ensure(e);
    if (e.detail) lane.lastDetail = e.detail;
    const data = e.data || {};
    switch (e.event_type) {
      case "work_order.started": {
        lane.role = String(data.role || "");
        lane.orderId = String(data.order_id || "");
        lane.family = String(data.family || "");
        lane.status = "running";
        const skills = Array.isArray(data.skills) ? data.skills : [];
        lane.skills = skills.map((s) => {
          const item = s as { skill?: string; version?: string };
          return item.version ? `${item.skill} v${item.version}` : String(item.skill || "");
        });
        const budget = data.budget as Mode3Budget | undefined;
        if (budget && typeof budget.rounds === "number") lane.budget = budget;
        break;
      }
      case "agent.round": {
        const m = /round\s+(\d+)\s*\/\s*(\d+)/i.exec(e.detail || "");
        if (m) {
          lane.rounds = Math.max(lane.rounds, num(m[1]));
          lane.maxRounds = Math.max(lane.maxRounds, num(m[2]));
        }
        break;
      }
      case "tool.call":
        lane.calls += 1;
        break;
      case "tool.result": {
        const summary = (data.summary || {}) as Record<string, unknown>;
        lane.rows += Math.max(
          num(summary.returned),
          num(summary.rows),
          Array.isArray(summary.hits) ? summary.hits.length : 0,
        );
        break;
      }
      case "work_order.completed": {
        lane.status = e.status || "ok";
        const m = /(\d+)\s+row\(s\)/i.exec(e.detail || "");
        if (m) lane.rows = Math.max(lane.rows, num(m[1]));
        break;
      }
      case "work_order.failed":
        lane.status = "fallback";
        break;
      case "agent.partial":
        lane.partial = true;
        break;
      default:
        break;
    }
  }
  return Array.from(lanes.values());
}

function TypeBadge({ kind }: { kind: string }) {
  const color =
    kind.startsWith("tool.")
      ? "var(--accent)"
      : kind.startsWith("work_order") || kind.startsWith("agent")
        ? "var(--success)"
        : kind.startsWith("run") || kind.startsWith("plan")
          ? "var(--warning)"
          : "var(--text-muted)";
  return (
    <span
      style={{
        color,
        border: `1px solid ${color}`,
        borderRadius: 3,
        padding: "0 4px",
        fontSize: 10,
        fontFamily: "monospace",
        whiteSpace: "nowrap",
      }}
    >
      {kind}
    </span>
  );
}

export default function AgentRun() {
  const [params, setParams] = useSearchParams();
  const [question, setQuestion] = useState("");
  const [maxOrders, setMaxOrders] = useState(6);
  const [runId, setRunId] = useState<string>(params.get("run") || "");
  const [attachId, setAttachId] = useState(params.get("run") || "");
  const [plan, setPlan] = useState<Mode3WorkOrder[] | null>(null);
  const [record, setRecord] = useState<Mode3RunStatusResponse | null>(null);
  const [events, setEvents] = useState<Mode3RunEvent[]>([]);
  const [steerText, setSteerText] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [stageResult, setStageResult] = useState<Mode3StageResult | null>(null);
  const [autoscroll, setAutoscroll] = useState(true);
  const [filters, setFilters] = useState<Record<string, boolean>>({
    tool: true,
    agent: true,
    lifecycle: true,
  });
  const streamRef = useRef<HTMLDivElement | null>(null);

  const refreshStatus = async (id: string) => {
    try {
      const status = await api.mode3RunStatus(id);
      setRecord(status);
      return status;
    } catch {
      return null;
    }
  };

  // Initial attach: latest run when no id is given.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        if (!runId) {
          const status = await api.mode3RunStatus();
          if (!cancelled) {
            setRecord(status);
            setRunId(status.run_id);
            setAttachId(status.run_id);
          }
        } else {
          await refreshStatus(runId);
        }
      } catch {
        /* no prior run — the setup card is the entry point */
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // SSE stream: live events + terminal close.
  useEffect(() => {
    if (!runId) return;
    setEvents([]);
    const source = new EventSource(mode3RunEventsPath(runId));
    const onAgent = (raw: MessageEvent) => {
      try {
        const event = JSON.parse(raw.data) as Mode3RunEvent;
        setEvents((prev) => {
          const next = [...prev, event];
          return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next;
        });
      } catch {
        /* ignore malformed frame */
      }
    };
    const onRun = () => {
      void refreshStatus(runId);
      source.close();
    };
    source.addEventListener("agent", onAgent);
    source.addEventListener("run", onRun);
    source.onerror = () => {
      /* EventSource reconnects automatically; status poll covers gaps. */
    };
    return () => {
      source.removeEventListener("agent", onAgent);
      source.removeEventListener("run", onRun);
      source.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId]);

  // Status poll while a run is live (events come over SSE; record fields poll).
  useEffect(() => {
    if (!runId) return;
    const timer = window.setInterval(async () => {
      const status = await refreshStatus(runId);
      if (status && TERMINAL.has(String(status.status || ""))) {
        window.clearInterval(timer);
      }
    }, 5000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId]);

  useEffect(() => {
    if (autoscroll && streamRef.current) {
      streamRef.current.scrollTop = streamRef.current.scrollHeight;
    }
  }, [events, autoscroll]);

  const lanes = useMemo(() => buildLanes(events), [events]);

  const shownEvents = useMemo(
    () =>
      events.filter((e) => {
        const t = e.event_type || "";
        if (t.startsWith("tool.")) return filters.tool;
        if (t.startsWith("work_order") || t.startsWith("agent") || t.startsWith("verify") || t.startsWith("finding")) {
          return filters.agent;
        }
        return filters.lifecycle;
      }),
    [events, filters],
  );

  const verdictFor = (title?: string): Mode3Verdict | undefined =>
    (record?.verdicts || []).find(
      (v) => (v.title || "").toLowerCase() === (title || "").toLowerCase(),
    );

  const setUrlRun = (id: string) => {
    const next = new URLSearchParams(params);
    if (id) next.set("run", id);
    else next.delete("run");
    setParams(next, { replace: true });
  };

  const handlePreview = async () => {
    setBusy("plan");
    setError("");
    setStageResult(null);
    try {
      const result = await api.mode3RunPlan({
        question: question.trim() || undefined,
        max_orders: maxOrders,
      });
      setPlan(result.orders);
      setQuestion(result.question || question);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Plan request failed");
    } finally {
      setBusy("");
    }
  };

  const handleStart = async () => {
    setBusy("run");
    setError("");
    setStageResult(null);
    try {
      const result = await api.mode3RunStart({
        question: question.trim() || undefined,
        max_orders: maxOrders,
      });
      setEvents([]);
      setRunId(result.run_id);
      setAttachId(result.run_id);
      setUrlRun(result.run_id);
      setPlan(null);
      void refreshStatus(result.run_id);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Run start failed");
    } finally {
      setBusy("");
    }
  };

  const handlePauseToggle = async () => {
    if (!runId || !record) return;
    setBusy("pause");
    try {
      const paused = !record.pause_requested;
      await api.mode3RunPause({ run_id: runId, paused });
      if (paused) {
        await refreshStatus(runId);
      } else {
        const res = await api.mode3RunResume({ run_id: runId });
        if (res.status) {
          window.setTimeout(() => void refreshStatus(runId), 500);
        }
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Pause/resume failed");
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
      await refreshStatus(runId);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Steering failed");
    } finally {
      setBusy("");
    }
  };

  const handleStop = async () => {
    if (!runId) return;
    setBusy("stop");
    try {
      await api.mode3RunStop({ run_id: runId });
      await refreshStatus(runId);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Stop failed");
    } finally {
      setBusy("");
    }
  };

  const handleStage = async () => {
    if (!runId) return;
    setBusy("stage");
    setError("");
    try {
      const result = await api.mode3RunStage({ run_id: runId });
      setStageResult(result);
      await refreshStatus(runId);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Staging failed");
    } finally {
      setBusy("");
    }
  };

  const handleExport = () => {
    if (!runId) return;
    const payload = { record, events };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${runId}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const status = record?.status || (runId ? "running" : "");
  const running = !!runId && !TERMINAL.has(status);

  return (
    <div className="agent-run">
      <div className="card" style={{ marginBottom: 12 }}>
        <div className="card-header">
          <span className="card-title">Agent Run — Mode 3</span>
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
            Supervised agents · read-only tools · every call audited · DRAFT-only
          </span>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <textarea
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Examiner question / task (blank uses the case intake question)"
            rows={2}
            style={{
              width: "100%",
              background: "var(--bg-tertiary)",
              color: "var(--text-primary)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              padding: "8px 10px",
              fontSize: 12,
              resize: "vertical",
            }}
          />
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
              Max work orders
              <input
                type="number"
                min={1}
                max={12}
                value={maxOrders}
                onChange={(e) => setMaxOrders(Math.max(1, Math.min(12, num(e.target.value) || 6)))}
                style={{
                  width: 56,
                  marginLeft: 6,
                  background: "var(--bg-tertiary)",
                  color: "var(--text-primary)",
                  border: "1px solid var(--border)",
                  borderRadius: 4,
                  padding: "3px 6px",
                  fontSize: 12,
                }}
              />
            </label>
            <button className="btn btn-sm" onClick={handlePreview} disabled={!!busy}>
              {busy === "plan" ? "Planning…" : "Preview plan"}
            </button>
            <button className="btn btn-sm btn-primary" onClick={handleStart} disabled={!!busy}>
              {busy === "run" ? "Starting…" : "Approve plan & run"}
            </button>
            <span style={{ flex: 1 }} />
            <label style={{ fontSize: 11, color: "var(--text-muted)" }}>
              Attach run
              <input
                value={attachId}
                onChange={(e) => setAttachId(e.target.value)}
                placeholder="M3-…"
                style={{
                  width: 210,
                  marginLeft: 6,
                  background: "var(--bg-tertiary)",
                  color: "var(--text-primary)",
                  border: "1px solid var(--border)",
                  borderRadius: 4,
                  padding: "3px 6px",
                  fontSize: 11,
                  fontFamily: "monospace",
                }}
              />
            </label>
            <button
              className="btn btn-sm"
              disabled={!attachId.trim()}
              onClick={() => {
                setRunId(attachId.trim());
                setUrlRun(attachId.trim());
              }}
            >
              Attach
            </button>
          </div>
          {error && <div style={{ color: "var(--danger)", fontSize: 12 }}>{error}</div>}
        </div>
      </div>

      {plan && (
        <div className="card" style={{ marginBottom: 12 }}>
          <div className="card-header">
            <span className="card-title">Plan preview — {plan.length} work order(s)</span>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              “Approve plan &amp; run” executes these with the previewed question
            </span>
          </div>
          <div className="agent-plan-list">
            {plan.map((order) => (
              <div key={order.order_id} className="agent-plan-item">
                <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <span className="badge draft">{(order.role || "?").toUpperCase()}</span>
                  {order.family && <span className="badge">{order.family}</span>}
                  <span style={{ fontFamily: "monospace", fontSize: 10, color: "var(--text-muted)" }}>
                    {order.order_id}
                  </span>
                </div>
                <div style={{ fontSize: 12, marginTop: 4 }}>{order.task}</div>
                {order.skill_refs && order.skill_refs.length > 0 && (
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                    skills:{" "}
                    {order.skill_refs
                      .map((s) => `${s.skill} v${s.version || "?"}`)
                      .join(", ")}
                  </div>
                )}
                {order.why && (
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                    why: {order.why}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {runId && (
        <div className="card" style={{ marginBottom: 12 }}>
          <div className="card-header">
            <span className="card-title" style={{ fontFamily: "monospace" }}>
              {runId}
            </span>
            <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span className="badge" style={{ color: statusColor(status), borderColor: statusColor(status) }}>
                {status || "attached"}
              </span>
              {record?.stop_reason && (
                <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                  stop: {record.stop_reason}
                </span>
              )}
            </span>
          </div>
          <div className="agent-meters">
            <span>
              orders <strong>{record?.order_index ?? 0}</strong>/{record?.orders ?? 0}
            </span>
            <span>
              results <strong>{record?.results ?? 0}</strong>
            </span>
            <span>
              follow-ups <strong>{record?.followup_rounds ?? 0}</strong>
            </span>
            <span>
              candidates <strong>{record?.candidates ?? 0}</strong>
            </span>
            <span>
              events <strong>{events.length}</strong>
            </span>
            <span>
              verdicts <strong>{record?.verdicts?.length ?? 0}</strong>
            </span>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginTop: 8 }}>
            <button className="btn btn-sm" onClick={handlePauseToggle} disabled={!!busy || (!running && !record?.pause_requested)}>
              {record?.pause_requested ? "Resume" : "Pause"}
            </button>
            <button
              className="btn btn-sm btn-danger"
              onClick={handleStop}
              disabled={!!busy || !running}
              title="Halt at the next work order (cooperative stop; nothing is staged or approved)"
            >
              {busy === "stop" ? "Stopping…" : "Stop"}
            </button>
            <input
              value={steerText}
              onChange={(e) => setSteerText(e.target.value)}
              placeholder="Steer the next work order (examiner directive)"
              style={{
                flex: 1,
                minWidth: 240,
                background: "var(--bg-tertiary)",
                color: "var(--text-primary)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                padding: "5px 8px",
                fontSize: 12,
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") void handleSteer();
              }}
            />
            <button className="btn btn-sm" onClick={handleSteer} disabled={!steerText.trim() || !!busy}>
              {busy === "steer" ? "Sending…" : "Steer"}
            </button>
            <button
              className="btn btn-sm btn-primary"
              onClick={handleStage}
              disabled={!!busy || !(record?.candidates ?? 0)}
              title="Stage the run's verified candidates as DRAFT findings (examiner action)"
            >
              {busy === "stage" ? "Staging…" : "Stage DRAFTs"}
            </button>
            <button
              className="btn btn-sm"
              onClick={handleExport}
              disabled={!runId}
              title="Download the run record + event stream as JSON (same payload as nexus mode3 export)"
            >
              Export run JSON
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
                  {s.verifier_class ? ` (verifier: ${s.verifier_class})` : ""}
                </div>
              ))}
              {(stageResult.skipped || []).map((s) => (
                <div key={s.title} style={{ color: "var(--warning)" }}>
                  skipped {s.title}: {s.reason}
                </div>
              ))}
              <div style={{ color: "var(--text-muted)", marginTop: 2 }}>
                DRAFT only — approval stays in the Approve desk.
              </div>
            </div>
          )}
        </div>
      )}

      <div className="agent-run-grid">
        <div className="card">
          <div className="card-header">
            <span className="card-title">Agents</span>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              {lanes.length} lane(s) — scoped read-only tools
            </span>
          </div>
          {lanes.length === 0 && (
            <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
              No agent activity yet. Preview a plan and run it, or attach an existing run.
            </div>
          )}
          <div className="agent-lanes">
            {lanes.map((lane) => (
              <div key={lane.agentId} className="agent-lane">
                <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <span className="badge draft">{(lane.role || "AGENT").toUpperCase()}</span>
                  <span style={{ fontFamily: "monospace", fontSize: 10, color: "var(--text-muted)" }}>
                    {lane.agentId}
                  </span>
                  <span style={{ color: statusColor(lane.status), fontSize: 11 }}>{lane.status}</span>
                  {lane.partial && (
                    <span className="badge" style={{ color: "var(--warning)", borderColor: "var(--warning)" }}>
                      partial
                    </span>
                  )}
                </div>
                <div className="agent-meters" style={{ marginTop: 4 }}>
                  <span>
                    rounds <strong>{lane.rounds}</strong>
                    {lane.maxRounds ? `/${lane.maxRounds}` : lane.budget ? `/${lane.budget.rounds}` : ""}
                  </span>
                  <span>
                    calls <strong>{lane.calls}</strong>
                    {lane.budget ? `/${lane.budget.calls}` : ""}
                  </span>
                  <span>
                    rows <strong>{lane.rows}</strong>
                  </span>
                </div>
                {lane.skills.length > 0 && (
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 3 }}>
                    skills: {lane.skills.join(", ")}
                  </div>
                )}
                {lane.lastDetail && (
                  <div
                    style={{
                      fontSize: 11,
                      color: "var(--text-muted)",
                      marginTop: 3,
                      overflowWrap: "anywhere",
                    }}
                  >
                    {lane.lastDetail}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">Live event stream</span>
            <span style={{ display: "flex", gap: 10, alignItems: "center", fontSize: 11 }}>
              {(
                [
                  ["tool", "tools"],
                  ["agent", "agents"],
                  ["lifecycle", "lifecycle"],
                ] as const
              ).map(([key, label]) => (
                <label key={key} style={{ color: "var(--text-muted)" }}>
                  <input
                    type="checkbox"
                    checked={filters[key]}
                    onChange={(e) => setFilters((f) => ({ ...f, [key]: e.target.checked }))}
                  />{" "}
                  {label}
                </label>
              ))}
              <label style={{ color: "var(--text-muted)" }}>
                <input
                  type="checkbox"
                  checked={autoscroll}
                  onChange={(e) => setAutoscroll(e.target.checked)}
                />{" "}
                follow
              </label>
            </span>
          </div>
          <div className="agent-stream" ref={streamRef}>
            {shownEvents.length === 0 && (
              <div style={{ color: "var(--text-muted)", fontSize: 12 }}>
                Waiting for events…
              </div>
            )}
            {shownEvents.map((e) => (
              <div key={e.event_id} className="agent-stream-line">
                <span style={{ color: "var(--text-muted)" }}>{fmtTs(e.ts)}</span>{" "}
                <TypeBadge kind={e.event_type} />{" "}
                {e.agent_id && (
                  <span style={{ color: "var(--text-muted)" }}>{e.agent_id}</span>
                )}{" "}
                {e.tool && <strong>{e.tool}</strong>}{" "}
                {e.why && <span style={{ color: "var(--text-muted)" }}>· {e.why}</span>}{" "}
                {e.audit_id && (
                  <span style={{ color: "var(--accent)", fontFamily: "monospace" }}>
                    audit={e.audit_id}
                  </span>
                )}{" "}
                {e.detail && <span>— {e.detail}</span>}
                {e.status && e.status !== "ok" && (
                  <span style={{ color: statusColor(e.status) }}> [{e.status}]</span>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">Hypotheses &amp; DRAFT candidates</span>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              verifier: confirmed / inferred / refuted
            </span>
          </div>
          {(record?.verdicts || []).length > 0 && (
            <div style={{ marginBottom: 10 }}>
              {(record?.verdicts || []).map((v) => (
                <div key={v.title || Math.random()} style={{ fontSize: 12, marginBottom: 4 }}>
                  <span style={{ color: verdictColor(v.class), fontWeight: 600 }}>
                    {(v.class || "?").toUpperCase()}
                  </span>{" "}
                  <strong>{v.title}</strong>
                  {v.basis && (
                    <span style={{ color: "var(--text-muted)" }}> — {v.basis}</span>
                  )}
                </div>
              ))}
            </div>
          )}
          {(record?.candidate_findings || []).length === 0 && (
            <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
              No candidate findings yet. Candidates appear after verification + synthesis.
            </div>
          )}
          {(record?.candidate_findings || []).map((c: Mode3CandidateFinding) => {
            const verdict = verdictFor(c.title);
            return (
              <div key={c.title || Math.random()} className="agent-candidate">
                <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <strong style={{ fontSize: 12 }}>{c.title}</strong>
                  <span className={`badge ${(c.confidence || "low").toLowerCase()}`}>
                    {c.confidence || "LOW"}
                  </span>
                  {verdict?.class && (
                    <span style={{ color: verdictColor(verdict.class), fontSize: 11 }}>
                      verifier: {verdict.class}
                    </span>
                  )}
                </div>
                {c.observation && (
                  <div style={{ fontSize: 12, marginTop: 3 }}>{c.observation}</div>
                )}
                {c.interpretation && (
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
                    {c.interpretation}
                  </div>
                )}
                {(c.audit_ids || []).length > 0 && (
                  <div
                    style={{
                      fontFamily: "monospace",
                      fontSize: 10,
                      color: "var(--accent)",
                      marginTop: 4,
                      overflowWrap: "anywhere",
                    }}
                  >
                    lineage: {(c.audit_ids || []).join(", ")}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
