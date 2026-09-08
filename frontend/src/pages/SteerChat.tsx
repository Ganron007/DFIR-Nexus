import { useEffect, useState, useRef } from "react";
import { api, type ChatEntry } from "../api/client";

interface ProposalData {
  needles?: string[];
  hits?: Array<{ audit_id: string; family: string; line: string }>;
  rationale?: string;
  iterations?: number;
  total_hits?: number;
}

function ProposalCard({ entry }: { entry: ChatEntry }) {
  const meta = (entry.meta || {}) as ProposalData;
  const isMode3 = entry.action === "mode3_plan" || entry.action === "mode3_execute";

  return (
    <div
      style={{
        background: "var(--bg-tertiary)",
        border: `1px solid ${isMode3 ? "var(--purple)" : "var(--orange)"}`,
        borderRadius: 8,
        padding: 12,
        margin: "8px 0",
        maxWidth: "85%",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <span
          style={{
            fontSize: 10,
            fontWeight: 600,
            textTransform: "uppercase",
            padding: "2px 6px",
            borderRadius: 4,
            background: isMode3 ? "rgba(163,113,247,0.2)" : "rgba(219,109,40,0.2)",
            color: isMode3 ? "var(--purple)" : "var(--orange)",
          }}
        >
          {isMode3 ? "Mode 3 Agent" : "Mode 2 Proposal"}
        </span>
        <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{entry.action}</span>
      </div>

      {entry.text && (
        <p style={{ fontSize: 13, color: "var(--text-primary)", marginBottom: 8 }}>
          {entry.text}
        </p>
      )}

      {meta.needles && meta.needles.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <span style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase" }}>Proposed Needles:</span>
          <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 4 }}>
            {meta.needles.map((n, i) => (
              <span
                key={i}
                style={{
                  fontFamily: "monospace",
                  fontSize: 11,
                  background: "var(--bg-secondary)",
                  padding: "2px 6px",
                  borderRadius: 4,
                  border: "1px solid var(--border)",
                }}
              >
                {n}
              </span>
            ))}
          </div>
        </div>
      )}

      {meta.hits && meta.hits.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <span style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase" }}>
            Hits ({meta.hits.length}):
          </span>
          <div style={{ marginTop: 4, maxHeight: 120, overflowY: "auto" }}>
            {meta.hits.slice(0, 5).map((h, i) => (
              <div key={i} style={{ fontSize: 11, color: "var(--text-secondary)", padding: "2px 0", borderBottom: "1px solid var(--border)" }}>
                <span style={{ fontFamily: "monospace", color: "var(--accent)" }}>{h.family}</span>
                {" — "}
                {h.line.slice(0, 100)}
                {h.line.length > 100 && "..."}
              </div>
            ))}
            {meta.hits.length > 5 && (
              <span style={{ fontSize: 10, color: "var(--text-muted)" }}>+ {meta.hits.length - 5} more...</span>
            )}
          </div>
        </div>
      )}

      {meta.rationale && (
        <div style={{ fontSize: 12, color: "var(--text-secondary)", fontStyle: "italic", marginTop: 8, paddingLeft: 8, borderLeft: "2px solid var(--border-light)" }}>
          {meta.rationale}
        </div>
      )}

      {meta.iterations !== undefined && (
        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8 }}>
          {meta.iterations} iterations · {meta.total_hits || 0} total hits
        </div>
      )}
    </div>
  );
}

export default function SteerChat() {
  const [messages, setMessages] = useState<ChatEntry[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [mode, setMode] = useState<"mode1" | "mode2" | "mode3">("mode1");
  const [mode2Iterations, setMode2Iterations] = useState(3);
  const [mode3Step, setMode3Step] = useState<"plan" | "execute" | "seal">("plan");
  const [mode3Plan, setMode3Plan] = useState<{ extras: string[]; skips: string[]; queries: string[] } | null>(null);
  const [sealChallenge, setSealChallenge] = useState<{ challenge_id: string; nonce: string } | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const load = () => {
    api.chat(200)
      .then(setMessages)
      .catch(() => {})
      .finally(() => {
        setTimeout(() => {
          scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
        }, 50);
      });
  };

  useEffect(() => load(), []);

  const send = async () => {
    if (!input.trim() || loading) return;
    setLoading(true);
    setError("");
    const text = input;
    setInput("");

    try {
      if (mode === "mode1") {
        await api.chatPost(text);
        load();
      } else if (mode === "mode2") {
        const r = await api.mode2Iterate({ question: text, max_iterations: mode2Iterations });
        if (r.chat_entries?.length) {
          setMessages((prev) => [...prev, ...r.chat_entries]);
        }
        load();
      } else if (mode === "mode3") {
        if (mode3Step === "plan") {
          const plan = await api.mode3Plan({ question: text });
          setMode3Plan(plan);
          setMessages((prev) => [
            ...prev,
            {
              role: "agent",
              action: "mode3_plan",
              text: `Plan: ${plan.extras.length} extras, ${plan.skips.length} skips, ${plan.queries.length} queries.`,
              meta: plan,
            },
          ]);
          setMode3Step("execute");
        }
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const executePlan = async () => {
    if (!mode3Plan) return;
    setLoading(true);
    setError("");
    try {
      const r = await api.mode3Execute({
        extras: mode3Plan.extras,
        queries: mode3Plan.queries,
      });
      setMessages((prev) => [
        ...prev,
        {
          role: "agent",
          action: "mode3_execute",
          text: `Executed: ${r.extras_persisted} extras persisted, ${r.queries_run} queries run.`,
          meta: r,
        },
      ]);
      setMode3Step("seal");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const getSealChallenge = async () => {
    setLoading(true);
    setError("");
    try {
      const ch = await api.getChallenge();
      setSealChallenge({ challenge_id: ch.challenge_id, nonce: ch.nonce });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const clear = async () => {
    await api.chatClear().catch(() => {});
    setMessages([]);
    setMode3Plan(null);
    setMode3Step("plan");
    setSealChallenge(null);
  };

  const isProposal = (entry: ChatEntry) =>
    entry.action === "mode2_proposal" ||
    entry.action === "mode2_iterate" ||
    entry.action === "mode3_plan" ||
    entry.action === "mode3_execute";

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 120px)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <h2>Steer Chat</h2>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <select
            value={mode}
            onChange={(e) => {
              setMode(e.target.value as "mode1" | "mode2" | "mode3");
              setMode3Step("plan");
              setMode3Plan(null);
              setSealChallenge(null);
            }}
            style={{ width: "auto" }}
          >
            <option value="mode1">Mode 1 — Scribe</option>
            <option value="mode2">Mode 2 — Iterative</option>
            <option value="mode3">Mode 3 — Agentic</option>
          </select>
          {mode === "mode2" && (
            <input
              type="number"
              min={1}
              max={10}
              value={mode2Iterations}
              onChange={(e) => setMode2Iterations(Number(e.target.value))}
              style={{ width: 60 }}
              title="Max iterations"
            />
          )}
          {mode === "mode3" && (
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              Step: <strong style={{ color: "var(--purple)" }}>{mode3Step}</strong>
            </span>
          )}
          <button className="btn btn-sm" onClick={clear}>Clear</button>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {/* Mode 3 action bar */}
      {mode === "mode3" && mode3Step === "execute" && mode3Plan && (
        <div className="card" style={{ padding: "8px 12px", marginBottom: 8 }}>
          <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
            Plan ready: {mode3Plan.extras.length} extras, {mode3Plan.queries.length} queries.
          </span>
          <button className="btn btn-primary btn-sm" style={{ marginLeft: 12 }} onClick={executePlan} disabled={loading}>
            Execute Plan
          </button>
        </div>
      )}
      {mode === "mode3" && mode3Step === "seal" && (
        <div className="card" style={{ padding: "8px 12px", marginBottom: 8 }}>
          <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
            Execution complete. Ready to seal the case file.
          </span>
          {!sealChallenge ? (
            <button className="btn btn-primary btn-sm" style={{ marginLeft: 12 }} onClick={getSealChallenge} disabled={loading}>
              Get Seal Challenge
            </button>
          ) : (
            <span style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: 12 }}>
              Challenge: {sealChallenge.nonce.slice(0, 24)}...
            </span>
          )}
        </div>
      )}

      {/* Chat transcript */}
      <div
        ref={scrollRef}
        className="card"
        style={{ flex: 1, overflowY: "auto", padding: 12 }}
      >
        {messages.length === 0 ? (
          <div className="empty-state">
            <h3>No messages</h3>
            <p>Ask a question to start the investigation loop.</p>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {messages.map((m, i) => {
              if (isProposal(m)) {
                return <ProposalCard key={i} entry={m} />;
              }
              return (
                <div
                  key={i}
                  style={{
                    alignSelf: m.role === "examiner" ? "flex-end" : "flex-start",
                    maxWidth: "80%",
                  }}
                >
                  <div
                    style={{
                      background: m.role === "examiner" ? "var(--accent)" : "var(--bg-tertiary)",
                      color: m.role === "examiner" ? "white" : "var(--text-primary)",
                      padding: "8px 12px",
                      borderRadius: 8,
                      fontSize: 13,
                    }}
                  >
                    {m.text}
                  </div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2, textAlign: m.role === "examiner" ? "right" : "left" }}>
                    {m.role} · {m.action}{m.timestamp ? ` · ${m.timestamp}` : ""}
                  </div>
                </div>
              );
            })}
            {loading && (
              <div style={{ alignSelf: "flex-start", color: "var(--text-muted)", fontSize: 13, padding: "4px 12px" }}>
                <span style={{ animation: "pulse 1s infinite" }}>●●●</span>
                <style>{`@keyframes pulse { 0%,100% { opacity: 0.3 } 50% { opacity: 1 } }`}</style>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Input bar */}
      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <input
          placeholder={
            mode === "mode1" ? "Ask a question..." :
            mode === "mode2" ? "Ask + iterate..." :
            mode3Step === "plan" ? "Set scope for agent..." :
            "Use action buttons above..."
          }
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && send()}
          disabled={loading || (mode === "mode3" && mode3Step !== "plan")}
        />
        <button
          className="btn btn-primary"
          onClick={send}
          disabled={loading || (mode === "mode3" && mode3Step !== "plan")}
        >
          {loading ? "..." : "Send"}
        </button>
      </div>
    </div>
  );
}
