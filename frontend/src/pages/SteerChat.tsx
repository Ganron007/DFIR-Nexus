import { useEffect, useState, useRef } from "react";
import { api, type ChatEntry, type Mode3PlanResponse } from "../api/client";
import { useCase } from "../context/CaseContext";

function ProposalCard({ entry }: { entry: ChatEntry }) {
  const meta = (entry.meta || {}) as Record<string, string>;
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

      {meta.needles && (
        <div style={{ marginBottom: 8 }}>
          <span style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase" }}>Proposed Needles:</span>
          <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 4 }}>
            {meta.needles.split(",").map((n, i) => (
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

      {meta.rationale && (
        <div style={{ fontSize: 12, color: "var(--text-secondary)", fontStyle: "italic", marginTop: 8, paddingLeft: 8, borderLeft: "2px solid var(--border-light)" }}>
          {meta.rationale}
        </div>
      )}

      {meta.hits && (
        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8 }}>
          {meta.hits} hits
        </div>
      )}
    </div>
  );
}

export default function SteerChat() {
  const { mode: caseMode } = useCase();
  const [messages, setMessages] = useState<ChatEntry[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [mode, setMode] = useState<"mode1" | "mode2" | "mode3">("mode1");
  const [mode2Iterations, setMode2Iterations] = useState(3);
  const [mode3Step, setMode3Step] = useState<"plan" | "execute" | "seal">("plan");
  const [mode3Plan, setMode3Plan] = useState<Mode3PlanResponse | null>(null);
  const [sealChallenge, setSealChallenge] = useState<{ challenge_id: string; nonce: string; salt: string } | null>(null);
  const [sealResponse, setSealResponse] = useState("");
  const [sealExaminer, setSealExaminer] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);
  const scrollTimerRef = useRef<number | null>(null);

  // WP 4b.6: chat mode follows the case-level investigation mode
  useEffect(() => {
    if (caseMode === "1" || caseMode === "2" || caseMode === "3") {
      setMode(`mode${caseMode}` as "mode1" | "mode2" | "mode3");
      if (caseMode === "3") setMode3Step("plan");
    }
  }, [caseMode]);

  const load = () => {
    api.chat(200)
      .then((r) => setMessages(r.messages))
      .catch((e) => setError((e as Error).message))
      .finally(() => {
        if (scrollTimerRef.current) clearTimeout(scrollTimerRef.current);
        scrollTimerRef.current = window.setTimeout(() => {
          scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
        }, 50);
      });
  };

  useEffect(() => {
    load();
    return () => {
      if (scrollTimerRef.current) clearTimeout(scrollTimerRef.current);
    };
  }, []);

  const send = async () => {
    if (!input.trim() || loading) return;
    setLoading(true);
    setError("");
    const text = input;
    setInput("");

    try {
      if (mode === "mode1") {
        // WP 4b.12: Wire api.ask to Mode 1 — translates English to needles
        const askResult = await api.ask(text);
        await api.chatPost(text);
        if (askResult.error) {
          setError(askResult.error);
        }
        load();
      } else if (mode === "mode2") {
        await api.mode2Iterate({ question: text, max_iterations: mode2Iterations });
        load();
      } else if (mode === "mode3") {
        if (mode3Step === "plan") {
          const plan = await api.mode3Plan({ question: text });
          setMode3Plan(plan);
          setMessages((prev) => [
            ...prev,
            {
              ts: new Date().toISOString(),
              role: "llm",
              action: "mode3_plan",
              text: `Plan: ${plan.items.length} step(s), ${plan.queries.length} corroboration query(ies). ${plan.rationale}`,
              meta: { rationale: plan.rationale },
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
        extras: mode3Plan.items.filter((i) => i.type === "extra" && i.key).map((i) => i.key!),
        queries: mode3Plan.queries,
      });
      setMessages((prev) => [
        ...prev,
        {
          ts: new Date().toISOString(),
          role: "llm",
          action: "mode3_execute",
          text: `Executed: ${r.extras_persisted.length} extras persisted, ${r.query_results.length} queries run. ${r.note}`,
          meta: {},
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
      setSealChallenge({ challenge_id: ch.challenge_id, nonce: ch.nonce, salt: ch.salt });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const sealCase = async () => {
    if (!sealChallenge || !sealResponse.trim()) return;
    setLoading(true);
    setError("");
    try {
      const r = await api.mode3Seal({
        challenge_id: sealChallenge.challenge_id,
        response: sealResponse,
        examiner: sealExaminer || undefined,
      });
      if (r.error) {
        setError(r.error);
      } else {
        setMessages((prev) => [
          ...prev,
          {
            ts: new Date().toISOString(),
            role: "llm",
            action: "mode3_seal",
            text: `Case sealed: ${r.status} — examiner: ${r.examiner}, case: ${r.case_id}`,
            meta: {},
          },
        ]);
        setSealChallenge(null);
        setSealResponse("");
        setMode3Step("plan");
        setMode3Plan(null);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const clear = async () => {
    try {
      await api.chatClear();
    } catch (e) {
      setError(`Failed to clear chat: ${(e as Error).message}`);
      return;
    }
    setMessages([]);
    setMode3Plan(null);
    setMode3Step("plan");
    setSealChallenge(null);
    setSealResponse("");
  };

  // WP 4b.14: Propose-draft UI — trigger LLM-drafted findings from the UI
  const [draftTitle, setDraftTitle] = useState("");
  const [showDraftForm, setShowDraftForm] = useState(false);
  const proposeDraft = async () => {
    if (!draftTitle.trim()) return;
    setLoading(true);
    setError("");
    try {
      const r = await api.mode2ProposeDraft({ title: draftTitle });
      if (r.error) {
        setError(Array.isArray(r.error) ? r.error.join("; ") : r.error);
      } else {
        setMessages((prev) => [
          ...prev,
          {
            ts: new Date().toISOString(),
            role: "llm",
            action: "mode2_proposal",
            text: `DRAFT finding staged: ${r.finding_id || draftTitle} (${r.status || "DRAFT"})`,
            meta: {},
          },
        ]);
        setDraftTitle("");
        setShowDraftForm(false);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const isProposal = (entry: ChatEntry) =>
    entry.action === "mode2_proposal" ||
    entry.action === "mode2_no_proposals" ||
    entry.action === "mode2_done" ||
    entry.action === "mode3_plan" ||
    entry.action === "mode3_execute" ||
    entry.action === "mode3_seal";

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
              setSealResponse("");
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
              max={4}
              value={mode2Iterations}
              onChange={(e) => setMode2Iterations(Math.max(1, Math.min(4, Number(e.target.value) || 2)))}
              style={{ width: 60 }}
              title="Max iterations (1-4)"
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

      {/* Mode 3 action bar — Execute */}
      {mode === "mode3" && mode3Step === "execute" && mode3Plan && (
        <div className="card" style={{ padding: "8px 12px", marginBottom: 8 }}>
          <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
            Plan ready: {mode3Plan.items.length} step(s), {mode3Plan.queries.length} query(ies).
            {!mode3Plan.lane_complete && (
              <span style={{ color: "var(--warning)", marginLeft: 8 }}>
                ⚠ Mandatory lane not complete — extras may be refused.
              </span>
            )}
          </span>
          <button className="btn btn-primary btn-sm" style={{ marginLeft: 12 }} onClick={executePlan} disabled={loading}>
            Execute Plan
          </button>
        </div>
      )}

      {/* Mode 3 action bar — Seal */}
      {mode === "mode3" && mode3Step === "seal" && (
        <div className="card" style={{ padding: "12px", marginBottom: 8 }}>
          <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 8 }}>
            Execution complete. Seal the case file with HMAC challenge-response.
          </div>
          {!sealChallenge ? (
            <button className="btn btn-primary btn-sm" onClick={getSealChallenge} disabled={loading}>
              Get Seal Challenge
            </button>
          ) : (
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                Nonce: {sealChallenge.nonce.slice(0, 32)}...
              </span>
              <input
                placeholder="Examiner name"
                value={sealExaminer}
                onChange={(e) => setSealExaminer(e.target.value)}
                style={{ width: 120 }}
              />
              <input
                placeholder="HMAC response (hex)"
                value={sealResponse}
                onChange={(e) => setSealResponse(e.target.value)}
                style={{ width: 300, fontFamily: "monospace", fontSize: 11 }}
              />
              <button
                className="btn btn-primary btn-sm"
                onClick={sealCase}
                disabled={loading || !sealResponse.trim()}
              >
                Seal Case
              </button>
            </div>
          )}
        </div>
      )}

      {/* WP 4b.14: Propose Draft button — Mode 2 */}
      {mode === "mode2" && (
        <div className="card" style={{ padding: "8px 12px", marginBottom: 8 }}>
          {!showDraftForm ? (
            <button className="btn btn-sm" onClick={() => setShowDraftForm(true)}>
              ✎ Propose Draft Finding
            </button>
          ) : (
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input
                placeholder="Finding title..."
                value={draftTitle}
                onChange={(e) => setDraftTitle(e.target.value)}
                style={{ flex: 1 }}
              />
              <button
                className="btn btn-primary btn-sm"
                onClick={proposeDraft}
                disabled={loading || !draftTitle.trim()}
              >
                {loading ? "..." : "Stage DRAFT"}
              </button>
              <button className="btn btn-sm" onClick={() => { setShowDraftForm(false); setDraftTitle(""); }}>
                Cancel
              </button>
            </div>
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
                    {m.role} · {m.action}{m.ts ? ` · ${m.ts.slice(0, 19)}` : ""}
                  </div>
                </div>
              );
            })}
            {loading && (
              <div style={{ alignSelf: "flex-start", color: "var(--text-muted)", fontSize: 13, padding: "4px 12px" }}>
                <span className="pulse-dots">●●●</span>
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
