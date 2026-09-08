import { useEffect, useState, useRef } from "react";
import { api, type ChatEntry } from "../api/client";

export default function SteerChat() {
  const [messages, setMessages] = useState<ChatEntry[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [mode, setMode] = useState<"mode1" | "mode2" | "mode3">("mode1");
  const [mode2Iterations, setMode2Iterations] = useState(3);
  const scrollRef = useRef<HTMLDivElement>(null);

  const load = () => {
    api.chat(200)
      .then(setMessages)
      .catch(() => {})
      .finally(() => {
        setTimeout(() => {
          scrollRef.current?.scrollTo(0, scrollRef.current.scrollHeight);
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
        // Append the chat entries returned by the iteration
        if (r.chat_entries?.length) {
          setMessages((prev) => [...prev, ...r.chat_entries]);
        }
        load();
      } else if (mode === "mode3") {
        const plan = await api.mode3Plan({ question: text });
        setMessages((prev) => [
          ...prev,
          {
            role: "agent",
            action: "mode3_plan",
            text: `Plan: ${plan.extras.length} extras, ${plan.skips.length} skips, ${plan.queries.length} queries.\n${plan.rationale}`,
            meta: plan,
          },
        ]);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const clear = async () => {
    await api.chatClear().catch(() => {});
    setMessages([]);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 120px)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <h2>Steer Chat</h2>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <select
            value={mode}
            onChange={(e) => setMode(e.target.value as "mode1" | "mode2" | "mode3")}
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
          <button className="btn btn-sm" onClick={clear}>Clear</button>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

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
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {messages.map((m, i) => (
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
                  {m.role} · {m.action}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <input
          placeholder={mode === "mode1" ? "Ask a question..." : mode === "mode2" ? "Ask + iterate..." : "Set scope for agent..."}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && send()}
          disabled={loading}
        />
        <button className="btn btn-primary" onClick={send} disabled={loading}>
          {loading ? "..." : "Send"}
        </button>
      </div>
    </div>
  );
}
