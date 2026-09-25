import { useEffect, useState, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api, chatStream, type ChatEntry, type Mode2IterateResponse, type Mode3PlanResponse, type N4Hit } from "../api/client";
import { computeApprovalResponse } from "../lib/crypto";
import { useCase } from "../context/CaseContext";

/**
 * WP 4d.3: live steer chat — Mode 1/2 turns stream over SSE with live
 * progress (status + iteration events) and hit cards rendered directly
 * in the transcript. Hit cards carry one-click bookmarking so interesting
 * items flow into the Workbench without leaving the conversation.
 */

/** Build an Explore URL from an N4 DSL query (family → facet, rest → needles). */
function dslToExplore(dsl: string): string {
  const familyMatch = dsl.match(/\bfamily\s*:\s*([A-Za-z0-9_-]+)/i);
  const family = familyMatch ? familyMatch[1] : "";
  const terms = dsl
    .replace(/\bfamily\s*:\s*[A-Za-z0-9_-]+/gi, " ")
    .replace(/\b(host|user|event|file|regex)\s*:\s*/gi, " ")
    .replace(/\b(AND|OR|NOT)\b/gi, " ")
    .replace(/["'()]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  const params = new URLSearchParams();
  if (terms) params.set("needles", terms);
  if (family) params.set("family", family);
  const query = params.toString();
  return query ? `/explore?${query}` : "/explore";
}

/** First meaningful line of an answer, stripped of markdown — DRAFT title. */
function answerTitle(text: string): string {
  const line = (text || "")
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l && !l.startsWith("|") && !l.startsWith("#"));
  return (line || "Mode 2 answer").replace(/[*_`>#]/g, "").slice(0, 120);
}

function HitCard({ hit: h }: { hit: N4Hit }) {
  // The server assigns the bookmark id (B-###) — removing by our own loc key
  // silently no-ops (the star would clear while the Workbench keeps the row).
  const [bookmarkId, setBookmarkId] = useState<string>("");
  const [busy, setBusy] = useState(false);

  const toggle = async () => {
    setBusy(true);
    try {
      if (bookmarkId) {
        await api.workbenchRemove(bookmarkId);
        setBookmarkId("");
      } else {
        const r = await api.workbenchAdd(h);
        setBookmarkId(r.bookmark_id || "");
      }
    } catch {
      // card-level failure is non-fatal; the star just stays as-is
    } finally {
      setBusy(false);
    }
  };

  const preview = Object.entries(h.fields || {}).slice(0, 4);
  const bookmarked = Boolean(bookmarkId);

  return (
    <div
      style={{
        background: "var(--bg-secondary)",
        border: "1px solid var(--border)",
        borderRadius: 6,
        padding: "6px 10px",
        fontSize: 11,
        display: "flex",
        gap: 8,
        alignItems: "flex-start",
      }}
    >
      <button
        onClick={toggle}
        disabled={busy}
        style={{ background: "none", border: "none", cursor: "pointer", color: bookmarked ? "var(--warning)" : "var(--text-muted)", fontSize: 13, padding: 0 }}
        title={bookmarked ? "Remove bookmark" : "Bookmark to Workbench"}
      >
        {bookmarked ? "★" : "☆"}
      </button>
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ fontSize: 10, color: "var(--text-muted)", marginBottom: 2 }}>
          <span style={{ fontFamily: "monospace" }}>{h.family}</span>
          {h.host ? ` · ${h.host}` : ""} · {h.file}:{h.line}
        </div>
        {preview.length > 0 ? (
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            {preview.map(([k, v]) => (
              <span key={k} style={{ fontSize: 11 }}>
                <span style={{ color: "var(--text-muted)" }}>{k}: </span>
                <span style={{ fontFamily: "monospace" }}>{v}</span>
              </span>
            ))}
          </div>
        ) : (
          <div style={{ fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {h.text}
          </div>
        )}
      </div>
    </div>
  );
}

function ProposalCard({ entry, caseMode, onAsk, busy, saved, onSave }: {
  entry: ChatEntry;
  caseMode: string;
  onAsk?: (question: string) => void;
  busy?: boolean;
  saved?: boolean;
  onSave?: () => Promise<void>;
}) {
  const meta = (entry.meta || {}) as Record<string, string>;
  const navigate = useNavigate();
  const isMode3 = entry.action === "mode3_plan" || entry.action === "mode3_execute";
  const isSteer = entry.action === "steer_answer";
  const badge = isMode3 ? "Mode 3 Agent"
    : isSteer ? "Mode 2 Answer"
    : (caseMode === "1" || caseMode === "" ? "Query hits" : "Mode 2 Proposal");
  const hits = entry.data?.hits || [];
  const queries = entry.data?.queries || [];
  const followups = entry.data?.followups || [];
  const firstHitQuery = queries.find((q) => q.hits > 0);
  const [draft, setDraft] = useState("");
  const [saveState, setSaveState] = useState(saved ? "Saved for report" : "");

  const saveAnswer = async () => {
    if (!onSave || saveState.startsWith("Saved") || saveState === "saving…") return;
    setSaveState("saving…");
    try {
      await onSave();
      setSaveState("Saved for report");
    } catch (e) {
      setSaveState((e as Error).message || "save failed");
    }
  };

  const stageDraft = async () => {
    if (draft) return;
    setDraft("staging…");
    try {
      const title = firstHitQuery
        ? `${answerTitle(entry.text)} — ${firstHitQuery.dsl}`.slice(0, 160)
        : answerTitle(entry.text);
      const r = await api.mode2ProposeDraft({
        title,
        query: firstHitQuery?.dsl,
        hits: hits.length > 0 ? hits : undefined,
      });
      if (r.error) {
        setDraft(typeof r.error === "string" ? r.error : r.error.join("; "));
        return;
      }
      setDraft(`DRAFT staged${r.finding_id ? ` (${r.finding_id})` : ""} — review in Approve`);
    } catch (e) {
      setDraft((e as Error).message);
    }
  };

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
          {badge}
        </span>
        <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{entry.action}</span>
        {meta.total_hits ? (
          <span style={{ fontSize: 10, color: "var(--text-muted)" }}>· {meta.total_hits} rows</span>
        ) : null}
      </div>

      {entry.text && (
        isSteer ? (
          <article className="report-markdown chat-markdown" style={{ marginBottom: 8 }}>
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{entry.text}</ReactMarkdown>
          </article>
        ) : (
          <p style={{ fontSize: 13, color: "var(--text-primary)", marginBottom: 8 }}>
            {entry.text}
          </p>
        )
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
          {/* WP 4j.11 — show the structured query actually executed, so the
              examiner can read/correct the LLM's translation */}
          {meta.dsl_query && (
            <div style={{ marginTop: 4, fontSize: 10, color: "var(--text-muted)" }}>
              {meta.dsl ? "Structured query: " : "Query (degraded to terms): "}
              <span style={{ fontFamily: "monospace", color: meta.dsl ? "var(--accent)" : "var(--warning)" }}>
                {meta.dsl_query}
              </span>
            </div>
          )}
        </div>
      )}

      {meta.rationale && (
        <div style={{ fontSize: 12, color: "var(--text-secondary)", fontStyle: "italic", marginTop: 8, paddingLeft: 8, borderLeft: "2px solid var(--border-light)" }}>
          {meta.rationale}
        </div>
      )}

      {meta.techniques && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8, alignItems: "center" }}>
          <span style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase" }}>ATT&CK</span>
          {meta.techniques.split(",").filter(Boolean).map((t) => (
            <span
              key={t}
              style={{
                fontFamily: "monospace",
                fontSize: 10,
                background: "rgba(163,113,247,0.12)",
                border: "1px solid rgba(163,113,247,0.4)",
                color: "var(--purple)",
                padding: "1px 6px",
                borderRadius: 4,
              }}
            >
              {t}
            </span>
          ))}
        </div>
      )}

      {/* Steering transparency — every query with its why, each explorable */}
      {isSteer && queries.length > 0 && (
        <div
          style={{
            marginTop: 4,
            fontSize: 11,
            fontFamily: "monospace",
            color: "var(--text-muted)",
            paddingLeft: 8,
            borderLeft: "2px solid var(--border)",
          }}
        >
          {queries.map((q, qi) => (
            <div key={qi} style={{ display: "flex", flexWrap: "wrap", gap: 6, alignItems: "baseline" }}>
              <span style={{ color: q.hits > 0 ? "var(--accent)" : "var(--warning)" }}>
                {q.dsl}
              </span>
              <span>→ {q.hits} hit(s)</span>
              {q.why ? <span>· {q.why}</span> : null}
              <button
                className="btn btn-sm clickable-tint"
                style={{ fontSize: 10, padding: "0 5px" }}
                title="Open these rows in Explore"
                onClick={() => navigate(dslToExplore(q.dsl))}
              >
                Explore
              </button>
            </div>
          ))}
        </div>
      )}

      {/* WP 4d.3: hit cards persisted in the transcript */}
      {hits.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", marginBottom: 4 }}>
            Cited rows ({hits.length}) — star to bookmark to the Workbench
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {hits.map((h, i) => <HitCard key={i} hit={h} />)}
          </div>
        </div>
      )}

      {/* Answer actions — continue the investigation or stage it for the report */}
      {isSteer && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8, alignItems: "center" }}>
          <button
            className="btn btn-sm"
            onClick={() => navigate(firstHitQuery ? dslToExplore(firstHitQuery.dsl) : "/explore")}
            title="Open the underlying rows in Explore"
          >
            Open in Explore
          </button>
          <button
            className="btn btn-sm"
            onClick={() => void stageDraft()}
            disabled={Boolean(draft)}
            title="Stage a DRAFT finding from this answer + its cited rows (examiner approval required)"
          >
            Stage DRAFT
          </button>
          <button
            className="btn btn-sm"
            onClick={() => void saveAnswer()}
            disabled={saveState === "saving…" || saveState.startsWith("Saved")}
            title="Bookmark this answer's cited rows to the Workbench and record the answer for the report"
          >
            {saveState.startsWith("Saved")
              ? "★ Saved for report"
              : saveState === "saving…"
                ? "saving…"
                : "☆ Save for report"}
          </button>
          {saveState && !saveState.startsWith("Saved") && saveState !== "saving…" && (
            <span style={{ fontSize: 11, color: "var(--warning)" }}>{saveState}</span>
          )}
          {draft && (
            <span style={{ fontSize: 11, color: draft.startsWith("DRAFT") ? "var(--ok)" : "var(--warning)" }}>
              {draft}
            </span>
          )}
        </div>
      )}

      {/* 4j-H.8 — deterministic drill-down chips for the next turn */}
      {isSteer && followups.length > 0 && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6 }}>
          {followups.map((f, fi) => (
            <button
              key={fi}
              className="btn btn-sm clickable-tint"
              style={{ fontSize: 11 }}
              disabled={busy}
              title={f.question}
              onClick={() => onAsk?.(f.question)}
            >
              {f.label}
            </button>
          ))}
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
  const { mode: caseMode, activeCase } = useCase();
  const [messages, setMessages] = useState<ChatEntry[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  // WP 4j.33/4j.34 — per-turn stage timings from the steering agent
  const [turnTimings, setTurnTimings] = useState("");
  // Last executed steering query — the server drafts a finding from hits and
  // needs a query (or hits) to draft from.
  const [lastQuery, setLastQuery] = useState("");
  // Phase 4f fix: depth is a case-level decision (single source = caseMode).
  // No private chat mode that can disagree with the case setting; changing it
  // persists to the case via setCaseMode.
  const modeKnown = caseMode === "1" || caseMode === "2" || caseMode === "3";
  const mode: "mode1" | "mode2" | "mode3" =
    caseMode === "2" ? "mode2" : caseMode === "3" ? "mode3" : "mode1";
  const [mode2Iterations, setMode2Iterations] = useState(3);
  const [mode3Step, setMode3Step] = useState<"plan" | "execute" | "seal">("plan");
  const [mode3Plan, setMode3Plan] = useState<Mode3PlanResponse | null>(null);
  const [sealChallenge, setSealChallenge] = useState<{ challenge_id: string; nonce: string; salt: string; iterations: number } | null>(null);
  const [sealPassword, setSealPassword] = useState("");
  // WP 4d.3: live progress while a streamed turn is running
  const [liveStatus, setLiveStatus] = useState("");
  const [liveIterations, setLiveIterations] = useState<Record<string, unknown>[]>([]);
  // Mode 2 suggested questions (LLM-generated when available, server-cached)
  const [suggestions, setSuggestions] = useState<{ text: string; source: string }[]>([]);
  const [suggBy, setSuggBy] = useState("");
  const [suggLoading, setSuggLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const scrollTimerRef = useRef<number | null>(null);

  // Reset the Mode-3 step whenever the case depth changes.
  useEffect(() => {
    if (caseMode === "3") setMode3Step("plan");
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

  const savedTs = new Set(
    messages
      .filter((m) => m.action === "answer_saved")
      .map((m) => String(m.data?.entry_ts || ""))
      .filter(Boolean),
  );

  const saveAnswer = async (entryTs: string) => {
    if (!entryTs) return;
    const r = await api.mode2SaveAnswer({ entry_ts: entryTs });
    if (r.error) {
      throw new Error(Array.isArray(r.error) ? r.error.join("; ") : r.error);
    }
    load();
  };

  const refreshSuggestions = () => {
    setSuggLoading(true);
    api.mode2Suggestions()
      .then((r) => {
        setSuggestions(r.suggestions || []);
        setSuggBy(r.generated_by || "");
      })
      .catch(() => { /* suggestions are optional — never block the chat */ })
      .finally(() => setSuggLoading(false));
  };

  useEffect(() => {
    load();
    return () => {
      if (scrollTimerRef.current) clearTimeout(scrollTimerRef.current);
    };
  }, [activeCase]);

  useEffect(() => {
    if (mode !== "mode2") return;
    refreshSuggestions();
    // Suggestions are server-cached (120 s) — refreshing on case/mode change is cheap.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeCase, mode]);

  const send = () => {
    if (!input.trim() || loading) return;
    const text = input;
    // Standard chatbox: the examiner's message posts immediately, the input
    // clears, and the field stays editable while the agent works.
    setInput("");
    void sendText(text);
  };

  const sendText = async (text: string) => {
    if (!text.trim() || loading) return;
    setLoading(true);
    setError("");
    setLiveStatus("");
    setLiveIterations([]);
    setMessages((prev) => [
      ...prev,
      {
        ts: new Date().toISOString(),
        role: "examiner",
        action: "steer_question",
        text,
        meta: {},
      },
    ]);

    try {
      if (mode === "mode1") {
        // WP 4d.3: streamed turn — live status + iteration events, then reload
        await chatStream(
          {
            message: text,
            mode,
            max_iterations: mode2Iterations,
          },
          (evt) => {
            if (evt.event === "status") {
              const stage = String((evt.data as { stage?: string }).stage || "");
              setLiveStatus(stage === "translating" ? "Translating question to needles…" : "Querying evidence…");
            } else if (evt.event === "iteration") {
              setLiveStatus("");
              setLiveIterations((prev) => [...prev, evt.data]);
            } else if (evt.event === "error") {
              setError(String((evt.data as { error?: string }).error || "stream error"));
            }
          },
        );
        load();
      } else if (mode === "mode2") {
        // WP 10.53/10.54 — live bounded tool loop. The server streams tool
        // events and persists the final/partial transcript; reloading shows
        // the exact tool chain, rows and partial state after the turn.
        await chatStream(
          {
            message: text,
            mode,
            max_iterations: mode2Iterations,
            history: messages.slice(-6).map((m) => ({ role: m.role, text: m.text })),
          },
          (evt) => {
            const data = evt.data as Record<string, unknown>;
            if (evt.event === "round") {
              setLiveStatus(`Round ${String(data.round ?? "?")} — deciding the next action…`);
            } else if (evt.event === "tool_call") {
              setLiveStatus(
                `tool ${String(data.tool || "")}: ${String(data.why || "retrieving evidence")}`,
              );
            } else if (evt.event === "tool_result") {
              const audit = data.audit_id ? ` · audit ${String(data.audit_id)}` : "";
              const err = data.error ? ` · ${String(data.error)}` : "";
              setLiveStatus(`tool ${String(data.tool || "")} returned${audit}${err}`);
            } else if (evt.event === "partial") {
              setLiveStatus(`Budget reached (${String(data.reason || "limit")}) — returning partial result…`);
            } else if (evt.event === "done") {
              const queries = Array.isArray(data.queries_executed)
                ? (data.queries_executed as { hits?: number; dsl?: string }[])
                : [];
              const firstQuery = queries.find((q) => (q.hits ?? 0) > 0);
              if (firstQuery?.dsl) setLastQuery(firstQuery.dsl);
              const timings = data.timings_ms as Record<string, number> | undefined;
              if (timings) {
                const text = Object.entries(timings)
                  .filter(([, v]) => typeof v === "number")
                  .map(([k, v]) => `${k} ${(v / 1000).toFixed(1)}s`)
                  .join(" · ");
                if (text) setTurnTimings(text);
              }
            } else if (evt.event === "error") {
              setError(String(data.error || "stream error"));
            }
          },
        );
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
      setLiveStatus("");
      setLiveIterations([]);
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
      setSealChallenge({
        challenge_id: ch.challenge_id,
        nonce: ch.nonce,
        salt: ch.salt,
        iterations: ch.iterations,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const sealCase = async () => {
    if (!sealChallenge || !sealPassword) {
      setError("Approval password required — sealing signs the case file with your examiner identity.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const response = await computeApprovalResponse(
        sealPassword,
        sealChallenge.salt,
        sealChallenge.iterations,
        sealChallenge.nonce,
      );
      const r = await api.sealCase({
        challenge_id: sealChallenge.challenge_id,
        response,
      });
      setSealPassword("");
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
        setSealPassword("");
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
    setSealPassword("");
  };

  // WP 4b.14: Propose-draft UI — trigger LLM-drafted findings from the UI
  const [draftTitle, setDraftTitle] = useState("");
  const [showDraftForm, setShowDraftForm] = useState(false);
  const proposeDraft = async () => {
    if (!draftTitle.trim()) return;
    setLoading(true);
    setError("");
    try {
      if (!lastQuery) {
        setError("Ask a question first — the DRAFT is drafted from the last query's hits.");
        return;
      }
      const r = await api.mode2ProposeDraft({ title: draftTitle, query: lastQuery });
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
    entry.action === "mode2_aggregation" ||
    entry.action === "mode3_plan" ||
    entry.action === "mode3_execute" ||
    entry.action === "mode3_seal";

  // WP 4j.13 — Mode 2 iterative loop from the UI: the full examiner
  // back-and-forth (queries + aggregations) in one tracked operation.
  const [iterateResult, setIterateResult] = useState<Mode2IterateResponse | null>(null);
  const runIterate = async () => {
    if (!input.trim() || loading) return;
    setLoading(true);
    setError("");
    const text = input;
    setInput("");
    setMessages((prev) => [
      ...prev,
      { ts: new Date().toISOString(), role: "examiner", action: "mode2_iterate_question", text, meta: {} },
    ]);
    try {
      const r = await api.mode2Iterate({ question: text, max_iterations: mode2Iterations });
      if (r.error) {
        setError(r.error);
      } else {
        setIterateResult(r);
        setMessages((prev) => [
          ...prev,
          {
            ts: new Date().toISOString(),
            role: "llm",
            action: "mode2_iteration",
            text: `Iterated: ${r.iterations.length} round(s), ${r.total_hits} total hits. `
              + `Queries: ${(r.needles_run || []).slice(0, 6).join(", ")}`,
            meta: { needles: (r.needles_run || []).join(","), hits: String(r.total_hits) },
          },
        ]);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  if (!modeKnown) {
    // Never guess the mode — sending a Mode 1 stream turn for a Mode 2 case
    // would silently run the wrong pipeline.
    return (
      <div className="card">
        <h2>Steer Chat</h2>
        <p style={{ fontSize: 13, color: "var(--text-muted)" }}>
          Reading the case mode… If this persists, the case's mode could not be
          loaded — reopen the case from the dashboard.
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 120px)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <h2>Steer Chat</h2>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {/* Mode is fixed at case creation — no in-case switching (segregation). */}
          <span
            className={`mode-badge mode-${mode === "mode2" ? "2" : mode === "mode3" ? "3" : "1"}`}
            title="Investigation mode was chosen when the case was created"
            style={{ fontSize: 11 }}
          >
            {mode === "mode1" ? "Mode 1 — Scribe" : mode === "mode2" ? "Mode 2 — LLM steering" : "Mode 3 — Agentic"}
          </span>
          {mode === "mode2" && (
            <input
              type="number"
              min={1}
              max={4}
              value={mode2Iterations}
              onChange={(e) => setMode2Iterations(Math.max(1, Math.min(4, Number(e.target.value) || 2)))}
              style={{ width: 60 }}
              title="Maximum rounds for Iterate (1-4)"
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
      <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: -4, marginBottom: 10 }}>
        {mode === "mode1"
          ? "Mode 1: you propose needles — the LLM scribes your findings. Evidence and the audit chain are shared."
          : mode === "mode2"
            ? "Mode 2: you ask in plain language — the LLM queries the case's evidence index and cites rows. Staging a DRAFT is a separate examiner-triggered action."
            : "Mode 3: the agent plans, hunts and corroborates across the case; you steer and seal."}
      </div>
      {mode === "mode3" && (
        <div
          className="card"
          style={{
            padding: "8px 12px",
            marginBottom: 8,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: 10,
            flexWrap: "wrap",
          }}
        >
          <span style={{ fontSize: 12 }}>
            This chat keeps the legacy plan/execute sliver. Supervised agents now run on the
            dedicated <strong>Agent Run</strong> page — agent board, live event stream, steering,
            pause/resume and DRAFT staging.
          </span>
          <Link className="btn btn-sm btn-primary" to="/agent-run">
            Open Agent Run →
          </Link>
        </div>
      )}
      {mode === "mode2" && (suggestions.length > 0 || suggLoading) && (
        <div
          className="card"
          style={{
            padding: "6px 10px",
            marginBottom: 8,
            display: "flex",
            alignItems: "center",
            gap: 6,
            flexWrap: "wrap",
          }}
        >
          <span style={{ fontSize: 10, textTransform: "uppercase", color: "var(--text-muted)" }}>
            Suggested questions{suggBy ? ` · ${suggBy}` : ""}
          </span>
          {suggestions.map((s, i) => (
            <button
              key={i}
              className="btn btn-sm clickable-tint"
              style={{ fontSize: 11 }}
              disabled={loading}
              title={s.text}
              onClick={() => void sendText(s.text)}
            >
              {s.text}
            </button>
          ))}
          <button
            className="btn btn-sm"
            style={{ fontSize: 10 }}
            onClick={refreshSuggestions}
            disabled={suggLoading}
            title="Refresh suggested questions (server-cached for 2 minutes)"
          >
            {suggLoading ? "…" : "↻"}
          </button>
        </div>
      )}
      {mode === "mode2" && turnTimings && (
        <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: -8, marginBottom: 8 }}>
          last turn: {turnTimings}
        </div>
      )}

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
                type="password"
                placeholder="Approval password"
                value={sealPassword}
                onChange={(e) => setSealPassword(e.target.value)}
                style={{ width: 220 }}
                title="Your examiner approval password — the HMAC is computed in your browser; the password never leaves it."
              />
              <button
                className="btn btn-primary btn-sm"
                onClick={sealCase}
                disabled={loading || !sealPassword}
              >
                Seal Case
              </button>
            </div>
          )}
        </div>
      )}

      {/* WP 4b.14: Propose Draft button — Mode 2 */}
      {mode === "mode2" && (
        <div className="card" style={{ padding: "8px 12px", marginBottom: 8, display: "flex", gap: 8, alignItems: "center" }}>
          <button className="btn btn-sm" onClick={() => setShowDraftForm(!showDraftForm)}>
            ✎ Propose Draft Finding
          </button>
          {/* WP 4j.13 — run the full Mode 2 iterative loop */}
          <button
            className="btn btn-sm btn-primary"
            onClick={runIterate}
            disabled={loading || !input.trim()}
            title="Run the multi-round investigation loop on this question (structured queries + aggregations)"
          >
            {loading ? "Investigating…" : "▶ Iterate (multi-round)"}
          </button>
          {mode2Iterations > 1 && (
            <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{mode2Iterations} rounds max</span>
          )}
        </div>
      )}
      {mode === "mode2" && showDraftForm && (
        <div className="card" style={{ padding: "8px 12px", marginBottom: 8 }}>
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
        </div>
      )}

      {/* WP 4j.13 — iteration result card (queries + aggregations) */}
      {mode === "mode2" && iterateResult && iterateResult.iterations.length > 0 && (
        <div className="card" style={{ padding: "10px 14px", marginBottom: 8 }}>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>
            Investigation loop — {iterateResult.iterations.length} round(s), {iterateResult.total_hits} hits
          </div>
          {iterateResult.iterations.map((it, i) => (
            <div key={i} style={{ fontSize: 11, marginBottom: 8, paddingLeft: 8, borderLeft: "2px solid var(--border)" }}>
              <div style={{ fontWeight: 600 }}>{it.action === "initial_query" ? "Round 0 (entry)" : `Round ${it.iteration}`}</div>
              {(it.queries || []).map((q, qi: number) => (
                <div key={qi} style={{ fontSize: 11, fontFamily: "monospace", marginTop: 2 }}>
                  <span style={{ color: q.dsl && !q.fallback ? "var(--accent)" : "var(--warning)" }}>
                    {q.query}
                  </span>
                  {" → "}
                  <span>{q.hits} hit(s)</span>
                </div>
              ))}
              {(it.aggregations || []).map((a, ai: number) => (
                <div key={`a${ai}`} style={{ fontSize: 11, marginTop: 4 }}>
                  <strong>Aggregation {a.field || "?"}</strong>: {a.distinct ?? 0} distinct
                  {(a.top || []).length > 0 && (
                    <span style={{ color: "var(--text-muted)" }}>
                      {" "}— {a.top!.slice(0, 5).map((t: { value: string; count: number }) => `${t.value}(${t.count})`).join(", ")}
                    </span>
                  )}
                </div>
              ))}
            </div>
          ))}
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
              if (isProposal(m) || (m.data?.hits && m.data.hits.length > 0)) {
                return (
                  <ProposalCard
                    key={i}
                    entry={m}
                    caseMode={caseMode}
                    busy={loading}
                    onAsk={(q) => void sendText(q)}
                    saved={savedTs.has(m.ts)}
                    onSave={() => saveAnswer(m.ts)}
                  />
                );
              }
              return (
                <div
                  key={i}
                  style={{
                    alignSelf: m.role === "examiner" ? "flex-end" : "flex-start",
                    maxWidth: "85%",
                  }}
                >
                  <div
                    style={{
                      background: m.role === "examiner" ? "var(--accent)" : "var(--bg-tertiary)",
                      color: m.role === "examiner" ? "white" : "var(--text-primary)",
                      padding: "8px 12px",
                      borderRadius: 8,
                      fontSize: 13,
                      whiteSpace: m.role === "examiner" ? "pre-wrap" : "normal",
                    }}
                  >
                    {m.role === "examiner" ? (
                      m.text
                    ) : (
                      <article className="report-markdown chat-markdown">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{m.text}</ReactMarkdown>
                      </article>
                    )}
                  </div>
                  {/* WP 4j.13 — the queries the agent actually ran (structured,
                      not a raw JSON blob), with the plan rationale */}
                  {m.role !== "examiner" && (m.data?.queries?.length ?? 0) > 0 && (
                    <div
                      style={{
                        marginTop: 4,
                        fontSize: 11,
                        fontFamily: "monospace",
                        color: "var(--text-muted)",
                        paddingLeft: 8,
                        borderLeft: "2px solid var(--border)",
                      }}
                    >
                      {m.data!.queries!.map((q, qi) => (
                        <div key={qi}>
                          <span style={{ color: q.hits > 0 ? "var(--accent)" : "var(--warning)" }}>
                            {q.dsl}
                          </span>
                          {" → "}
                          <span>{q.hits} hit(s)</span>
                          {q.why ? <span> · {q.why}</span> : null}
                        </div>
                      ))}
                    </div>
                  )}
                  {/* 4j-H.8 — deterministic drill-down chips for the next turn */}
                  {m.role !== "examiner" && (m.data?.followups?.length ?? 0) > 0 && (
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6 }}>
                      {m.data!.followups!.map((f, fi) => (
                        <button
                          key={fi}
                          className="btn btn-sm clickable-tint"
                          style={{ fontSize: 11 }}
                          disabled={loading}
                          title={f.question}
                          onClick={() => void sendText(f.question)}
                        >
                          {f.label}
                        </button>
                      ))}
                    </div>
                  )}
                  {m.data?.partial && (
                    <div style={{ fontSize: 11, color: "var(--warning)", marginTop: 4 }}>
                      Partial answer — the budget was reached before completion;
                      the rows retrieved so far are shown above.
                    </div>
                  )}
                  <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2, textAlign: m.role === "examiner" ? "right" : "left" }}>
                    {m.role} · {m.action}{m.ts ? ` · ${m.ts.slice(0, 19)}` : ""}
                    {m.meta?.total_hits ? ` · ${m.meta.total_hits} rows` : ""}
                    {m.meta?.timings ? ` · ${m.meta.timings}` : ""}
                  </div>
                </div>
              );
            })}
            {/* WP 4d.3: live progress while streaming */}
            {loading && (
              <div style={{ alignSelf: "flex-start", padding: "4px 12px" }}>
                {liveStatus && (
                  <div style={{ fontSize: 12, color: "var(--text-muted)" }}>{liveStatus}</div>
                )}
                {liveIterations.map((it, i) => {
                  const needles = Array.isArray(it.needles) ? (it.needles as string[]).join(", ") : "";
                  return (
                    <div key={i} style={{ fontSize: 12, color: "var(--accent)", padding: "2px 0" }}>
                      ⟳ iteration {String(it.iteration ?? i)}: {String(it.action || "")}
                      {needles ? ` — ${needles}` : ""} · {String(it.hits ?? 0)} hits
                    </div>
                  );
                })}
                {!liveStatus && liveIterations.length === 0 && (
                  <div style={{ color: "var(--text-muted)", fontSize: 13 }}>
                    <span className="pulse-dots">●●●</span>
                  </div>
                )}
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
            mode === "mode2" ? "Ask about the evidence..." :
            mode3Step === "plan" ? "Set scope for agent..." :
            "Use action buttons above..."
          }
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && !loading && send()}
          placeholder-style={{ color: loading ? "var(--text-muted)" : undefined }}
          disabled={mode === "mode3" && mode3Step !== "plan"}
        />
        <button
          className="btn btn-primary"
          onClick={send}
          disabled={loading || (mode === "mode3" && mode3Step !== "plan")}
        >
          {loading ? "Working…" : "Send"}
        </button>
      </div>
    </div>
  );
}
