/**
 * Steer Chat (WP 4d.3 / 10.53 / 10.54), migrated to the kit (WO-U8a).
 *
 * The gain beyond the port, both of them accessibility:
 *
 * * **Labelled controls.** The composer had a placeholder and no label; the
 *   iteration depth sat next to a Clear button with nothing naming it. Both
 *   now carry real labels, so a screen reader announces what each control is
 *   and U9's axe sweep has something to find. An examiner who cannot see the
 *   placeholder text still knows what the box asks for.
 * * **Message components.** Turns were inlined in a `messages.map()` with the
 *   query trace, follow-up chips, partial notice and metadata interleaved in
 *   one 80-style-object expression. They are components now
 *   (`components/steer/`), which is also what makes the transcript readable.
 *
 * Two defects fixed on the way:
 * * the composer carried a `placeholder-style` attribute, which is not a valid
 *   DOM attribute and did nothing;
 * * the transcript had no live-region semantics, so a streamed answer
 *   appeared silently below the fold.
 *
 * Behaviour preserved: the SSE turn handler and every event it consumes, the
 * bounded tool loop, hit bookmarking into the Workbench, staging a DRAFT
 * (approval still required), saving an answer for the report, and the
 * suggestion chips.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import {
  api,
  chatStream,
  type ChatEntry,
  type Mode1IterateResponse,
} from "../api/client";
import { useCase } from "../context/CaseContext";
import { Badge, Button, EmptyState, Field, Input, Panel } from "@/ui";
import { ProposalCard } from "../components/steer/Cards";
import {
  FollowupChips,
  LiveStatus,
  MessageBubble,
  MessageMeta,
  PartialNotice,
  QueryTrace,
} from "../components/steer/Message";
import styles from "../components/steer/SteerChat.module.css";

/** Build an Explore URL from an N4 DSL query (family -> facet, rest -> needles). */
export function dslToExplore(dsl: string, caseId: string): string {
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
  const base = caseId
    ? `/case/${encodeURIComponent(caseId)}/explore`
    : "/explore";
  return query ? `${base}?${query}` : base;
}

/** First meaningful line of an answer, stripped of markdown - DRAFT title. */
export function answerTitle(text: string): string {
  const line = (text || "")
    .split("\n")
    .map((value) => value.trim())
    .find((value) => value && !value.startsWith("|") && !value.startsWith("#"));
  return (line || "Mode 1 answer").replace(/[*_`>#]/g, "").slice(0, 120);
}

/**
 * A fixed whitelist, deliberately. Guessing from the shape routed a plain
 * `steer_answer` into the proposal card, which hid the partial-answer notice -
 * an answer that hit its budget would have looked complete.
 */
function isProposal(message: ChatEntry): boolean {
  return [
    "mode1_proposal",
    "mode1_no_proposals",
    "mode1_done",
    "mode1_aggregation",
    "mode2_plan",
    "mode2_execute",
    "mode2_seal",
  ].includes(message.action);
}

export default function SteerChat() {
  const { mode: caseMode, activeCase } = useCase();
  const navigate = useNavigate();

  const [messages, setMessages] = useState<ChatEntry[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [turnTimings, setTurnTimings] = useState("");
  const [lastQuery, setLastQuery] = useState("");
  const [mode1Iterations, setMode1Iterations] = useState(3);
  const [liveStatus, setLiveStatus] = useState("");
  const [suggestions, setSuggestions] = useState<{ text: string; source: string }[]>([]);
  const [suggBy, setSuggBy] = useState("");
  const [suggLoading, setSuggLoading] = useState(false);
  const [showDraftForm, setShowDraftForm] = useState(false);
  const [draftTitle, setDraftTitle] = useState("");
  // The iterate card renders when a caller supplies a result; the Mode 1
  // stream does not produce one, so it stays null until something does.
  const [iterateResult] = useState<Mode1IterateResponse | null>(null);

  const modeKnown = caseMode === "1" || caseMode === "2" || caseMode === "3";
  const mode: "mode1" | "mode2" | "mode3" =
    caseMode === "1" ? "mode1" : caseMode === "2" ? "mode2" : caseMode === "3" ? "mode3" : "mode1";

  const scrollRef = useRef<HTMLDivElement | null>(null);
  const scrollTimerRef = useRef<number | null>(null);

  const scrollToEnd = useCallback(() => {
    if (scrollTimerRef.current) window.clearTimeout(scrollTimerRef.current);
    scrollTimerRef.current = window.setTimeout(() => {
      scrollRef.current?.scrollTo({
        top: scrollRef.current.scrollHeight,
        behavior: "smooth",
      });
    }, 50);
  }, []);

  const load = useCallback(() => {
    api.chat(200)
      .then((response) => {
        setMessages(response.messages);
        scrollToEnd();
      })
      .catch((exc) => setError((exc as Error).message));
  }, [scrollToEnd]);

  useEffect(() => {
    void load();
    return () => {
      if (scrollTimerRef.current) window.clearTimeout(scrollTimerRef.current);
    };
  }, [activeCase, load]);

  const refreshSuggestions = useCallback(() => {
    setSuggLoading(true);
    api
      .mode1Suggestions()
      .then((response) => {
        setSuggestions(response.suggestions || []);
        setSuggBy(response.generated_by || "");
      })
      .catch(() => {
        /* suggestions are optional - never block the chat */
      })
      .finally(() => setSuggLoading(false));
  }, []);

  useEffect(() => {
    if (mode !== "mode1") return;
    refreshSuggestions();
  }, [activeCase, mode, refreshSuggestions]);

  const savedTs = useMemo(
    () =>
      new Set(
        messages
          .filter((message) => message.action === "answer_saved")
          .map((message) => String(message.data?.entry_ts || ""))
          .filter(Boolean),
      ),
    [messages],
  );

  const sendText = useCallback(
    async (text: string) => {
      if (!text.trim() || loading) return;
      setLoading(true);
      setError("");
      setLiveStatus("");
      setMessages((previous) => [
        ...previous,
        {
          ts: new Date().toISOString(),
          role: "examiner",
          action: "steer_question",
          text,
          meta: {},
        },
      ]);

      try {
        if (mode !== "mode1") return;
        await chatStream(
          {
            message: text,
            mode,
            max_iterations: mode1Iterations,
            history: messages.slice(-6).map((message) => ({
              role: message.role,
              text: message.text,
            })),
          },
          (event) => {
            const data = event.data as Record<string, unknown>;
            if (event.event === "round") {
              setLiveStatus(
                `Round ${String(data.round ?? "?")} — deciding the next action.`,
              );
            } else if (event.event === "tool_call") {
              setLiveStatus(
                `tool ${String(data.tool || "")}: ${String(data.why || "retrieving evidence")}`,
              );
            } else if (event.event === "tool_result") {
              const audit = data.audit_id ? ` · audit ${String(data.audit_id)}` : "";
              const failure = data.error ? ` · ${String(data.error)}` : "";
              setLiveStatus(
                `tool ${String(data.tool || "")} returned${audit}${failure}`,
              );
            } else if (event.event === "partial") {
              setLiveStatus(
                `Budget reached (${String(data.reason || "limit")}) — returning partial result.`,
              );
            } else if (event.event === "done") {
              const executed = Array.isArray(data.queries_executed)
                ? (data.queries_executed as { hits?: number; dsl?: string }[])
                : [];
              const first = executed.find((query) => (query.hits ?? 0) > 0);
              if (first?.dsl) setLastQuery(first.dsl);
              const timings = data.timings_ms as Record<string, number> | undefined;
              if (timings) {
                const rendered = Object.entries(timings)
                  .filter(([, value]) => typeof value === "number")
                  .map(([key, value]) => `${key} ${(value / 1000).toFixed(1)}s`)
                  .join(" · ");
                if (rendered) setTurnTimings(rendered);
              }
            } else if (event.event === "error") {
              setError(String(data.error || "stream error"));
            }
          },
        );
        load();
      } catch (exc) {
        setError((exc as Error).message);
      } finally {
        setLoading(false);
        setLiveStatus("");
      }
    },
    [load, loading, messages, mode, mode1Iterations],
  );

  const send = () => {
    if (!input.trim() || loading) return;
    const text = input;
    setInput("");
    void sendText(text);
  };

  const saveAnswer = async (entryTs: string) => {
    if (!entryTs) return;
    const response = await api.mode1SaveAnswer({ entry_ts: entryTs });
    if (response.error) {
      throw new Error(
        Array.isArray(response.error) ? response.error.join("; ") : response.error,
      );
    }
    load();
  };

  const stageDraft = async (entry: ChatEntry, title: string) => {
    const response = await api.mode1ProposeDraft({
      title,
      query: lastQuery || undefined,
      hits: entry.data?.hits,
    });
    if (response.error) {
      throw new Error(
        Array.isArray(response.error) ? response.error.join("; ") : response.error,
      );
    }
    load();
  };

  const explore = (dsl: string) => {
    navigate(dsl ? dslToExplore(dsl, activeCase || "") : "/explore");
  };

  // --- Mode 2/3 cases: this surface is Mode 1's -----------------------
  if (modeKnown && mode !== "mode1") {
    return (
      <div className={styles.page}>
        <Panel>
          <p>
            This case runs{" "}
            <strong>Mode {caseMode === "2" ? "2 (multi-role)" : "3 (multi-agent)"}</strong>
            . Steer Chat is the Mode 1 surface — a guided chat over the case
            index.
          </p>
          <Link
            to={`/case/${encodeURIComponent(activeCase || "")}/agent-run`}
            className="nx-button nx-button-primary"
          >
            Open Agent Run
          </Link>
        </Panel>
      </div>
    );
  }

  return (
    <div className={styles.page}>
      <div className={styles.topBar}>
        <div>
          <h2>Steer Chat</h2>
          <p className={styles.hint}>
            Mode 1 — ask about the evidence. Answers are LLM-drafted and never
            examiner-approved; stage a finding to have it signed.
          </p>
        </div>
        <div className={styles.topControls}>
          {/* The iteration depth has a real cost (more rounds, more evidence
              read), so it is labelled rather than a bare number. */}
          <Field label="Max rounds">
            {({ id }) => (
              <Input
                id={id}
                className={styles.iterations}
                type="number"
                min={1}
                max={8}
                value={mode1Iterations}
                onChange={(event) =>
                  setMode1Iterations(
                    Math.max(1, Math.min(8, Number(event.target.value) || 2)),
                  )
                }
              />
            )}
          </Field>
          <Button size="sm" onClick={load}>
            Refresh
          </Button>
        </div>
      </div>

      {error ? (
        <div role="alert" className="error-banner">
          {error}
        </div>
      ) : null}
      {turnTimings ? (
        <p className={styles.hint} data-testid="turn-timings">
          Last turn: {turnTimings}
        </p>
      ) : null}

      {mode === "mode1" && (suggestions.length > 0 || suggLoading) ? (
        <div className={styles.suggestions} data-testid="suggestions">
          <span className={styles.label}>
            Suggested questions{suggBy ? ` · ${suggBy}` : ""}
          </span>
          <div className={styles.chips}>
            {suggestions.map((suggestion, index) => (
              <Button
                key={index}
                size="sm"
                variant="ghost"
                onClick={() => void sendText(suggestion.text)}
                title={suggestion.source}
              >
                {suggestion.text}
              </Button>
            ))}
            <Button size="sm" variant="ghost" onClick={refreshSuggestions}>
              Refresh
            </Button>
          </div>
        </div>
      ) : null}

      {mode === "mode1" && showDraftForm ? (
        <div className={styles.draftRow}>
          <Field label="DRAFT title">
            {({ id }) => (
              <Input
                id={id}
                value={draftTitle}
                onChange={(event) => setDraftTitle(event.target.value)}
                placeholder="One line that states the claim"
              />
            )}
          </Field>
          <Button
            variant="primary"
            size="sm"
            disabled={loading || !draftTitle.trim()}
            onClick={async () => {
              const last = messages[messages.length - 1];
              if (!last) return;
              await stageDraft(last, draftTitle.trim());
              setShowDraftForm(false);
              setDraftTitle("");
            }}
          >
            Stage DRAFT
          </Button>
          <Button
            size="sm"
            onClick={() => {
              setShowDraftForm(false);
              setDraftTitle("");
            }}
          >
            Cancel
          </Button>
        </div>
      ) : null}

      {mode === "mode1" && iterateResult && iterateResult.iterations.length > 0 ? (
        <Panel
          className={styles.iterateCard}
          title={`Investigation loop — ${iterateResult.iterations.length} round(s), ${iterateResult.total_hits} hits`}
        >
          {iterateResult.iterations.map((iteration, index) => (
            <div key={index} className={styles.iterateRound}>
              <strong>
                {iteration.action === "initial_query"
                  ? "Round 0 (entry)"
                  : `Round ${iteration.iteration}`}
              </strong>
              {(iteration.queries || []).map((query, queryIndex: number) => (
                <div key={queryIndex} className={styles.traceRow}>
                  <span className={query.dsl && !query.fallback ? styles.dslHit : styles.dslEmpty}>
                    {query.query}
                  </span>
                  <span>· {query.hits} hit(s)</span>
                </div>
              ))}
              {(iteration.aggregations || []).map((aggregation, aggIndex: number) => (
                <div key={`a${aggIndex}`} className={styles.hint}>
                  <strong>Aggregation {aggregation.field || "?"}</strong>:{" "}
                  {aggregation.distinct ?? 0} distinct
                  {aggregation.top?.length
                    ? ` — ${aggregation.top
                        .slice(0, 5)
                        .map((top) => `${top.value}(${top.count})`)
                        .join(", ")}`
                    : ""}
                </div>
              ))}
            </div>
          ))}
        </Panel>
      ) : null}

      {/* A live region: a streamed answer is announced, not silently appended. */}
      <div
        ref={scrollRef}
        className={`${styles.transcript} card`}
        role="log"
        aria-live="polite"
        aria-label="Conversation transcript"
        data-testid="transcript"
      >
        {messages.length === 0 ? (
          <EmptyState
            title="No messages yet"
            hint="Ask a question to start the investigation loop."
          />
        ) : (
          messages.map((message, index) => {
            if (isProposal(message) || (message.data?.hits?.length ?? 0) > 0) {
              return (
                <ProposalCard
                  key={message.ts || index}
                  entry={message}
                  caseMode={caseMode}
                  busy={loading}
                  saved={savedTs.has(message.ts)}
                  onAsk={(question) => void sendText(question)}
                  onExplore={explore}
                  onSave={() => saveAnswer(message.ts)}
                  onStage={(title) => stageDraft(message, title)}
                />
              );
            }
            return (
              <div key={message.ts || index}>
                <MessageBubble role={message.role} text={message.text}>
                  {message.role !== "examiner" &&
                  (message.data?.queries?.length ?? 0) > 0 ? (
                    <QueryTrace
                      queries={message.data?.queries || []}
                      onExplore={explore}
                    />
                  ) : null}
                  {message.data?.partial ? <PartialNotice /> : null}
                  <FollowupChips
                    followups={message.data?.followups || []}
                    disabled={loading}
                    onAsk={(question) => void sendText(question)}
                  />
                  <MessageMeta
                    role={message.role}
                    action={message.action}
                    ts={message.ts}
                    totalHits={Number(message.meta?.total_hits ?? 0) || undefined}
                    timings={message.meta?.timings}
                  />
                </MessageBubble>
              </div>
            );
          })
        )}
        {loading ? (
          liveStatus ? (
            <LiveStatus status={liveStatus} />
          ) : (
            <LiveStatus status="Working…" />
          )
        ) : null}
      </div>

      <div className={styles.composer}>
        <div className={styles.composerInput}>
          <Field label="Ask about the evidence">
            {({ id }) => (
              <Input
                id={id}
                placeholder="e.g. what ran on WS01 between 03:00 and 04:00?"
                value={input}
                disabled={loading}
                onChange={(event) => setInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !loading) send();
                }}
              />
            )}
          </Field>
        </div>
        <Button variant="primary" onClick={send} disabled={loading} data-testid="send">
          {loading ? "Working…" : "Send"}
        </Button>
      </div>

      {messages.length > 0 ? (
        <div className={styles.actions}>
          <Button size="sm" onClick={() => explore(lastQuery)}>
            Open the last query in Explore
          </Button>
          <Button size="sm" onClick={() => setShowDraftForm((open) => !open)}>
            Stage a DRAFT from the last answer
          </Button>
          <Badge tone="origin-llm">LLM output is never examiner-approved</Badge>
        </div>
      ) : null}
    </div>
  );
}