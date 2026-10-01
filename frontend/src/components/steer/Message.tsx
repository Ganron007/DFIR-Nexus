/**
 * Steer Chat message components (WO-U8a / WP 14.8).
 *
 * The WO asked for "message components" and the page had messages inlined in a
 * `messages.map()` with 80-odd inline style objects between them. These are the
 * pieces, each with its own job:
 *
 * * `MessageBubble`   - one turn, examiner or agent, with an accessible role
 * * `QueryTrace`      - every query the agent actually ran, with its why.
 *                       This is what makes an LLM answer checkable instead of
 *                       something to take on trust, so it is a component of its
 *                       own rather than a fragment inside the bubble.
 * * `FollowupChips`   - deterministic drill-down for the next turn
 * * `PartialNotice`   - an answer that hit its budget, said plainly
 * * `MessageMeta`     - role, action, timestamp, rows, timings
 *
 * The transcript is a `role="log"` with `aria-live="polite"`, so a streamed
 * answer is announced instead of appearing silently below the fold.
 */
import type { ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { Button } from "@/ui";
import styles from "./SteerChat.module.css";

export interface TraceQuery {
  dsl?: string;
  hits?: number;
  why?: string;
}

export function QueryTrace({
  queries,
  onExplore,
}: {
  queries: TraceQuery[];
  onExplore: (dsl: string) => void;
}) {
  if (queries.length === 0) return null;
  return (
    <div className={styles.trace} data-testid="query-trace">
      {queries.map((query, index) => (
        <div key={index} className={styles.traceRow}>
          <span
            className={(query.hits ?? 0) > 0 ? styles.dslHit : styles.dslEmpty}
            title={query.why || undefined}
          >
            {query.dsl || "(no query)"}
          </span>
          <span>· {query.hits ?? 0} hit(s)</span>
          {query.why ? <span>— {query.why}</span> : null}
          {query.dsl ? (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => onExplore(query.dsl as string)}
              title="Open these rows in Explore"
            >
              Explore
            </Button>
          ) : null}
        </div>
      ))}
    </div>
  );
}

export function FollowupChips({
  followups,
  disabled,
  onAsk,
}: {
  followups: { label: string; question: string }[];
  disabled?: boolean;
  onAsk: (question: string) => void;
}) {
  if (followups.length === 0) return null;
  return (
    <div className={styles.followups}>
      {followups.map((followup, index) => (
        <Button
          key={index}
          size="sm"
          variant="ghost"
          disabled={disabled}
          title={followup.question}
          onClick={() => onAsk(followup.question)}
        >
          {followup.label}
        </Button>
      ))}
    </div>
  );
}

export function PartialNotice() {
  return (
    <p className={styles.partial} data-testid="partial-notice">
      Partial answer — the budget was reached before completion; the rows
      retrieved so far are shown above.
    </p>
  );
}

export function MessageMeta({
  role,
  action,
  ts,
  totalHits,
  timings,
}: {
  role: string;
  action?: string;
  ts?: string;
  totalHits?: number;
  timings?: string;
}) {
  return (
    <div
      className={role === "examiner" ? `${styles.meta} ${styles.metaExaminer}` : styles.meta}
    >
      {role}
      {action ? ` · ${action}` : ""}
      {ts ? ` · ${ts.slice(0, 19)}` : ""}
      {totalHits ? ` · ${totalHits} rows` : ""}
      {timings ? ` · ${timings}` : ""}
    </div>
  );
}

export function MessageBubble({
  role,
  text,
  children,
}: {
  role: string;
  text: string;
  children?: ReactNode;
}) {
  const examiner = role === "examiner";
  return (
    <div
      className={
        examiner
          ? `${styles.bubbleRow} ${styles.bubbleRowExaminer}`
          : `${styles.bubbleRow} ${styles.bubbleRowAgent}`
      }
    >
      <div
        className={examiner ? `${styles.bubble} ${styles.bubbleExaminer}` : `${styles.bubble} ${styles.bubbleAgent}`}
      >
        {examiner ? (
          text
        ) : (
          <article className={styles.markdown}>
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
          </article>
        )}
        {children}
      </div>
    </div>
  );
}

export function LiveStatus({ status }: { status: string }) {
  return (
    <div className={styles.livenStatus} data-testid="live-status">
      {status}
    </div>
  );
}
/** The agent's markdown body, shared so the bubble and the card render alike. */
export function MarkdownBody({ text }: { text: string }) {
  return (
    <article className={styles.markdown}>
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
    </article>
  );
}
