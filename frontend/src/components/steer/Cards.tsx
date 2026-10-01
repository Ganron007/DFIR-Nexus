/**
 * Steer Chat cards (WO-U8a / WP 14.8).
 *
 * `HitCard` and `ProposalCard` were inline in the page with their own inline
 * styles; they are components here so the transcript reads as components and
 * the styles live in one module.
 *
 * Behaviour kept exactly:
 * * a hit can be starred to the Workbench without leaving the conversation,
 * * a proposal can be staged as a DRAFT (examiner approval still required) or
 *   saved for the report, and saving is idempotent in the UI,
 * * "LLM-drafted" is labelled as such - the card never implies a human wrote
 *   it.
 */
import { useState } from "react";

import { api, type ChatEntry, type N4Hit } from "../../api/client";
import { Badge, Button } from "@/ui";
import styles from "./SteerChat.module.css";
import { FollowupChips, MarkdownBody, QueryTrace } from "./Message";

export function HitCard({ hit }: { hit: N4Hit }) {
  const [bookmarkId, setBookmarkId] = useState("");
  const [bookmarkError, setBookmarkError] = useState("");
  const [busy, setBusy] = useState(false);

  const fields = Object.entries(hit.fields || {}).slice(0, 6);
  const bookmarked = Boolean(bookmarkId);

  // The server assigns the bookmark id (B-###). Removing by our own loc key
  // silently no-ops, which would clear the star while the Workbench kept the
  // row - so the id the server gave us is the one we remove with.
  const toggle = async () => {
    setBusy(true);
    setBookmarkError("");
    try {
      if (bookmarkId) {
        await api.workbenchRemove(bookmarkId);
        setBookmarkId("");
      } else {
        const response = await api.workbenchAdd(hit);
        setBookmarkId(response.bookmark_id || "");
      }
    } catch (error) {
      // card-level failure is non-fatal; the star just stays as it was
      setBookmarkError((error as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={styles.hit} data-testid="hit-card">
      <div className={styles.hitHead}>
        <button
          type="button"
          className={bookmarked ? `${styles.star} ${styles.starActive}` : styles.star}
          onClick={toggle}
          disabled={busy || bookmarked}
          aria-pressed={bookmarked}
          aria-label={
            bookmarked ? `Bookmarked ${hit.file}:${hit.line}` : `Bookmark ${hit.file}:${hit.line} to the Workbench`
          }
          title="Bookmark to the Workbench"
        >
          {bookmarked ? "★" : "☆"}
        </button>
        <span className={styles.hitFamily}>
          {hit.family} · {hit.file}:{hit.line}
        </span>
      </div>
      {fields.length > 0 ? (
        <div className={styles.hitFields}>
          {fields.map(([key, value]) => (
            <span key={key}>
              <span className={styles.hitFieldKey}>{key}: </span>
              <span className={styles.hitFieldValue}>{String(value)}</span>
            </span>
          ))}
        </div>
      ) : null}
      <div className={styles.hitText} title={hit.text}>
        {hit.text}
      </div>
      {bookmarkError ? (
        <p className={styles.warn} role="alert">
          {bookmarkError}
        </p>
      ) : null}
    </div>
  );
}

export function ProposalCard({
  entry,
  caseMode,
  busy,
  saved,
  onAsk,
  onExplore,
  onSave,
  onStage,
}: {
  entry: ChatEntry;
  caseMode: string;
  busy: boolean;
  saved: boolean;
  onAsk: (question: string) => void;
  onExplore: (dsl: string) => void;
  onSave: () => Promise<void>;
  onStage: (title: string) => Promise<void>;
}) {
  const [draftTitle, setDraftTitle] = useState("");
  const [showDraftForm, setShowDraftForm] = useState(false);
  const [saveState, setSaveState] = useState("");
  const [draftState, setDraftState] = useState("");

  const meta = (entry.meta || {}) as Record<string, unknown>;
  const queries = (entry.data?.queries || []) as { dsl?: string; hits?: number; why?: string }[];
  const followups = (entry.data?.followups || []) as { label: string; question: string }[];
  const hits = (entry.data?.hits || []) as N4Hit[];
  const firstHitQuery = queries.find((query) => (query.hits ?? 0) > 0)?.dsl;
  // Terms are carried on the cited rows, not on the entry.
  const hitTerms = [...new Set(hits.flatMap((hit) => hit.terms?.split(/\s+/).filter(Boolean) ?? []))].slice(0, 24);

  return (
    <div className={styles.card} data-testid="proposal-card">
      <div className={styles.cardHead}>
        <Badge tone="origin-llm">LLM-drafted</Badge>
        <Badge>{entry.action}</Badge>
        <span className={styles.note}>
          {String(meta.total_hits ?? 0)} rows
          {caseMode ? ` · mode ${caseMode}` : ""}
        </span>
      </div>

      {entry.text ? (
        <div className={styles.markdown}>
          <MarkdownBody text={entry.text} />
        </div>
      ) : null}

      {hitTerms.length > 0 ? (
        <div className={styles.terms}>
          {hitTerms.map((term, index) => (
            <span key={index} className={styles.term}>
              {term}
            </span>
          ))}
        </div>
      ) : null}

      <QueryTrace queries={queries} onExplore={onExplore} />

      {hits.length > 0 ? (
        <div>
          <span className={styles.label}>
            Cited rows ({hits.length}) — star to bookmark to the Workbench
          </span>
          <div className={styles.terms}>
            {hits.map((hit, index) => (
              <HitCard key={index} hit={hit} />
            ))}
          </div>
        </div>
      ) : null}

      <div className={styles.actions}>
        <Button
          size="sm"
          onClick={() => onExplore(firstHitQuery ?? "")}
          title="Open the underlying rows in Explore"
        >
          Open in Explore
        </Button>
        <Button
          size="sm"
          onClick={() => setShowDraftForm((open) => !open)}
          disabled={busy}
          title="Stage a DRAFT finding from this answer and its cited rows (examiner approval required)"
        >
          Stage DRAFT
        </Button>
        <Button
          size="sm"
          onClick={async () => {
            setSaveState("saving…");
            try {
              await onSave();
              setSaveState("Saved for report");
            } catch (error) {
              setSaveState((error as Error).message);
            }
          }}
          disabled={saved || saveState === "saving…"}
          title="Bookmark this answer's cited rows to the Workbench and record the answer for the report"
        >
          {saved || saveState === "Saved for report" ? "Saved for report" : "Save for report"}
        </Button>
        {saveState && saveState !== "Saved for report" && saveState !== "saving…" ? (
          <span className={styles.warn}>{saveState}</span>
        ) : null}
      </div>

      {showDraftForm ? (
        <div className={styles.draftRow}>
          <label className={styles.label} htmlFor={`draft-title-${entry.ts}`}>
            DRAFT title
          </label>
          <input
            id={`draft-title-${entry.ts}`}
            value={draftTitle}
            onChange={(event) => setDraftTitle(event.target.value)}
            placeholder="One line that states the claim"
          />
          <Button
            size="sm"
            variant="primary"
            disabled={busy || !draftTitle.trim()}
            onClick={async () => {
              setDraftState("");
              await onStage(draftTitle.trim());
              setDraftTitle("");
              setShowDraftForm(false);
              setDraftState("Staged as DRAFT — examiner approval required.");
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
          {draftState ? <span className={styles.ok}>{draftState}</span> : null}
        </div>
      ) : null}

      <FollowupChips followups={followups} disabled={busy} onAsk={onAsk} />
    </div>
  );
}
