/**
 * Transparency log (HMAC audit chain verification), migrated to the kit
 * (WO-U8a).
 *
 * Kit: PageHeader + Panel + KeyValue + Badge, styles in a CSS module, zero
 * inline style objects. Two defects fixed on the way:
 *
 * 1. The verdict glyph rendered as a mojibake pair - the source had lost its
 *    UTF-8 bytes, so "chain valid" showed two replacement characters and
 *    "chain tampered" showed a literal "?". A tampered chain is the one state
 *    that must never be ambiguous, and it was the least legible thing on the
 *    page. The glyph now comes from the token layer and the state is carried
 *    by a Badge tone and the word, never by the symbol alone.
 * 2. The fetch was an uncached `useEffect` keyed on nothing, so a case switch
 *    could leave the previous case's verdict on screen.
 */
import { useCase } from "../context/CaseContext";
import { useTransparency } from "../api/queries/transparency";
import { Badge, KeyValue, PageHeader, Panel, EmptyState } from "@/ui";
import styles from "./Page.module.css";

export default function Transparency() {
  const { activeCase } = useCase();
  const { data, isLoading, error } = useTransparency(activeCase);

  const result = data ?? null;
  const message = (error as Error | null)?.message ?? "";
  const valid = Boolean(result?.valid);

  const rows = result
    ? [
        { label: "Total entries", value: String(result.entries) },
        ...(result.error
          ? [{ label: "Error", value: result.error, tone: "verifier-refuted" as const }]
          : []),
        ...(result.tampered !== undefined
          ? [
              {
                label: "Tampered at index",
                value: String(result.tampered),
                tone: "verifier-refuted" as const,
              },
            ]
          : []),
        ...(result.expected
          ? [{ label: "Expected hash", value: `${result.expected.slice(0, 32)}…` }]
          : []),
        ...(result.actual
          ? [
              {
                label: "Actual hash",
                value: `${result.actual.slice(0, 32)}…`,
                tone: "verifier-refuted" as const,
              },
            ]
          : []),
      ]
    : [];

  return (
    <div className={styles.page}>
      <PageHeader
        title="Transparency Log"
        subtitle="HMAC-SHA256 audit chain — every tool call links to the one before it"
        stageCode="N8"
        actions={
          result ? (
            <span data-testid="chain-verdict">
              <Badge tone={valid ? "seal-verified" : "seal-broken"}>
                {valid ? "Chain valid" : "Chain tampered"}
              </Badge>
            </span>
          ) : null
        }
      />

      {message ? (
        <div role="alert" className="error-banner">
          The transparency log could not be read: {message}. This is a backend
          problem, not a statement about the chain.
        </div>
      ) : null}

      <Panel>
        {isLoading ? (
          <div className="loading">Verifying the audit chain…</div>
        ) : rows.length > 0 ? (
          <KeyValue items={rows} />
        ) : (
          <EmptyState
            title="No transparency data"
            hint="The audit chain appears once the case has recorded tool calls."
          />
        )}
      </Panel>
    </div>
  );
}
