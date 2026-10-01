/**
 * IOCs — indicators of compromise (WP 4d.4), migrated to the kit (WO-U8a).
 *
 * Kit: PageHeader + Panel + EmptyState + Badge, styles in a CSS module.
 * Data: a case-scoped query hook, so switching cases cannot leave the previous
 * case's indicators on screen while the new ones load.
 */
import { useCase } from "../context/CaseContext";
import { useIocs } from "../api/queries/iocs";
import { Badge, EmptyState, PageHeader, Panel, type SemanticTone } from "@/ui";
import type { Ioc } from "../api/client";
import styles from "./Iocs.module.css";

/**
 * Status -> semantic tone. The vocabulary is the kit's, not a second set of
 * colour words: an approved indicator reads as a verified seal, a rejected one
 * as a refuted claim, a draft as unsupported. Anything unrecognised gets the
 * neutral badge rather than a guess.
 */
function toneFor(status: string): SemanticTone | undefined {
  const upper = status.toUpperCase();
  if (upper.includes("APPROV") || upper === "PROVEN") return "seal-verified";
  if (upper.includes("REJECT") || upper.includes("FAIL")) return "verifier-refuted";
  if (upper.includes("DRAFT") || upper.includes("UNSUPPORTED")) return "l1-unsupported";
  if (upper === "CONFIRMED") return "verifier-confirmed";
  return undefined;
}

function cell(value: unknown): string {
  const text = String(value ?? "");
  return text.length ? text : "—";
}

export default function Iocs() {
  const { activeCase } = useCase();
  const { data, isLoading, error } = useIocs(activeCase);

  const iocs: Ioc[] = data?.iocs ?? [];
  const message = (error as Error | null)?.message ?? "";

  return (
    <div className={styles.page}>
      <PageHeader
        title="Indicators of Compromise"
        subtitle={
          isLoading
            ? "Loading…"
            : `${iocs.length} indicator${iocs.length === 1 ? "" : "s"} extracted from evidence and findings`
        }
        stageCode="N7"
      />

      {message ? (
        <div role="alert" className="error-banner">
          IOCs could not be read: {message}
        </div>
      ) : null}

      {iocs.length === 0 && !isLoading && !message ? (
        <EmptyState
          title="No IOCs yet"
          hint="IOCs aggregate from registered evidence (hashes, IPs, hosts) and from findings — auto-extracted from finding text at stage time or attached explicitly."
        />
      ) : iocs.length > 0 ? (
        <Panel>
          <table className={styles.table}>
            <caption className="visually-hidden">
              Indicators of compromise extracted from this case
            </caption>
            <thead>
              <tr>
                <th scope="col">Type</th>
                <th scope="col">Value</th>
                <th scope="col">Source</th>
                <th scope="col">Finding</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc, index) => (
                <tr key={`${ioc.type}-${ioc.value}-${index}`}>
                  <td>
                    <Badge>{String(ioc.type || "unknown")}</Badge>
                  </td>
                  <td className={styles.value}>{cell(ioc.value)}</td>
                  <td>{cell(ioc.source ?? (ioc.finding_title ? "finding" : ""))}</td>
                  <td>{cell(ioc.finding_title)}</td>
                  <td>
                    <Badge tone={toneFor(String(ioc.finding_status ?? ioc.status ?? ""))}>
                      {cell(ioc.finding_status ?? ioc.status)}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      ) : null}
    </div>
  );
}
