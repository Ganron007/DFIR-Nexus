/**
 * Entity pivot (WP 4b.9), migrated to the kit (WO-U8a).
 *
 * Kit: PageHeader + Panel + EmptyState + Badge + Button/Input, styles in a
 * CSS module, zero inline style objects.
 * Data: a case-scoped mutation. The previous version fetched on mount with
 * `useEffect` and kept its own loading state, so switching case left the old
 * table on screen until the new response arrived - the last case's entity
 * counts shown under the new case's name.
 */
import { useState } from "react";

import { useCase } from "../context/CaseContext";
import { useExtractEntities } from "../api/queries/entities";
import { Badge, Button, EmptyState, Field, Input, PageHeader, Panel } from "@/ui";
import styles from "./Page.module.css";

export default function Entities() {
  const { activeCase } = useCase();
  const [needles, setNeedles] = useState("");
  const extract = useExtractEntities(activeCase);

  const result = extract.data;
  const rows = result?.rows ?? [];
  const message = extract.error?.message ?? "";

  const run = () => extract.mutate(needles);

  return (
    <div className={styles.page}>
      <PageHeader
        title="Entity Pivot"
        subtitle={
          result
            ? `${result.total} hits scanned — ${rows.length} entities extracted`
            : "Extract hosts, users, IPs and paths from the matching hits"
        }
        stageCode="N4"
      />

      <Panel>
        <div className={styles.toolbar}>
          <Field label="Needles" hint="Commas separate terms; a leading - excludes.">
            {({ id }) => (
              <Input
                id={id}
                placeholder="sdelete, powershell, 192.168.1.1"
                value={needles}
                onChange={(event) => setNeedles(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") run();
                }}
              />
            )}
          </Field>
          <Button
            variant="primary"
            onClick={run}
            disabled={extract.isPending}
            data-testid="entities-extract"
          >
            {extract.isPending ? "Extracting…" : "Extract"}
          </Button>
        </div>

        {message ? (
          <div role="alert" className="error-banner">
            Entity extraction failed: {message}
          </div>
        ) : null}

        {extract.isPending ? (
          <div className="loading">Extracting entities…</div>
        ) : rows.length > 0 ? (
          <table className={styles.table}>
            <caption className="visually-hidden">
              Entities extracted from the matching hits
            </caption>
            <thead>
              <tr>
                <th scope="col">Type</th>
                <th scope="col">Value</th>
                <th scope="col" className={styles.numeric}>
                  Count
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={`${row.type}:${row.value}`}>
                  <td>
                    <Badge>{row.type}</Badge>
                  </td>
                  <td className={styles.mono}>{row.value}</td>
                  <td className={styles.numeric}>{row.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <EmptyState
            title="Nothing extracted yet"
            hint="Enter needles and choose Extract to find entities in the matching hits."
          />
        )}
      </Panel>
    </div>
  );
}
