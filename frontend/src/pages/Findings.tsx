/**
 * Findings (WP 4b.8 / 4b.12 / 4b.13), migrated to the kit (WO-U8a).
 *
 * The page used to be a stack of cards, one per finding, each carrying its own
 * corroboration and audit-trail state in component dictionaries. It is now a
 * DataGrid of findings with the detail in a Drawer:
 *
 * * the table is filterable and sortable, which a card per finding cannot be -
 *   an examiner asking "every DRAFT" had to scroll;
 * * corroboration (FD-006/007) and the audit trail are per-finding queries,
 *   so they are cached per finding, cannot bleed across a case switch, and no
 *   longer pile up in component state;
 * * the Drawer is a Radix dialog, so focus is trapped, Esc closes it and focus
 *   returns to the row that opened it.
 */
import { useMemo, useState } from "react";

import { useCase } from "../context/CaseContext";
import {
  severityTone,
  statusTone,
  useCorroboration,
  useFindingAuditTrail,
  useFindings,
} from "../api/queries/findings";
import {
  Badge,
  Button,
  DataGrid,
  Drawer,
  EmptyState,
  KeyValue,
  PageHeader,
  type DataGridColumn,
} from "@/ui";
import type { Finding } from "../api/client";
import styles from "./Findings.module.css";

const COLUMNS: DataGridColumn<Finding>[] = [
  {
    id: "id",
    header: "Finding",
    accessorFn: (row) => row.id,
    filterable: true,
    pinnable: true,
    width: 170,
  },
  {
    id: "title",
    header: "Title",
    accessorFn: (row) => row.title,
    filterable: true,
    width: 320,
  },
  {
    id: "status",
    header: "Status",
    accessorFn: (row) => row.status,
    filterable: true,
    width: 110,
  },
  {
    id: "severity",
    header: "Severity",
    accessorFn: (row) => row.severity || "",
    filterable: true,
    width: 100,
  },
  {
    id: "confidence",
    header: "Confidence",
    accessorFn: (row) => row.confidence,
    filterable: true,
    width: 100,
  },
  {
    id: "audit",
    header: "Audit refs",
    accessorFn: (row) => String(row.audit_ids?.length ?? 0),
    width: 100,
  },
  {
    // Origin matters to a reviewer: an LLM draft that no examiner selected is
    // a different claim from one the examiner picked, and the column says so.
    id: "origin",
    header: "Origin",
    accessorFn: (row) => (row.examiner_selected ? "examiner" : "LLM-drafted"),
    filterable: true,
    width: 120,
  },
];

function FindingDetail({ finding }: { finding: Finding }) {
  const { activeCase } = useCase();
  const [wantCorroboration, setWantCorroboration] = useState(false);
  const [wantAudit, setWantAudit] = useState(false);
  const corroboration = useCorroboration(activeCase, wantCorroboration ? finding.id : null);
  const audit = useFindingAuditTrail(activeCase, wantAudit ? finding.id : null);

  return (
    <div>
      <div className={styles.badgeRow}>
        <Badge tone={statusTone(finding.status)}>{finding.status}</Badge>
        {finding.severity ? (
          <Badge tone={severityTone(finding.severity)}>
            {finding.severity}
          </Badge>
        ) : null}
        <Badge>{finding.confidence}</Badge>
        <Badge tone={finding.examiner_selected ? "origin-examiner" : "origin-llm"}>
          {finding.examiner_selected ? "examiner-selected" : "LLM-drafted"}
        </Badge>
      </div>

      <KeyValue
        className={styles.section}
        items={[
          { label: "Finding id", value: finding.id, mono: true },
          { label: "Audit references", value: String(finding.audit_ids?.length ?? 0) },
        ]}
      />

      {finding.observation ? (
        <p className={styles.body}>{finding.observation}</p>
      ) : null}
      {finding.interpretation ? (
        <p className={styles.body}>
          <strong>Interpretation:</strong> {finding.interpretation}
        </p>
      ) : null}
      {finding.confidence_justification ? (
        <p className={`${styles.body} ${styles.justification}`}>
          <strong>Justification:</strong> {finding.confidence_justification}
        </p>
      ) : null}

      <div className={styles.section}>
        <h4>Corroboration (FD-006 / FD-007)</h4>
        {!corroboration.data ? (
          <div className={styles.actionRow}>
            <Button size="sm" onClick={() => setWantCorroboration(true)}>
              Check corroboration
            </Button>
          </div>
        ) : corroboration.isPending ? (
          <div className="loading">Checking…</div>
        ) : corroboration.error ? (
          <p role="alert" className="error-banner">
            Corroboration check failed: {corroboration.error.message}
          </p>
        ) : (
          <div>
            <div className={styles.badgeRow}>
              <Badge tone={corroboration.data.ok ? "verifier-confirmed" : "verifier-refuted"}>
                {corroboration.data.ok ? "PASS" : "FAIL"}
              </Badge>
              <span className={styles.justification}>
                {corroboration.data.distinct_families} distinct famil
                {corroboration.data.distinct_families === 1 ? "y" : "ies"} ·{" "}
                {corroboration.data.confidence}
              </span>
            </div>
            {corroboration.data.problems?.length ? (
              <ul className={styles.problems}>
                {corroboration.data.problems.map((problem, index) => (
                  <li key={index}>{problem}</li>
                ))}
              </ul>
            ) : null}
            {corroboration.data.suggested_queries?.length ? (
              <div>
                <span className={styles.justification}>Suggested corroboration queries:</span>
                <div className={styles.queryList}>
                  {corroboration.data.suggested_queries.map((query, index) => (
                    <span key={index} className={styles.query}>
                      {query}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
        )}
      </div>

      <div className={styles.section}>
        <h4>Audit trail</h4>
        {!audit.data ? (
          <div className={styles.actionRow}>
            <Button size="sm" onClick={() => setWantAudit(true)}>
              View audit trail
            </Button>
          </div>
        ) : audit.isPending ? (
          <div className="loading">Loading…</div>
        ) : audit.error ? (
          <p role="alert" className="error-banner">
            Audit trail load failed: {audit.error.message}
          </p>
        ) : (
          <pre className={styles.audit}>{JSON.stringify(audit.data, null, 2)}</pre>
        )}
      </div>
    </div>
  );
}

export default function Findings() {
  const { activeCase } = useCase();
  const { data, isLoading, error } = useFindings(activeCase);
  const [openId, setOpenId] = useState<string | null>(null);

  const findings = useMemo(() => data?.findings ?? [], [data]);
  const selected = findings.find((finding) => finding.id === openId) ?? null;

  return (
    <div className={styles.page}>
      <PageHeader
        title="Findings"
        subtitle={
          isLoading
            ? "Loading…"
            : `${findings.length} finding${findings.length === 1 ? "" : "s"} — all staged DRAFT until an examiner approves them`
        }
        stageCode="N6"
      />

      {error ? (
        <div role="alert" className="error-banner">
          Findings could not be read: {(error as Error).message}
        </div>
      ) : null}

      {findings.length === 0 && !isLoading ? (
        <EmptyState
          title="No findings yet"
          hint="Use Explore and Workbench to promote matching hits into DRAFT findings."
        />
      ) : (
        <DataGrid<Finding>
          mode="client"
          columns={COLUMNS}
          rows={findings}
          getRowId={(row) => row.id}
          viewId="findings"
          height={520}
          ariaLabel="Findings"
          emptyMessage="No findings yet."
          onOpenRow={(row) => setOpenId(row.id)}
        />
      )}

      <Drawer
        open={Boolean(selected)}
        onOpenChange={(next) => {
          if (!next) setOpenId(null);
        }}
        title={selected ? `${selected.id} — ${selected.title}` : "Finding"}
        width={620}
      >
        {selected ? <FindingDetail finding={selected} /> : null}
      </Drawer>
    </div>
  );
}
