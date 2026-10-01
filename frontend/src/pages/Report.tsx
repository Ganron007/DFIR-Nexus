/**
 * Official case report (N7/N8), migrated to the kit (WO-U8a).
 *
 * The gain beyond the port: **the report prints**. There was no `@media print`
 * anywhere in the app, and the cockpit is dark - so printing produced a
 * dark page that is unreadable in a case file and wastes toner. The print
 * rules invert to ink-on-paper, drop the chrome, and force a provenance header
 * onto the page: which case, how many approved findings were compiled in,
 * and when. A printed report with no provenance is not evidence.
 *
 * Kit: PageHeader + Tabs (Radix) + Panel + Field/Input/Select + Button +
 * EmptyState. Styles in a CSS module; zero inline style objects.
 *
 * Data: five case-scoped queries and two mutations. Steering now invalidates
 * exactly the report view and the round log it changed.
 *
 * Behaviour preserved: the report is built from APPROVED findings only, the
 * seal uses the same HMAC challenge-response as approval (the password never
 * leaves the browser), and a sealed case explains itself instead of offering
 * an action that would 409.
 */
import { useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import {
  useApprovedFindings,
  useFindingsSummary,
  useGenerateReport,
  useReportRounds,
  useReportView,
  useSteerReport,
  type FindingsSummary,
} from "../api/queries/report";
import { computeApprovalResponse } from "../lib/crypto";
import { api } from "../api/client";
import { useCase } from "../context/CaseContext";
import {
  Badge,
  Button,
  EmptyState,
  Field,
  Input,
  PageHeader,
  Panel,
  Select,
  Tabs,
} from "@/ui";
import type { Finding } from "../api/client";
import { originMark, verifierMark } from "../lib/draftMarks";
import styles from "./Report.module.css";

const STATUS_LABEL_SEALED: Record<string, string> = {
  sealed: "sealed (completed)",
  closed: "closed",
  archived: "archived",
};

export default function Report() {
  const { activeCase, caseSummaries, refreshStages, refreshCases } = useCase();

  const findingsQuery = useApprovedFindings(activeCase);
  const summaryQuery = useFindingsSummary(activeCase);
  const viewQuery = useReportView(activeCase);
  const roundsQuery = useReportRounds(activeCase);
  const generate = useGenerateReport(activeCase);
  const steer = useSteerReport(activeCase);

  const [tab, setTab] = useState<string>("official");
  const [steerText, setSteerText] = useState("");
  const [steerScope, setSteerScope] = useState("");
  const [sealOpen, setSealOpen] = useState(false);
  const [sealPassword, setSealPassword] = useState("");
  const [sealing, setSealing] = useState(false);
  const [sealError, setSealError] = useState("");
  const [notice, setNotice] = useState("");

  const findings: Finding[] = useMemo(
    () => findingsQuery.data?.findings ?? [],
    [findingsQuery.data],
  );
  const summary: FindingsSummary | null = summaryQuery.data ?? null;
  const officialMarkdown = viewQuery.data?.markdown ?? "";
  const rounds = roundsQuery.data?.rounds ?? [];

  const caseStatus = activeCase ? caseSummaries[activeCase]?.status || "" : "";
  const isSealed = ["sealed", "closed", "archived"].includes(caseStatus);

  const error =
    (findingsQuery.error as Error | null)?.message ||
    (generate.error as Error | null)?.message ||
    (steer.error as Error | null)?.message ||
    sealError ||
    "";

  const compiledAt = useMemo(
    () => (officialMarkdown ? new Date().toISOString().slice(0, 19).replace("T", " ") : ""),
    [officialMarkdown],
  );

  const download = (markdown: string, filename: string) => {
    const blob = new Blob([markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    window.setTimeout(() => URL.revokeObjectURL(url), 200);
  };

  const handleGenerate = async () => {
    setNotice("");
    try {
      const response = await generate.mutateAsync();
      setNotice(
        `Official report generated — ${response.findings_count ?? 0} approved finding${
          (response.findings_count ?? 0) === 1 ? "" : "s"
        } incorporated.`,
      );
      setTab("official");
      if (activeCase) refreshStages(activeCase);
    } catch {
      // the mutation carries the message
    }
  };

  const handleSteer = async () => {
    if (!steerText.trim()) return;
    setNotice("");
    try {
      const response = await steer.mutateAsync({
        instruction: steerText.trim(),
        finding_id: steerScope || undefined,
      });
      setNotice(
        `Round ${response.round} applied — analysis re-read with your direction (${response.instructions_applied} instruction${
          response.instructions_applied === 1 ? "" : "s"
        } in effect).`,
      );
      setSteerText("");
      if (activeCase) refreshStages(activeCase);
    } catch {
      // the mutation carries the message
    }
  };

  const handleSeal = async () => {
    if (!sealPassword) {
      setSealError(
        "Approval password required — sealing signs the case file with your examiner identity.",
      );
      return;
    }
    setSealing(true);
    setSealError("");
    setNotice("");
    try {
      const challenge = await api.getChallenge();
      const responseHmac = await computeApprovalResponse(
        sealPassword,
        challenge.salt,
        challenge.iterations,
        challenge.nonce,
      );
      const result = await api.sealCase({
        challenge_id: challenge.challenge_id,
        response: responseHmac,
      });
      if (result.error) throw new Error(result.error);
      setSealPassword("");
      setSealOpen(false);
      setNotice(
        `Case sealed as ${result.status} — signed by ${result.examiner}. All actions are locked until you reopen the case.`,
      );
      await refreshCases();
      if (activeCase) refreshStages(activeCase);
    } catch (exc) {
      setSealError((exc as Error).message || "Seal failed");
    } finally {
      setSealing(false);
    }
  };

  const provenance = (
    <div className={styles.provenance} data-testid="report-provenance">
      Case {activeCase || "—"} · approved findings in this document:{" "}
      {summary ? `${findings.length} of ${summary.total}` : findings.length} ·{" "}
      {compiledAt ? `compiled ${compiledAt} UTC` : "not compiled"}
    </div>
  );

  return (
    <div className={styles.page}>
      <PageHeader
        title="Official Case Report"
        subtitle="Compiled from APPROVED findings only — DRAFT and REJECTED are excluded per FD-001"
        stageCode="N7"
        actions={
          <div className={styles.actions}>
            <Button variant="primary" size="sm" onClick={handleGenerate} disabled={generate.isPending}>
              {generate.isPending ? "Generating…" : "Generate official report"}
            </Button>
            <Button
              size="sm"
              onClick={() => window.print()}
              disabled={!officialMarkdown}
              title="Print or save as PDF — ink-on-paper, chrome removed"
            >
              Print / Save PDF
            </Button>
            <Button
              size="sm"
              onClick={() =>
                download(
                  officialMarkdown || "",
                  officialMarkdown ? "REPORT.md" : "DFIR-Nexus-Report.md",
                )
              }
              disabled={!officialMarkdown && findings.length === 0}
            >
              Export Markdown
            </Button>
          </div>
        }
      />

      {error ? (
        <div role="alert" className="error-banner">
          {error}
        </div>
      ) : null}
      {notice ? (
        <div role="status" className={styles.success} data-testid="report-notice">
          {notice}
        </div>
      ) : null}

      <Tabs
        label="Report view"
        value={tab}
        onValueChange={setTab}
        items={[
          {
            value: "official",
            label: `Official document ${officialMarkdown ? "(ready)" : "(not generated)"}`,
          },
          { value: "findings", label: `Approved findings (${findings.length})` },
        ]}
      />

      {tab === "official" ? (
        <Panel
          title="reports/REPORT.md"
          actions={
            summary ? (
              <span data-testid="report-coverage">
                Approved findings included: {findings.length} / {summary.total}
              </span>
            ) : null
          }
        >
          <div className={`${styles.body} noPrint`}>
            <div className={styles.steer}>
              <div className={styles.steerRow}>
                <div className={styles.steerScope}>
                  <Field label="Scope">
                    {({ id }) => (
                      <Select
                        id={id}
                        value={steerScope}
                        disabled={steer.isPending}
                        onChange={(event) => setSteerScope(event.target.value)}
                      >
                        <option value="">Entire report</option>
                        {findings.map((finding) => (
                          <option key={finding.id} value={finding.id}>
                            {finding.id} — {finding.title}
                          </option>
                        ))}
                      </Select>
                    )}
                  </Field>
                </div>
                <div className={styles.steerText}>
                  <Field label="Steer the analysis">
                    {({ id }) => (
                      <Input
                        id={id}
                        placeholder="Dig into the mshta execution chain · focus on persistence · that inference is wrong because…"
                        value={steerText}
                        disabled={steer.isPending}
                        onChange={(event) => setSteerText(event.target.value)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter") void handleSteer();
                        }}
                      />
                    )}
                  </Field>
                </div>
                <Button
                  variant="primary"
                  onClick={handleSteer}
                  disabled={steer.isPending || !steerText.trim()}
                  data-testid="report-steer"
                >
                  {steer.isPending ? "Re-analysing…" : "Steer & re-analyse"}
                </Button>
              </div>
              <p className={styles.hint}>
                Each round re-reads the live evidence and findings with your
                direction and regenerates the document. Steering is recorded per
                round for audit — LLM output is never examiner-approved.
              </p>
              {rounds.length > 0 ? (
                <div className={styles.rounds} data-testid="report-rounds">
                  {rounds.map((round) => (
                    <div key={round.round} className={styles.roundRow}>
                      <span className={styles.roundTag}>r{round.round}</span>{" "}
                      {round.instruction}
                      {round.finding_id ? (
                        <span className={styles.roundTag}>
                          {" "}
                          · focus {round.finding_id}
                        </span>
                      ) : null}
                      <span className={styles.dim}>
                        {" "}
                        · {round.model || "heuristic"} ·{" "}
                        {String(round.ts || "").slice(0, 19).replace("T", " ")}
                      </span>
                      {round.report_sha256 ? (
                        <span
                          className={styles.dim}
                          title={`${round.report_sha256}${
                            round.snapshot_path ? `\n${round.snapshot_path}` : ""
                          }`}
                        >
                          {" "}
                          · sha {round.report_sha256.slice(0, 12)}
                        </span>
                      ) : null}
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
          </div>

          {officialMarkdown ? (
            <div className={styles.body}>
              {provenance}
              <article
                className={styles.markdown}
                data-testid="report-document"
                aria-label="Official case report"
              >
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {officialMarkdown}
                </ReactMarkdown>
              </article>
            </div>
          ) : (
            <EmptyState
              title="No official report for this case yet"
              hint="A report is compiled from APPROVED findings. Generate one to produce the document."
              action={
                <Button variant="primary" onClick={handleGenerate} disabled={generate.isPending}>
                  Compile official report now
                </Button>
              }
            />
          )}
        </Panel>
      ) : (
        <Panel title={`Approved findings (${findings.length})`}>
          <div className={styles.body}>
            {findings.length === 0 ? (
              <EmptyState
                title="No approved findings"
                hint="Use the Approval Desk to review and sign DRAFT findings. The report never includes an unapproved claim."
              />
            ) : (
              <>
                {summary ? (
                  <p className={styles.findingMeta} data-testid="report-summary">
                    Total {summary.total} · approved {summary.approved} · draft{" "}
                    {summary.draft} · rejected {summary.rejected}
                  </p>
                ) : null}
                {findings.map((finding) => (
                  <article key={finding.id} className={styles.finding}>
                    <h3>{finding.title}</h3>
                    <p className={styles.findingMeta}>
                      <Badge tone={originMark(finding).tone}>{originMark(finding).label}</Badge>
                      {" "}
                      <Badge tone={verifierMark(finding).tone}>{verifierMark(finding).label}</Badge>
                    </p>
                    <p className={styles.findingMeta}>
                      {finding.id} · confidence {finding.confidence} · approved by{" "}
                      {finding.approved_by || "N/A"}
                      {finding.approved_at ? ` · ${finding.approved_at}` : ""}
                    </p>
                    {finding.observation ? (
                      <p className={styles.findingBody}>
                        <strong>Observation:</strong> {finding.observation}
                      </p>
                    ) : null}
                    {finding.interpretation ? (
                      <p className={styles.findingBody}>
                        <strong>Interpretation:</strong> {finding.interpretation}
                      </p>
                    ) : null}
                    {finding.confidence_justification ? (
                      <p className={styles.findingBody}>
                        <strong>Justification:</strong>{" "}
                        {finding.confidence_justification}
                      </p>
                    ) : null}
                    {finding.audit_ids?.length ? (
                      <p className={styles.findingMeta}>
                        Evidence audit ids: {finding.audit_ids.join(", ")}
                      </p>
                    ) : null}
                  </article>
                ))}
              </>
            )}
          </div>
        </Panel>
      )}

      <Panel title="Close the investigation" className="noPrint">
        <div className={styles.body}>
          {isSealed ? (
            <p className={styles.sealCopy}>
              This case is <strong>{STATUS_LABEL_SEALED[caseStatus] || caseStatus}</strong>{" "}
              — all investigation actions are locked. Reopen it from the banner or the
              case dashboard to continue working.
            </p>
          ) : !sealOpen ? (
            <div className={styles.sealRow}>
              <p className={styles.sealCopy}>
                Sealing HMAC-signs the case file under your examiner identity and locks
                all mutations (409) — findings, workbench, timeline, reports. You can
                reopen the case later; the seal and every reopen are audit-chained.
              </p>
              <Button size="sm" onClick={() => setSealOpen(true)}>
                Seal &amp; close case…
              </Button>
            </div>
          ) : (
            <div className={styles.sealRow}>
              <div className={styles.sealPassword}>
                <Field label="Examiner approval password">
                  {({ id }) => (
                    <Input
                      id={id}
                      type="password"
                      value={sealPassword}
                      disabled={sealing}
                      onChange={(event) => setSealPassword(event.target.value)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter") void handleSeal();
                      }}
                    />
                  )}
                </Field>
              </div>
              <Button
                variant="primary"
                size="sm"
                onClick={handleSeal}
                disabled={sealing || !sealPassword}
                data-testid="report-seal"
              >
                {sealing ? "Signing…" : "Seal case"}
              </Button>
              <Button
                size="sm"
                onClick={() => {
                  setSealOpen(false);
                  setSealPassword("");
                }}
                disabled={sealing}
              >
                Cancel
              </Button>
              <span className={styles.hint}>
                Same HMAC challenge-response as approval — the password never leaves this
                browser.
              </span>
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
