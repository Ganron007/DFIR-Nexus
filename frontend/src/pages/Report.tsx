import { useEffect, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api, type Finding } from "../api/client";
import { computeApprovalResponse } from "../lib/crypto";
import { useCase } from "../context/CaseContext";

export default function Report() {
  const { activeCase, caseSummaries, refreshStages, refreshCases } = useCase();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<{
    total: number;
    approved: number;
    draft: number;
    rejected: number;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [officialMarkdown, setOfficialMarkdown] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"official" | "findings">("official");
  const [steer, setSteer] = useState("");
  const [steering, setSteering] = useState(false);
  const [steerFindingId, setSteerFindingId] = useState("");
  const [rounds, setRounds] = useState<Array<{
    round: number;
    ts: string;
    instruction: string;
    finding_id?: string;
    model?: string;
    findings_hash?: string;
    report_sha256?: string;
    snapshot_path?: string;
    previous_report_sha256?: string;
  }>>([]);

  // Case lifecycle — seal & close (N8 is the natural end of the spine).
  const [sealOpen, setSealOpen] = useState(false);
  const [sealPassword, setSealPassword] = useState("");
  const [sealing, setSealing] = useState(false);
  const caseStatus = activeCase ? caseSummaries[activeCase]?.status || "" : "";
  const isSealed = caseStatus === "sealed" || caseStatus === "closed" || caseStatus === "archived";

  const loadData = async () => {
    setLoading(true);
    setError("");
    try {
      const [fRes, sRes, repRes] = await Promise.all([
        api.findings("APPROVED").catch((e) => {
          setError((e as Error).message);
          return { findings: [] as Finding[], total: 0 };
        }),
        api.summary().catch(() => null),
        api.reportView().catch(() => null),
      ]);

      setFindings(fRes.findings);
      if (sRes) {
        setSummary({
          total: sRes.findings.total,
          approved: sRes.findings.approved,
          draft: sRes.findings.draft,
          rejected: sRes.findings.rejected,
        });
      }
      if (repRes && repRes.ok && repRes.markdown) {
        setOfficialMarkdown(repRes.markdown);
        setActiveTab("official");
      } else {
        setActiveTab("findings");
      }
      api.reportRounds().then((r) => setRounds(r.rounds || [])).catch(() => {});
    } finally {
      setLoading(false);
    }
  };

  const handleSteer = async () => {
    if (!steer.trim()) return;
    setSteering(true);
    setError("");
    setSuccess("");
    try {
      const res = await api.reportSteer({
        instruction: steer.trim(),
        finding_id: steerFindingId || undefined,
      });
      if (!res.ok) throw new Error(res.error || "Steer failed");
      setSuccess(`Round ${res.round} applied — analysis re-read with your direction (${res.instructions_applied} instruction${res.instructions_applied === 1 ? "" : "s"} in effect)`);
      setSteer("");
      if (activeCase) refreshStages(activeCase);
      const rep = await api.reportView();
      if (rep && rep.ok && rep.markdown) setOfficialMarkdown(rep.markdown);
      const r = await api.reportRounds();
      setRounds(r.rounds || []);
    } catch (err: unknown) {
      setError((err as Error).message || "Error steering report");
    } finally {
      setSteering(false);
    }
  };

  const handleSeal = async () => {
    if (!sealPassword) {
      setError("Approval password required — sealing signs the case file with your examiner identity.");
      return;
    }
    setSealing(true);
    setError("");
    setSuccess("");
    try {
      const ch = await api.getChallenge();
      const responseHmac = await computeApprovalResponse(
        sealPassword,
        ch.salt,
        ch.iterations,
        ch.nonce
      );
      const r = await api.sealCase({
        challenge_id: ch.challenge_id,
        response: responseHmac,
      });
      if (r.error) throw new Error(r.error);
      setSealPassword("");
      setSealOpen(false);
      setSuccess(`Case sealed as ${r.status} — signed by ${r.examiner}. All actions are locked until you reopen the case from the dashboard or the banner above.`);
      await refreshCases();
      if (activeCase) refreshStages(activeCase);
    } catch (err: unknown) {
      setError((err as Error).message || "Seal failed");
    } finally {
      setSealing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [activeCase]);

  const handleGenerateReport = async () => {
    setGenerating(true);
    setError("");
    setSuccess("");
    try {
      const res = await api.reportGenerate({ profile: "markdown" });
      if (!res.ok) {
        throw new Error(res.error || "Failed to generate report");
      }
      setSuccess(`Official report generated (${res.findings_count} approved finding${res.findings_count === 1 ? "" : "s"} incorporated)`);
      if (activeCase) refreshStages(activeCase);
      const rep = await api.reportView();
      if (rep && rep.ok && rep.markdown) {
        setOfficialMarkdown(rep.markdown);
        setActiveTab("official");
      }
    } catch (err: unknown) {
      setError((err as Error).message || "Error generating report");
    } finally {
      setGenerating(false);
    }
  };

  const exportMarkdown = () => {
    const md = activeTab === "official" && officialMarkdown ? officialMarkdown : buildMarkdown();
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = activeTab === "official" ? "REPORT.md" : "DFIR-Nexus-Report.md";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 200);
  };

  const buildMarkdown = (): string => {
    const lines: string[] = [];
    lines.push("# DFIR-Nexus Case Report");
    lines.push("");
    lines.push("> This report is generated from APPROVED findings only.");
    lines.push("> DRAFT and REJECTED findings are excluded per FD-001.");
    lines.push("");
    if (summary) {
      lines.push("## Summary");
      lines.push("");
      lines.push(`- Total findings: ${summary.total}`);
      lines.push(`- Approved: ${summary.approved}`);
      lines.push(`- Draft: ${summary.draft}`);
      lines.push(`- Rejected: ${summary.rejected}`);
      lines.push("");
    }
    if (findings.length > 0) {
      lines.push("## Findings");
      lines.push("");
      for (const f of findings) {
        lines.push(`### ${f.title}`);
        lines.push("");
        lines.push(`- **ID:** ${f.id}`);
        lines.push(`- **Confidence:** ${f.confidence}`);
        lines.push(`- **Status:** ${f.status}`);
        if (f.approved_by) {
          lines.push(`- **Approved by:** ${f.approved_by}`);
        }
        if (f.approved_at) {
          lines.push(`- **Approved at:** ${f.approved_at}`);
        }
        if (f.observation) {
          lines.push("");
          lines.push("**Observation:**");
          lines.push("");
          lines.push(f.observation);
        }
        if (f.interpretation) {
          lines.push("");
          lines.push("**Interpretation:**");
          lines.push("");
          lines.push(f.interpretation);
        }
        if (f.confidence_justification) {
          lines.push("");
          lines.push(`**Confidence justification:** ${f.confidence_justification}`);
        }
        if (f.audit_ids && f.audit_ids.length > 0) {
          lines.push("");
          lines.push(`**Evidence audit IDs:** ${f.audit_ids.join(", ")}`);
        }
        lines.push("");
      }
    } else {
      lines.push("## No APPROVED findings");
      lines.push("");
      lines.push("No findings have been approved yet. Use the Approve desk to approve DRAFT findings.");
      lines.push("");
    }
    return lines.join("\n");
  };

  if (loading) return <div className="loading">Loading report...</div>;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h2>Official Case Report</h2>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            className="btn btn-primary btn-sm"
            onClick={handleGenerateReport}
            disabled={generating}
          >
            {generating ? "Generating..." : "⚡ Generate Official Report"}
          </button>
          <button
            className="btn btn-sm"
            onClick={exportMarkdown}
            disabled={!officialMarkdown && findings.length === 0}
          >
            Export Markdown
          </button>
        </div>
      </div>

      {error && <div className="error-banner" style={{ marginBottom: 16 }}>{error}</div>}
      {success && (
        <div style={{ padding: "10px 14px", background: "rgba(16, 185, 129, 0.15)", border: "1px solid rgba(16, 185, 129, 0.4)", borderRadius: 6, color: "#10b981", marginBottom: 16, fontSize: 13 }}>
          {success}
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16, borderBottom: "1px solid var(--border)", paddingBottom: 8 }}>
        <button
          className={`btn btn-sm ${activeTab === "official" ? "btn-primary" : ""}`}
          onClick={() => setActiveTab("official")}
          style={{ background: activeTab === "official" ? undefined : "transparent", border: "1px solid var(--border)" }}
        >
          📄 Official Document {officialMarkdown ? "(Ready)" : "(Not Generated)"}
        </button>
        <button
          className={`btn btn-sm ${activeTab === "findings" ? "btn-primary" : ""}`}
          onClick={() => setActiveTab("findings")}
          style={{ background: activeTab === "findings" ? undefined : "transparent", border: "1px solid var(--border)" }}
        >
          🔍 Approved Findings ({findings.length})
        </button>
      </div>

      {activeTab === "official" ? (
        <div className="card">
          <div className="card-header">
            <span className="card-title">reports/REPORT.md</span>
            {summary && (
              <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                Approved Findings Included: {findings.length} / {summary.total}
              </span>
            )}
          </div>
          <div style={{ padding: 16 }}>
            {/* Mode 1 narrative loop — steer the LLM analysis, iterate until satisfied */}
            <div style={{ marginBottom: 14, padding: "10px 14px", border: "1px solid var(--border)", borderRadius: 6, background: "rgba(56, 189, 248, 0.05)" }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <select
                  value={steerFindingId}
                  onChange={(e) => setSteerFindingId(e.target.value)}
                  disabled={steering}
                  title="Scope this round to one approved finding, or the whole report"
                  style={{ width: "auto", maxWidth: 240, padding: "8px 6px", fontSize: 12, background: "var(--bg-secondary, #0f172a)", border: "1px solid var(--border)", borderRadius: 4, color: "var(--text-primary, #f8fafc)" }}
                >
                  <option value="">Entire report</option>
                  {findings.map((f) => (
                    <option key={f.id} value={f.id}>{f.id} — {f.title}</option>
                  ))}
                </select>
                <input
                  type="text"
                  value={steer}
                  onChange={(e) => setSteer(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSteer()}
                  placeholder="Steer the analysis — e.g. 'dig into the mshta execution chain', 'focus on persistence', 'that inference is wrong because…'"
                  style={{ flex: 1, padding: "8px 10px", fontSize: 13, background: "var(--bg-secondary, #0f172a)", border: "1px solid var(--border)", borderRadius: 4, color: "var(--text-primary, #f8fafc)" }}
                  disabled={steering}
                />
                <button className="btn btn-primary btn-sm" onClick={handleSteer} disabled={steering || !steer.trim()}>
                  {steering ? "Re-analyzing…" : "Steer & re-analyze"}
                </button>
              </div>
              <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 6 }}>
                Each round re-reads the live evidence + findings with your direction and regenerates the report. Steering is recorded per round for audit — LLM output is never examiner-approved.
              </div>
              {rounds.length > 0 && (
                <div style={{ marginTop: 8, fontSize: 12, color: "var(--text-secondary)" }}>
                  {rounds.map((r) => (
                    <div key={r.round} style={{ padding: "2px 0" }}>
                      <span style={{ color: "var(--accent, #38bdf8)" }}>r{r.round}</span> {r.instruction}
                      {r.finding_id && <span style={{ color: "var(--accent, #38bdf8)" }}> · focus {r.finding_id}</span>}
                      <span style={{ opacity: 0.6 }}> · {r.model || "heuristic"} · {String(r.ts || "").slice(0, 19).replace("T", " ")}</span>
                      {r.report_sha256 && (
                        <span
                          style={{ opacity: 0.6, fontFamily: "monospace" }}
                          title={`${r.report_sha256}${r.snapshot_path ? `\n${r.snapshot_path}` : ""}`}
                        >
                          {" "}· sha {r.report_sha256.slice(0, 12)}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
            {officialMarkdown ? (
              <article className="report-markdown">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{officialMarkdown}</ReactMarkdown>
              </article>
            ) : (
              <div style={{ textAlign: "center", padding: "40px 20px", color: "var(--text-secondary)" }}>
                <p style={{ marginBottom: 12 }}>No official report has been compiled for this case yet.</p>
                <button className="btn btn-primary" onClick={handleGenerateReport} disabled={generating}>
                  Compile Official Report Now
                </button>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              Approved Findings ({findings.length} finding{findings.length !== 1 ? "s" : ""})
            </span>
          </div>
          {findings.length === 0 ? (
            <div style={{ padding: 16, color: "var(--text-secondary)" }}>
              No APPROVED findings to display. Use the Approval Desk to review and sign DRAFT findings.
            </div>
          ) : (
            <div style={{ padding: 16 }}>
              {summary && (
                <div style={{ marginBottom: 16, fontSize: 13, color: "var(--text-secondary)" }}>
                  Total: {summary.total} | Approved: {summary.approved} | Draft: {summary.draft} | Rejected: {summary.rejected}
                </div>
              )}
              {findings.map((f) => (
                <div key={f.id} style={{ marginBottom: 24, borderBottom: "1px solid var(--border)", paddingBottom: 16 }}>
                  <h3 style={{ margin: "0 0 8px" }}>{f.title}</h3>
                  <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 8 }}>
                    ID: {f.id} | Confidence: {f.confidence} | Approved by: {f.approved_by || "N/A"}
                  </div>
                  {f.observation && (
                    <div style={{ marginBottom: 8 }}>
                      <strong>Observation:</strong> {f.observation}
                    </div>
                  )}
                  {f.interpretation && (
                    <div style={{ marginBottom: 8 }}>
                      <strong>Interpretation:</strong> {f.interpretation}
                    </div>
                  )}
                  {f.confidence_justification && (
                    <div style={{ marginBottom: 8, fontSize: 13, color: "var(--text-secondary)" }}>
                      <strong>Justification:</strong> {f.confidence_justification}
                    </div>
                  )}
                  {f.audit_ids && f.audit_ids.length > 0 && (
                    <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                      Evidence: {f.audit_ids.join(", ")}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Case lifecycle — sealing is the completion gate for every mode */}
      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-header">
          <span className="card-title">Close the investigation</span>
        </div>
        <div style={{ padding: 16 }}>
          {isSealed ? (
            <p style={{ margin: 0, fontSize: 13, color: "var(--text-secondary)" }}>
              This case is <strong>{STATUS_LABEL_SEALED[caseStatus] || caseStatus}</strong> — all
              investigation actions are locked. Reopen it from the banner above or the case
              dashboard to continue working.
            </p>
          ) : !sealOpen ? (
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <p style={{ margin: 0, fontSize: 13, color: "var(--text-secondary)", flex: 1 }}>
                Sealing HMAC-signs the case file under your examiner identity and locks all
                mutations (409) — findings, workbench, timeline, reports. You can reopen the
                case later; the seal and every reopen are audit-chained.
              </p>
              <button className="btn btn-sm" onClick={() => setSealOpen(true)}>
                Seal &amp; close case…
              </button>
            </div>
          ) : (
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <input
                type="password"
                placeholder="Examiner approval password"
                value={sealPassword}
                onChange={(e) => setSealPassword(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSeal()}
                disabled={sealing}
                style={{ width: 260 }}
              />
              <button
                className="btn btn-primary btn-sm"
                onClick={handleSeal}
                disabled={sealing || !sealPassword}
              >
                {sealing ? "Signing…" : "Seal case"}
              </button>
              <button className="btn btn-sm" onClick={() => { setSealOpen(false); setSealPassword(""); }} disabled={sealing}>
                Cancel
              </button>
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                Same HMAC challenge-response as approval — the password never leaves this browser.
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

const STATUS_LABEL_SEALED: Record<string, string> = {
  sealed: "sealed (completed)",
  closed: "closed",
  archived: "archived",
};
