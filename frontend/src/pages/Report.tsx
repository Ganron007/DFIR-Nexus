import { useEffect, useState } from "react";
import { api, type Finding } from "../api/client";

export default function Report() {
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
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

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
            {officialMarkdown ? (
              <pre
                style={{
                  background: "var(--bg-secondary, #0f172a)",
                  color: "var(--text-primary, #f8fafc)",
                  padding: 16,
                  borderRadius: 6,
                  fontSize: 13,
                  lineHeight: 1.5,
                  overflowX: "auto",
                  whiteSpace: "pre-wrap",
                  fontFamily: "monospace",
                }}
              >
                {officialMarkdown}
              </pre>
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
    </div>
  );
}
