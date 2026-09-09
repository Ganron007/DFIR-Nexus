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
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      api.findings("APPROVED").catch((e) => {
        setError((e as Error).message);
        return { findings: [] as Finding[], total: 0 };
      }),
      api.summary().catch(() => null),
    ]).then(([fRes, sRes]) => {
      setFindings(fRes.findings);
      if (sRes) {
        setSummary({
          total: sRes.findings.total,
          approved: sRes.findings.approved,
          draft: sRes.findings.draft,
          rejected: sRes.findings.rejected,
        });
      }
      setLoading(false);
    });
  }, []);

  const exportMarkdown = () => {
    const md = buildMarkdown();
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "DFIR-Nexus-Report.md";
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
      <h2 style={{ marginBottom: 16 }}>Report</h2>
      {error && <div className="error-banner">{error}</div>}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            Generated Report (APPROVED findings only — {findings.length} finding{findings.length !== 1 ? "s" : ""})
          </span>
          <button className="btn btn-sm" onClick={exportMarkdown} disabled={findings.length === 0}>
            Export Markdown
          </button>
        </div>
        {findings.length === 0 ? (
          <div style={{ padding: 16, color: "var(--text-secondary)" }}>
            No APPROVED findings to generate a report from. Approve findings in the Approve desk first.
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
    </div>
  );
}
