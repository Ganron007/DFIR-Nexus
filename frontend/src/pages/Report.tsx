import { useEffect, useState } from "react";

export default function Report() {
  const [report, setReport] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    // Try to fetch the actual report from the case directory
    fetch("/portal/api/summary")
      .then((r) => r.json())
      .then((d) => {
        const lines: string[] = [];
        lines.push("# DFIR-Nexus Case Report");
        lines.push("");
        lines.push("> This report is generated from APPROVED findings only.");
        lines.push("> DRAFT and REJECTED findings are excluded per FD-001.");
        lines.push("");
        if (d.findings_count !== undefined) {
          lines.push(`## Summary`);
          lines.push("");
          lines.push(`- Total findings: ${d.findings_count}`);
          lines.push(`- Approved: ${d.approved_count || 0}`);
          lines.push(`- Draft: ${d.draft_count || 0}`);
          lines.push(`- Rejected: ${d.rejected_count || 0}`);
            lines.push("");
        }
        if (d.case_id) {
          lines.push(`## Case: ${d.case_id}`);
            lines.push("");
        }
        if (d.examiner) {
            lines.push(`**Examiner:** ${d.examiner}`);
            lines.push("");
        }
        // Add findings list if available
        if (d.findings && Array.isArray(d.findings)) {
          lines.push("## Findings");
          lines.push("");
          for (const f of d.findings) {
            const finding = f as Record<string, unknown>;
            if (finding.status !== "APPROVED") continue;
            lines.push(`### ${finding.title}`);
            lines.push("");
            lines.push(`- **ID:** ${finding.id}`);
            lines.push(`- **Confidence:** ${finding.confidence}`);
            lines.push(`- **Status:** ${finding.status}`);
            if (finding.observation) {
              lines.push("");
              lines.push(`**Observation:** ${finding.observation}`);
            }
            if (finding.interpretation) {
              lines.push("");
              lines.push(`**Interpretation:** ${finding.interpretation}`);
            }
            lines.push("");
          }
        }
        setReport(lines.join("\n"));
        setLoading(false);
      })
      .catch((e) => {
        setError((e as Error).message);
        setReport("# No report available\n\nNo APPROVED findings to generate a report from.");
        setLoading(false);
      });
  }, []);

  const exportMarkdown = () => {
    const blob = new Blob([report], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "DFIR-Nexus-Report.md";
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) return <div className="loading">Loading report...</div>;

  // Simple markdown to HTML rendering
  const renderMarkdown = (md: string): string => {
    let html = md;
    // Headers
    html = html.replace(/^### (.+)$/gm, "<h3>$1</h3>");
    html = html.replace(/^## (.+)$/gm, "<h2>$1</h2>");
    html = html.replace(/^# (.+)$/gm, "<h1>$1</h1>");
    // Blockquotes
    html = html.replace(/^> (.+)$/gm, "<blockquote>$1</blockquote>");
    // Bold
    html = html.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
    // List items
    html = html.replace(/^- (.+)$/gm, "<li>$1</li>");
    html = html.replace(/(<li>.*<\/li>\n?)+/g, (m) => `<ul>${m}</ul>`);
    // Paragraphs (lines not already wrapped)
    html = html
      .split("\n\n")
      .map((block) => {
        if (block.startsWith("<")) return block;
        return `<p>${block.replace(/\n/g, "<br/>")}</p>`;
      })
      .join("\n");
    return html;
  };

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Report</h2>
      {error && <div className="error-banner">{error}</div>}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Generated Report (APPROVED findings only)</span>
          <button className="btn btn-sm" onClick={exportMarkdown}>Export Markdown</button>
        </div>
        <div
          style={{
            whiteSpace: "pre-wrap",
            fontSize: 13,
            lineHeight: 1.6,
            color: "var(--text-primary)",
          }}
          dangerouslySetInnerHTML={{ __html: renderMarkdown(report) }}
        />
      </div>
    </div>
  );
}
