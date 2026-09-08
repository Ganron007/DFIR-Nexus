import { useEffect, useState } from "react";

export default function Report() {
  const [report, setReport] = useState<string>("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/portal/api/summary")
      .then((r) => r.json())
      .then((d) => {
        setReport(`# Case Report\n\nReport generation from APPROVED findings only.\n\nSummary: ${JSON.stringify(d, null, 2)}`);
        setLoading(false);
      })
      .catch(() => {
        setReport("# No report available\n\nNo APPROVED findings to generate a report from.");
        setLoading(false);
      });
  }, []);

  if (loading) return <div className="loading">Loading report...</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Report</h2>
      <div className="card">
        <div className="card-header">
          <span className="card-title">Generated Report (APPROVED findings only)</span>
          <button className="btn btn-sm">Export Markdown</button>
        </div>
        <pre style={{ whiteSpace: "pre-wrap", fontSize: 13, lineHeight: 1.6 }}>
          {report}
        </pre>
      </div>
    </div>
  );
}
