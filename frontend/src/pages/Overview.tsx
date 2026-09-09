import { useEffect, useState } from "react";
import { api, type SummaryResponse } from "../api/client";

export default function Overview() {
  const [cases, setCases] = useState<string[]>([]);
  const [activeCase, setActiveCase] = useState("");
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      api.cases().catch((e) => { setError((e as Error).message); return null; }),
      api.summary().catch(() => null),
    ]).then(([c, s]) => {
      if (c) {
        setCases(c.cases || []);
        setActiveCase(c.active || "");
      }
      if (s) setSummary(s);
      setLoading(false);
    });
  }, []);

  if (loading) return <div className="loading">Loading case overview...</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Case Overview</h2>
      {error && <div className="error-banner">{error}</div>}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Active Case: {activeCase || "None"}</span>
        </div>
        {summary ? (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, padding: 16 }}>
            <div className="stat-box">
              <div className="stat-label">Findings (total)</div>
              <div className="stat-value">{summary.findings.total}</div>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {summary.findings.approved} approved · {summary.findings.draft} draft · {summary.findings.rejected} rejected
              </div>
            </div>
            <div className="stat-box">
              <div className="stat-label">Timeline Events</div>
              <div className="stat-value">{summary.timeline}</div>
            </div>
            <div className="stat-box">
              <div className="stat-label">Evidence Items</div>
              <div className="stat-value">{summary.evidence}</div>
            </div>
            <div className="stat-box">
              <div className="stat-label">TODOs</div>
              <div className="stat-value">{summary.todos.total}</div>
              <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                {summary.todos.open} open
              </div>
            </div>
          </div>
        ) : (
          <div style={{ padding: 16, color: "var(--text-muted)" }}>
            No summary available — no active case or case not processed yet.
          </div>
        )}
      </div>
      <div className="card">
        <div className="card-header">
          <span className="card-title">Cases ({cases.length})</span>
        </div>
        {cases.length === 0 ? (
          <div style={{ padding: 16, color: "var(--text-muted)" }}>No cases found.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Case ID</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => (
                <tr key={c} style={{ background: c === activeCase ? "rgba(47,129,247,0.1)" : undefined }}>
                  <td style={{ fontFamily: "monospace" }}>{c}</td>
                  <td>{c === activeCase ? "✓ Active" : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
