import { useEffect, useState } from "react";
import { api, type CaseInfo } from "../api/client";

export default function Overview() {
  const [cases, setCases] = useState<CaseInfo[]>([]);
  const [summary, setSummary] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.cases(), api.summary()])
      .then(([c, s]) => {
        setCases(c);
        setSummary(s);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading">Loading case overview...</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Case Overview</h2>
      <div className="card">
        <div className="card-header">
          <span className="card-title">Active Case Summary</span>
        </div>
        <pre style={{ fontSize: 12, color: "var(--text-secondary)", whiteSpace: "pre-wrap" }}>
          {JSON.stringify(summary, null, 2)}
        </pre>
      </div>
      <div className="card">
        <div className="card-header">
          <span className="card-title">Cases ({cases.length})</span>
        </div>
        <table>
          <thead>
            <tr>
              <th>Case ID</th>
              <th>Name</th>
              <th>Status</th>
              <th>Examiner</th>
            </tr>
          </thead>
          <tbody>
            {cases.map((c) => (
              <tr key={c.case_id}>
                <td style={{ fontFamily: "monospace" }}>{c.case_id}</td>
                <td>{c.case_name}</td>
                <td>{c.status || "—"}</td>
                <td>{c.examiner || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
