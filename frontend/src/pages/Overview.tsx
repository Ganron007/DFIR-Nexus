/**
 * WP 4b.3: Landing page → Case Dashboard.
 *
 * The Overview page is now a functional case dashboard, not just a summary.
 * Lists all cases with details, "New Investigation" button, and system health.
 */
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, type SummaryResponse, type CaseDetailsResponse } from "../api/client";
import { useCase } from "../context/CaseContext";

export default function Overview() {
  const navigate = useNavigate();
  const { cases, activeCase, setActiveCase, mode, health } = useCase();
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [caseDetails, setCaseDetails] = useState<Record<string, CaseDetailsResponse>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.summary().catch(() => null),
    ]).then(([s]) => {
      if (s) setSummary(s);
      setLoading(false);
    });

    // Load details for each case
    cases.forEach(async (c) => {
      try {
        const d = await api.caseDetails(c);
        setCaseDetails((prev) => ({ ...prev, [c]: d }));
      } catch {
        // ignore
      }
    });
  }, [cases]);

  if (loading) return <div className="loading">Loading case dashboard...</div>;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h2>Case Dashboard</h2>
        <button className="btn btn-primary" onClick={() => navigate("/case-setup")}>
          + New Investigation
        </button>
      </div>

      {/* System health */}
      <div className="card" style={{ marginBottom: 16, padding: 12 }}>
        <div style={{ display: "flex", gap: 24, fontSize: 12 }}>
          <span>
            <span style={{ color: "var(--text-muted)" }}>Backend:</span>{" "}
            <span style={{ color: health === "ok" ? "var(--success)" : "var(--danger)" }}>
              {health === "ok" ? "✓ Healthy" : health === "down" ? "✗ Down" : "Checking..."}
            </span>
          </span>
          {activeCase && mode && (
            <span>
              <span style={{ color: "var(--text-muted)" }}>Mode:</span>{" "}
              <span style={{ color: "var(--accent)", fontWeight: 600 }}>Mode {mode}</span>
            </span>
          )}
        </div>
      </div>

      {/* Active case summary */}
      {activeCase && summary && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header">
            <span className="card-title">Active Case: {activeCase}</span>
          </div>
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
        </div>
      )}

      {/* Cases table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">All Cases ({cases.length})</span>
        </div>
        {cases.length === 0 ? (
          <div className="empty-state">
            <h3>No cases yet</h3>
            <p>Click "New Investigation" to create your first case.</p>
            <button className="btn btn-primary" onClick={() => navigate("/case-setup")} style={{ marginTop: 12 }}>
              + New Investigation
            </button>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Case ID</th>
                <th>Name</th>
                <th>Mode</th>
                <th>Evidence</th>
                <th>Findings</th>
                <th>Pipeline</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => {
                const d = caseDetails[c];
                return (
                  <tr
                    key={c}
                    style={{
                      background: c === activeCase ? "rgba(47,129,247,0.1)" : undefined,
                      cursor: "pointer",
                    }}
                    onClick={() => setActiveCase(c)}
                  >
                    <td style={{ fontFamily: "monospace", fontSize: 11 }}>{c}</td>
                    <td>{d?.name || c}</td>
                    <td>{d?.investigation_mode ? `Mode ${d.investigation_mode}` : "—"}</td>
                    <td>{d?.evidence_count ?? "—"}</td>
                    <td>{d?.findings_count ?? "—"}</td>
                    <td>{d?.pipeline_complete ? "✓ Done" : "—"}</td>
                    <td>{c === activeCase ? "✓ Active" : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
