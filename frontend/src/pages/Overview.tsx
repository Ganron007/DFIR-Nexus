/**
 * WP 4b.3: Case Dashboard (SPA Overview).
 *
 * Functional dashboard: all cases with details, "New Investigation",
 * system health (backend/ES/RAG/LLM/parser), and active-case summary.
 * The landing page links here as "Case Dashboard".
 */
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, type SummaryResponse, type CaseDetailsResponse, type SystemHealthResponse } from "../api/client";
import { useCase } from "../context/CaseContext";

export default function Overview() {
  const navigate = useNavigate();
  const { cases, activeCase, setActiveCase, mode, health } = useCase();
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [caseDetails, setCaseDetails] = useState<Record<string, CaseDetailsResponse>>({});
  const [sys, setSys] = useState<SystemHealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);
  const [seedMsg, setSeedMsg] = useState("");

  const handleSeedDemo = async () => {
    setSeeding(true);
    setSeedMsg("");
    try {
      const res = await api.seedDemo({ name: "Demo Investigation — WS01 Incident" });
      if (res.ok) {
        setSeedMsg(`Loaded demo case ${res.case_id} (${res.evidence_count} evidence, ${res.findings_count} findings)`);
        await setActiveCase(res.case_id);
        const [s, h] = await Promise.all([
          api.summary().catch(() => null),
          api.systemHealth().catch(() => null),
        ]);
        if (s) setSummary(s);
        if (h) setSys(h);
      }
    } catch (e) {
      setSeedMsg(`Failed to seed demo: ${(e as Error).message}`);
    } finally {
      setSeeding(false);
    }
  };

  useEffect(() => {
    Promise.all([
      api.summary().catch(() => null),
      api.systemHealth().catch(() => null),
    ]).then(([s, h]) => {
      if (s) setSummary(s);
      if (h) setSys(h);
      setLoading(false);
    });

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
        <div style={{ display: "flex", gap: 8 }}>
          <button
            className="btn btn-sm"
            onClick={handleSeedDemo}
            disabled={seeding}
            title="Instantly create a pre-populated test case with evidence, extractions, findings, and timeline"
            style={{ background: "rgba(47, 129, 247, 0.15)", border: "1px solid rgba(47, 129, 247, 0.4)", color: "var(--accent)" }}
          >
            {seeding ? "Seeding..." : "⚡ Seed Demo Investigation"}
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => navigate("/case-setup")}>
            + New Investigation
          </button>
        </div>
      </div>

      {seedMsg && (
        <div style={{ padding: "10px 14px", background: "rgba(16, 185, 129, 0.15)", border: "1px solid rgba(16, 185, 129, 0.4)", borderRadius: 6, color: "#10b981", marginBottom: 16, fontSize: 13 }}>
          {seedMsg}
        </div>
      )}

      {/* System health */}
      <div className="card" style={{ marginBottom: 16, padding: 12 }}>
        <div style={{ display: "flex", gap: 20, flexWrap: "wrap", fontSize: 12 }}>
          <span>
            <span style={{ color: "var(--text-muted)" }}>Backend:</span>{" "}
            <span style={{ color: health === "ok" ? "var(--success)" : "var(--danger)" }}>
              {health === "ok" ? "✓ Healthy" : health === "down" ? "✗ Down" : "Checking..."}
            </span>
          </span>
          <span>
            <span style={{ color: "var(--text-muted)" }}>Elasticsearch:</span>{" "}
            <span style={{ color: sys?.es?.configured === false ? "var(--text-muted)" : sys?.es?.reachable ? "var(--success)" : "var(--danger)" }}>
              {sys?.es?.configured === false ? "CSV pack (not configured)" : sys?.es?.reachable ? "✓ reachable" : "✗ unreachable"}
            </span>
          </span>
          <span>
            <span style={{ color: "var(--text-muted)" }}>RAG index:</span>{" "}
            <span style={{ color: sys?.rag?.configured ? "var(--success)" : "var(--danger)" }}>
              {sys?.rag?.configured ? "✓ present" : "✗ missing"}
            </span>
          </span>
          <span>
            <span style={{ color: "var(--text-muted)" }}>LLM:</span>{" "}
            <span style={{ color: sys?.llm?.configured ? "var(--success)" : "var(--warning)" }}>
              {sys?.llm?.configured ? `✓ ${sys.llm.model || "configured"}` : "heuristic fallback"}
            </span>
          </span>
          <span>
            <span style={{ color: "var(--text-muted)" }}>Parser lane:</span>{" "}
            <span style={{ color: sys?.parser === "ok" ? "var(--success)" : "var(--danger)" }}>
              {sys?.parser === "ok" ? "✓ available" : "✗ missing"}
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
            <p>Get started immediately with a pre-populated test case or create a new one.</p>
            <div style={{ display: "flex", gap: 12, justifyContent: "center", marginTop: 16 }}>
              <button className="btn btn-primary" onClick={handleSeedDemo} disabled={seeding}>
                {seeding ? "Seeding Demo..." : "⚡ Load Demo Investigation"}
              </button>
              <button className="btn" onClick={() => navigate("/case-setup")}>
                + New Investigation
              </button>
            </div>
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
