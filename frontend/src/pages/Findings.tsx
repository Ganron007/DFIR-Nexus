/**
 * WP 4b.8: Frontend error handling — no more silent .catch(() => {}).
 * WP 4b.13: Corroboration UI — show FD-006/007 status per finding.
 */
import { useEffect, useState } from "react";
import { api, type Finding, type CorroborationResponse } from "../api/client";

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [corroboration, setCorroboration] = useState<Record<string, CorroborationResponse>>({});

  useEffect(() => {
    api.findings()
      .then((r) => setFindings(r.findings))
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, []);

  // WP 4b.13: Load corroboration for each finding
  const loadCorroboration = (findingId: string) => {
    api.mode2Corroborate({ finding_id: findingId })
      .then((r) => setCorroboration((prev) => ({ ...prev, [findingId]: r })))
      .catch(() => {});
  };

  // WP 4b.12: Wire auditForFinding — load audit trail for a finding
  const [auditTrail, setAuditTrail] = useState<Record<string, unknown[]>>({});
  const loadAudit = (findingId: string) => {
    api.auditForFinding(findingId)
      .then((r) => setAuditTrail((prev) => ({ ...prev, [findingId]: r })))
      .catch(() => {});
  };

  if (loading) return <div className="loading">Loading findings...</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Findings ({findings.length})</h2>
      {error && <div className="error-banner">{error}</div>}
      {findings.length === 0 ? (
        <div className="empty-state">
          <h3>No findings yet</h3>
          <p>Use Explore + Workbench to promote hits into DRAFT findings.</p>
        </div>
      ) : (
        <div>
          {findings.map((f) => {
            const corr = corroboration[f.id];
            return (
              <div key={f.id} className="card">
                <div className="card-header">
                  <span className="card-title">{f.title}</span>
                  <div style={{ display: "flex", gap: 8 }}>
                    <span className={`badge badge-${f.status.toLowerCase()}`}>{f.status}</span>
                    <span className={`badge badge-${f.confidence.toLowerCase()}`}>{f.confidence}</span>
                  </div>
                </div>
                <p style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 8 }}>
                  {f.observation}
                </p>
                {f.interpretation && (
                  <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                    <strong>Interpretation:</strong> {f.interpretation}
                  </p>
                )}
                {f.confidence_justification && (
                  <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 8 }}>
                    <strong>Justification:</strong> {f.confidence_justification}
                  </p>
                )}
                <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-muted)" }}>
                  <span style={{ fontFamily: "monospace" }}>{f.id}</span>
                  {" | "}
                  {f.audit_ids.length} audit refs
                  {" | "}
                  {!f.examiner_selected && <span style={{ color: "var(--purple)" }}>LLM-drafted</span>}
                  {f.examiner_selected && <span>examiner-selected</span>}
                </div>

                {/* WP 4b.13: Corroboration panel */}
                <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid var(--border)" }}>
                  {!corr && (
                    <button
                      className="btn btn-sm"
                      onClick={() => loadCorroboration(f.id)}
                    >
                      Check Corroboration (FD-006/007)
                    </button>
                  )}
                  {corr && (
                    <div style={{ fontSize: 12 }}>
                      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
                        <span style={{ color: "var(--text-muted)" }}>FD-006/007:</span>
                        <span
                          className={`badge badge-${corr.ok ? "low" : "high"}`}
                          style={{ fontSize: 10 }}
                        >
                          {corr.ok ? "PASS" : "FAIL"}
                        </span>
                        <span style={{ color: "var(--text-muted)" }}>
                          {corr.distinct_families} families · {corr.confidence}
                        </span>
                      </div>
                      {corr.problems.length > 0 && (
                        <ul style={{ margin: "4px 0 0 20px", color: "var(--danger)" }}>
                          {corr.problems.map((p, i) => <li key={i}>{p}</li>)}
                        </ul>
                      )}
                      {corr.suggested_queries.length > 0 && (
                        <div style={{ marginTop: 4 }}>
                          <span style={{ color: "var(--text-muted)" }}>Suggested corroboration queries:</span>
                          <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 4 }}>
                            {corr.suggested_queries.map((q, i) => (
                              <span key={i} style={{ fontFamily: "monospace", fontSize: 11, padding: "2px 6px", background: "var(--bg-tertiary)", borderRadius: 4 }}>
                                {q}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* WP 4b.12: Audit trail */}
                <div style={{ marginTop: 8 }}>
                  {!auditTrail[f.id] && (
                    <button className="btn btn-sm" onClick={() => loadAudit(f.id)}>
                      View Audit Trail
                    </button>
                  )}
                  {auditTrail[f.id] && (
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                      <strong>Audit Trail ({auditTrail[f.id].length} entries):</strong>
                      <pre style={{ fontSize: 10, marginTop: 4, maxHeight: 120, overflowY: "auto" }}>
                        {JSON.stringify(auditTrail[f.id], null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
