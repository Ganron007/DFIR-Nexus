import { useEffect, useState } from "react";
import { api, type Finding } from "../api/client";

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.findings()
      .then(setFindings)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading">Loading findings...</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Findings ({findings.length})</h2>
      {findings.length === 0 ? (
        <div className="empty-state">
          <h3>No findings yet</h3>
          <p>Use Explore + Workbench to promote hits into DRAFT findings.</p>
        </div>
      ) : (
        <div>
          {findings.map((f) => (
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
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
