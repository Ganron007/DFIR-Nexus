/**
 * WP 4b.8: Frontend error handling — no more silent .catch(() => {}).
 * Lifecycle-aware empty states: the page tells the examiner which stage
 * (N1 intake / N2 processing) unblocks it.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useCase } from "../context/CaseContext";

export default function Evidence() {
  const { activeCase } = useCase();
  const [evidence, setEvidence] = useState<unknown[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!activeCase) {
      setEvidence([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    api.evidence()
      .then((r) => setEvidence(r.evidence))
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, [activeCase]);

  if (loading) return <div className="loading">Loading evidence registry...</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Evidence Registry ({evidence.length})</h2>
      {error && <div className="error-banner">{error}</div>}
      {evidence.length === 0 ? (
        <div className="empty-state">
          <h3>N2 — no evidence registered</h3>
          {!activeCase ? (
            <>
              <p>No active case. Start at <strong>N1 Case Setup</strong> to create a case and register evidence.</p>
              <Link to="/case-setup" className="btn btn-primary" style={{ marginTop: 12, display: "inline-block" }}>
                Go to Case Setup (N1)
              </Link>
            </>
          ) : (
            <>
              <p>Case <strong>{activeCase}</strong> has no registered evidence yet.</p>
              <p>Register evidence in the Case Setup wizard (step 2), then run the N2 processing lane (step 4).</p>
              <Link to="/case-setup" className="btn btn-primary" style={{ marginTop: 12, display: "inline-block" }}>
                Open Case Setup
              </Link>
            </>
          )}
        </div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Path</th>
                <th>SHA-256</th>
                <th>Description</th>
                <th>Status</th>
                <th>Registered</th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((e, i) => {
                const item = e as Record<string, string>;
                return (
                  <tr key={i}>
                    <td style={{ fontFamily: "monospace", fontSize: 11 }}>{item.path}</td>
                    <td style={{ fontFamily: "monospace", fontSize: 11 }}>{item.sha256?.slice(0, 16)}...</td>
                    <td>{item.description}</td>
                    <td>{item.status}</td>
                    <td>{item.registered_at}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
