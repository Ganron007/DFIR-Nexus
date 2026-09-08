import { useEffect, useState } from "react";
import { api } from "../api/client";

export default function Evidence() {
  const [evidence, setEvidence] = useState<unknown[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.evidence()
      .then(setEvidence)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading">Loading evidence registry...</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Evidence Registry ({evidence.length})</h2>
      {evidence.length === 0 ? (
        <div className="empty-state">
          <h3>No evidence registered</h3>
          <p>Run <code>nexus evidence register /path/to/evidence</code> to register.</p>
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
