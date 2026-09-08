import { useEffect, useState } from "react";
import { api } from "../api/client";

export default function Transparency() {
  const [entries, setEntries] = useState<unknown[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.transparency()
      .then(setEntries)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading">Loading transparency log...</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Transparency Log</h2>
      <div className="card">
        <div className="card-header">
          <span className="card-title">HMAC Audit Chain ({entries.length} entries)</span>
        </div>
        {entries.length === 0 ? (
          <div className="empty-state">
            <h3>No transparency entries</h3>
            <p>Transparency log entries appear after case-file sealing.</p>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Examiner</th>
                <th>HMAC</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e, i) => {
                const entry = e as Record<string, string>;
                return (
                  <tr key={i}>
                    <td style={{ fontSize: 11, whiteSpace: "nowrap" }}>{entry.timestamp}</td>
                    <td style={{ fontSize: 11 }}>{entry.action}</td>
                    <td style={{ fontSize: 11 }}>{entry.examiner}</td>
                    <td style={{ fontFamily: "monospace", fontSize: 10 }}>
                      {entry.hmac?.slice(0, 24)}...
                    </td>
                    <td style={{ fontSize: 11 }}>{entry.details}</td>
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
