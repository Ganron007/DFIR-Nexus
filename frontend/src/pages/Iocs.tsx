/**
 * WP 4d.4: IOCs page — indicators of compromise extracted from findings.
 */
import { useEffect, useState } from "react";
import { api, type Ioc } from "../api/client";
import { useCase } from "../context/CaseContext";

export default function Iocs() {
  const { activeCase } = useCase();
  const [iocs, setIocs] = useState<Ioc[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!activeCase) {
      setIocs([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    api.iocs()
      .then((r) => setIocs(r.iocs))
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, [activeCase]);

  if (loading) return <div className="loading">Loading IOCs...</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Indicators of Compromise ({iocs.length})</h2>
      {error && <div className="error-banner">{error}</div>}
      {iocs.length === 0 ? (
        <div className="empty-state">
          <h3>No IOCs extracted</h3>
          <p>IOCs are collected from finding evidence. Create findings with IOC entries to populate this page.</p>
        </div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Finding</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {iocs.map((ioc, i) => (
                <tr key={i}>
                  <td><span className="badge badge-medium">{String(ioc.type || "unknown")}</span></td>
                  <td style={{ fontFamily: "monospace", fontSize: 12 }}>{String(ioc.value || "")}</td>
                  <td>{String(ioc.finding_title || "")}</td>
                  <td>{String(ioc.finding_status || "")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
