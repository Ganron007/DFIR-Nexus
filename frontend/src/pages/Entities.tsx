/**
 * WP 4b.9: Entities loads on mount — call api.entities({}) in useEffect
 * so the page isn't empty on arrival.
 */
import { useEffect, useState } from "react";
import { api, type EntitiesResponse } from "../api/client";

export default function Entities() {
  const [entities, setEntities] = useState<EntitiesResponse["entities"] | null>(null);
  const [total, setTotal] = useState(0);
  const [needles, setNeedles] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // WP 4b.9: Load on mount with empty needles
  useEffect(() => {
    setLoading(true);
    setError("");
    api.entities({ needles: undefined })
      .then((r) => {
        setEntities(r.entities);
        setTotal(r.total);
      })
      .catch((e) => {
        setError((e as Error).message);
        setEntities(null);
      })
      .finally(() => setLoading(false));
  }, []);

  const search = () => {
    setLoading(true);
    setError("");
    api.entities({ needles: needles || undefined })
      .then((r) => {
        setEntities(r.entities);
        setTotal(r.total);
      })
      .catch((e) => {
        setError((e as Error).message);
        setEntities(null);
      })
      .finally(() => setLoading(false));
  };

  const allEntities: Array<{ type: string; value: string; count: number }> = [];
  if (entities) {
    for (const [type, dict] of Object.entries(entities)) {
      for (const [value, count] of Object.entries(dict)) {
        allEntities.push({ type, value, count });
      }
    }
    allEntities.sort((a, b) => b.count - a.count);
  }

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Entity Pivot</h2>
      {error && <div className="error-banner">{error}</div>}
      <div className="card">
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          <input
            placeholder="Needles (e.g. sdelete, powershell, 192.168.1.1)"
            value={needles}
            onChange={(e) => setNeedles(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && search()}
          />
          <button className="btn btn-primary" onClick={search}>Extract</button>
        </div>
        {loading && <div className="loading">Extracting entities...</div>}
        {!loading && entities && (
          <>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
              {total} hits scanned · {allEntities.length} entities extracted
            </div>
            <table>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>Count</th>
                </tr>
              </thead>
              <tbody>
                {allEntities.map((e) => (
                  <tr key={`${e.type}:${e.value}`}>
                    <td><span className="badge badge-medium">{e.type}</span></td>
                    <td style={{ fontFamily: "monospace" }}>{e.value}</td>
                    <td>{e.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
        {!loading && !entities && (
          <div className="empty-state">
            <p>Enter needles and click Extract to find entities in matching hits.</p>
          </div>
        )}
      </div>
    </div>
  );
}
