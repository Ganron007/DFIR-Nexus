import { useState } from "react";
import { api, type EntityResult } from "../api/client";

export default function Entities() {
  const [entities, setEntities] = useState<EntityResult[]>([]);
  const [needles, setNeedles] = useState("");
  const [loading, setLoading] = useState(false);

  const search = () => {
    setLoading(true);
    api.entities({ needles })
      .then(setEntities)
      .catch(() => setEntities([]))
      .finally(() => setLoading(false));
  };

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Entity Pivot</h2>
      <div className="card">
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          <input
            placeholder="Needles (e.g. sdelete | powershell | 192.168.1.1)"
            value={needles}
            onChange={(e) => setNeedles(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && search()}
          />
          <button className="btn btn-primary" onClick={search}>Extract</button>
        </div>
        {loading && <div className="loading">Extracting entities...</div>}
        {!loading && entities.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              {entities.map((e, i) => (
                <tr key={i}>
                  <td><span className="badge badge-medium">{e.type}</span></td>
                  <td style={{ fontFamily: "monospace" }}>{e.value}</td>
                  <td>{e.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {!loading && entities.length === 0 && needles && (
          <div className="empty-state">
            <p>No entities found. Run a search first.</p>
          </div>
        )}
      </div>
    </div>
  );
}
