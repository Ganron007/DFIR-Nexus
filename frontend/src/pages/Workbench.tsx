import { useEffect, useState } from "react";
import { api, type WorkbenchItem } from "../api/client";

export default function Workbench() {
  const [items, setItems] = useState<WorkbenchItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [title, setTitle] = useState("");
  const [observation, setObservation] = useState("");
  const [interpretation, setInterpretation] = useState("");
  const [confidence, setConfidence] = useState("MEDIUM");
  const [justification, setJustification] = useState("");
  const [result, setResult] = useState("");
  const [error, setError] = useState("");

  const load = () => {
    setLoading(true);
    api.workbench()
      .then(setItems)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => load(), []);

  const remove = async (id: string) => {
    await api.workbenchRemove(id).catch(() => {});
    load();
  };

  const clear = async () => {
    await api.workbenchClear().catch(() => {});
    setItems([]);
  };

  const promote = async () => {
    setError("");
    setResult("");
    if (!title.trim() || !observation.trim()) {
      setError("Title and observation are required");
      return;
    }
    try {
      const r = await api.workbenchPromote({
        title,
        observation,
        interpretation: interpretation || undefined,
        confidence,
        confidence_justification: justification || undefined,
      });
      setResult(`Promoted to DRAFT: ${r.finding_id}`);
      setTitle("");
      setObservation("");
      setInterpretation("");
      setJustification("");
      clear();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  if (loading) return <div className="loading">Loading workbench...</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Finding Workbench</h2>
      {error && <div className="error-banner">{error}</div>}
      {result && (
        <div style={{ background: "rgba(63,185,80,0.1)", border: "1px solid var(--success)", borderRadius: 6, padding: 10, marginBottom: 16, color: "var(--success)" }}>
          {result}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div className="card">
          <div className="card-header">
            <span className="card-title">Bookmarked Hits ({items.length})</span>
            {items.length > 0 && (
              <button className="btn btn-sm" onClick={clear}>Clear All</button>
            )}
          </div>
          {items.length === 0 ? (
            <div className="empty-state">
              <h3>No bookmarks</h3>
              <p>Star hits in Explore to bookmark them here.</p>
            </div>
          ) : (
            <div style={{ maxHeight: "50vh", overflowY: "auto" }}>
              {items.map((item) => (
                <div
                  key={item.id}
                  style={{
                    padding: 8,
                    borderBottom: "1px solid var(--border)",
                    fontSize: 12,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--text-muted)" }}>
                      {item.hit.family} · {item.hit.host}
                    </span>
                    <button
                      className="btn btn-sm"
                      onClick={() => remove(item.id)}
                      style={{ padding: "2px 6px" }}
                    >
                      ×
                    </button>
                  </div>
                  <div style={{ marginTop: 4, color: "var(--text-secondary)" }}>
                    {item.hit.line}
                  </div>
                  <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
                    {item.hit.timestamp}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">DRAFT Finding Builder</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <input
              placeholder="Title (required)"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
            <textarea
              placeholder="Observation (required) — what the evidence shows"
              value={observation}
              onChange={(e) => setObservation(e.target.value)}
              rows={4}
            />
            <textarea
              placeholder="Interpretation — what it means"
              value={interpretation}
              onChange={(e) => setInterpretation(e.target.value)}
              rows={3}
            />
            <div style={{ display: "flex", gap: 8 }}>
              <select
                value={confidence}
                onChange={(e) => setConfidence(e.target.value)}
                style={{ width: "auto" }}
              >
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
              </select>
              <input
                placeholder="Confidence justification (FD-005)"
                value={justification}
                onChange={(e) => setJustification(e.target.value)}
              />
            </div>
            <button className="btn btn-primary" onClick={promote}>
              Promote to DRAFT
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
