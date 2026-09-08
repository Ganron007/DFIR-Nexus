import { useEffect, useState, useCallback } from "react";
import { api, type WorkbenchItem } from "../api/client";

interface HistoryState {
  past: Array<{ title: string; observation: string; interpretation: string; confidence: string; justification: string }>;
  present: { title: string; observation: string; interpretation: string; confidence: string; justification: string };
  future: Array<{ title: string; observation: string; interpretation: string; confidence: string; justification: string }>;
}

const initialState: HistoryState = {
  past: [],
  present: { title: "", observation: "", interpretation: "", confidence: "MEDIUM", justification: "" },
  future: [],
};

function useHistory<T>(initial: T) {
  const [state, setState] = useState<{ past: T[]; present: T; future: T[] }>({
    past: [],
    present: initial,
    future: [],
  });

  const set = useCallback((updater: (prev: T) => T) => {
    setState((s) => {
      const newPresent = updater(s.present);
      if (JSON.stringify(newPresent) === JSON.stringify(s.present)) return s;
      return { past: [...s.past, s.present], present: newPresent, future: [] };
    });
  }, []);

  const undo = useCallback(() => {
    setState((s) => {
      if (s.past.length === 0) return s;
      const previous = s.past[s.past.length - 1];
      return { past: s.past.slice(0, -1), present: previous, future: [s.present, ...s.future] };
    });
  }, []);

  const redo = useCallback(() => {
    setState((s) => {
      if (s.future.length === 0) return s;
      const next = s.future[0];
      return { past: [...s.past, s.present], present: next, future: s.future.slice(1) };
    });
  }, []);

  const reset = useCallback((value: T) => {
    setState({ past: [], present: value, future: [] });
  }, []);

  return { state, set, undo, redo, reset, canUndo: state.past.length > 0, canRedo: state.future.length > 0 };
}

export default function Workbench() {
  const [items, setItems] = useState<WorkbenchItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [dragIndex, setDragIndex] = useState<number | null>(null);

  const form = useHistory(initialState.present);

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
    const f = form.state.present;
    if (!f.title.trim() || !f.observation.trim()) {
      setError("Title and observation are required");
      return;
    }
    try {
      const r = await api.workbenchPromote({
        title: f.title,
        observation: f.observation,
        interpretation: f.interpretation || undefined,
        confidence: f.confidence,
        confidence_justification: f.justification || undefined,
      });
      setResult(`Promoted to DRAFT: ${r.finding_id}`);
      form.reset(initialState.present);
      clear();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  // Drag-and-drop reordering (visual only — workbench order is client-side)
  const handleDragStart = (index: number) => setDragIndex(index);
  const handleDragOver = (e: React.DragEvent) => e.preventDefault();
  const handleDrop = (index: number) => {
    if (dragIndex === null || dragIndex === index) return;
    const next = [...items];
    const [moved] = next.splice(dragIndex, 1);
    next.splice(index, 0, moved);
    setItems(next);
    setDragIndex(null);
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
        {/* Bookmarked hits with drag-and-drop */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Bookmarked Hits ({items.length})</span>
            {items.length > 0 && (
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Drag to reorder</span>
            )}
          </div>
          {items.length === 0 ? (
            <div className="empty-state">
              <h3>No bookmarks</h3>
              <p>Star hits in Explore to bookmark them here.</p>
            </div>
          ) : (
            <>
              <div style={{ marginBottom: 8 }}>
                <button className="btn btn-sm" onClick={clear}>Clear All</button>
              </div>
              <div style={{ maxHeight: "50vh", overflowY: "auto" }}>
                {items.map((item, i) => (
                  <div
                    key={item.id}
                    draggable
                    onDragStart={() => handleDragStart(i)}
                    onDragOver={handleDragOver}
                    onDrop={() => handleDrop(i)}
                    style={{
                      padding: 8,
                      marginBottom: 4,
                      borderBottom: "1px solid var(--border)",
                      fontSize: 12,
                      cursor: "grab",
                      background: dragIndex === i ? "var(--bg-hover)" : "transparent",
                      borderLeft: "2px solid transparent",
                      borderLeftColor: dragIndex === i ? "var(--accent)" : "transparent",
                      transition: "background 0.1s",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--text-muted)" }}>
                        {item.hit.family} · {item.hit.host}
                      </span>
                      <div style={{ display: "flex", gap: 4 }}>
                        <span style={{ fontSize: 10, color: "var(--text-muted)" }}>#{i + 1}</span>
                        <button
                          className="btn btn-sm"
                          onClick={(e) => { e.stopPropagation(); remove(item.id); }}
                          style={{ padding: "2px 6px" }}
                        >
                          ×
                        </button>
                      </div>
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
            </>
          )}
        </div>

        {/* Finding builder with undo/redo */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">DRAFT Finding Builder</span>
            <div style={{ display: "flex", gap: 4 }}>
              <button
                className="btn btn-sm"
                onClick={form.undo}
                disabled={!form.canUndo}
                title="Undo"
              >
                ↶ Undo
              </button>
              <button
                className="btn btn-sm"
                onClick={form.redo}
                disabled={!form.canRedo}
                title="Redo"
              >
                ↷ Redo
              </button>
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <input
              placeholder="Title (required)"
              value={form.state.present.title}
              onChange={(e) => form.set((p) => ({ ...p, title: e.target.value }))}
            />
            <textarea
              placeholder="Observation (required) — what the evidence shows"
              value={form.state.present.observation}
              onChange={(e) => form.set((p) => ({ ...p, observation: e.target.value }))}
              rows={4}
            />
            <textarea
              placeholder="Interpretation — what it means"
              value={form.state.present.interpretation}
              onChange={(e) => form.set((p) => ({ ...p, interpretation: e.target.value }))}
              rows={3}
            />
            <div style={{ display: "flex", gap: 8 }}>
              <select
                value={form.state.present.confidence}
                onChange={(e) => form.set((p) => ({ ...p, confidence: e.target.value }))}
                style={{ width: "auto" }}
              >
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
              </select>
              <input
                placeholder="Confidence justification (FD-005)"
                value={form.state.present.justification}
                onChange={(e) => form.set((p) => ({ ...p, justification: e.target.value }))}
              />
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn btn-primary" onClick={promote} style={{ flex: 1 }}>
                Promote to DRAFT
              </button>
              <button
                className="btn"
                onClick={() => form.reset(initialState.present)}
                title="Reset form"
              >
                Reset
              </button>
            </div>
            {items.length > 0 && (
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                {items.length} bookmarked hit(s) will be attached as evidence.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
