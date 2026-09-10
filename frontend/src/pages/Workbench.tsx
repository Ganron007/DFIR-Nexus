import { useEffect, useState, useCallback } from "react";
import { api, type Bookmark } from "../api/client";
import { useCase } from "../context/CaseContext";

interface FormState {
  title: string;
  interpretation: string;
  confidence: string;
  justification: string;
}

interface HistoryState {
  past: FormState[];
  present: FormState;
  future: FormState[];
}

const initialForm: FormState = { title: "", interpretation: "", confidence: "MEDIUM", justification: "" };

const initialState: HistoryState = {
  past: [],
  present: initialForm,
  future: [],
};

function useHistory() {
  const [state, setState] = useState<HistoryState>(initialState);

  const set = useCallback((updater: (prev: FormState) => FormState) => {
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

  const reset = useCallback((value: FormState) => {
    setState({ past: [], present: value, future: [] });
  }, []);

  return { state, set, undo, redo, reset, canUndo: state.past.length > 0, canRedo: state.future.length > 0 };
}

export default function Workbench() {
  const { activeCase } = useCase();
  const [items, setItems] = useState<Bookmark[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [result, setResult] = useState("");
  const [error, setError] = useState("");
  const [dragIndex, setDragIndex] = useState<number | null>(null);

  const form = useHistory();

  const load = () => {
    setLoading(true);
    api.workbench()
      .then((r) => {
        setItems(r.bookmarks);
        setSelected(new Set(r.bookmarks.map((b) => b.id)));
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => load(), [activeCase]);

  const remove = async (id: string) => {
    try {
      await api.workbenchRemove(id);
    } catch (e) {
      setError(`Failed to remove bookmark: ${(e as Error).message}`);
    }
    load();
  };

  const clearAll = async () => {
    try {
      await api.workbenchClear();
    } catch (e) {
      setError(`Failed to clear workbench: ${(e as Error).message}`);
      return;
    }
    setItems([]);
    setSelected(new Set());
  };

  const toggleSelect = (id: string) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  };

  const promote = async () => {
    setError("");
    setResult("");
    const f = form.state.present;
    if (!f.title.trim()) {
      setError("Title is required");
      return;
    }
    if (selected.size === 0) {
      setError("Select at least one bookmark to promote");
      return;
    }
    try {
      const r = await api.workbenchPromote({
        bookmark_ids: Array.from(selected),
        title: f.title,
        interpretation: f.interpretation || undefined,
      });
      if (r.error) {
        setError(Array.isArray(r.error) ? r.error.join("; ") : r.error);
        return;
      }
      setResult(`Promoted to DRAFT: ${r.finding_id} (${r.bookmark_count} bookmark(s))`);
      form.reset(initialForm);
      // Reload workbench — promoted bookmarks are consumed but others remain
      load();
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
  const handleDragEnd = () => setDragIndex(null);

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
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Drag to reorder · {selected.size} selected</span>
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
                <button className="btn btn-sm" onClick={clearAll}>Clear All</button>
                <button className="btn btn-sm" style={{ marginLeft: 4 }} onClick={() => setSelected(new Set(items.map((i) => i.id)))}>Select All</button>
                <button className="btn btn-sm" style={{ marginLeft: 4 }} onClick={() => setSelected(new Set())}>Deselect All</button>
              </div>
              <div style={{ maxHeight: "50vh", overflowY: "auto" }}>
                {items.map((item, i) => (
                  <div
                    key={item.id}
                    draggable
                    onDragStart={() => handleDragStart(i)}
                    onDragOver={handleDragOver}
                    onDrop={() => handleDrop(i)}
                    onDragEnd={handleDragEnd}
                    style={{
                      padding: 8,
                      marginBottom: 4,
                      borderBottom: "1px solid var(--border)",
                      fontSize: 12,
                      cursor: "grab",
                      background: dragIndex === i ? "var(--bg-hover)" : "transparent",
                      borderLeft: "2px solid transparent",
                      borderLeftColor: selected.has(item.id) ? "var(--accent)" : "transparent",
                      transition: "background 0.1s",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <label style={{ display: "flex", alignItems: "center", gap: 4, cursor: "pointer" }}>
                        <input
                          type="checkbox"
                          checked={selected.has(item.id)}
                          onChange={() => toggleSelect(item.id)}
                          style={{ margin: 0 }}
                        />
                        <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--text-muted)" }}>
                          {item.id} · {item.family}
                        </span>
                      </label>
                      <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
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
                    <div style={{ marginTop: 4, color: "var(--text-secondary)", fontSize: 11 }}>
                      {item.file}:{item.line}
                    </div>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {item.text}
                    </div>
                    {item.time && (
                      <div style={{ fontSize: 10, color: "var(--text-muted)" }}>
                        {item.time}
                      </div>
                    )}
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
              placeholder="Interpretation — what the evidence shows and what it means"
              value={form.state.present.interpretation}
              onChange={(e) => form.set((p) => ({ ...p, interpretation: e.target.value }))}
              rows={4}
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
              <button className="btn btn-primary" onClick={promote} style={{ flex: 1 }} disabled={selected.size === 0}>
                Promote to DRAFT ({selected.size} bookmark{selected.size !== 1 ? "s" : ""})
              </button>
              <button
                className="btn"
                onClick={() => form.reset(initialForm)}
                title="Reset form"
              >
                Reset
              </button>
            </div>
            {selected.size > 0 && (
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                {selected.size} bookmarked hit(s) will be attached as evidence. Scribe will auto-generate observation.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
