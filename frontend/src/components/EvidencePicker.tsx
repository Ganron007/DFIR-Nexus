/**
 * WP: evidence picker — browse the local filesystem (via the backend's
 * read-only /fs/list API) and select single or multiple files/folders as
 * evidence. The server runs on the examiner's machine, so the picker
 * browses the same filesystem the pipeline will read from.
 */
import { useEffect, useState } from "react";
import { api, type FsEntry } from "../api/client";

interface EvidencePickerProps {
  open: boolean;
  onClose: () => void;
  onAdd: (paths: string[]) => Promise<void> | void;
}

export default function EvidencePicker({ open, onClose, onAdd }: EvidencePickerProps) {
  const [currentPath, setCurrentPath] = useState("");
  const [entries, setEntries] = useState<FsEntry[]>([]);
  const [parent, setParent] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [adding, setAdding] = useState(false);

  const browse = (path: string) => {
    setLoading(true);
    setError("");
    api.fsList(path || undefined)
      .then((r) => {
        setCurrentPath(r.path);
        setParent(r.parent);
        setEntries(r.entries || []);
        setSelected(new Set());
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (open) browse("");
  }, [open]);

  if (!open) return null;

  const addSelected = async () => {
    if (selected.size === 0) return;
    setAdding(true);
    setError("");
    try {
      await onAdd(Array.from(selected));
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setAdding(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.6)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 100,
      }}
      onClick={onClose}
    >
      <div
        className="card"
        style={{
          width: 720,
          maxHeight: "80vh",
          display: "flex",
          flexDirection: "column",
          padding: 16,
          background: "var(--bg-secondary)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <strong>Select evidence — files or folders</strong>
          <button className="btn btn-sm" onClick={onClose}>×</button>
        </div>

        {/* Path bar */}
        <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
          <input
            defaultValue={currentPath}
            onKeyDown={(e) => e.key === "Enter" && browse(e.currentTarget.value)}
            placeholder="Type a path and press Enter, or browse below"
            style={{ flex: 1, fontFamily: "monospace", fontSize: 12 }}
          />
          <button className="btn btn-sm" onClick={() => {
            const el = document.querySelector<HTMLInputElement>("input[placeholder^='Type a path']");
            if (el) browse(el.value);
          }}>Go</button>
          <button className="btn btn-sm" disabled={!parent} onClick={() => browse(parent)}>
            ↑ Up
          </button>
        </div>

        {error && <div className="error-banner" style={{ marginBottom: 8 }}>{error}</div>}

        {/* Listing */}
        <div style={{ flex: 1, overflowY: "auto", border: "1px solid var(--border)", borderRadius: 6, minHeight: 300 }}>
          {loading && <div className="loading" style={{ padding: 12 }}>Loading…</div>}
          {!loading && (
            <table style={{ width: "100%", fontSize: 12 }}>
              <tbody>
                {entries.map((e) => (
                  <tr
                    key={e.path}
                    style={{
                      borderBottom: "1px solid var(--border)",
                      background: selected.has(e.path) ? "rgba(47,129,247,0.12)" : undefined,
                      cursor: "pointer",
                    }}
                  >
                    <td style={{ width: 28, padding: "4px 8px" }}>
                      <input
                        type="checkbox"
                        checked={selected.has(e.path)}
                        onChange={() =>
                          setSelected((prev) => {
                            const next = new Set(prev);
                            if (next.has(e.path)) next.delete(e.path);
                            else next.add(e.path);
                            return next;
                          })
                        }
                      />
                    </td>
                    <td
                      style={{ padding: "5px 8px" }}
                      onClick={() => {
                        if (e.is_dir) browse(e.path);
                        else
                          setSelected((prev) => {
                            const next = new Set(prev);
                            if (next.has(e.path)) next.delete(e.path);
                            else next.add(e.path);
                            return next;
                          });
                      }}
                    >
                      <span style={{ marginRight: 6 }}>{e.is_dir ? "📁" : "📄"}</span>
                      {e.name}
                      {e.is_dir && <span style={{ color: "var(--text-muted)", fontSize: 10 }}> (open)</span>}
                    </td>
                    <td style={{ padding: "4px 10px", color: "var(--text-muted)", fontSize: 11, textAlign: "right" }}>
                      {e.size != null ? `${(e.size / 1024).toFixed(1)} KB` : ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            )}
        </div>

        {/* Footer */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 12, gap: 8 }}>
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
            {selected.size} selected · folders are registered whole (parsers walk them)
          </span>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn-sm" onClick={onClose}>Cancel</button>
            <button
              className="btn btn-primary btn-sm"
              onClick={addSelected}
              disabled={selected.size === 0 || adding}
            >
              {adding ? "Registering…" : `Add ${selected.size || ""} selected`}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
