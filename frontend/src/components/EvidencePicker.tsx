/**
 * WP 4e.9: EvidencePicker — browse the local filesystem (via the backend's
 * read-only /fs/list API) and select files and/or folders as evidence.
 *
 * Features:
 * - Mode toggle: Files / Folders / Both — filters the listing
 * - "Select This Folder" button — register the folder you're viewing
 * - Breadcrumb trail for navigation
 * - Folder rows: checkbox (select) + arrow (navigate) — separate actions
 * - File paths in the path bar are detected and offered for direct addition
 * - Quote-safe: strips surrounding quotes from manual path input
 */
import { useEffect, useState, useCallback } from "react";
import { api, type FsEntry } from "../api/client";

interface EvidencePickerProps {
  open: boolean;
  onClose: () => void;
  onAdd: (paths: string[]) => Promise<void> | void;
}

type PickerMode = "both" | "files" | "folders";

/** Strip surrounding quotes and whitespace from a path string. */
function cleanPath(p: string): string {
  return p.trim().replace(/^["']+|["']+$/g, "").trim();
}

export default function EvidencePicker({ open, onClose, onAdd }: EvidencePickerProps) {
  const [currentPath, setCurrentPath] = useState("");
  const [entries, setEntries] = useState<FsEntry[]>([]);
  const [isDrives, setIsDrives] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [adding, setAdding] = useState(false);
  const [pathInput, setPathInput] = useState("");
  const [mode, setMode] = useState<PickerMode>("both");
  const [filePrompt, setFilePrompt] = useState<FsEntry | null>(null);

  const browse = useCallback((path: string) => {
    const cleaned = cleanPath(path);
    setLoading(true);
    setError("");
    setFilePrompt(null);
    api.fsList(cleaned || undefined)
      .then((r) => {
        if (r.is_file && r.file_entry) {
          // User typed a file path — offer to add it directly
          setFilePrompt(r.file_entry);
          setCurrentPath(r.path);
          setEntries([]);
          setIsDrives(false);
          setPathInput(r.file_entry.path);
          setSelected(new Set());
        } else {
          setCurrentPath(r.path);
          setIsDrives(r.drives || false);
          setEntries(r.entries || []);
          setSelected(new Set());
          setPathInput(r.path);
        }
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (open) browse("");
  }, [open, browse]);

  if (!open) return null;

  const toggleSelect = (path: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  const addPaths = async (paths: string[]) => {
    if (paths.length === 0) return;
    setAdding(true);
    setError("");
    try {
      await onAdd(paths);
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setAdding(false);
    }
  };

  const addSelected = () => addPaths(Array.from(selected));

  const addCurrentFolder = () => {
    if (!currentPath || isDrives) return;
    addPaths([currentPath]);
  };

  const addFilePrompt = () => {
    if (!filePrompt) return;
    addPaths([filePrompt.path]);
  };

  /** Filter entries by mode. */
  const visibleEntries = entries.filter((e) => {
    if (mode === "files") return !e.is_dir;
    if (mode === "folders") return e.is_dir;
    return true;
  });

  /** Build breadcrumb segments from the current path. */
  const breadcrumbs = (): { label: string; path: string }[] => {
    if (!currentPath) return [];
    const parts: { label: string; path: string }[] = [];
    const isWindows = /^[A-Za-z]:\\/.test(currentPath);
    const sep = isWindows ? "\\" : "/";
    const segments = currentPath.split(sep).filter(Boolean);
    let acc = "";
    for (let i = 0; i < segments.length; i++) {
      if (isWindows && i === 0) {
        acc = segments[i] + "\\";
      } else {
        acc = acc ? acc + sep + segments[i] : sep + segments[i];
      }
      parts.push({ label: segments[i], path: acc });
    }
    return parts;
  };

  const crumbs = breadcrumbs();
  const allVisibleSelected = visibleEntries.length > 0 && visibleEntries.every((e) => selected.has(e.path));

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
          width: 780,
          maxHeight: "85vh",
          display: "flex",
          flexDirection: "column",
          padding: 16,
          background: "var(--bg-secondary)",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header + mode toggle */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <strong>Select Evidence</strong>
          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            {/* Mode toggle */}
            <div style={{ display: "flex", gap: 0, border: "1px solid var(--border)", borderRadius: 4, overflow: "hidden" }}>
              {(["both", "files", "folders"] as PickerMode[]).map((m) => (
                <button
                  key={m}
                  onClick={() => setMode(m)}
                  style={{
                    padding: "3px 10px",
                    fontSize: 11,
                    border: "none",
                    cursor: "pointer",
                    background: mode === m ? "var(--accent)" : "var(--bg-tertiary)",
                    color: mode === m ? "#fff" : "var(--text-muted)",
                  }}
                >
                  {m === "both" ? "Files + Folders" : m === "files" ? "Files" : "Folders"}
                </button>
              ))}
            </div>
            <button className="btn btn-sm" onClick={onClose}>×</button>
          </div>
        </div>

        {/* Manual path bar */}
        <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
          <input
            value={pathInput}
            onChange={(e) => setPathInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && browse(pathInput)}
            placeholder="Type or paste a path and press Enter (quotes auto-stripped)"
            style={{ flex: 1, fontFamily: "monospace", fontSize: 12 }}
          />
          <button className="btn btn-sm" onClick={() => browse(pathInput)}>Go</button>
        </div>

        {/* Breadcrumb trail */}
        {crumbs.length > 0 && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 2, marginBottom: 8, fontSize: 11, alignItems: "center" }}>
            {isDrives ? (
              <span style={{ color: "var(--text-muted)" }}>Drives</span>
            ) : (
              crumbs.map((c, i) => (
                <span key={c.path} style={{ display: "flex", alignItems: "center", gap: 2 }}>
                  {i > 0 && <span style={{ color: "var(--text-muted)" }}>›</span>}
                  <button
                    onClick={() => browse(c.path)}
                    style={{
                      background: "none",
                      border: "none",
                      color: i === crumbs.length - 1 ? "var(--text-primary)" : "var(--accent)",
                      cursor: "pointer",
                      fontFamily: "monospace",
                      fontSize: 11,
                      padding: "2px 4px",
                      borderRadius: 3,
                    }}
                  >
                    {c.label}
                  </button>
                </span>
              ))
            )}
          </div>
        )}

        {/* File prompt — when user typed a file path */}
        {filePrompt && (
          <div style={{ padding: "12px 14px", background: "rgba(47,129,247,0.12)", border: "1px solid rgba(47,129,247,0.4)", borderRadius: 6, marginBottom: 8, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <span style={{ marginRight: 8 }}>📄</span>
              <strong>{filePrompt.name}</strong>
              <span style={{ color: "var(--text-muted)", fontSize: 11, marginLeft: 8 }}>
                {filePrompt.size != null ? `${(filePrompt.size / 1024).toFixed(1)} KB` : ""}
              </span>
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>This is a file. Add it directly as evidence.</div>
            </div>
            <button
              className="btn btn-primary btn-sm"
              onClick={addFilePrompt}
              disabled={adding}
            >
              {adding ? "Adding…" : "Add This File"}
            </button>
          </div>
        )}

        {error && <div className="error-banner" style={{ marginBottom: 8 }}>{error}</div>}

        {/* Listing */}
        {!filePrompt && (
          <div style={{ flex: 1, overflowY: "auto", border: "1px solid var(--border)", borderRadius: 6, minHeight: 280 }}>
            {loading && <div className="loading" style={{ padding: 12 }}>Loading…</div>}
            {!loading && visibleEntries.length === 0 && (
              <div style={{ padding: 16, color: "var(--text-muted)", fontSize: 12 }}>
                {entries.length === 0 ? "This folder is empty." : `No ${mode === "files" ? "files" : "folders"} in this location.`}
              </div>
            )}
            {!loading && visibleEntries.length > 0 && (
              <table style={{ width: "100%", fontSize: 12 }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border)", background: "var(--bg-tertiary)" }}>
                    <th style={{ width: 28, padding: "4px 8px", textAlign: "left" }}>
                      <input
                        type="checkbox"
                        checked={allVisibleSelected}
                        onChange={() => {
                          if (allVisibleSelected) setSelected(new Set());
                          else setSelected(new Set(visibleEntries.map((e) => e.path)));
                        }}
                      />
                    </th>
                    <th style={{ padding: "4px 8px", textAlign: "left", fontSize: 11, color: "var(--text-muted)" }}>Name</th>
                    <th style={{ width: 40, padding: "4px 8px", textAlign: "center", fontSize: 11, color: "var(--text-muted)" }}>Open</th>
                    <th style={{ width: 80, padding: "4px 10px", textAlign: "right", fontSize: 11, color: "var(--text-muted)" }}>Size</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleEntries.map((e) => (
                    <tr
                      key={e.path}
                      style={{
                        borderBottom: "1px solid var(--border)",
                        background: selected.has(e.path) ? "rgba(47,129,247,0.12)" : undefined,
                      }}
                    >
                      <td style={{ padding: "4px 8px" }}>
                        <input
                          type="checkbox"
                          checked={selected.has(e.path)}
                          onChange={() => toggleSelect(e.path)}
                        />
                      </td>
                      <td
                        style={{ padding: "5px 8px", cursor: "pointer" }}
                        onClick={() => toggleSelect(e.path)}
                      >
                        <span style={{ marginRight: 6 }}>{e.is_dir ? "📁" : "📄"}</span>
                        {e.name}
                      </td>
                      <td style={{ padding: "4px 8px", textAlign: "center" }}>
                        {e.is_dir && (
                          <button
                            className="btn btn-sm"
                            onClick={(ev) => { ev.stopPropagation(); browse(e.path); }}
                            style={{ padding: "1px 6px", fontSize: 11 }}
                            title="Open folder"
                          >
                            →
                          </button>
                        )}
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
        )}

        {/* Footer */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 12, gap: 8, flexWrap: "wrap" }}>
          <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
            {selected.size} selected · folders register whole (parsers walk them)
          </span>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {!isDrives && currentPath && !filePrompt && (
              <button
                className="btn btn-sm"
                onClick={addCurrentFolder}
                disabled={adding}
                title="Register the current folder as evidence"
                style={{ background: "rgba(47,129,247,0.15)", border: "1px solid rgba(47,129,247,0.4)", color: "var(--accent)" }}
              >
                📁 Select This Folder
              </button>
            )}
            <button className="btn btn-sm" onClick={onClose}>Cancel</button>
            {!filePrompt && (
              <button
                className="btn btn-primary btn-sm"
                onClick={addSelected}
                disabled={selected.size === 0 || adding}
              >
                {adding ? "Registering…" : `Add ${selected.size || ""} selected`}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
