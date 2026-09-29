/**
 * Ingest — the post-N1–N8 stage (operator 2026-09-29).
 *
 * Two paths on one page:
 *   1. Importers — bring logs/artifacts (Zeek, Suricata, SIEM, cloud, PCAP,
 *      …) onto the same case index via the auto-detect importer registry.
 *   2. SIFT outputs (Option B) — the examiner ran SIFT elsewhere; the outputs
 *      are staged into sift/extractions where the indexer + field mappings
 *      pick them up. No SIFT host or MCP is required for this path.
 *
 * Everything lands on the same case index, so the normal N4–N8 surfaces see
 * it immediately after the index refresh that both actions trigger.
 */
import { useState } from "react";
import { api } from "../api/client";
import { useCase } from "../context/CaseContext";

export default function Ingest() {
  const { activeCase } = useCase();
  const [impPath, setImpPath] = useState("");
  const [impSource, setImpSource] = useState("");
  const [impBusy, setImpBusy] = useState(false);
  const [impResult, setImpResult] = useState("");
  const [siftPath, setSiftPath] = useState("");
  const [siftFamily, setSiftFamily] = useState("");
  const [siftBusy, setSiftBusy] = useState(false);
  const [siftResult, setSiftResult] = useState("");
  const [error, setError] = useState("");

  const runImporter = async () => {
    if (!impPath.trim()) return;
    setImpBusy(true);
    setError("");
    setImpResult("");
    try {
      const r = await api.ingest(impPath.trim(), impSource.trim() || undefined, activeCase);
      if (r.ok) {
        const res = r.result ? JSON.stringify(r.result) : "";
        setImpResult(`Ingested.${res ? ` ${res.slice(0, 400)}` : ""}\n${(r.index || []).join("\n")}`);
      } else {
        setError(r.error || "ingest failed");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setImpBusy(false);
    }
  };

  const runSiftIngest = async () => {
    if (!siftPath.trim()) return;
    setSiftBusy(true);
    setError("");
    setSiftResult("");
    try {
      const r = await api.siftIngest(siftPath.trim(), siftFamily.trim() || undefined, activeCase);
      if (r.ok) {
        setSiftResult(
          `Staged: ${(r.staged || []).join(", ")}\n${(r.index || []).join("\n")}`,
        );
      } else {
        setError(r.error || "SIFT ingest failed");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSiftBusy(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <h2 style={{ margin: 0 }}>Ingest</h2>
      <p style={{ margin: 0, fontSize: 13, color: "var(--text-muted)" }}>
        Bring later-arriving evidence onto the same case index. Ingested rows join the normal
        N4–N8 surfaces (Explore, Briefing, Modes) after the index refresh.
      </p>
      {error && (
        <div className="card" style={{ borderColor: "var(--danger)", color: "var(--danger)", fontSize: 13 }}>
          {error}
        </div>
      )}

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Importers — logs &amp; artifacts</h3>
        <p style={{ fontSize: 12, color: "var(--text-muted)" }}>
          Auto-detect and import Zeek/Suricata/SIEM exports, cloud logs, PCAP (flow projection),
          mailboxes and more. Leave “source” empty to let the sniffer decide.
        </p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <input
            className="input"
            style={{ flex: "2 1 340px" }}
            placeholder="Path to file or directory (e.g. D:\evidence\conn.log)"
            value={impPath}
            onChange={(e) => setImpPath(e.target.value)}
          />
          <input
            className="input"
            style={{ flex: "1 1 140px" }}
            placeholder="source (optional)"
            value={impSource}
            onChange={(e) => setImpSource(e.target.value)}
          />
          <button className="btn btn-primary" onClick={runImporter} disabled={impBusy || !impPath.trim()}>
            {impBusy ? "Ingesting…" : "Ingest"}
          </button>
        </div>
        {impResult && (
          <pre style={{ fontSize: 11, marginTop: 10, whiteSpace: "pre-wrap" }}>{impResult}</pre>
        )}
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>SIFT outputs — Option B (no SIFT host required)</h3>
        <p style={{ fontSize: 12, color: "var(--text-muted)" }}>
          Ran SIFT yourself (plaso, vol3, SleuthKit, bulk_extractor)? Stage the outputs here as a
          file, directory, or .zip. Name the family (<code>plaso</code>, <code>vol</code>,{" "}
          <code>fls</code>, <code>bulk_extractor</code>) so the field mappings apply — or leave it
          empty to use the file/folder name.
        </p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <input
            className="input"
            style={{ flex: "2 1 340px" }}
            placeholder="Path to SIFT output (file / dir / .zip)"
            value={siftPath}
            onChange={(e) => setSiftPath(e.target.value)}
          />
          <input
            className="input"
            style={{ flex: "1 1 140px" }}
            placeholder="family (optional)"
            value={siftFamily}
            onChange={(e) => setSiftFamily(e.target.value)}
          />
          <button className="btn btn-primary" onClick={runSiftIngest} disabled={siftBusy || !siftPath.trim()}>
            {siftBusy ? "Staging…" : "Stage & index"}
          </button>
        </div>
        {siftResult && (
          <pre style={{ fontSize: 11, marginTop: 10, whiteSpace: "pre-wrap" }}>{siftResult}</pre>
        )}
      </div>
    </div>
  );
}
