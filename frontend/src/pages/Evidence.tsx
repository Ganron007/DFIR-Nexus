/**
 * WP 4b.8 + 4d: error handling + lifecycle-aware empty states + N2 run
 * controls. The examiner can register evidence (wizard) and run/monitor
 * the N2 processing lane without touching the CLI.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type LedgerRow } from "../api/client";
import { useCase } from "../context/CaseContext";
import EvidencePicker from "../components/EvidencePicker";

export default function Evidence() {
  const { activeCase } = useCase();
  const [evidence, setEvidence] = useState<unknown[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [pipelineComplete, setPipelineComplete] = useState(false);
  const [busy, setBusy] = useState(false);
  const [runId, setRunId] = useState("");
  const [runStatus, setRunStatus] = useState("");
  const [showPicker, setShowPicker] = useState(false);
  const [ledger, setLedger] = useState<LedgerRow[]>([]);
  const [ledgerRunId, setLedgerRunId] = useState("");

  const load = () => {
    if (!activeCase) {
      setEvidence([]);
      setPipelineComplete(false);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    Promise.all([
      api.evidence(),
      api.caseDetails(activeCase).catch(() => null),
      api.pipelineLedger().catch(() => null),
    ])
      .then(([ev, d, lg]) => {
        setEvidence(ev.evidence);
        setPipelineComplete(d?.pipeline_complete || false);
        if (lg && !lg.error) {
          setLedger(lg.ledger || []);
          setLedgerRunId(lg.run_id || "");
        }
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeCase]);

  const registerPaths = async (paths: string[]) => {
    setError("");
    const failures: string[] = [];
    for (const p of paths) {
      try {
        const res = await fetch("/portal/api/evidence", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path: p }),
        });
        const body = await res.json();
        if (!body.ok) {
          failures.push(`${p}: ${body.error || "failed"}`);
        }
      } catch (e) {
        failures.push(`${p}: ${(e as Error).message}`);
      }
    }
    if (failures.length) setError(`Some paths failed: ${failures.join("; ")}`);
    load();
  };

  const runN2 = async () => {
    setBusy(true);
    setError("");
    try {
      const r = await api.pipelineRun({ mode: "tools", case_id: activeCase });
      setRunId(r.run_id);
      setRunStatus("running");
      const poll = setInterval(async () => {
        try {
          const s = await api.pipelineStatus(r.run_id);
          setRunStatus(s.status);
          if (s.status === "complete") {
            clearInterval(poll);
            setBusy(false);
            setPipelineComplete(true);
          } else if (s.status === "error") {
            clearInterval(poll);
            setError(s.error || "Pipeline failed");
            setBusy(false);
          }
        } catch {
          // keep polling
        }
      }, 3000);
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  if (loading) return <div className="loading">Loading evidence registry...</div>;

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h2>Evidence Registry ({evidence.length})</h2>
        {activeCase && (
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span style={{ fontSize: 12, color: pipelineComplete ? "var(--success)" : "var(--text-muted)" }}>
              {pipelineComplete ? "✓ N2 lane complete" : "N2 lane not run"}
            </span>
            <button className="btn btn-sm" onClick={() => setShowPicker(true)}>
              + Add evidence
            </button>
            <button
              className="btn btn-primary btn-sm"
              onClick={runN2}
              disabled={busy || runStatus === "running"}
            >
              {busy ? "Starting…" : "▶ Run N2 lane"}
            </button>
          </div>
        )}
      </div>
      {error && <div className="error-banner">{error}</div>}
      {runId && (
        <div className="card" style={{ padding: "8px 12px", marginBottom: 12 }}>
          <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
            Pipeline run <code>{runId}</code> —{" "}
            <strong style={{ color: runStatus === "complete" ? "var(--success)" : runStatus === "error" ? "var(--danger)" : "var(--warning)" }}>
              {runStatus}
            </strong>
            {runStatus === "running" && " (polling…)"}
          </span>
        </div>
      )}

      {/* Parser lane ledger — which parsers ran (WP: parser visibility) */}
      {activeCase && ledger.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header">
            <span className="card-title">
              N2 Parser Lane — {ledger.filter((r) => (r.status || "").toUpperCase() === "OK").length}/{ledger.length} OK
              {ledgerRunId ? ` · run ${ledgerRunId}` : ""}
            </span>
          </div>
          <div style={{ maxHeight: 240, overflowY: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>Tool</th>
                  <th>Status</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {ledger.map((row, i) => (
                  <tr key={i}>
                    <td style={{ fontFamily: "monospace", fontSize: 11 }}>{String(row.tool || "—")}</td>
                    <td>
                      <span
                        className={`badge ${(row.status || "").toLowerCase() === "ok" ? "approved" : (row.status || "").toUpperCase() === "SKIP" ? "draft" : "rejected"}`}
                        style={{ fontSize: 10 }}
                      >
                        {String(row.status || "—")}
                      </span>
                    </td>
                    <td style={{ fontSize: 11, color: "var(--text-muted)" }}>{String(row.detail || "")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <EvidencePicker
        open={showPicker}
        onClose={() => setShowPicker(false)}
        onAdd={registerPaths}
      />

      {evidence.length === 0 ? (
        <div className="empty-state">
          <h3>N2 — no evidence registered</h3>
          {!activeCase ? (
            <>
              <p>No active case. Start at <strong>N1 Case Setup</strong> to create a case and register evidence.</p>
              <Link to="/case-setup" className="btn btn-primary" style={{ marginTop: 12, display: "inline-block" }}>
                Go to Case Setup (N1)
              </Link>
            </>
          ) : (
            <>
              <p>Case <strong>{activeCase}</strong> has no registered evidence yet.</p>
              <p>Click <strong>"+ Add evidence"</strong> to browse files/folders, or register via the Case Setup wizard.</p>
              <button className="btn btn-primary" style={{ marginTop: 12 }} onClick={() => setShowPicker(true)}>
                + Add evidence
              </button>
            </>
          )}
        </div>
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Path</th>
                <th>SHA-256</th>
                <th>Description</th>
                <th>Status</th>
                <th>Registered</th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((e, i) => {
                const item = e as Record<string, string>;
                return (
                  <tr key={i}>
                    <td style={{ fontFamily: "monospace", fontSize: 11 }}>{item.path}</td>
                    <td style={{ fontFamily: "monospace", fontSize: 11 }}>{item.sha256?.slice(0, 16)}...</td>
                    <td>{item.description}</td>
                    <td>{item.status}</td>
                    <td>{item.registered_at}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
