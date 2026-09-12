/**
 * WP 4b.1: Case Setup Wizard — 4 steps.
 *
 * Step 1: Case details (name, description, examiner)
 * Step 2: Register evidence (path input, SHA-256 display, custody log)
 * Step 3: Choose investigation mode (1/2/3) — with explanation
 * Step 4: Run N2 processing lane (trigger pipeline, show progress)
 *
 * On completion, lands in the Cockpit with the case active and N2 complete.
 */
import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { api, type LedgerRow } from "../api/client";
import { useCase } from "../context/CaseContext";
import EvidencePicker from "../components/EvidencePicker";

const STEPS = ["Case Details", "Register Evidence", "Choose Mode", "Run Processing"];

export default function CaseSetup() {
  const navigate = useNavigate();
  const { setActiveCase } = useCase();
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // Poll cleanup ref — clears interval on unmount to prevent poll leak
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  // Step 1 state
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [examiner, setExaminer] = useState("");
  const [caseId, setCaseId] = useState("");

  // Step 2 state
  const [registeredPaths, setRegisteredPaths] = useState<string[]>([]);
  const [showPicker, setShowPicker] = useState(false);
  const [manualPath, setManualPath] = useState("");

  // Step 3 state
  const [mode, setModeState] = useState("");

  // Step 4 state
  const [pipelineRunId, setPipelineRunId] = useState("");
  const [pipelineStatus, setPipelineStatus] = useState("");
  const [pipelineProg, setPipelineProg] = useState<{ done: number; total: number; current?: string } | null>(null);
  const [pipelineStages, setPipelineStages] = useState<{ tool?: string; host?: string; status?: string }[]>([]);
  const [ledger, setLedger] = useState<LedgerRow[]>([]);

  const createCase = async () => {
    if (!name.trim()) {
      setError("Case name is required");
      return;
    }
    setBusy(true);
    setError("");
    try {
      // Phase 4e: create only — activation happens on "Enter Cockpit".
      const r = await api.caseCreate({ name, description, examiner, mode, activate: false });
      if (r.ok) {
        setCaseId(r.case_id);
        setStep(1);
      } else {
        setError(r.error || "Failed to create case");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const registerPaths = async (paths: string[]) => {
    if (!paths.length) return;
    setBusy(true);
    setError("");
    const failures: string[] = [];
    for (const raw of paths) {
      // Strip surrounding quotes — examiners often paste "C:\path with spaces"
      const p = raw.trim().replace(/^["']+|["']+$/g, "").trim();
      if (!p) continue;
      try {
        const res = await api.registerEvidence(p, caseId);
        if (res.ok) {
          setRegisteredPaths((prev) => [...prev, p]);
        } else {
          failures.push(`${p}: ${res.error || "failed"}`);
        }
      } catch (e) {
        failures.push(`${p}: ${(e as Error).message}`);
      }
    }
    setBusy(false);
    if (failures.length) {
      setError(`Some paths failed: ${failures.join("; ")}`);
    }
  };

  const registerManual = async () => {
    const cleaned = manualPath.trim().replace(/^["']+|["']+$/g, "").trim();
    if (!cleaned) {
      setError("Evidence path is required");
      return;
    }
    await registerPaths([cleaned]);
    setManualPath("");
  };

  const chooseMode = (m: string) => {
    setModeState(m);
  };

  const confirmMode = async () => {
    if (!mode) {
      setError("Please choose an investigation mode");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await api.setCaseMode(mode, caseId);
      setStep(3);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const runPipeline = async () => {
    setBusy(true);
    setError("");
    try {
      // Map product mode to pipeline mode
      const pipelineMode = mode === "1" ? "tools" : mode === "2" ? "coverage" : "design";
      const r = await api.pipelineRun({ mode: pipelineMode, case_id: caseId });
      setPipelineRunId(r.run_id);
      setPipelineStatus("running");

      // Poll status
      const poll = setInterval(async () => {
        try {
          const s = await api.pipelineStatus(r.run_id);
          setPipelineStatus(s.status);
          if (s.progress) setPipelineProg(s.progress);
          if (s.stages) setPipelineStages(s.stages);
          if (s.status === "complete" || s.status === "error") {
            clearInterval(poll);
            pollRef.current = null;
            setBusy(false);
            if (s.status === "error") {
              setError(s.error || "Pipeline failed");
            } else {
              // Show exactly which parsers ran before the examiner enters.
              try {
                const lg = await api.pipelineLedger(caseId);
                setLedger(lg.ledger || []);
              } catch {
                setLedger([]);
              }
            }
          }
        } catch {
          // ignore
        }
      }, 3000);
      pollRef.current = poll;
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  const okCount = ledger.filter((r) => (r.status || "").toUpperCase() === "OK").length;
  const skipCount = ledger.filter((r) => (r.status || "").toUpperCase() === "SKIP").length;
  const failCount = ledger.filter((r) => (r.status || "").toUpperCase() === "FAIL").length;
  const hasEvidence = registeredPaths.length > 0;

  const finish = async () => {
    if (!caseId) {
      navigate("/");
      return;
    }
    setBusy(true);
    setError("");
    try {
      // Enter Cockpit = the explicit activation point.
      await setActiveCase(caseId);
      navigate(mode === "1" ? "/briefing" : "/steer");
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>New Investigation Setup</h2>

      {/* Step indicator */}
      <div className="card" style={{ padding: 12, marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 8 }}>
          {STEPS.map((label, i) => (
            <div
              key={i}
              style={{
                flex: 1,
                textAlign: "center",
                padding: "8px 4px",
                borderRadius: 6,
                background: i === step ? "var(--accent)" : i < step ? "rgba(63,185,80,0.15)" : "var(--bg-tertiary)",
                color: i === step ? "#fff" : i < step ? "var(--success)" : "var(--text-muted)",
                fontSize: 12,
                fontWeight: i === step ? 600 : 400,
                cursor: i < step ? "pointer" : "default",
              }}
              onClick={() => i < step && setStep(i)}
            >
              {i + 1}. {label}
            </div>
          ))}
        </div>
      </div>

      {error && <div className="error-banner" style={{ marginBottom: 16 }}>{error}</div>}

      {/* Step 1: Case Details */}
      {step === 0 && (
        <div className="card">
          <h3>Case Details</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 12 }}>
            <div>
              <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                Case Name *
              </label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Campaign H — WS01 Investigation"
                style={{ width: "100%" }}
              />
            </div>
            <div>
              <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                Description
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Brief description of the investigation..."
                rows={3}
                style={{ width: "100%" }}
              />
            </div>
            <div>
              <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                Examiner
              </label>
              <input
                value={examiner}
                onChange={(e) => setExaminer(e.target.value)}
                placeholder="e.g. analyst_t1"
                style={{ width: "100%" }}
              />
            </div>
            <button className="btn btn-primary" onClick={createCase} disabled={busy}>
              {busy ? "Creating..." : "Create Case →"}
            </button>
          </div>
        </div>
      )}

      {/* Step 2: Register Evidence */}
      {step === 1 && (
        <div className="card">
          <h3>Register Evidence</h3>
          <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 12 }}>
            Case <strong>{caseId}</strong> created. Browse and select single or multiple
            files/folders — or paste a path. Folders are registered whole.
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn btn-primary" onClick={() => setShowPicker(true)}>
                📁 Browse files & folders…
              </button>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                value={manualPath}
                onChange={(e) => setManualPath(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && registerManual()}
                placeholder="…or paste an absolute path (e.g. C:\Evidence\ws01\evtx) and press Enter"
                style={{ flex: 1, fontFamily: "monospace", fontSize: 12 }}
              />
              <button className="btn" onClick={registerManual} disabled={busy}>
                Add path
              </button>
            </div>
            {registeredPaths.length > 0 && (
              <div style={{ fontSize: 13 }}>
                <div style={{ color: "var(--success)", marginBottom: 4 }}>
                  ✓ {registeredPaths.length} item(s) registered:
                </div>
                <ul style={{ margin: "0 0 0 20px", fontSize: 11, color: "var(--text-secondary)" }}>
                  {registeredPaths.map((p) => (
                    <li key={p} style={{ fontFamily: "monospace", fontSize: 11 }}>{p}</li>
                  ))}
                </ul>
              </div>
            )}
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn btn-primary" onClick={() => setStep(2)}>
                Continue →
              </button>
              <button className="btn" onClick={() => setStep(2)}>
                Skip for now →
              </button>
            </div>
          </div>
        </div>
      )}

      <EvidencePicker
        open={showPicker}
        onClose={() => setShowPicker(false)}
        onAdd={registerPaths}
      />

      {/* Step 3: Choose Mode */}
      {step === 2 && (
        <div className="card">
          <h3>Choose Investigation Mode</h3>
          <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 16 }}>
            The mode determines who initiates the next action and which UI surface is primary.
            It can be changed later.
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div
              onClick={() => chooseMode("1")}
              style={{
                padding: 16,
                borderRadius: 8,
                border: `2px solid ${mode === "1" ? "var(--accent)" : "var(--border)"}`,
                cursor: "pointer",
                background: mode === "1" ? "rgba(37,99,235,0.08)" : "transparent",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                <strong>Mode 1 — Examiner-Driven</strong>
                {mode === "1" && <span style={{ color: "var(--accent)" }}>✓</span>}
              </div>
              <p style={{ fontSize: 12, color: "var(--text-muted)" }}>
                Examiner searches, reviews hits, and selects evidence. LLM only scribes findings.
                Best for experienced examiners and legal cases. Explore is the primary surface.
              </p>
            </div>
            <div
              onClick={() => chooseMode("2")}
              style={{
                padding: 16,
                borderRadius: 8,
                border: `2px solid ${mode === "2" ? "var(--accent)" : "var(--border)"}`,
                cursor: "pointer",
                background: mode === "2" ? "rgba(37,99,235,0.08)" : "transparent",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                <strong>Mode 2 — LLM-Guided</strong>
                {mode === "2" && <span style={{ color: "var(--accent)" }}>✓</span>}
              </div>
              <p style={{ fontSize: 12, color: "var(--text-muted)" }}>
                LLM proposes next queries and corroborates with RAG + playbook context.
                Examiner validates and steers. Steer Chat is the primary surface.
              </p>
            </div>
            <div
              onClick={() => chooseMode("3")}
              style={{
                padding: 16,
                borderRadius: 8,
                border: `2px solid ${mode === "3" ? "var(--accent)" : "var(--border)"}`,
                cursor: "pointer",
                background: mode === "3" ? "rgba(37,99,235,0.08)" : "transparent",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                <strong>Mode 3 — Agentic</strong>
                {mode === "3" && <span style={{ color: "var(--accent)" }}>✓</span>}
              </div>
              <p style={{ fontSize: 12, color: "var(--text-muted)" }}>
                Multi-agent orchestrator dispatches specialist agents per evidence family.
                Agent drafts findings, examiner seals. Steer Chat (plan/execute/seal) is primary.
              </p>
            </div>
            <button className="btn btn-primary" onClick={confirmMode} disabled={busy || !mode}>
              {busy ? "Saving..." : "Confirm Mode →"}
            </button>
          </div>
        </div>
      )}

      {/* Step 4: Run Processing */}
      {step === 3 && (
        <div className="card">
          <h3>Run N2 Processing Lane</h3>
          <p style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 12 }}>
            Case <strong>{caseId}</strong> ready. Mode <strong>{mode}</strong> selected.
            Run the deterministic parser lane (N2) to process evidence. The lane
            output decides whether you can enter the cockpit.
          </p>
          {!pipelineRunId && (
            <button className="btn btn-primary" onClick={runPipeline} disabled={busy}>
              {busy ? "Starting..." : "Run N2 Pipeline →"}
            </button>
          )}
          {pipelineRunId && (
            <div>
              <div style={{ fontSize: 13, marginBottom: 8 }}>
                Run ID: <code>{pipelineRunId}</code>
              </div>
              <div style={{ fontSize: 13, marginBottom: 8 }}>
                Status:{" "}
                <span
                  style={{
                    color: pipelineStatus === "complete" ? "var(--success)" : pipelineStatus === "error" ? "var(--danger)" : "var(--warning)",
                    fontWeight: 600,
                  }}
                >
                  {pipelineStatus}
                </span>
              </div>
              {pipelineStatus === "running" && (
                <div>
                  {/* WP 4j.5d: real per-tool progress, not a bare spinner */}
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
                    <span>
                      {pipelineProg?.current
                        ? `Running: ${pipelineProg.current}`
                        : "Pipeline is running…"}
                    </span>
                    {pipelineProg && pipelineProg.total > 0 && (
                      <span>{pipelineProg.done}/{pipelineProg.total} tools</span>
                    )}
                  </div>
                  <div style={{ height: 8, background: "var(--bg-tertiary)", borderRadius: 4, overflow: "hidden", marginBottom: 8 }}>
                    <div
                      style={{
                        height: "100%",
                        width: pipelineProg && pipelineProg.total > 0
                          ? `${Math.round((pipelineProg.done / pipelineProg.total) * 100)}%`
                          : "15%",
                        background: "var(--accent)",
                        transition: "width 0.5s ease",
                      }}
                    />
                  </div>
                  {pipelineStages.length > 0 && (
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 4, fontSize: 10 }}>
                      {pipelineStages.map((st, i) => (
                        <span
                          key={i}
                          className={`badge ${(st.status || "").toUpperCase() === "OK" ? "approved" : (st.status || "").toUpperCase() === "SKIP" ? "draft" : "rejected"}`}
                          title={`${st.host || ""} — ${st.status || ""}`}
                        >
                          {st.tool}
                        </span>
                      ))}
                    </div>
                  )}
                  {!pipelineProg && (
                    <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      This may take several minutes.
                    </div>
                  )}
                </div>
              )}
              {pipelineStatus === "complete" && (
                <div style={{ marginTop: 8 }}>
                  <div style={{ fontSize: 13, marginBottom: 8 }}>
                    Parser lane:{" "}
                    <strong style={{ color: "var(--success)" }}>{okCount} OK</strong>
                    {skipCount ? ` · ${skipCount} SKIP` : ""}
                    {failCount ? ` · ${failCount} FAIL` : ""}
                  </div>
                  {ledger.length > 0 ? (
                    <div style={{ maxHeight: 260, overflowY: "auto" }}>
                      <table>
                        <thead>
                          <tr>
                            <th>Tool</th>
                            <th>Status</th>
                            <th>Command</th>
                            <th>Output</th>
                            <th>Detail / reason</th>
                          </tr>
                        </thead>
                        <tbody>
                          {ledger.map((row, i) => (
                            <tr key={i}>
                              <td style={{ fontFamily: "monospace", fontSize: 11 }}>{String(row.tool || "—")}</td>
                              <td>
                                <span
                                  className={`badge ${(row.status || "").toUpperCase() === "OK" ? "approved" : (row.status || "").toUpperCase() === "SKIP" ? "draft" : "rejected"}`}
                                  style={{ fontSize: 10 }}
                                >
                                  {String(row.status || "—")}
                                </span>
                              </td>
                              <td
                                style={{ fontFamily: "monospace", fontSize: 10, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                                title={Array.isArray(row.argv) ? row.argv.join(" ") : ""}
                              >
                                {Array.isArray(row.argv) && row.argv.length ? row.argv.join(" ") : "—"}
                              </td>
                              <td
                                style={{ fontFamily: "monospace", fontSize: 10, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                                title={String(row.output_saved_to || "")}
                              >
                                {String(row.output_saved_to || "—")}
                              </td>
                              <td style={{ fontSize: 11, color: "var(--text-muted)" }}>
                                {String(row.reason || row.detail || "")}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div style={{ fontSize: 12, color: "var(--text-muted)" }}>No parser ledger produced.</div>
                  )}
                  {okCount === 0 && failCount === 0 && (
                    <div style={{ fontSize: 12, color: "var(--warning)", marginTop: 8 }}>
                      No parser produced output — see the reason above. Supported evidence:
                      a Windows root / KAPE drive tree (…/C/Windows/System32), a Stage-0
                      pack (&lt;pack&gt;/wevtutil/*.evtx), any EVTX file or folder, or a known
                      artifact (.pf / hive / $MFT / SRUDB.dat / Amcache.hve / .lnk).
                    </div>
                  )}
                  <button className="btn btn-primary" onClick={finish} style={{ marginTop: 12 }}>
                    Enter Cockpit →
                  </button>
                </div>
              )}
              {pipelineStatus === "error" && (
                <div>
                  <div className="error-banner" style={{ marginTop: 8 }}>{error}</div>
                  <button className="btn" onClick={() => { setPipelineRunId(""); setPipelineStatus(""); setLedger([]); }} style={{ marginTop: 8 }}>
                    Retry
                  </button>
                </div>
              )}
            </div>
          )}
          {!hasEvidence && !pipelineRunId && (
            <button className="btn" onClick={finish} style={{ marginTop: 12, marginLeft: 8 }}>
              Enter Cockpit (no evidence registered)
            </button>
          )}
        </div>
      )}
    </div>
  );
}
