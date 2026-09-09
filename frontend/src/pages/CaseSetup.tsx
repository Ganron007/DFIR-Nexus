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
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useCase } from "../context/CaseContext";

const STEPS = ["Case Details", "Register Evidence", "Choose Mode", "Run Processing"];

export default function CaseSetup() {
  const navigate = useNavigate();
  const { setActiveCase, setMode } = useCase();
  const [step, setStep] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // Step 1 state
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [examiner, setExaminer] = useState("");
  const [caseId, setCaseId] = useState("");

  // Step 2 state
  const [evidencePath, setEvidencePath] = useState("");
  const [evidenceRegistered, setEvidenceRegistered] = useState(false);

  // Step 3 state
  const [mode, setModeState] = useState("");

  // Step 4 state
  const [pipelineRunId, setPipelineRunId] = useState("");
  const [pipelineStatus, setPipelineStatus] = useState("");

  const createCase = async () => {
    if (!name.trim()) {
      setError("Case name is required");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const r = await api.caseCreate({ name, description, examiner, mode });
      if (r.ok) {
        setCaseId(r.case_id);
        await setActiveCase(r.case_id);
        if (mode) await setMode(mode);
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

  const registerEvidence = async () => {
    if (!evidencePath.trim()) {
      setError("Evidence path is required");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const res = await fetch("/portal/api/evidence", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: evidencePath }),
      });
      const body = await res.json();
      if (body.ok) {
        setEvidenceRegistered(true);
        setStep(2);
      } else {
        setError(body.error || "Failed to register evidence");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
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
      await api.setCaseMode(mode);
      await setMode(mode);
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
          if (s.status === "complete" || s.status === "error") {
            clearInterval(poll);
            setBusy(false);
            if (s.status === "error") {
              setError(s.error || "Pipeline failed");
            }
          }
        } catch {
          // ignore
        }
      }, 3000);
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  const finish = () => {
    navigate("/");
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
            Case <strong>{caseId}</strong> created. Now register evidence for processing.
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div>
              <label style={{ fontSize: 12, color: "var(--text-muted)", display: "block", marginBottom: 4 }}>
                Evidence Path *
              </label>
              <input
                value={evidencePath}
                onChange={(e) => setEvidencePath(e.target.value)}
                placeholder="e.g. /cases/campaign-h/ws01/extractions or /path/to/evidence.csv"
                style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
              />
            </div>
            {evidenceRegistered && (
              <div style={{ color: "var(--success)", fontSize: 13 }}>
                ✓ Evidence registered successfully
              </div>
            )}
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn btn-primary" onClick={registerEvidence} disabled={busy}>
                {busy ? "Registering..." : "Register Evidence →"}
              </button>
              <button className="btn" onClick={() => setStep(2)}>
                Skip for now →
              </button>
            </div>
          </div>
        </div>
      )}

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
            Run the deterministic parser lane (N2) to process evidence.
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
                <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  Pipeline is running... This may take several minutes.
                </div>
              )}
              {pipelineStatus === "complete" && (
                <button className="btn btn-primary" onClick={finish} style={{ marginTop: 12 }}>
                  Enter Cockpit →
                </button>
              )}
              {pipelineStatus === "error" && (
                <div>
                  <div className="error-banner" style={{ marginTop: 8 }}>{error}</div>
                  <button className="btn" onClick={() => { setPipelineRunId(""); setPipelineStatus(""); }} style={{ marginTop: 8 }}>
                    Retry
                  </button>
                </div>
              )}
            </div>
          )}
          <button className="btn" onClick={finish} style={{ marginTop: 12, marginLeft: 8 }}>
            Skip — Enter Cockpit
          </button>
        </div>
      )}
    </div>
  );
}
