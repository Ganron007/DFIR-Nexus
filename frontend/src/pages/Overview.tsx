/**
 * Case Dashboard (SPA Overview, Phase 4e.6).
 *
 * The one case-management surface: every case with status/counts, click to
 * preview, explicit Enter to activate. Creating or seeding a case never
 * switches the active case by itself.
 */
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  api,
  type CaseDetailsResponse,
  type SystemHealthResponse,
} from "../api/client";
import { useCase } from "../context/CaseContext";

const STATUS_LABEL: Record<string, string> = {
  created: "Created",
  intake: "Intake",
  processing: "Processing",
  active: "Active",
  sealed: "Sealed",
  open: "Open",
  in_progress: "In Progress",
  closed: "Closed",
  archived: "Archived",
};

function statusClass(status: string): string {
  switch (status) {
    case "active":
    case "sealed":
      return "approved";
    case "closed":
    case "archived":
      return "rejected";
    default:
      return "draft";
  }
}

export default function Overview() {
  const navigate = useNavigate();
  const {
    cases,
    caseSummaries,
    activeCase,
    previewCase,
    setPreviewCase,
    setActiveCase,
    mode,
    health,
    refreshCases,
  } = useCase();
  const [sys, setSys] = useState<SystemHealthResponse | null>(null);
  const [previewDetails, setPreviewDetails] = useState<CaseDetailsResponse | null>(null);
  const [banner, setBanner] = useState("");
  const [seeding, setSeeding] = useState(false);
  const [entering, setEntering] = useState("");
  // Environment preflight — fix missing deps without leaving the portal.
  const [editing, setEditing] = useState<"" | "es" | "llm">("");
  const [envForm, setEnvForm] = useState({ es_url: "", llm_model: "", llm_base: "", llm_key: "" });
  const [setupMsg, setSetupMsg] = useState("");
  const [setupErr, setSetupErr] = useState("");
  const [ragState, setRagState] = useState("");

  const recheck = () => {
    api.systemHealth().then(setSys).catch(() => setSys(null));
  };

  useEffect(() => {
    recheck();
  }, [activeCase]);

  useEffect(() => {
    if (!previewCase) {
      setPreviewDetails(null);
      return;
    }
    api
      .caseDetails(previewCase)
      .then(setPreviewDetails)
      .catch(() => setPreviewDetails(null));
  }, [previewCase]);

  const enterCase = async (caseId: string) => {
    setEntering(caseId);
    setBanner("");
    try {
      await setActiveCase(caseId);
      const caseMode = caseSummaries[caseId]?.mode || "1";
      navigate(caseMode === "1" ? "/briefing" : "/steer");
    } catch (e) {
      setBanner(`Failed to open ${caseId}: ${(e as Error).message}`);
    } finally {
      setEntering("");
    }
  };

  const saveEnv = async (env: Record<string, string>) => {
    setSetupErr(""); setSetupMsg("");
    try {
      const r = await api.setupEnv(env);
      if (r.error) { setSetupErr(r.error); return; }
      setSetupMsg(`Applied (${r.env_file?.split(/[\\/]/).pop()})`);
      setEditing("");
      recheck();
    } catch (e) {
      setSetupErr((e as Error).message);
    }
  };

  const startRagDownload = async () => {
    setSetupErr(""); setSetupMsg(""); setRagState("starting");
    try {
      const r = await api.setupRag();
      if (r.error) { setSetupErr(r.error); setRagState(""); return; }
      // Poll task status until the download finishes, then re-check health.
      const poll = setInterval(async () => {
        try {
          const s = await api.setupStatus();
          const t = s.tasks?.rag;
          if (!t || t.status === "running") { setRagState("running"); return; }
          clearInterval(poll);
          setRagState(t.status === "done" ? "" : "error");
          if (t.status === "error") setSetupErr(`RAG download failed: ${t.detail || "unknown"}`);
          else setSetupMsg("RAG index installed.");
          recheck();
        } catch { clearInterval(poll); setRagState(""); }
      }, 2000);
    } catch (e) {
      setSetupErr((e as Error).message);
      setRagState("");
    }
  };

  const handleSeedDemo = async () => {
    setSeeding(true);
    setBanner("");
    try {
      const res = await api.seedDemo({ name: "Demo Investigation — WS01 Incident" });
      await refreshCases();
      if (res.ok && res.case_id) {
        setPreviewCase(res.case_id);
        setBanner(
          `Seeded ${res.case_id} (${res.evidence_count} evidence, ${res.findings_count} findings). ` +
            "It is not active — click Enter on the row to open it.",
        );
      } else {
        setBanner(res.error || "Seed failed");
      }
    } catch (e) {
      setBanner(`Failed to seed demo: ${(e as Error).message}`);
    } finally {
      setSeeding(false);
    }
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h2>Case Dashboard</h2>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            className="btn btn-sm"
            onClick={handleSeedDemo}
            disabled={seeding}
            title="Create a pre-populated test case (does not switch the active case)"
            style={{ background: "rgba(47, 129, 247, 0.15)", border: "1px solid rgba(47, 129, 247, 0.4)", color: "var(--accent)" }}
          >
            {seeding ? "Seeding..." : "⚡ Seed Demo Investigation"}
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => navigate("/case-setup")}>
            + New Investigation
          </button>
        </div>
      </div>

      {banner && (
        <div style={{ padding: "10px 14px", background: "rgba(47,129,247,0.12)", border: "1px solid rgba(47,129,247,0.4)", borderRadius: 6, color: "var(--text-primary)", marginBottom: 16, fontSize: 13 }}>
          {banner}
        </div>
      )}

      {/* Continue banner — an investigation is already active */}
      {activeCase && (
        <div className="card" style={{ marginBottom: 16, padding: 12, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 13 }}>
            Current investigation: <strong>{activeCase}</strong>
            {mode && <> · Mode {mode}</>}
          </span>
          <button className="btn btn-primary btn-sm" onClick={() => navigate(mode === "1" ? "/briefing" : "/steer")}>
            Continue →
          </button>
        </div>
      )}

      {/* System health + environment preflight — fix missing pieces in place */}
      <div className="card" style={{ marginBottom: 16, padding: 12 }}>
        <div style={{ display: "flex", gap: 20, flexWrap: "wrap", fontSize: 12, alignItems: "center" }}>
          <span>
            <span style={{ color: "var(--text-muted)" }}>Backend:</span>{" "}
            <span style={{ color: health === "ok" ? "var(--success)" : "var(--danger)" }}>
              {health === "ok" ? "✓ Healthy" : health === "down" ? "✗ Down" : "Checking..."}
            </span>
          </span>
          <span>
            <span style={{ color: "var(--text-muted)" }}>Elasticsearch:</span>{" "}
            <span style={{ color: sys?.es?.configured === false ? "var(--text-muted)" : sys?.es?.reachable ? "var(--success)" : "var(--danger)" }}>
              {sys?.es?.configured === false ? "CSV pack (not configured)" : sys?.es?.reachable ? "✓ reachable" : "✗ unreachable"}
            </span>
            {sys && (
              <button className="btn btn-sm" style={{ marginLeft: 6, padding: "0 6px", fontSize: 10 }}
                onClick={() => { setEditing(editing === "es" ? "" : "es"); setEnvForm({ ...envForm, es_url: sys.es?.url || "" }); }}
                title="Set or test the ES URL">
                {sys.es?.configured ? "edit" : "set up"}
              </button>
            )}
          </span>
          <span>
            <span style={{ color: "var(--text-muted)" }}>RAG index:</span>{" "}
            <span style={{ color: sys?.rag?.configured ? "var(--success)" : "var(--danger)" }}>
              {sys?.rag?.configured ? "✓ present" : "✗ missing"}
            </span>
            {sys && !sys.rag?.configured && (
              <button className="btn btn-sm" style={{ marginLeft: 6, padding: "0 6px", fontSize: 10 }}
                onClick={startRagDownload} disabled={ragState === "running" || ragState === "starting"}
                title="Download the ~50MB IR knowledge index">
                {ragState === "running" ? "downloading…" : ragState === "starting" ? "starting…" : "download"}
              </button>
            )}
            {ragState === "running" && <span style={{ color: "var(--warning)", fontSize: 11 }}> (in background)</span>}
          </span>
          <span>
            <span style={{ color: "var(--text-muted)" }}>LLM:</span>{" "}
            <span style={{ color: sys?.llm?.configured ? "var(--success)" : "var(--warning)" }}>
              {sys?.llm?.configured ? `✓ ${sys.llm.model || "configured"}` : "heuristic fallback"}
            </span>
            {sys && (
              <button className="btn btn-sm" style={{ marginLeft: 6, padding: "0 6px", fontSize: 10 }}
                onClick={() => setEditing(editing === "llm" ? "" : "llm")}>
                {sys.llm?.configured ? "edit" : "set up"}
              </button>
            )}
          </span>
          <span>
            <span style={{ color: "var(--text-muted)" }}>Parser lane:</span>{" "}
            <span style={{ color: sys?.parser === "ok" ? "var(--success)" : "var(--danger)" }}
              title={sys?.parser_error || ""}>
              {sys?.parser === "ok" ? "✓ available" : "✗ missing"}
            </span>
          </span>
          <button className="btn btn-sm" style={{ marginLeft: "auto", padding: "0 8px", fontSize: 10 }}
            onClick={recheck} title="Re-run all checks">
            re-check
          </button>
        </div>
        {sys?.parser === "missing" && sys.parser_error && (
          <div style={{ fontSize: 11, color: "var(--danger)", marginTop: 6 }}>
            Parser lane import failed: {sys.parser_error}
          </div>
        )}
        {(setupMsg || setupErr) && (
          <div style={{ fontSize: 11, marginTop: 6, color: setupErr ? "var(--danger)" : "var(--success)" }}>
            {setupErr || setupMsg}
          </div>
        )}
        {editing === "es" && (
          <div style={{ display: "flex", gap: 6, marginTop: 8, alignItems: "center" }}>
            <input
              placeholder="NEXUS_ES_URL — e.g. http://127.0.0.1:9200 (empty = CSV pack)"
              value={envForm.es_url}
              onChange={(e) => setEnvForm({ ...envForm, es_url: e.target.value })}
              style={{ flex: 1, fontSize: 12 }}
            />
            <button className="btn btn-sm btn-primary" onClick={() => saveEnv({ NEXUS_ES_URL: envForm.es_url })}>
              Save &amp; test
            </button>
          </div>
        )}
        {editing === "llm" && (
          <div style={{ display: "flex", gap: 6, marginTop: 8, flexWrap: "wrap" }}>
            <input placeholder="Model (NEXUS_LLM_MODEL)" value={envForm.llm_model}
              onChange={(e) => setEnvForm({ ...envForm, llm_model: e.target.value })} style={{ flex: 1, fontSize: 12, minWidth: 140 }} />
            <input placeholder="Base URL (NEXUS_LLM_BASE_URL)" value={envForm.llm_base}
              onChange={(e) => setEnvForm({ ...envForm, llm_base: e.target.value })} style={{ flex: 2, fontSize: 12, minWidth: 200 }} />
            <input placeholder="API key (optional)" type="password" value={envForm.llm_key}
              onChange={(e) => setEnvForm({ ...envForm, llm_key: e.target.value })} style={{ flex: 1, fontSize: 12, minWidth: 140 }} />
            <button className="btn btn-sm btn-primary"
              onClick={() => saveEnv({
                ...(envForm.llm_model && { NEXUS_LLM_MODEL: envForm.llm_model }),
                ...(envForm.llm_base && { NEXUS_LLM_BASE_URL: envForm.llm_base }),
                ...(envForm.llm_key && { NEXUS_LLM_API_KEY: envForm.llm_key }),
              })}>
              Save
            </button>
          </div>
        )}
        {sys && (sys.es?.configured === false || !sys.rag?.configured || !sys.llm?.configured || sys.parser !== "ok") && (
          <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 6 }}>
            CLI equivalents — ES/LLM: <code>nexus config env KEY=VALUE</code> · RAG: <code>nexus data download-rag</code> · full check: <code>nexus doctor</code>
          </div>
        )}
      </div>

      {/* Preview panel — inspect a case without activating it */}
      {previewCase && previewDetails && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header">
            <span className="card-title">Preview: {previewDetails.name || previewCase}</span>
          </div>
          <div style={{ padding: 16, display: "flex", gap: 24, flexWrap: "wrap", alignItems: "center" }}>
            <span style={{ fontSize: 12 }}>
              <span style={{ color: "var(--text-muted)" }}>ID:</span> <code>{previewCase}</code>
            </span>
            <span style={{ fontSize: 12 }}>
              <span style={{ color: "var(--text-muted)" }}>Status:</span>{" "}
              <span className={`badge ${statusClass(previewDetails.status || "")}`}>
                {STATUS_LABEL[previewDetails.status || ""] || previewDetails.status || "—"}
              </span>
            </span>
            <span style={{ fontSize: 12 }}>
              <span style={{ color: "var(--text-muted)" }}>Mode:</span> {previewDetails.investigation_mode || "—"}
            </span>
            <span style={{ fontSize: 12 }}>
              <span style={{ color: "var(--text-muted)" }}>Evidence:</span> {previewDetails.evidence_count ?? 0}
            </span>
            <span style={{ fontSize: 12 }}>
              <span style={{ color: "var(--text-muted)" }}>Findings:</span> {previewDetails.findings_count ?? 0}
            </span>
            <button
              className="btn btn-primary btn-sm"
              onClick={() => enterCase(previewCase)}
              disabled={entering === previewCase}
            >
              {entering === previewCase ? "Opening…" : "Enter Investigation →"}
            </button>
          </div>
          {previewDetails.synthetic && (
            <p style={{ padding: "0 16px 8px", fontSize: 12, color: "var(--warning)" }}>
              Synthetic demo case — evidence files are mocks and no parsers ran on this
              case. Use it to try UI flows; run a real evidence pack for processing.
            </p>
          )}
          {previewDetails.description && (
            <p style={{ padding: "0 16px 16px", fontSize: 12, color: "var(--text-muted)" }}>
              {previewDetails.description}
            </p>
          )}
        </div>
      )}

      {/* Cases table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">All Cases ({cases.length})</span>
        </div>
        {cases.length === 0 ? (
          <div className="empty-state">
            <h3>No cases yet</h3>
            <p>Start with a pre-populated demo case or create a new investigation.</p>
            <div style={{ display: "flex", gap: 12, justifyContent: "center", marginTop: 16 }}>
              <button className="btn btn-primary" onClick={handleSeedDemo} disabled={seeding}>
                {seeding ? "Seeding Demo..." : "⚡ Load Demo Investigation"}
              </button>
              <button className="btn" onClick={() => navigate("/case-setup")}>
                + New Investigation
              </button>
            </div>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Case ID</th>
                <th>Name</th>
                <th>Status</th>
                <th>Mode</th>
                <th>Evidence</th>
                <th>Findings</th>
                <th>Pipeline</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {cases.map((c) => {
                const d = caseSummaries[c];
                const isPreview = c === previewCase;
                const isActive = c === activeCase;
                return (
                  <tr
                    key={c}
                    style={{
                      background: isPreview ? "rgba(47,129,247,0.14)" : isActive ? "rgba(63,185,80,0.08)" : undefined,
                      cursor: "pointer",
                    }}
                    onClick={() => setPreviewCase(c)}
                  >
                    <td style={{ fontFamily: "monospace", fontSize: 11 }}>{c}</td>
                    <td>
                      {d?.name || c}
                      {d?.synthetic && (
                        <span
                          className="badge draft"
                          style={{ fontSize: 9, marginLeft: 6 }}
                          title="Seeded demo — mock evidence, no parsers ran"
                        >
                          synthetic
                        </span>
                      )}
                    </td>
                    <td>
                      <span className={`badge ${statusClass(d?.status || "")}`} style={{ fontSize: 10 }}>
                        {STATUS_LABEL[d?.status || ""] || d?.status || "—"}
                      </span>
                    </td>
                    <td>{d?.mode ? `Mode ${d.mode}` : "—"}</td>
                    <td>{d?.evidence_count ?? "—"}</td>
                    <td>{d?.findings_count ?? "—"}</td>
                    <td>{d?.pipeline_complete ? "✓ Done" : "—"}</td>
                    <td>
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          enterCase(c);
                        }}
                        disabled={entering === c}
                      >
                        {entering === c ? "Opening…" : isActive ? "Continue" : "Enter"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
