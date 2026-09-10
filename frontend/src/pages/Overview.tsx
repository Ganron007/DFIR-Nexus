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

  useEffect(() => {
    api
      .systemHealth()
      .then(setSys)
      .catch(() => setSys(null));
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
      navigate(caseMode === "1" ? "/explore" : "/steer");
    } catch (e) {
      setBanner(`Failed to open ${caseId}: ${(e as Error).message}`);
    } finally {
      setEntering("");
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
          <button className="btn btn-primary btn-sm" onClick={() => navigate(mode === "1" ? "/explore" : "/steer")}>
            Continue →
          </button>
        </div>
      )}

      {/* System health */}
      <div className="card" style={{ marginBottom: 16, padding: 12 }}>
        <div style={{ display: "flex", gap: 20, flexWrap: "wrap", fontSize: 12 }}>
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
          </span>
          <span>
            <span style={{ color: "var(--text-muted)" }}>RAG index:</span>{" "}
            <span style={{ color: sys?.rag?.configured ? "var(--success)" : "var(--danger)" }}>
              {sys?.rag?.configured ? "✓ present" : "✗ missing"}
            </span>
          </span>
          <span>
            <span style={{ color: "var(--text-muted)" }}>LLM:</span>{" "}
            <span style={{ color: sys?.llm?.configured ? "var(--success)" : "var(--warning)" }}>
              {sys?.llm?.configured ? `✓ ${sys.llm.model || "configured"}` : "heuristic fallback"}
            </span>
          </span>
          <span>
            <span style={{ color: "var(--text-muted)" }}>Parser lane:</span>{" "}
            <span style={{ color: sys?.parser === "ok" ? "var(--success)" : "var(--danger)" }}>
              {sys?.parser === "ok" ? "✓ available" : "✗ missing"}
            </span>
          </span>
        </div>
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
                    <td>{d?.name || c}</td>
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
