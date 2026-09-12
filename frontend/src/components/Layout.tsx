import type { ReactNode } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useCase, type EsStatus } from "../context/CaseContext";

/**
 * Phase 4e: the sidebar follows the N1-N8 investigation spine only when a
 * case is active. The case switcher previews with a click and switches only
 * through the explicit "Switch" button; "Exit to Dashboard" detaches.
 */
const NAV_SPINE = [
  { to: "/evidence", label: "Evidence", stage: "N2", hint: "Registered evidence + N2 processing status" },
  { to: "/briefing", label: "Briefing", stage: "N3.5", hint: "Case briefing — what was found before you dig" },
  { to: "/explore", label: "Explore", stage: "N3·N4", hint: "Index-backed search over parsed evidence" },
  { to: "/steer", label: "Steer Chat", stage: "N5", hint: "Interpretation — scribe, iterative, or agentic" },
  { to: "/workbench", label: "Workbench", stage: "N5", hint: "Build DRAFT findings from bookmarked hits" },
  { to: "/approve", label: "Approve", stage: "N6", hint: "HMAC challenge-response approval desk" },
  { to: "/timeline", label: "Timeline", stage: "N7", hint: "Per-family event lanes and brush" },
  { to: "/report", label: "Report", stage: "N8", hint: "Approved findings export" },
];

const NAV_UTILITIES = [
  { to: "/entities", label: "Entities", hint: "Entity pivot across hits" },
  { to: "/iocs", label: "IOCs", hint: "Indicators of compromise from findings" },
  { to: "/todos", label: "TODOs", hint: "Investigation follow-ups" },
  { to: "/transparency", label: "Transparency", hint: "HMAC audit chain verification" },
];

// WP 4b.4: N1-N8 stage stepper
const STAGES = [
  { id: "N1", label: "Intake", to: "/evidence" },
  { id: "N2", label: "Process", to: "/evidence" },
  { id: "N3", label: "Index", to: "/explore" },
  { id: "N4", label: "Query", to: "/explore" },
  { id: "N5", label: "Interpret", to: "/steer" },
  { id: "N6", label: "Approve", to: "/approve" },
  { id: "N7", label: "Timeline", to: "/timeline" },
  { id: "N8", label: "Report", to: "/report" },
];

const LOGO_SVG = `<svg width="28" height="32" viewBox="0 0 128 148" fill="none" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="blueGradNav" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#2563eb"/>
      <stop offset="55%" stop-color="#1e3a8a"/>
      <stop offset="100%" stop-color="#030712"/>
    </linearGradient>
  </defs>
  <g transform="translate(9,3)">
    <path d="M55 0 L110 18 V62 C110 100 86 128 55 145 C24 128 0 100 0 62 V18 Z" fill="url(#blueGradNav)" stroke="#091a3a" stroke-width="2"/>
    <path d="M78 26 Q78 34 86 34 Q78 34 78 42 Q78 34 70 34 Q78 34 78 26 Z" fill="#ffffff" opacity="0.9"/>
    <path d="M38 62 C38 52, 62 52, 62 62" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" opacity="0.75"/>
    <path d="M42 62 C42 56, 58 56, 58 62" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" opacity="0.75"/>
    <path d="M46 62 C46 59, 54 59, 54 62" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" opacity="0.75"/>
    <path d="M34 62 C34 46, 66 46, 66 62" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" opacity="0.5"/>
    <path d="M50 62 V76" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" opacity="0.75"/>
    <path d="M46 62 Q46 72 42 75" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" opacity="0.6"/>
    <path d="M54 62 Q54 72 58 75" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" opacity="0.6"/>
    <circle cx="50" cy="62" r="22" fill="none" stroke="#ffffff" stroke-width="4.5" opacity="0.95"/>
    <path d="M36 50 A20 20 0 0 1 64 50" fill="none" stroke="#ffffff" stroke-width="1.5" opacity="0.6" stroke-linecap="round"/>
    <line x1="65" y1="77" x2="85" y2="97" stroke="#ffffff" stroke-width="6.5" stroke-linecap="round" opacity="0.95"/>
  </g>
</svg>`;

/** WP 4b.4: N1-N8 stage stepper — live completion states from CaseContext. */
function StageStepper({ stages }: { stages: Record<string, boolean> }) {
  return (
    <div className="stage-stepper">
      {STAGES.map((stage, i) => (
        <NavLink
          key={stage.id}
          to={stage.to}
          className={`stage-step ${stages[stage.id] ? "complete" : ""}`}
          title={`${stage.id}: ${stage.label}`}
        >
          <span className="stage-id">{stage.id}</span>
          <span className="stage-label">{stage.label}</span>
          {i < STAGES.length - 1 && <span className="stage-arrow">→</span>}
        </NavLink>
      ))}
    </div>
  );
}

/**
 * Backend liveness + Elasticsearch state as two separate signals — a green
 * backend dot must never be read as "ES is up". ES truthfully shows:
 *   off      — NEXUS_ES_URL not set (Mode 1 runs on the CSV pack)
 *   down     — configured but unreachable (Mode 2/3 processing is blocked)
 *   (green)  — reachable; the N3 index can receive evidence
 */
function StatusCluster({ health, es }: { health: "ok" | "down" | "checking"; es: EsStatus }) {
  const esTitle = !es.configured
    ? "Elasticsearch not configured — Mode 1 searches the CSV pack. Mode 2/3 require NEXUS_ES_URL."
    : es.reachable
      ? "Elasticsearch reachable — evidence can land in the N3 index for Mode 2/3 queries."
      : "Elasticsearch configured but UNREACHABLE — Mode 2/3 processing is blocked until ES comes online.";
  const esColor = !es.configured ? "var(--text-muted)" : es.reachable ? "var(--success)" : "var(--danger)";
  const esLabel = !es.configured ? "ES off" : es.reachable ? "ES" : "ES down";
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
      <span
        title={health === "ok" ? "Backend reachable" : health === "down" ? "Backend unreachable" : "Checking…"}
        style={{
          width: 8,
          height: 8,
          borderRadius: "50%",
          background: health === "ok" ? "var(--success)" : health === "down" ? "var(--danger)" : "var(--warning)",
          boxShadow: health === "ok" ? "0 0 6px rgba(63,185,80,0.6)" : "none",
        }}
      />
      <span
        title={esTitle}
        style={{
          fontSize: 9,
          fontFamily: "monospace",
          letterSpacing: 0.4,
          color: esColor,
          border: `1px solid ${esColor}`,
          borderRadius: 3,
          padding: "0 3px",
          lineHeight: 1.4,
        }}
      >
        {esLabel}
      </span>
    </span>
  );
}

export default function Layout({ children }: { children: ReactNode }) {
  const {
    cases,
    caseSummaries,
    activeCase,
    mode,
    health,
    es,
    stages,
    setActiveCase,
    setPreviewCase,
    exitToDashboard,
    refreshCases,
  } = useCase();
  const location = useLocation();
  const navigate = useNavigate();

  const activeStatus = activeCase ? caseSummaries[activeCase]?.status || "" : "";
  const isSealed = activeStatus === "sealed";

  const handleSwitch = async (caseId: string) => {
    if (!caseId) return;
    await setActiveCase(caseId);
    setPreviewCase(caseId);
  };

  const handleReopen = async () => {
    try {
      await api.reopenCase(activeCase);
      await refreshCases();
    } catch (e) {
      console.error("Reopen failed:", e);
    }
  };

  const handleExit = async () => {
    await exitToDashboard();
    navigate("/");
  };

  const currentLabel =
    [...NAV_SPINE, ...NAV_UTILITIES].find((n) => n.to === location.pathname)?.label || "Dashboard";

  // WP 4.8: Landing page is a clean case dashboard — no cockpit sidebar.
  // The cockpit sidebar only appears on investigation pages (requires active case).
  const isDashboard = location.pathname === "/" || location.pathname === "/case-setup";

  if (isDashboard) {
    return (
      <div className="dashboard-layout">
        <header className="dashboard-header">
          <a
            href="/"
            title="Back to landing page"
            style={{ display: "flex", alignItems: "center", gap: 12, textDecoration: "none", color: "inherit" }}
          >
            <span dangerouslySetInnerHTML={{ __html: LOGO_SVG }} />
            <div>
              <h1 className="brand">DFIR-Nexus</h1>
              <span className="brand-sub">Case Management</span>
            </div>
          </a>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <StatusCluster health={health} es={es} />
          </div>
        </header>
        <main className="dashboard-main">
          <div className="dashboard-content">{children}</div>
        </main>
      </div>
    );
  }

  // Cockpit layout — investigation pages only (requires active case via RequireCase)
  return (
    <div className="cockpit">
      <aside className="sidebar">
        <div className="sidebar-header">
          <a
            href="/"
            title="Back to landing page"
            style={{ display: "flex", alignItems: "center", gap: 8, textDecoration: "none", color: "inherit" }}
          >
            <span dangerouslySetInnerHTML={{ __html: LOGO_SVG }} />
            <div>
              <h1 className="brand">DFIR-Nexus</h1>
              <span className="brand-sub">Examiner Cockpit</span>
            </div>
          </a>
        </div>

        <div className="case-switcher">
          <label htmlFor="case-select" className="case-label">Active Case</label>
          <select
            id="case-select"
            aria-label="Active case"
            value={cases.includes(activeCase) ? activeCase : ""}
            onChange={(e) => handleSwitch(e.target.value)}
            disabled={cases.length === 0}
            title="Switch the active case"
          >
            <option value="">
              {cases.length === 0 ? "No cases" : "Select a case…"}
            </option>
            {cases.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>

        {/* WP 4b.6: Mode indicator — click navigates to the mode's primary surface */}
        {activeCase && mode && (
          <div className="mode-indicator">
            <NavLink
              to={mode === "1" ? "/explore" : "/steer"}
              className={`mode-badge mode-${mode}`}
              title={
                mode === "1"
                  ? "Mode 1 — Examiner-driven. Primary surface: Explore"
                  : mode === "2"
                    ? "Mode 2 — LLM-guided. Primary surface: Steer Chat"
                    : "Mode 3 — Agentic. Primary surface: Steer Chat (plan/execute/seal)"
              }
            >
              Mode {mode} · {mode === "1" ? "Explore" : "Steer Chat"} primary
            </NavLink>
          </div>
        )}

        <nav className="nav">
          <NavLink
            to="/"
            className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
            title="Case Dashboard — all cases, no case required"
          >
            <span className="nav-stage">⌂</span>
            <span className="nav-label">Dashboard</span>
          </NavLink>

          {activeCase ? (
            <>
              <div className="nav-group-label" style={{ marginTop: 8 }}>Investigation Spine</div>
              {NAV_SPINE.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
                  title={item.hint}
                >
                  <span className="nav-stage">{item.stage}</span>
                  <span className="nav-label">{item.label}</span>
                </NavLink>
              ))}
              <div className="nav-group-label" style={{ marginTop: 12 }}>Utilities</div>
              {NAV_UTILITIES.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
                  title={item.hint}
                >
                  <span className="nav-stage">·</span>
                  <span className="nav-label">{item.label}</span>
                </NavLink>
              ))}
            </>
          ) : (
            <div style={{ padding: "12px 8px", fontSize: 11, color: "var(--text-muted)", lineHeight: 1.5 }}>
              Select a case on the dashboard (preview → Enter) to open the investigation cockpit.
            </div>
          )}
        </nav>

        <div className="sidebar-footer">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
            <span className="version">v2.0 — Phase 4e</span>
            {activeCase && (
              <button className="btn btn-sm" onClick={handleExit} title="Detach this case and return to the dashboard">
                Exit
              </button>
            )}
            <StatusCluster health={health} es={es} />
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <span className="breadcrumb">
            DFIR-Nexus / <strong style={{ color: "var(--text-primary)" }}>{currentLabel}</strong>
          </span>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            {activeCase ? (
              <button
                className="btn btn-sm"
                onClick={handleExit}
                style={{ fontSize: 11 }}
                title="Detach this case and return to the dashboard"
              >
                ← Exit to Dashboard
              </button>
            ) : (
              <a href="/" style={{ fontSize: 12, color: "var(--text-muted)", textDecoration: "none" }}>
                ← Landing
              </a>
            )}
            <span className="active-case-badge">
              {activeCase || "no case"}
            </span>
          </div>
        </header>
        {isSealed && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
              background: "rgba(210,153,34,0.12)",
              border: "1px solid rgba(210,153,34,0.4)",
              borderRadius: 6,
              padding: "8px 12px",
              margin: "8px 16px 0",
              fontSize: 12,
            }}
          >
            <span>
              This case is <strong>sealed (completed)</strong> — actions are locked.
              Reopen it to continue the investigation.
            </span>
            <button className="btn btn-sm" onClick={handleReopen}>
              Reopen case
            </button>
          </div>
        )}
        {/* WP 4b.4: N1-N8 stage stepper — only inside an investigation */}
        {activeCase && <StageStepper stages={stages} />}
        <div className="content">{children}</div>
      </main>
    </div>
  );
}
