import { useState, useEffect } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { api } from "../api/client";
import { useCase } from "../context/CaseContext";

/**
 * WP 4b.4 + lifecycle ordering fix: the sidebar follows the N1-N8
 * investigation spine in order. Each item carries its stage badge so the
 * examiner sees where they are in the lifecycle as they move down the list.
 */
const NAV_SPINE = [
  { to: "/case-setup", label: "Case Setup", stage: "N1", hint: "Create case · register evidence · choose mode" },
  { to: "/evidence", label: "Evidence", stage: "N2", hint: "Registered evidence + N2 processing status" },
  { to: "/explore", label: "Explore", stage: "N3·N4", hint: "Index-backed search over parsed evidence" },
  { to: "/steer", label: "Steer Chat", stage: "N5", hint: "Interpretation — scribe, iterative, or agentic" },
  { to: "/workbench", label: "Workbench", stage: "N5", hint: "Build DRAFT findings from bookmarked hits" },
  { to: "/approve", label: "Approve", stage: "N6", hint: "HMAC challenge-response approval desk" },
  { to: "/timeline", label: "Timeline", stage: "N7", hint: "Per-family event lanes and brush" },
  { to: "/report", label: "Report", stage: "N8", hint: "Approved findings export" },
];

const NAV_UTILITIES = [
  { to: "/entities", label: "Entities", hint: "Entity pivot across hits" },
  { to: "/transparency", label: "Transparency", hint: "HMAC audit chain verification" },
];

// WP 4b.4: N1-N8 stage stepper
const STAGES = [
  { id: "N1", label: "Intake", to: "/case-setup" },
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

// WP 4b.4: Stage Stepper component
function StageStepper({ activeCase }: { activeCase: string }) {
  const [stageStatus, setStageStatus] = useState<Record<string, boolean>>({});
  const [loadFailed, setLoadFailed] = useState(false);

  useEffect(() => {
    if (!activeCase) return;
    setLoadFailed(false);
    api.caseDetails(activeCase).then((d) => {
      setStageStatus({
        N1: true, // case exists = intake done
        N2: d.pipeline_complete || false,
        N3: d.pipeline_complete || false, // index built during N2
        N4: (d.findings_count || 0) > 0 || (d.evidence_count || 0) > 0,
        N5: (d.findings_count || 0) > 0,
        N6: (d.findings_count || 0) > 0,
        N7: (d.findings_count || 0) > 0,
        N8: (d.findings_count || 0) > 0,
      });
      setLoadFailed(false);
    }).catch(() => setLoadFailed(true));
  }, [activeCase]);

  return (
    <div className="stage-stepper">
      {loadFailed && (
        <span className="stage-step" style={{ color: "var(--warning)" }} title="Stage status unavailable — case details could not be loaded">
          ⚠ stage status unavailable
        </span>
      )}
      {STAGES.map((stage, i) => (
        <NavLink
          key={stage.id}
          to={stage.to}
          className={`stage-step ${stageStatus[stage.id] ? "complete" : ""}`}
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

export default function Layout({ children }: { children: React.ReactNode }) {
  const { cases, activeCase, mode, health, setActiveCase } = useCase();
  const [caseMenuOpen, setCaseMenuOpen] = useState(false);
  const location = useLocation();

  const handleActivate = async (caseId: string) => {
    await setActiveCase(caseId);
    setCaseMenuOpen(false);
  };

  const currentLabel =
    [...NAV_SPINE, ...NAV_UTILITIES].find((n) => n.to === location.pathname)?.label || "Unknown";

  return (
    <div className="cockpit">
      <aside className="sidebar">
        <div className="sidebar-header">
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span dangerouslySetInnerHTML={{ __html: LOGO_SVG }} />
            <div>
              <h1 className="brand">DFIR-Nexus</h1>
              <span className="brand-sub">Examiner Cockpit</span>
            </div>
          </div>
        </div>

        <div className="case-switcher">
          <button
            className="case-current"
            onClick={() => setCaseMenuOpen(!caseMenuOpen)}
          >
            <span className="case-label">Active Case</span>
            <span className="case-name">{activeCase || "No case"}</span>
            <span className="case-id">{activeCase || ""}</span>
          </button>
          {caseMenuOpen && (
            <ul className="case-list">
              {cases.map((c) => (
                <li key={c}>
                  <button onClick={() => handleActivate(c)}>
                    <span className="case-name">{c}</span>
                    <span className="case-id">{c}</span>
                  </button>
                </li>
              ))}
              {cases.length === 0 && (
                <li className="empty">No cases found</li>
              )}
            </ul>
          )}
        </div>

        {/* WP 4b.6: Mode indicator — click navigates to the mode's primary surface */}
        {mode && (
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
          <div className="nav-group-label">Investigation Spine</div>
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
        </nav>

        <div className="sidebar-footer">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span className="version">v2.0 — Phase 4b</span>
            <span
              title={health === "ok" ? "System healthy" : health === "down" ? "Backend unreachable" : "Checking…"}
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: health === "ok" ? "var(--success)" : health === "down" ? "var(--danger)" : "var(--warning)",
                boxShadow: health === "ok" ? "0 0 6px rgba(63,185,80,0.6)" : "none",
              }}
            />
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <span className="breadcrumb">
            DFIR-Nexus / <strong style={{ color: "var(--text-primary)" }}>{currentLabel}</strong>
          </span>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <a href="/" style={{ fontSize: 12, color: "var(--text-muted)", textDecoration: "none" }}>
              ← Landing
            </a>
            <span className="active-case-badge">
              {activeCase || "no case"}
            </span>
          </div>
        </header>
        {/* WP 4b.4: N1-N8 stage stepper */}
        {activeCase && <StageStepper activeCase={activeCase} />}
        <div className="content">{children}</div>
      </main>
    </div>
  );
}
