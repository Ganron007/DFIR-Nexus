import { useState, useEffect } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { api } from "../api/client";

const NAV_ITEMS = [
  { to: "/", label: "Overview", icon: "O" },
  { to: "/explore", label: "Explore", icon: "E" },
  { to: "/timeline", label: "Timeline", icon: "T" },
  { to: "/steer", label: "Steer Chat", icon: "S" },
  { to: "/workbench", label: "Workbench", icon: "W" },
  { to: "/findings", label: "Findings", icon: "F" },
  { to: "/approve", label: "Approve", icon: "A" },
  { to: "/report", label: "Report", icon: "R" },
  { to: "/evidence", label: "Evidence", icon: "V" },
  { to: "/entities", label: "Entities", icon: "N" },
  { to: "/transparency", label: "Transparency", icon: "X" },
];

const LOGO_SVG = `<svg width="28" height="28" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M32 4 L56 18 L56 46 L32 60 L8 46 L8 18 Z" fill="#0d1117" stroke="#2f81f7" stroke-width="2.5"/>
  <path d="M32 12 L48 21 L48 43 L32 52 L16 43 L16 21 Z" fill="none" stroke="#2f81f7" stroke-width="1" opacity="0.4"/>
  <circle cx="32" cy="32" r="6" fill="#2f81f7"/>
  <line x1="32" y1="12" x2="32" y2="26" stroke="#2f81f7" stroke-width="1.5" opacity="0.6"/>
  <line x1="32" y1="38" x2="32" y2="52" stroke="#2f81f7" stroke-width="1.5" opacity="0.6"/>
  <line x1="16" y1="21" x2="27" y2="29" stroke="#2f81f7" stroke-width="1.5" opacity="0.6"/>
  <line x1="48" y1="21" x2="37" y2="29" stroke="#2f81f7" stroke-width="1.5" opacity="0.6"/>
  <line x1="16" y1="43" x2="27" y2="35" stroke="#2f81f7" stroke-width="1.5" opacity="0.6"/>
  <line x1="48" y1="43" x2="37" y2="35" stroke="#2f81f7" stroke-width="1.5" opacity="0.6"/>
  <circle cx="32" cy="12" r="2.5" fill="#3fb950"/>
  <circle cx="32" cy="52" r="2.5" fill="#d29922"/>
  <circle cx="16" cy="21" r="2" fill="#8b949e"/>
  <circle cx="48" cy="21" r="2" fill="#8b949e"/>
  <circle cx="16" cy="43" r="2" fill="#8b949e"/>
  <circle cx="48" cy="43" r="2" fill="#8b949e"/>
</svg>`;

export default function Layout({ children }: { children: React.ReactNode }) {
  const [cases, setCases] = useState<string[]>([]);
  const [activeCase, setActiveCase] = useState<string>("");
  const [caseMenuOpen, setCaseMenuOpen] = useState(false);
  const [health, setHealth] = useState<"ok" | "down" | "checking">("checking");
  const location = useLocation();

  useEffect(() => {
    api.cases()
      .then((r) => {
        setCases(r.cases || []);
        setActiveCase(r.active || (r.cases[0] || ""));
      })
      .catch(() => {});
    fetch("/health")
      .then((r) => setHealth(r.ok ? "ok" : "down"))
      .catch(() => setHealth("down"));
  }, []);

  const handleActivate = async (caseId: string) => {
    try {
      await api.activateCase(caseId);
      setActiveCase(caseId);
      setCaseMenuOpen(false);
    } catch (e) {
      console.error("Failed to activate case:", e);
    }
  };

  const currentLabel = NAV_ITEMS.find((n) => n.to === location.pathname)?.label || "Unknown";

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

        <nav className="nav">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `nav-item ${isActive ? "active" : ""}`
              }
            >
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span className="version">v2.0 — Phase 4</span>
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
        <div className="content">{children}</div>
      </main>
    </div>
  );
}
