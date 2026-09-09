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
