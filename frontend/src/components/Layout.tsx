import { useState, useEffect } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { api, type CaseInfo } from "../api/client";

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
];

export default function Layout({ children }: { children: React.ReactNode }) {
  const [cases, setCases] = useState<CaseInfo[]>([]);
  const [activeCase, setActiveCase] = useState<string>("");
  const [caseMenuOpen, setCaseMenuOpen] = useState(false);
  const location = useLocation();

  useEffect(() => {
    api.cases().then(setCases).catch(() => {});
  }, []);

  const current = cases.find((c) => c.case_id === activeCase) || cases[0];

  const handleActivate = async (caseId: string) => {
    try {
      await api.activateCase(caseId);
      setActiveCase(caseId);
      setCaseMenuOpen(false);
    } catch (e) {
      console.error("Failed to activate case:", e);
    }
  };

  return (
    <div className="cockpit">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h1 className="brand">DFIR-Nexus</h1>
          <span className="brand-sub">Examiner Cockpit</span>
        </div>

        <div className="case-switcher">
          <button
            className="case-current"
            onClick={() => setCaseMenuOpen(!caseMenuOpen)}
          >
            <span className="case-label">Active Case</span>
            <span className="case-name">{current?.case_name || "No case"}</span>
            <span className="case-id">{current?.case_id || ""}</span>
          </button>
          {caseMenuOpen && (
            <ul className="case-list">
              {cases.map((c) => (
                <li key={c.case_id}>
                  <button onClick={() => handleActivate(c.case_id)}>
                    <span className="case-name">{c.case_name}</span>
                    <span className="case-id">{c.case_id}</span>
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
          <span className="version">v2.0 — Phase 4</span>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <span className="breadcrumb">
            DFIR-Nexus / {NAV_ITEMS.find((n) => n.to === location.pathname)?.label || "Unknown"}
          </span>
          <span className="active-case-badge">
            {current?.case_id || "no case"}
          </span>
        </header>
        <div className="content">{children}</div>
      </main>
    </div>
  );
}
