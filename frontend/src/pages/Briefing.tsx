/**
 * Briefing — WP 4i.4. The examiner's first view of a processed case.
 *
 * What was collected (inventory + parser ledger), what the signatures already
 * caught (alert surface), where the signal density is (playbook auto-scan),
 * top entities, hosts, time range, and the intake echo. Deterministic — no
 * LLM required. Clicking a needle drops into Explore with that needle set.
 */
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type BriefingResponse } from "../api/client";
import { useCase } from "../context/CaseContext";

export default function Briefing() {
  const { activeCase } = useCase();
  const navigate = useNavigate();
  const [brief, setBrief] = useState<BriefingResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  // WP 4j.1: alert rows expand to show interpretation (meaning + what to check)
  const [openAlert, setOpenAlert] = useState<number | null>(null);

  useEffect(() => {
    setLoading(true);
    setError("");
    api.caseBriefing()
      .then(setBrief)
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, [activeCase]);

  const searchNeedle = (needle: string, family?: string) => {
    const params = new URLSearchParams({ needles: needle });
    if (family) params.set("family", family);
    navigate(`/explore?${params}`);
  };

  if (loading) return <div className="loading">Building briefing…</div>;
  if (error) return <div className="error-banner">{error}</div>;
  if (!brief) return null;

  const ledger = brief.ledger || { entries: [], ok: 0, skip: 0, fail: 0 };
  const inv = brief.inventory || {};
  const scan = brief.needle_scan || [];
  const alerts = brief.alerts || [];
  const entities = brief.entities || {};
  const intake = brief.intake || {};
  const directions = brief.directions || [];

  return (
    <div>
      <h2 style={{ marginBottom: 4 }}>Case Briefing</h2>
      <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 16 }}>
        Auto-generated after processing — what was collected, what the signatures
        already caught, and where to start digging.
      </p>

      {/* Intake echo — what the examiner said they were looking for */}
      {(intake.question || intake.subjects || intake.hypothesis) && (
        <div className="card" style={{ borderLeft: "3px solid var(--accent)" }}>
          <div className="card-title" style={{ marginBottom: 8 }}>Investigation Focus</div>
          {intake.question && <div style={{ fontSize: 13, marginBottom: 4 }}><strong>Question:</strong> {intake.question}</div>}
          {intake.subjects && <div style={{ fontSize: 13, marginBottom: 4 }}><strong>Subjects:</strong> {intake.subjects}</div>}
          {intake.hypothesis && <div style={{ fontSize: 13 }}><strong>Hypothesis:</strong> {intake.hypothesis}</div>}
        </div>
      )}

      {/* WP 4i.5 — LLM investigation directions grounded in the deterministic numbers */}
      {directions.length > 0 && (
        <div className="card" style={{ borderLeft: "3px solid var(--warning)" }}>
          <div className="card-title" style={{ marginBottom: 8 }}>
            Suggested Directions <span style={{ fontSize: 10, color: "var(--text-muted)" }}>(LLM — grounded in the numbers below)</span>
          </div>
          {directions.map((d, i) => (
            <div key={i} style={{ marginBottom: 10, paddingBottom: 10, borderBottom: i < directions.length - 1 ? "1px solid var(--border)" : "none" }}>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 2 }}>{i + 1}. {d.title}</div>
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>{d.why}</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {(d.needles || []).map((n) => (
                  <button
                    key={n}
                    className="btn btn-sm"
                    style={{ fontFamily: "monospace", fontSize: 10 }}
                    onClick={() => searchNeedle(n, d.family || undefined)}
                  >
                    {n}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Top-line stats */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 4 }}>
        <div className="card" style={{ flex: 1, minWidth: 140 }}>
          <div style={{ fontSize: 22, fontWeight: 700 }}>{brief.total_files}</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>parsed files</div>
        </div>
        <div className="card" style={{ flex: 1, minWidth: 140 }}>
          <div style={{ fontSize: 22, fontWeight: 700 }}>{(brief.total_rows || 0).toLocaleString()}</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>evidence rows</div>
        </div>
        <div className="card" style={{ flex: 1, minWidth: 140 }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: alerts.length ? "var(--danger)" : undefined }}>
            {brief.alert_count}
          </div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>crit/high alerts</div>
        </div>
        <div className="card" style={{ flex: 1, minWidth: 140 }}>
          <div style={{ fontSize: 22, fontWeight: 700 }}>{scan.length}</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>needles with hits</div>
        </div>
        <div className="card" style={{ flex: 1, minWidth: 140 }}>
          <div style={{ fontSize: 22, fontWeight: 700 }}>{brief.hosts?.length || 0}</div>
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>hosts</div>
        </div>
      </div>

      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-start" }}>
        <div style={{ flex: "2 1 420px", minWidth: 320 }}>
          {/* Alerts — what the signatures already caught */}
          <div className="card">
            <div className="card-title" style={{ marginBottom: 8 }}>
              Alert Surface <span style={{ fontSize: 10, color: "var(--text-muted)" }}>(Hayabusa / Sigma severity)</span>
            </div>
            {alerts.length === 0 ? (
              <p style={{ fontSize: 12, color: "var(--text-muted)" }}>No critical/high severity rows in the scanned hits.</p>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <tbody>
                  {alerts.slice(0, 20).map((a, i) => {
                    const it = a.interpret;
                    const open = openAlert === i;
                    return (
                      <tr key={i} style={{ borderBottom: "1px solid var(--border)", verticalAlign: "top" }}>
                        <td colSpan={3} style={{ padding: 0 }}>
                          <div
                            style={{ display: "flex", cursor: "pointer", padding: "4px 6px" }}
                            onClick={() => setOpenAlert(open ? null : i)}
                            title={it ? "click for what this means + what to check next" : "click to search this alert"}
                          >
                            <span className={`badge ${a.level === "critical" ? "danger" : "draft"}`}
                                  style={{ fontSize: 9, width: 54, flexShrink: 0 }}>
                              {a.level.toUpperCase()}
                            </span>
                            <span style={{ fontSize: 11, flex: 1, padding: "0 6px" }}>
                              {a.title || "(untitled rule)"}
                            </span>
                            <span style={{ fontSize: 10, color: "var(--text-muted)", width: 150, flexShrink: 0 }}>
                              {a.host} · {a.time.slice(0, 19)}
                            </span>
                            <span style={{ fontSize: 10, color: "var(--text-muted)", width: 14 }}>{open ? "▾" : "▸"}</span>
                          </div>
                          {open && (
                            <div style={{
                              padding: "6px 10px 8px 66px", fontSize: 11,
                              borderTop: "1px dashed var(--border)",
                            }}>
                              {it?.meaning && <div style={{ marginBottom: 4 }}>{it.meaning}</div>}
                              {it && it.look_for.length > 0 && (
                                <div style={{ marginBottom: 4 }}>
                                  <strong style={{ color: "var(--text-secondary)" }}>Check next:</strong>
                                  <ul style={{ margin: "2px 0 0 16px", padding: 0 }}>
                                    {it.look_for.slice(0, 4).map((lf, j) => <li key={j}>{lf}</li>)}
                                  </ul>
                                </div>
                              )}
                              {it && it.next_queries.length > 0 && (
                                <div style={{ marginBottom: 4 }}>
                                  <strong style={{ color: "var(--text-secondary)" }}>Run:</strong>{" "}
                                  {it.next_queries.slice(0, 4).map((q) => (
                                    <button key={q} className="btn btn-sm"
                                            style={{ fontFamily: "monospace", fontSize: 10, marginRight: 4 }}
                                            onClick={(e) => { e.stopPropagation(); searchNeedle(q, a.family); }}>
                                      {q.length > 40 ? q.slice(0, 40) + "…" : q}
                                    </button>
                                  ))}
                                </div>
                              )}
                              {it && it.caveats.length > 0 && (
                                <div style={{ fontSize: 10, color: "var(--warning)" }}>
                                  {it.caveats.slice(0, 3).map((c, j) => <div key={j}>⚠ {c}</div>)}
                                </div>
                              )}
                              {!it && (
                                <button className="btn btn-sm" style={{ fontSize: 10 }}
                                        onClick={(e) => { e.stopPropagation(); searchNeedle(a.title || a.family, a.family); }}>
                                  Search this alert in Explore →
                                </button>
                              )}
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>

          {/* Signal map — playbook auto-scan needle → hit count */}
          <div className="card">
            <div className="card-title" style={{ marginBottom: 8 }}>
              Signal Map <span style={{ fontSize: 10, color: "var(--text-muted)" }}>({brief.scanned_needles} playbook/ATT&CK/Sigma needles scanned)</span>
            </div>
            {scan.length === 0 ? (
              <p style={{ fontSize: 12, color: "var(--text-muted)" }}>
                No playbook needles matched. Try the Explore page with your own terms.
              </p>
            ) : (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {scan.slice(0, 60).map((s) => (
                  <button
                    key={s.needle}
                    className="btn btn-sm"
                    style={{ fontFamily: "monospace", fontSize: 11 }}
                    title={`${s.hits} hits — ${s.source}`}
                    onClick={() => searchNeedle(s.needle)}
                  >
                    {s.needle} <strong>{s.hits}</strong>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        <div style={{ flex: "1 1 300px", minWidth: 260 }}>
          {/* Evidence inventory */}
          <div className="card">
            <div className="card-title" style={{ marginBottom: 8 }}>Evidence Inventory</div>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <tbody>
                {Object.entries(inv).sort((a, b) => b[1].rows - a[1].rows).map(([fam, e]) => (
                  <tr key={fam} style={{ borderBottom: "1px solid var(--border)", cursor: "pointer" }}
                      onClick={() => navigate(`/explore?family=${fam}`)}>
                    <td style={{ padding: "4px 6px", fontFamily: "monospace", fontSize: 11 }}>{fam}</td>
                    <td style={{ padding: "4px 6px", fontSize: 11, textAlign: "right" }}>
                      {e.rows.toLocaleString()}{e.capped ? "+" : ""} rows · {e.files} files
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {brief.hosts && brief.hosts.length > 0 && (
              <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-muted)" }}>
                Hosts: {brief.hosts.slice(0, 10).join(", ")}
              </div>
            )}
            {brief.time_range?.start && (
              <div style={{ marginTop: 4, fontSize: 11, color: "var(--text-muted)" }}>
                {brief.time_range.start.slice(0, 19)} → {brief.time_range.end?.slice(0, 19)}
              </div>
            )}
          </div>

          {/* Parser ledger */}
          <div className="card">
            <div className="card-title" style={{ marginBottom: 8 }}>
              Parser Lane <span style={{ fontSize: 10, color: "var(--text-muted)" }}>{ledger.ok} OK · {ledger.skip} skip · {ledger.fail} fail</span>
            </div>
            <div style={{ maxHeight: 200, overflowY: "auto" }}>
              {ledger.entries.slice(0, 30).map((e, i) => (
                <div key={i} style={{ fontSize: 10, padding: "2px 0", display: "flex", gap: 6 }}>
                  <span style={{
                    color: e.status === "OK" ? "var(--success)" : e.status.startsWith("SKIP") ? "var(--text-muted)" : "var(--danger)",
                    width: 40, flexShrink: 0, fontFamily: "monospace",
                  }}>
                    {e.status}
                  </span>
                  <span style={{ fontFamily: "monospace" }}>{e.tool}</span>
                  {e.reason && <span style={{ color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.reason}</span>}
                </div>
              ))}
            </div>
          </div>

          {/* Top entities */}
          {Object.keys(entities).length > 0 && (
            <div className="card">
              <div className="card-title" style={{ marginBottom: 8 }}>Top Entities</div>
              {Object.entries(entities).map(([etype, list]) => (
                <div key={etype} style={{ marginBottom: 6 }}>
                  <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase" }}>{etype}</div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 3, marginTop: 2 }}>
                    {list.slice(0, 6).map((e) => (
                      <button
                        key={e.value}
                        className="btn btn-sm"
                        style={{ fontFamily: "monospace", fontSize: 10, padding: "1px 6px" }}
                        title={`${e.hits} hits across ${(e.families || []).join(", ")}`}
                        onClick={() => searchNeedle(e.value)}
                      >
                        {e.value}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div style={{ marginTop: 12, fontSize: 12, color: "var(--text-muted)" }}>
        Backend: {brief.backend || "csv"} · {brief.hits_examined} hits examined ·{" "}
        <Link to="/explore" style={{ color: "var(--accent)" }}>Open Explore →</Link>
      </div>
    </div>
  );
}
