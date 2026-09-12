/**
 * WP 4d.1: Timeline — per-family aggregate lanes PLUS a type-aware event
 * panel. Clicking a lane filters events to that family; the brush range
 * filters the event list; events render parsed per-family columns via the
 * shared column picker. "Search in Explore" hands the range to Explore.
 */
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, type TimelineLaneEntry, type N4Hit, type HitInterpretation } from "../api/client";
import { pickHitColumns } from "../lib/hitColumns";
import VirtualTable, { type Column } from "../components/VirtualTable";
import { useCase } from "../context/CaseContext";

/** Severity → lane/event color. Mirrors _severity_from_hits on the backend. */
const SEV_COLORS: Record<string, string> = {
  critical: "var(--danger)",
  high: "#f0883e",
  medium: "var(--warning)",
  low: "var(--accent)",
  informational: "var(--text-muted)",
};
const LEVEL_SEV: Record<string, string> = {
  crit: "critical", critical: "critical", high: "high", med: "medium",
  medium: "medium", low: "low", info: "informational", informational: "informational",
};
const DETECTION_FAMILIES = new Set(["hayabusa", "chainsaw", "sigma", "suzaku"]);

function hitSeverity(h: N4Hit): string {
  const fam = (h.family || "").toLowerCase();
  if (!DETECTION_FAMILIES.has(fam)) return "";
  const fields = h.fields || {};
  const raw = (fields.Level || fields.level || fields.Severity || "").toLowerCase().trim();
  if (LEVEL_SEV[raw]) return LEVEL_SEV[raw];
  if ((fields.detections || "").trim()) return "medium";
  return "";
}

function sevColor(sev: string): string {
  return SEV_COLORS[sev] || "var(--accent)";
}

export default function Timeline() {
  const { activeCase } = useCase();
  const navigate = useNavigate();
  const [lanes, setLanes] = useState<TimelineLaneEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [brushStart, setBrushStart] = useState<number | null>(null);
  const [brushEnd, setBrushEnd] = useState<number | null>(null);
  const [selectedLane, setSelectedLane] = useState<string | null>(null);
  // WP: type-aware event panel under the lanes
  const [events, setEvents] = useState<N4Hit[]>([]);
  const [eventCount, setEventCount] = useState(0);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventError, setEventError] = useState("");
  // Event → interpretation drawer
  const [selected, setSelected] = useState<N4Hit | null>(null);
  const [interp, setInterp] = useState<HitInterpretation | null>(null);
  const [interpLoading, setInterpLoading] = useState(false);

  useEffect(() => {
    api.timelineLanes({})
      .then((r) => {
        setLanes(r.families || []);
        setTotal(r.total);
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, [activeCase]);

  const laneData = lanes.map((lane) => {
    const buckets = Object.entries(lane.buckets)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([hour, count]) => ({ hour, count, sev: lane.buckets_sev?.[hour] || "" }));
    return { family: lane.family, buckets };
  });

  const maxCount = Math.max(0, ...laneData.flatMap((l) => l.buckets.map((b) => b.count)));
  const totalEvents = laneData.reduce((s, l) => s + l.buckets.reduce((s2, b) => s2 + b.count, 0), 0);

  const allHours = laneData.length > 0
    ? [...new Set(laneData.flatMap((l) => l.buckets.map((b) => b.hour)))].sort()
    : [];
  const hourToIndex = new Map(allHours.map((h, i) => [h, i]));

  const handleBarClick = (hour: string) => {
    const idx = hourToIndex.get(hour) ?? 0;
    if (brushStart === null) {
      setBrushStart(idx);
      setBrushEnd(null);
    } else if (brushEnd === null) {
      setBrushEnd(idx);
    } else {
      setBrushStart(idx);
      setBrushEnd(null);
    }
  };

  const inBrush = (hour: string): boolean => {
    const idx = hourToIndex.get(hour);
    if (idx === undefined || brushStart === null) return false;
    if (brushEnd === null) return idx === brushStart;
    return idx >= Math.min(brushStart, brushEnd) && idx <= Math.max(brushStart, brushEnd);
  };

  // Brushed range as start/end strings for the event panel + Explore handoff
  const brushRange = (() => {
    if (brushStart === null) return { start: "", end: "" };
    const startIdx = brushEnd !== null ? Math.min(brushStart, brushEnd) : brushStart;
    const endIdx = brushEnd !== null ? Math.max(brushStart, brushEnd) : brushStart;
    return { start: allHours[startIdx] || "", end: allHours[endIdx] || "" };
  })();

  // Reload events when the lane or brush changes
  useEffect(() => {
    if (!selectedLane && brushRange.start === "" && brushRange.end === "") {
      setEvents([]);
      setEventCount(0);
      return;
    }
    setEventsLoading(true);
    api.search({
      family: selectedLane || undefined,
      start: brushRange.start || undefined,
      end: brushRange.end || undefined,
      limit: 200,
      offset: 0,
    })
      .then((r) => {
        setEvents(r.hits);
        setEventCount(r.count);
      })
      .catch((e) => setEventError((e as Error).message))
      .finally(() => setEventsLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedLane, brushRange.start, brushRange.end, activeCase]);

  // Event → interpretation drawer: fetch what the row means + next checks.
  const openEvent = (h: N4Hit) => {
    setSelected(h);
    setInterp(null);
    setInterpLoading(true);
    api.hitInterpret(h)
      .then(setInterp)
      .catch(() => setInterp(null))
      .finally(() => setInterpLoading(false));
  };

  // WP 4b.10: hand the brushed range to Explore
  const sendToExplore = () => {
    if (brushStart === null) return;
    const params = new URLSearchParams();
    if (brushRange.start) params.set("start", brushRange.start);
    if (brushRange.end) params.set("end", brushRange.end);
    if (selectedLane) params.set("family", selectedLane);
    navigate(`/explore?${params.toString()}`);
  };

  if (loading) return <div className="loading">Loading timeline...</div>;
  if (error) return <div className="error-banner">{error}</div>;

  const visibleLanes = laneData.filter((lane) => !selectedLane || lane.family === selectedLane);
  const typeColumns = pickHitColumns(events);

  const eventColumns: Column<N4Hit>[] = [
    {
      key: "sev",
      header: "",
      width: 26,
      render: (h) => {
        const sev = hitSeverity(h);
        if (!sev) return null;
        return (
          <span
            title={sev}
            style={{
              display: "inline-block", width: 8, height: 8, borderRadius: "50%",
              background: sevColor(sev),
            }}
          />
        );
      },
    },
    {
      key: "time",
      header: "Time",
      width: 150,
      render: (h) => {
        const m = /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/.exec(h.text || "");
        return <span style={{ fontFamily: "monospace", fontSize: 11 }}>{m ? m[1] : "—"}</span>;
      },
    },
    {
      key: "family",
      header: "Family",
      width: 90,
      render: (h) => <span style={{ fontFamily: "monospace", fontSize: 11 }}>{h.family}</span>,
    },
    {
      key: "host",
      header: "Host",
      width: 90,
      render: (h) => <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--text-secondary)" }}>{h.host || "—"}</span>,
    },
    ...typeColumns.map((fieldName) => ({
      key: `field-${fieldName}`,
      header: fieldName,
      width: fieldName.toLowerCase().includes("message") ? undefined : 150,
      render: (h: N4Hit) => (
        <span style={{ fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", display: "block", whiteSpace: "nowrap" }}>
          {h.fields?.[fieldName] ?? ""}
        </span>
      ),
    })),
    {
      key: "source",
      header: "Source",
      width: 150,
      render: (h) => (
        <span style={{ fontSize: 10, color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis", display: "block", whiteSpace: "nowrap" }}>
          {h.file}:{h.line}
        </span>
      ),
    },
  ];

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>
        Timeline ({totalEvents.toLocaleString()} events · {total} total hits)
      </h2>
      {error && <div className="error-banner">{error}</div>}
      {laneData.length === 0 ? (
        <div className="empty-state">
          <h3>No timeline data</h3>
          <p>Run the N2 processing lane and query evidence to populate timeline lanes.</p>
        </div>
      ) : (
        <>
          {/* Brush controls */}
          {brushStart !== null && (
            <div className="card" style={{ padding: "8px 12px", marginBottom: 8 }}>
              <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                Brush: {allHours[brushStart]}
                {brushEnd !== null && ` → ${allHours[brushEnd]}`}
              </span>
              <button
                className="btn btn-sm"
                style={{ marginLeft: 12 }}
                onClick={() => { setBrushStart(null); setBrushEnd(null); }}
              >
                Clear
              </button>
              <button
                className="btn btn-sm btn-primary"
                style={{ marginLeft: 8 }}
                onClick={sendToExplore}
              >
                Search in Explore →
              </button>
            </div>
          )}

          {/* Lane filter */}
          {selectedLane && (
            <div className="card" style={{ padding: "8px 12px" }}>
              <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                Filtered to lane: <strong>{selectedLane}</strong>
              </span>
              <button
                className="btn btn-sm"
                style={{ marginLeft: 12 }}
                onClick={() => setSelectedLane(null)}
              >
                Show all
              </button>
            </div>
          )}

          {/* Aggregate lanes */}
          <div>
            {visibleLanes.map((lane) => {
              const laneEvents = lane.buckets.reduce((s, b) => s + b.count, 0);
              return (
                <div key={lane.family} className="card" style={{ marginBottom: 12 }}>
                  <div className="card-header">
                    <span
                      className="card-title"
                      style={{ cursor: "pointer", color: "var(--accent)" }}
                      onClick={() => setSelectedLane(lane.family === selectedLane ? null : lane.family)}
                      title="Click to show this family's events below"
                    >
                      {lane.family} ({laneEvents.toLocaleString()} events)
                    </span>
                    <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                      {lane.buckets.length} time buckets
                    </span>
                  </div>
                  <div style={{ display: "flex", gap: 1, alignItems: "flex-end", height: 80, overflowX: "auto", paddingBottom: 4 }}>
                    {lane.buckets.map((b, i) => {
                      const height = maxCount > 0 ? (b.count / maxCount) * 100 : 0;
                      const highlighted = inBrush(b.hour);
                      const barColor = highlighted
                        ? "var(--warning)"
                        : b.sev && b.sev !== "low" && b.sev !== "informational"
                          ? sevColor(b.sev)
                          : "var(--accent)";
                      return (
                        <div
                          key={i}
                          onClick={() => handleBarClick(b.hour)}
                          title={`${b.hour} — ${b.count} events${b.sev ? ` · max ${b.sev}` : ""}`}
                          style={{
                            flex: "0 0 8px",
                            height: `${height}%`,
                            minHeight: b.count > 0 ? 3 : 1,
                            background: b.count > 0 ? barColor : "var(--bg-tertiary)",
                            borderRadius: "2px 2px 0 0",
                            cursor: "pointer",
                            opacity: brushStart !== null && !highlighted ? 0.4 : 1,
                            transition: "opacity 0.15s, background 0.15s",
                          }}
                        />
                      );
                    })}
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
                    <span>{lane.buckets[0]?.hour}</span>
                    <span>{lane.buckets[Math.floor(lane.buckets.length / 2)]?.hour}</span>
                    <span>{lane.buckets[lane.buckets.length - 1]?.hour}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* WP 4d.1: type-aware event list for the selected lane / brush */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">
                Events{selectedLane ? ` — ${selectedLane}` : ""}
                {brushRange.start || brushRange.end
                  ? ` · ${brushRange.start || "…"} → ${brushRange.end || "…"}`
                  : ""}
                {` (${eventCount.toLocaleString()})`}
              </span>
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                click bars to set a range · click a lane title to filter
              </span>
            </div>
            {eventsLoading ? (
              <div className="loading">Loading events...</div>
            ) : eventError ? (
              <div className="error-banner">{eventError}</div>
            ) : events.length === 0 ? (
              <div className="empty-state">
                <p>No events in this view. Click a lane or brush a time range above.</p>
              </div>
            ) : (
              <VirtualTable
                rows={events}
                columns={eventColumns}
                rowKey={(h, i) => `${h.family}:${h.file}:${h.line}:${i}`}
                maxHeight="45vh"
                onRowClick={openEvent}
              />
            )}
          </div>

          {/* Legend */}
          <div className="card" style={{ padding: "8px 12px" }}>
            <span style={{ fontSize: 11, color: "var(--text-muted)", marginRight: 16 }}>
              <span style={{ display: "inline-block", width: 10, height: 10, background: "var(--accent)", borderRadius: 2, marginRight: 4, verticalAlign: "middle" }} />
              Normal
            </span>
            {(["critical", "high", "medium"] as const).map((s) => (
              <span key={s} style={{ fontSize: 11, color: "var(--text-muted)", marginRight: 16 }}>
                <span style={{ display: "inline-block", width: 10, height: 10, background: sevColor(s), borderRadius: 2, marginRight: 4, verticalAlign: "middle" }} />
                {s}
              </span>
            ))}
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              <span style={{ display: "inline-block", width: 10, height: 10, background: "var(--warning)", borderRadius: 2, marginRight: 4, verticalAlign: "middle" }} />
              Brushed
            </span>
            <span style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: 16 }}>
              Click a bar to start a range, a second to set the end. Click an event row for interpretation.
            </span>
          </div>

          {/* Event → interpretation drawer */}
          {selected && (
            <div
              style={{
                position: "fixed", top: 0, right: 0, bottom: 0, width: 420,
                background: "var(--bg-secondary)", borderLeft: "1px solid var(--border)",
                padding: 16, overflowY: "auto", zIndex: 40,
                boxShadow: "-8px 0 24px rgba(0,0,0,0.4)",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                <strong style={{ fontSize: 13 }}>Event interpretation</strong>
                <button className="btn btn-sm" onClick={() => setSelected(null)}>✕</button>
              </div>
              {(() => {
                const sev = hitSeverity(selected);
                return (
                  <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10, fontFamily: "monospace" }}>
                    {selected.family}
                    {sev && (
                      <span style={{ color: sevColor(sev), marginLeft: 8, fontWeight: 600 }}>
                        ● {sev}
                      </span>
                    )}
                    <div style={{ marginTop: 4, wordBreak: "break-all" }}>{selected.file}:{selected.line}</div>
                  </div>
                );
              })()}
              {selected.fields && Object.keys(selected.fields).length > 0 && (
                <div style={{ marginBottom: 12 }}>
                  {Object.entries(selected.fields).slice(0, 14).map(([k, v]) => (
                    <div key={k} style={{ fontSize: 11, marginBottom: 3 }}>
                      <span style={{ color: "var(--text-muted)" }}>{k}: </span>
                      <span style={{ wordBreak: "break-all" }}>{v}</span>
                    </div>
                  ))}
                </div>
              )}
              {interpLoading && <div className="loading">Interpreting…</div>}
              {interp && !interp.error && (
                <div>
                  {interp.meaning && (
                    <p style={{ fontSize: 12, lineHeight: 1.5 }}>{interp.meaning}</p>
                  )}
                  {(() => {
                    const tids = interp.techniques?.length
                      ? interp.techniques
                      : [...new Set((interp.skills || []).flatMap((s) => s.mitre || []))];
                    return tids.length > 0 && (
                      <div style={{ margin: "8px 0" }}>
                        {tids.slice(0, 10).map((t) => (
                          <span key={t} className="badge" style={{ marginRight: 4, fontSize: 10 }}>{t}</span>
                        ))}
                      </div>
                    );
                  })()}
                  {interp.look_for?.length > 0 && (
                    <>
                      <div style={{ fontSize: 11, fontWeight: 600, marginTop: 10 }}>Look for</div>
                      <ul style={{ fontSize: 11, paddingLeft: 16, margin: "4px 0" }}>
                        {interp.look_for.slice(0, 6).map((x, i) => <li key={i}>{x}</li>)}
                      </ul>
                    </>
                  )}
                  {interp.corroborate?.length > 0 && (
                    <>
                      <div style={{ fontSize: 11, fontWeight: 600, marginTop: 10 }}>Corroborate</div>
                      <ul style={{ fontSize: 11, paddingLeft: 16, margin: "4px 0" }}>
                        {interp.corroborate.slice(0, 5).map((x, i) => <li key={i}>{x}</li>)}
                      </ul>
                    </>
                  )}
                  {interp.next_queries?.length > 0 && (
                    <>
                      <div style={{ fontSize: 11, fontWeight: 600, marginTop: 10 }}>Next queries</div>
                      <ul style={{ fontSize: 11, paddingLeft: 16, margin: "4px 0", fontFamily: "monospace" }}>
                        {interp.next_queries.slice(0, 5).map((x, i) => <li key={i}>{x}</li>)}
                      </ul>
                    </>
                  )}
                  {interp.caveats?.length > 0 && (
                    <>
                      <div style={{ fontSize: 11, fontWeight: 600, marginTop: 10, color: "var(--warning)" }}>Caveats</div>
                      <ul style={{ fontSize: 11, paddingLeft: 16, margin: "4px 0" }}>
                        {interp.caveats.slice(0, 4).map((x, i) => <li key={i}>{x}</li>)}
                      </ul>
                    </>
                  )}
                </div>
              )}
              {interp?.error && <div className="error-banner">{interp.error}</div>}
            </div>
          )}
        </>
      )}
    </div>
  );
}
