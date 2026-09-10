/**
 * WP 4d.1: Timeline — per-family aggregate lanes PLUS a type-aware event
 * panel. Clicking a lane filters events to that family; the brush range
 * filters the event list; events render parsed per-family columns via the
 * shared column picker. "Search in Explore" hands the range to Explore.
 */
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, type TimelineLaneEntry, type N4Hit } from "../api/client";
import { pickHitColumns } from "../lib/hitColumns";
import VirtualTable, { type Column } from "../components/VirtualTable";
import { useCase } from "../context/CaseContext";

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
      .map(([hour, count]) => ({ hour, count }));
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
                      return (
                        <div
                          key={i}
                          onClick={() => handleBarClick(b.hour)}
                          title={`${b.hour} — ${b.count} events`}
                          style={{
                            flex: "0 0 8px",
                            height: `${height}%`,
                            minHeight: b.count > 0 ? 3 : 1,
                            background: b.count > 0
                              ? (highlighted ? "var(--warning)" : "var(--accent)")
                              : "var(--bg-tertiary)",
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
              />
            )}
          </div>

          {/* Legend */}
          <div className="card" style={{ padding: "8px 12px" }}>
            <span style={{ fontSize: 11, color: "var(--text-muted)", marginRight: 16 }}>
              <span style={{ display: "inline-block", width: 10, height: 10, background: "var(--accent)", borderRadius: 2, marginRight: 4, verticalAlign: "middle" }} />
              Normal
            </span>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
              <span style={{ display: "inline-block", width: 10, height: 10, background: "var(--warning)", borderRadius: 2, marginRight: 4, verticalAlign: "middle" }} />
              Brushed
            </span>
            <span style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: 16 }}>
              Click a bar to start a range, a second to set the end. "Search in Explore" opens the range there.
            </span>
          </div>
        </>
      )}
    </div>
  );
}
