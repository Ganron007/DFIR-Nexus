import { useEffect, useState, useRef } from "react";
import { api, type TimelineLaneEntry } from "../api/client";

export default function Timeline() {
  const [lanes, setLanes] = useState<TimelineLaneEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [brushStart, setBrushStart] = useState<number | null>(null);
  const [brushEnd, setBrushEnd] = useState<number | null>(null);
  const [selectedLane, setSelectedLane] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.timelineLanes({})
      .then((r) => {
        setLanes(r.families || []);
        setTotal(r.total);
      })
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, []);

  // Convert lane buckets from Record<string, number> to sorted array
  const laneData = lanes.map((lane) => {
    const buckets = Object.entries(lane.buckets)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([hour, count]) => ({ hour, count }));
    return { family: lane.family, buckets };
  });

  // Find max count for scaling across all lanes
  const maxCount = Math.max(0, ...laneData.flatMap((l) => l.buckets.map((b) => b.count)));
  const totalEvents = laneData.reduce((s, l) => s + l.buckets.reduce((s2, b) => s2 + b.count, 0), 0);

  // Collect all unique hours for the x-axis
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
      // Reset brush
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

  if (loading) return <div className="loading">Loading timeline...</div>;
  if (error) return <div className="error-banner">{error}</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Timeline ({totalEvents.toLocaleString()} events · {total} total hits)</h2>
      {laneData.length === 0 ? (
        <div className="empty-state">
          <h3>No timeline data</h3>
          <p>Run a search first to populate timeline lanes.</p>
        </div>
      ) : (
        <>
          {/* Brush controls */}
          {brushStart !== null && (
            <div className="card" style={{ padding: "8px 12px" }}>
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

          <div ref={containerRef}>
            {laneData
              .filter((lane) => !selectedLane || lane.family === selectedLane)
              .map((lane) => {
                const laneEvents = lane.buckets.reduce((s, b) => s + b.count, 0);
                return (
                  <div key={lane.family} className="card" style={{ marginBottom: 12 }}>
                    <div className="card-header">
                      <span
                        className="card-title"
                        style={{ cursor: "pointer", color: "var(--accent)" }}
                        onClick={() => setSelectedLane(lane.family)}
                      >
                        {lane.family} ({laneEvents.toLocaleString()} events)
                      </span>
                      <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        {lane.buckets.length} time buckets
                      </span>
                    </div>
                    {/* Bar chart */}
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
                    {/* Time axis */}
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
                      <span>{lane.buckets[0]?.hour}</span>
                      <span>{lane.buckets[Math.floor(lane.buckets.length / 2)]?.hour}</span>
                      <span>{lane.buckets[lane.buckets.length - 1]?.hour}</span>
                    </div>
                  </div>
                );
              })}
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
              Click a bar to start a brush range. Click a second bar to set the end.
            </span>
          </div>
        </>
      )}
    </div>
  );
}
