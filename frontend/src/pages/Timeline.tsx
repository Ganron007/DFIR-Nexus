import { useEffect, useState } from "react";
import { api, type TimelineLane } from "../api/client";

export default function Timeline() {
  const [lanes, setLanes] = useState<TimelineLane[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    api.timelineLanes({})
      .then(setLanes)
      .catch((e) => setError((e as Error).message))
      .finally(() => setLoading(false));
  }, []);

  // Find max count for scaling
  const maxCount = Math.max(0, ...lanes.flatMap((l) => l.buckets.map((b) => b.count)));

  if (loading) return <div className="loading">Loading timeline...</div>;
  if (error) return <div className="error-banner">{error}</div>;

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Timeline</h2>
      {lanes.length === 0 ? (
        <div className="empty-state">
          <h3>No timeline data</h3>
          <p>Run a search first to populate timeline lanes.</p>
        </div>
      ) : (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Per-Family Hour Buckets</span>
          </div>
          {lanes.map((lane) => (
            <div key={lane.family} style={{ marginBottom: 20 }}>
              <h4 style={{ fontSize: 13, marginBottom: 8, color: "var(--accent)" }}>
                {lane.family} ({lane.buckets.reduce((s, b) => s + b.count, 0)} events)
              </h4>
              <div style={{ display: "flex", gap: 2, alignItems: "flex-end", height: 60, overflowX: "auto" }}>
                {lane.buckets.map((b, i) => {
                  const height = maxCount > 0 ? (b.count / maxCount) * 100 : 0;
                  return (
                    <div
                      key={i}
                      title={`${b.hour} — ${b.count} events`}
                      style={{
                        flex: "0 0 8px",
                        height: `${height}%`,
                        background: b.count > 0 ? "var(--accent)" : "var(--bg-tertiary)",
                        borderRadius: "2px 2px 0 0",
                        minHeight: b.count > 0 ? 4 : 2,
                      }}
                    />
                  );
                })}
              </div>
              <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
                {lane.buckets[0]?.hour} — {lane.buckets[lane.buckets.length - 1]?.hour}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
