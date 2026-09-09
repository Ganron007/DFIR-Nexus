/**
 * Histogram bar chart for explore search results.
 * Shows event count per time bucket.
 */

import { useState } from "react";

interface HistogramProps {
  buckets: Record<string, number>;
  maxBars?: number;
  onBarClick?: (hour: string) => void;
}

export default function Histogram({ buckets, maxBars = 100, onBarClick }: HistogramProps) {
  const [hovered, setHovered] = useState<number | null>(null);

  // Convert Record<string, number> to sorted array of [key, count] pairs
  const entries = Object.entries(buckets).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) return null;

  const maxCount = Math.max(0, ...entries.map(([, c]) => c));

  // Downsample if too many bars — aggregate consecutive buckets by summing
  let display = entries;
  if (entries.length > maxBars) {
    const step = Math.ceil(entries.length / maxBars);
    display = [];
    for (let i = 0; i < entries.length; i += step) {
      const chunk = entries.slice(i, i + step);
      const sum = chunk.reduce((s, [, c]) => s + c, 0);
      display.push([chunk[0][0], sum] as [string, number]);
    }
  }

  return (
    <div style={{ position: "relative", padding: "8px 0" }}>
      <div style={{ display: "flex", gap: 1, alignItems: "flex-end", height: 80, overflowX: "auto" }}>
        {display.map(([key, cnt], i) => {
          const height = maxCount > 0 ? (cnt / maxCount) * 100 : 0;
          return (
            <div
              key={i}
              onMouseEnter={() => setHovered(i)}
              onMouseLeave={() => setHovered(null)}
              onClick={onBarClick ? () => onBarClick(key) : undefined}
              title={`${key} — ${cnt} events`}
              style={{
                flex: "0 0 6px",
                height: `${height}%`,
                minHeight: cnt > 0 ? 3 : 1,
                background: cnt > 0
                  ? (hovered === i ? "var(--accent-hover)" : "var(--accent)")
                  : "var(--bg-tertiary)",
                borderRadius: "2px 2px 0 0",
                cursor: onBarClick ? "pointer" : "default",
                transition: "background 0.1s",
              }}
            />
          );
        })}
      </div>
      {display.length > 0 && (
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
          <span>{display[0][0]}</span>
          <span>{display[display.length - 1][0]}</span>
        </div>
      )}
      {hovered !== null && display[hovered] && (
        <div style={{
          position: "absolute",
          bottom: "100%",
          left: `${(hovered / display.length) * 100}%`,
          background: "var(--bg-tertiary)",
          border: "1px solid var(--border-light)",
          borderRadius: 4,
          padding: "4px 8px",
          fontSize: 11,
          whiteSpace: "nowrap",
          pointerEvents: "none",
          zIndex: 10,
        }}>
          {display[hovered][0]} — {display[hovered][1]} events
        </div>
      )}
    </div>
  );
}
