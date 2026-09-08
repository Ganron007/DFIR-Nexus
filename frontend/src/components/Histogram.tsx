/**
 * Histogram bar chart for explore search results.
 * Shows event count per hour bucket, colored by family.
 */

import { useState } from "react";

export interface HistogramBucket {
  hour: string;
  count: number;
  family?: string;
}

interface HistogramProps {
  buckets: HistogramBucket[];
  maxBars?: number;
  onBarClick?: (hour: string) => void;
}

export default function Histogram({ buckets, maxBars = 100, onBarClick }: HistogramProps) {
  const [hovered, setHovered] = useState<number | null>(null);
  const maxCount = Math.max(0, ...buckets.map((b) => b.count));

  if (buckets.length === 0) return null;

  // Downsample if too many bars
  const step = Math.ceil(buckets.length / maxBars);
  const display = step > 1 ? buckets.filter((_, i) => i % step === 0) : buckets;

  return (
    <div style={{ position: "relative", padding: "8px 0" }}>
      <div style={{ display: "flex", gap: 1, alignItems: "flex-end", height: 80, overflowX: "auto" }}>
        {display.map((b, i) => {
          const height = maxCount > 0 ? (b.count / maxCount) * 100 : 0;
          return (
            <div
              key={i}
              onMouseEnter={() => setHovered(i)}
              onMouseLeave={() => setHovered(null)}
              onClick={onBarClick ? () => onBarClick(b.hour) : undefined}
              title={`${b.hour} — ${b.count} events${b.family ? ` (${b.family})` : ""}`}
              style={{
                flex: "0 0 6px",
                height: `${height}%`,
                minHeight: b.count > 0 ? 3 : 1,
                background: b.count > 0
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
          <span>{display[0].hour}</span>
          <span>{display[display.length - 1].hour}</span>
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
          {display[hovered].hour} — {display[hovered].count} events
        </div>
      )}
    </div>
  );
}
