/**
 * TimeLanes (WO-U6 / WP 14.6) - N lanes, ONE scale.
 *
 * This is the component the spec's test names: two lanes whose own data covers
 * wildly different spans still share the same scale, so a mark at 03:00 sits at
 * the same pixel in both and a brush means one instant range for the whole
 * stack. The per-lane scale the old timeline cards used is what made
 * cross-lane reading impossible.
 */
import { useMemo } from "react";

import { useBrush } from "./brush";
import { createUtcScale, utcTicks } from "./scale";
import styles from "./TimeAxis.module.css";
import type { TimeLanesProps } from "./types";

export function TimeLanes(props: TimeLanesProps) {
  const {
    lanes,
    range,
    width,
    laneHeight = 28,
    tickCount = 6,
    onRangeChange,
    onSelectLane,
    selectedLaneId = null,
    ariaLabel = "Timeline lanes",
  } = props;

  const scale = useMemo(() => createUtcScale(range, width), [range, width]);
  const ticks = useMemo(() => utcTicks(scale, range, tickCount), [scale, range, tickCount]);
  const { brush, handlers } = useBrush({ scale, width, onRangeChange });

  const axisY = lanes.length * laneHeight + 6;
  // one bar width for every lane, so marks line up vertically
  const barWidth = Math.max(1, Math.min(4, width / 120));

  return (
    <div className={styles.wrapper} data-testid="time-lanes">
      <svg
        width={width}
        height={axisY + 22}
        role="group"
        aria-label={ariaLabel}
        className={styles.svg}
        data-testid="time-lanes-svg"
        {...handlers}
      >
        {ticks.map((tick) => (
          <g key={tick.t.toISOString()} data-testid="tick">
            <line
              x1={tick.x}
              y1={0}
              x2={tick.x}
              y2={axisY}
              className={styles.gridline}
            />
            <text
              x={tick.x}
              y={axisY + 16}
              className={styles.tickLabel}
              textAnchor="middle"
            >
              {tick.label}
            </text>
          </g>
        ))}

        {lanes.map((lane, laneIndex) => {
          const y = laneIndex * laneHeight;
          const peak = lane.buckets.reduce((max, b) => Math.max(max, b.count), 0) || 1;
          return (
            <g
              key={lane.id}
              data-testid={`lane-${lane.id}`}
              data-selected={selectedLaneId === lane.id ? "true" : undefined}
              className={styles.lane}
              onClick={() => onSelectLane?.(lane.id)}
            >
              <title>{lane.label}</title>
              <rect
                x={0}
                y={y}
                width={width}
                height={laneHeight - 4}
                className={styles.laneBand}
                data-selected={selectedLaneId === lane.id ? "true" : undefined}
              />
              <text x={4} y={y + laneHeight / 2} className={styles.laneLabel}>
                {lane.label}
              </text>
              {lane.buckets.map((bucket) => {
                const x = scale(new Date(bucket.t));
                const h = Math.max(2, (bucket.count / peak) * (laneHeight - 8));
                return (
                  <rect
                    key={bucket.t}
                    x={x - barWidth / 2}
                    y={y + laneHeight - 4 - h}
                    width={barWidth}
                    height={h}
                    className={styles.laneMark}
                    data-testid={`lane-mark-${lane.id}`}
                    data-t={bucket.t}
                  />
                );
              })}
            </g>
          );
        })}

        {brush ? (
          <rect
            x={brush.x0}
            y={0}
            width={Math.max(1, brush.x1 - brush.x0)}
            height={axisY}
            className={styles.brush}
            data-testid="brush-rect"
          />
        ) : null}
      </svg>
    </div>
  );
}