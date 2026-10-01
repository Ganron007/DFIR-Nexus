/**
 * TimeAxis (WO-U6 / WP 14.6) - the timeline's one UTC axis.
 *
 * Own SVG, no chart library: an axis, ticks, an optional histogram lane, zoom
 * controls and the shared brush. Every other lane on the page must be built
 * from `createUtcScale(range, width)` - a second scale is how a timeline ends up
 * lying about when two artefacts happened.
 */
import { useMemo } from "react";

import { useBrush } from "./brush";
import { createUtcScale, utcTicks, zoomRange } from "./scale";
import styles from "./TimeAxis.module.css";
import type { TimeAxisProps } from "./types";

export function TimeAxis(props: TimeAxisProps) {
  const {
    range,
    width,
    height = 64,
    tickCount = 6,
    histogram,
    onRangeChange,
    onBrushPreview,
    ariaLabel = "Time axis",
  } = props;

  // one scale, built once per range/width - every lane shares it
  const scale = useMemo(() => createUtcScale(range, width), [range, width]);
  const ticks = useMemo(() => utcTicks(scale, range, tickCount), [scale, range, tickCount]);
  const { brush, handlers } = useBrush({ scale, width, onRangeChange, onBrushPreview });

  const axisY = histogram && histogram.length > 0 ? 34 : 44;
  const peak = histogram?.reduce((max, bucket) => Math.max(max, bucket.count), 0) ?? 0;

  return (
    <div className={styles.wrapper} data-testid="time-axis">
      <div className={styles.controls}>
        <button
          type="button"
          aria-label="Zoom in"
          data-testid="zoom-in"
          onClick={() => onRangeChange?.(zoomRange(range, 0.5))}
        >
          +
        </button>
        <button
          type="button"
          aria-label="Zoom out"
          data-testid="zoom-out"
          onClick={() => onRangeChange?.(zoomRange(range, 2))}
        >
          −
        </button>
        <span className={styles.readout} data-testid="axis-range">
          {range.start.toISOString()} → {range.end.toISOString()}
        </span>
      </div>

      <svg
        width={width}
        height={height}
        role="group"
        aria-label={ariaLabel}
        className={styles.svg}
        data-testid="time-axis-svg"
        {...handlers}
      >
        {histogram && peak > 0 ? (
          <g data-testid="histogram-lane">
            {histogram.map((bucket) => {
              const x = scale(new Date(bucket.t));
              const h = Math.max(1, (bucket.count / peak) * (axisY - 4));
              return (
                <rect
                  key={bucket.t}
                  x={x}
                  y={axisY - h}
                  width={Math.max(1, width / Math.max(1, histogram.length) - 1)}
                  height={h}
                  className={styles.histogramBar}
                  data-testid="histogram-bar"
                />
              );
            })}
          </g>
        ) : null}

        <line x1={0} y1={axisY} x2={width} y2={axisY} className={styles.axisLine} />
        {ticks.map((tick) => (
          <g key={tick.t.toISOString()} data-testid="tick">
            <line x1={tick.x} y1={axisY} x2={tick.x} y2={axisY + 5} className={styles.tick} />
            <text x={tick.x} y={axisY + 16} className={styles.tickLabel} textAnchor="middle">
              {tick.label}
            </text>
          </g>
        ))}

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