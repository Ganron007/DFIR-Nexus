/**
 * Time-axis types (WO-U6 / WP 14.6, UD4: d3-scale + d3-time, no chart library).
 *
 * The contract that matters: every lane draws against ONE scale. A timeline
 * whose lanes each invent their own scale cannot be read across, and a brush
 * that means different instants per lane is a lie.
 */

export interface TimeRange {
  /** inclusive start (UTC) */
  start: Date;
  /** exclusive end (UTC) */
  end: Date;
}

export interface HistogramBucket {
  /** epoch milliseconds (UTC) */
  t: number;
  count: number;
}

export interface LaneSeries {
  id: string;
  label: string;
  buckets: HistogramBucket[];
  /** Optional severity-ish tone key resolved by the caller, never a raw colour. */
  tone?: string;
}

export interface TimeAxisProps {
  range: TimeRange;
  width: number;
  height?: number;
  tickCount?: number;
  histogram?: HistogramBucket[];
  onRangeChange?: (range: TimeRange) => void;
  onBrushPreview?: (range: TimeRange | null) => void;
  ariaLabel?: string;
}

export interface TimeLanesProps {
  lanes: LaneSeries[];
  range: TimeRange;
  width: number;
  laneHeight?: number;
  tickCount?: number;
  onRangeChange?: (range: TimeRange) => void;
  onSelectLane?: (laneId: string) => void;
  selectedLaneId?: string | null;
  ariaLabel?: string;
}