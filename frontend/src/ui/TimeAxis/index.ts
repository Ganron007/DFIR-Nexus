/**
 * TimeAxis + TimeLanes (WO-U6 / WP 14.6) - one UTC scale for every lane.
 * Import from "@/ui" - never deep-import a file from page code.
 */
export { TimeAxis } from "./TimeAxis";
export { TimeLanes } from "./TimeLanes";
export {
  createUtcScale,
  formatForSpan,
  niceUtcRange,
  parseUtc,
  utcTicks,
  zoomRange,
  type UtcScale,
} from "./scale";
export { useBrush, type BrushOptions, type BrushState } from "./brush";
export type {
  HistogramBucket,
  LaneSeries,
  TimeAxisProps,
  TimeLanesProps,
  TimeRange,
} from "./types";