/**
 * One UTC scale for every lane (WO-U6 / WP 14.6).
 *
 * Everything here is UTC on purpose. A forensic timeline is read across
 * timezones (the examiner's laptop, the UTC-labelled ingest rows, the report
 * handed to a court); a local-time axis silently shifts every lane by the
 * viewer's offset and makes two artefacts disagree. The scale is UTC, the
 * formatter is UTC, and the only place a local time may appear is a tooltip
 * the examiner asked for.
 */
import { scaleUtc, type ScaleTime } from "d3-scale";
import { utcFormat } from "d3-time-format";

import type { TimeRange } from "./types";

export type UtcScale = ScaleTime<number, number>;

/** The one function that builds the scale every lane must use. */
export function createUtcScale(range: TimeRange, width: number): UtcScale {
  const start = range.start.getTime();
  const end = Math.max(range.end.getTime(), start + 1);
  return scaleUtc()
    .domain([new Date(start), new Date(end)])
    .range([0, Math.max(0, width)]);
}

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** Tick format by span: seconds only when the span is seconds. */
export function formatForSpan(spanMs: number): string {
  if (spanMs < 2 * MINUTE) return "%H:%M:%S";
  if (spanMs < 2 * HOUR) return "%H:%M";
  if (spanMs < 2 * DAY) return "%m-%d %H:%M";
  if (spanMs < 90 * DAY) return "%Y-%m-%d";
  return "%Y-%m";
}

/** Ticks + their UTC labels for a range. Shared by the axis and the lanes. */
export function utcTicks(
  scale: UtcScale,
  range: TimeRange,
  count = 6,
): { t: Date; label: string; x: number }[] {
  const span = range.end.getTime() - range.start.getTime();
  const format = utcFormat(formatForSpan(span));
  return scale.ticks(Math.max(2, count)).map((t) => ({
    t,
    label: format(t),
    x: scale(t),
  }));
}

/** Round a range out to whole units (used by zoom). Never invents data. */
export function niceUtcRange(range: TimeRange): TimeRange {
  const start = new Date(Math.floor(range.start.getTime() / SECOND) * SECOND);
  const end = new Date(Math.ceil(range.end.getTime() / SECOND) * SECOND);
  return end.getTime() > start.getTime() ? { start, end } : { start, end: new Date(start.getTime() + SECOND) };
}

/**
 * Zoom around an anchor instant (default: the middle of the range).
 * `factor < 1` zooms in, `> 1` zooms out. The span never drops below a second.
 */
export function zoomRange(range: TimeRange, factor: number, anchorMs?: number): TimeRange {
  const start = range.start.getTime();
  const end = range.end.getTime();
  const anchor = anchorMs ?? (start + end) / 2;
  const nextSpan = Math.max(SECOND, (end - start) * factor);
  const ratio = (anchor - start) / Math.max(1, end - start);
  const nextStart = anchor - ratio * nextSpan;
  return niceUtcRange({
    start: new Date(nextStart),
    end: new Date(nextStart + nextSpan),
  });
}

/** Parse an ISO-8601 instant as UTC. Returns null when it is not a time. */
export function parseUtc(value: string | number | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === "") return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === "number") {
    const fromNumber = new Date(value);
    return Number.isNaN(fromNumber.getTime()) ? null : fromNumber;
  }
  const text = value.trim();
  // a bare hour bucket ("2026-09-29T13" or "13:00") means UTC, not local
  const normalised = /^\d{4}-\d{2}-\d{2}T\d{2}$/.test(text) ? `${text}:00Z` : text;
  const parsed = new Date(/[zZ]|[+-]\d{2}:?\d{2}$/.test(normalised) ? normalised : `${normalised}Z`);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}