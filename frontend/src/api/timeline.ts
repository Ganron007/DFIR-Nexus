/**
 * Timeline event types (WO-A10) - the shape `GET /portal/api/timeline/events`
 * returns. One declaration shared by the API client, the grid and the axis, so
 * a field added on the server without the UI noticing is a type error rather
 * than a blank column.
 */

export interface TimelineEvent {
  event_id: string;
  ts: string;
  ts_raw?: string;
  /** "column" = registry-typed, "column-heuristic" = looked like a date. */
  ts_src?: string;
  ts_precision?: string;
  /** Which timestamp this event is: Created0x10, LastModified0x30, ingest… */
  ts_desc?: string;
  host?: string;
  user?: string;
  family?: string;
  artifact?: string;
  event_type?: string;
  source_file?: string;
  source_line?: number;
  audit_id?: string;
  finding_ids?: string[];
  /** Reserved per design review §5 #6 - present, never guessed. */
  host_clock_skew?: number | null;
  fields?: Record<string, unknown>;
}

export interface TimelineEventPage {
  /** "es", or "unavailable" when the endpoint degraded (it 503s). */
  backend: string;
  index?: string;
  rows: TimelineEvent[];
  next_cursor: string | null;
  total: number | null;
  /** false when ES reported the count as a floor (relation "gte"). */
  exact: boolean;
  capped: boolean;
}

export interface TimelineFacetsResponse {
  backend: string;
  facets: Record<string, { value: string; count: number }[]>;
}

export interface TimelineHistogramResponse {
  backend: string;
  buckets: { ts: string | number; count: number }[];
}

export interface TimelineContextResponse {
  backend: string;
  anchor: TimelineEvent | null;
  rows: TimelineEvent[];
  seconds: number;
  total?: number | null;
  capped?: boolean;
}

/** The timestamp the grid sorts on, in milliseconds (NaN if unparseable). */
export function eventEpoch(event: TimelineEvent): number {
  const parsed = Date.parse(event.ts);
  return Number.isNaN(parsed) ? 0 : parsed;
}

/** A display timestamp: UTC, seconds precision unless the source had more. */
export function formatEventTs(ts: string | undefined): string {
  if (!ts) return "";
  const parsed = Date.parse(ts);
  if (Number.isNaN(parsed)) return ts;
  return new Date(parsed).toISOString().replace("T", " ").replace("Z", "Z");
}
