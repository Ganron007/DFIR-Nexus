/**
 * Timeline events domain (WO-A10).
 *
 * One client for the six reads the timeline makes, so the grid, the axis and
 * the export cannot disagree about which events exist. The honesty flags
 * (`exact`, `capped`, `backend`) travel with every page because the grid has
 * to be able to say "at least N" rather than implying a total.
 */
import { get, post } from "../transport";
import type {
  TimelineContextResponse,
  TimelineEventPage,
  TimelineFacetsResponse,
  TimelineHistogramResponse,
} from "../../api/timeline";

export const timelineApi = {
  events: (params: {
    caseId: string;
    cursor?: string | null;
    size?: number;
    filters?: Record<string, unknown>;
    sortBy?: string;
    sortDir?: "asc" | "desc";
  }) => {
    const query = new URLSearchParams({ case_id: params.caseId });
    if (params.cursor) query.set("cursor", params.cursor);
    if (params.size) query.set("size", String(params.size));
    if (params.sortBy) query.set("sort_by", params.sortBy);
    if (params.sortDir) query.set("sort_dir", params.sortDir);
    if (params.filters && Object.keys(params.filters).length > 0) {
      query.set("filters", JSON.stringify(params.filters));
    }
    return get<TimelineEventPage>(`/timeline/events?${query.toString()}`);
  },

  facets: (caseId: string, filters?: Record<string, unknown>) => {
    const query = new URLSearchParams({ case_id: caseId });
    if (filters && Object.keys(filters).length > 0) {
      query.set("filters", JSON.stringify(filters));
    }
    return get<TimelineFacetsResponse>(`/timeline/events/facets?${query.toString()}`);
  },

  histogram: (caseId: string, params?: { start?: string; end?: string; interval?: string; buckets?: number }) => {
    const query = new URLSearchParams({ case_id: caseId });
    if (params?.start) query.set("start", params.start);
    if (params?.end) query.set("end", params.end);
    if (params?.interval) query.set("interval", params.interval);
    if (params?.buckets) query.set("buckets", String(params.buckets));
    return get<TimelineHistogramResponse>(`/timeline/events/histogram?${query.toString()}`);
  },

  context: (caseId: string, eventId: string, seconds = 300) =>
    get<TimelineContextResponse>(
      `/timeline/events/${encodeURIComponent(eventId)}/context` +
        `?case_id=${encodeURIComponent(caseId)}&seconds=${seconds}`,
    ),

  build: (caseId: string, force = false) =>
    post<{ built: boolean; events?: number; index?: string; reason?: string }>(
      `/timeline/events/build?case_id=${encodeURIComponent(caseId)}${force ? "&force=1" : ""}`,
      {},
    ),

  /** The CSV URL for the browser - not fetched through the JSON client. */
  exportUrl: (caseId: string, filters?: Record<string, unknown>) => {
    const query = new URLSearchParams({ case_id: caseId });
    if (filters && Object.keys(filters).length > 0) {
      query.set("filters", JSON.stringify(filters));
    }
    return `/portal/api/timeline/events/export?${query.toString()}`;
  },
};
