/**
 * Search & analysis domain (WO-U4): Explore queries, aggregations, hit
 * interpretation, entity pivot, timeline lanes and needle vocabulary.
 */
import { post, request } from "../transport";
import type {
  AggregateResponse,
  EntitiesResponse,
  HistogramResponse,
  HitInterpretation,
  N4Hit,
  PlaybookNeedlesResponse,
  SearchResponse,
  TimelineLanesResponse,
} from "../client";

export const searchApi = {
  search: (params: {
    query?: string;
    needles?: string;
    family?: string;
    host?: string;
    start?: string;
    end?: string;
    limit?: number;
    offset?: number;
    /** Timeline events panel — resolve the case's needle vocabulary when
     *  no query/needles are given (empty-intake portal cases). */
    default_needles?: boolean;
  }) => post<SearchResponse>("/explore/search", params),
  aggregate: (params: { query?: string; group_by: string }) =>
    post<AggregateResponse>("/explore/aggregate", params),
  histogram: (params: {
    needles?: string;
    family?: string;
    start?: string;
    end?: string;
    bucket?: number;
  }) => post<HistogramResponse>("/explore/histogram", params),
  // WP 4j.1: hit interpretation — what the row means + what to check next
  hitInterpret: (hit: N4Hit, rag = true) =>
    post<HitInterpretation>("/hit/interpret", { hit, rag }),
  entities: (params: { query?: string; needles?: string }) =>
    post<EntitiesResponse>("/entities", params),
  timelineLanes: (params?: {
    query?: string;
    needles?: string;
    family?: string;
    start?: string;
    end?: string;
    bucket?: string;
  }) => post<TimelineLanesResponse>("/timeline/lanes", params || {}),
  timelineRebuild: () =>
    post<{ events: number; status: string }>("/timeline/rebuild", {}),
  playbookNeedles: (families?: string) =>
    request<PlaybookNeedlesResponse>(`/playbook/needles${families ? `?families=${families}` : ""}`),
  needleFeedback: (params: {
    needles: string[];
    family?: string;
    source?: string;
    verdict: "accept" | "reject" | "promote";
  }) =>
    post<{ ok: boolean; verdict: string; promoted?: Record<string, unknown>; error?: string }>(
      "/needles/feedback",
      params,
    ),
};
