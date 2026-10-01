/**
 * The queryable timeline grid (WO-A10).
 *
 * A tab on the Timeline page: the U5 DataGrid in server mode over the events
 * index, with the U6 TimeAxis as its scrub bar. Three properties the component
 * exists to hold:
 *
 * 1. **Windowed, not paged-by-page.** The grid fetches a page at a time and
 *    renders only the visible window (the DataGrid's virtualiser). A 100k-event
 *    case does not put 100k rows in the DOM, and it does not ask the examiner
 *    to click "next" 500 times.
 * 2. **The count is honest.** A total the server reported as a floor renders
 *    as "at least N", never as N.
 * 3. **A down backend is a state, not an empty grid.** An empty table beside
 *    a case with hours of activity reads as "nothing happened". The endpoint's
 *    503 is surfaced with its reason.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { api } from "../api/client";
import {
  formatEventTs,
  type TimelineEvent,
} from "../api/timeline";
import { DataGrid, type DataGridColumn } from "../ui/DataGrid";
import type { GridFetchRequest, GridPage } from "../ui/DataGrid/types";
import { TimeAxis, type HistogramBucket, type TimeRange } from "../ui/TimeAxis";

const PAGE_SIZE = 200;

const COLUMNS: DataGridColumn<TimelineEvent>[] = [
  {
    id: "ts",
    header: "Time (UTC)",
    accessorFn: (row) => formatEventTs(row.ts),
    filterable: true,
    pinnable: true,
    width: 210,
  },
  { id: "ts_desc", header: "Timestamp", accessorFn: (row) => row.ts_desc ?? "", filterable: true, width: 170 },
  { id: "family", header: "Family", accessorFn: (row) => row.family ?? "", filterable: true, width: 110 },
  { id: "user", header: "User", accessorFn: (row) => row.user || "-", filterable: true, width: 140 },
  { id: "host", header: "Host", accessorFn: (row) => row.host || "-", filterable: true, width: 150 },
  { id: "artifact", header: "Artifact", accessorFn: (row) => row.artifact ?? "", width: 170 },
  {
    id: "source",
    header: "Source",
    accessorFn: (row) => `${row.source_file ?? ""}:${row.source_line ?? ""}`,
    width: 220,
  },
  {
    id: "ts_src",
    header: "Source of time",
    // A heuristic column and a registry-typed one are different kinds of
    // evidence; the grid says which, rather than showing both as a timestamp.
    accessorFn: (row) => (row.ts_src === "column-heuristic" ? "heuristic" : row.ts_src ?? ""),
    filterable: true,
    width: 120,
  },
  { id: "audit_id", header: "Audit", accessorFn: (row) => row.audit_id ?? "", width: 140 },
  {
    id: "findings",
    header: "Findings",
    accessorFn: (row) => (row.finding_ids ?? []).join(", "),
    width: 140,
  },
];

interface Props {
  caseId: string;
  /** Forwarded to the grid's virtualiser. jsdom has no layout engine, so the
   *  tests pass one; in the browser the virtualiser measures the scroller. */
  initialViewport?: { width: number; height: number };
}

export default function TimelineEventsGrid({ caseId, initialViewport }: Props) {
  const [range, setRange] = useState<TimeRange | null>(null);
  const [buckets, setBuckets] = useState<HistogramBucket[]>([]);
  const [axisError, setAxisError] = useState("");
  const [backendError, setBackendError] = useState("");
  const [count, setCount] = useState<{ total: number | null; exact: boolean }>({
    total: null,
    exact: true,
  });
  const [selected, setSelected] = useState<TimelineEvent | null>(null);
  const [contextRows, setContextRows] = useState<TimelineEvent[] | null>(null);
  const [contextSeconds, setContextSeconds] = useState(300);
  const [contextBusy, setContextBusy] = useState(false);
  const [width, setWidth] = useState(880);
  const frameRef = useRef<HTMLDivElement | null>(null);

  // measure the axis once, then on resize - jsdom has no layout engine, so the
  // tests set an explicit width through the same prop path
  useEffect(() => {
    const node = frameRef.current;
    if (!node || typeof ResizeObserver === "undefined") return undefined;
    const observer = new ResizeObserver((entries) => {
      const next = Math.round(entries[0]?.contentRect?.width ?? 0);
      if (next > 0) setWidth(next);
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  const filters = useMemo(() => {
    if (!range) return {};
    return {
      ts: {
        gte: range.start.toISOString(),
        lte: range.end.toISOString(),
      },
    };
  }, [range]);

  // the axis: one fetch per range change, not per scroll
  useEffect(() => {
    let cancelled = false;
    if (!caseId) return undefined;
    api.timeline
      .histogram(caseId, {
        start: range?.start.toISOString(),
        end: range?.end.toISOString(),
        buckets: 400,
      })
      .then((response) => {
        if (cancelled) return;
        setAxisError("");
        const parsed = (response.buckets ?? [])
          .map((bucket) => ({
            t: typeof bucket.ts === "number" ? bucket.ts : Date.parse(String(bucket.ts)),
            count: bucket.count,
          }))
          .filter((bucket) => !Number.isNaN(bucket.t));
        setBuckets(parsed);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        // An unreachable backend must not read as "no activity in this window".
        setAxisError(String((error as Error)?.message ?? error));
      });
    return () => {
      cancelled = true;
    };
  }, [caseId, range?.start.toISOString, range?.end.toISOString]);

  const fetchPage = useCallback(
    async (request: GridFetchRequest): Promise<GridPage<TimelineEvent>> => {
      try {
        const response = await api.timeline.events({
          caseId,
          cursor: request.cursor,
          size: PAGE_SIZE,
          // the window wins over the text filters: an examiner who brushed a
          // range then typed a family means both
          filters: { ...filters, ...request.query.filters },
          sortBy: request.query.sort?.by ?? "ts",
          sortDir: request.query.sort?.dir ?? "asc",
        });
        setBackendError("");
        setCount({ total: response.total ?? null, exact: response.exact });
        return {
          rows: response.rows ?? [],
          nextCursor: response.next_cursor ?? null,
          total: response.total ?? null,
        };
      } catch (error) {
        setBackendError(String((error as Error)?.message ?? error));
        // not an empty page: the grid's empty message would claim no activity
        throw error;
      }
    },
    [caseId, filters],
  );

  const openContext = useCallback(
    async (event: TimelineEvent, seconds: number) => {
      setSelected(event);
      setContextBusy(true);
      try {
        const response = await api.timeline.context(caseId, event.event_id, seconds);
        setContextRows(response.rows ?? []);
        setContextSeconds(response.seconds ?? seconds);
      } catch (error) {
        setContextRows([]);
        setBackendError(String((error as Error)?.message ?? error));
      } finally {
        setContextBusy(false);
      }
    },
    [caseId],
  );

  if (!caseId) {
    return (
      <p data-testid="timeline-events-no-case">
        Open a case to read its timeline.
      </p>
    );
  }

  return (
    <section data-testid="timeline-events" aria-label="Timeline events">
      <header className="tl-head">
        <h2>Events</h2>
        <p data-testid="timeline-count">
          {count.total === null
            ? "count unknown"
            : count.exact
              ? `${count.total} event${count.total === 1 ? "" : "s"}`
              : `at least ${count.total} events`}
        </p>
        <a
          data-testid="timeline-export"
          href={api.timeline.exportUrl(caseId, filters)}
          className="btn btn-sm"
        >
          Export CSV
        </a>
      </header>

      {backendError ? (
        <p role="alert" data-testid="timeline-backend-error" className="tl-error">
          The timeline is not available: {backendError}. This is a backend
          problem, not an absence of activity.
        </p>
      ) : null}
      {axisError && !backendError ? (
        <p data-testid="timeline-axis-error" className="tl-warn">
          The activity histogram is unavailable ({axisError}); the event list
          below is still queryable.
        </p>
      ) : null}

      <div ref={frameRef} className="tl-axis">
        <TimeAxis
          width={width}
          height={72}
          histogram={buckets}
          range={
            range ?? {
              start: new Date(Date.now() - 24 * 3600 * 1000),
              end: new Date(),
            }
          }
          onRangeChange={setRange}
          ariaLabel="Timeline activity"
        />
      </div>

      {range ? (
        <p data-testid="timeline-window" className="tl-window">
          {range.start.toISOString()} → {range.end.toISOString()}
          <button
            type="button"
            className="btn btn-sm"
            data-testid="timeline-clear-window"
            onClick={() => setRange(null)}
          >
            Clear window
          </button>
        </p>
      ) : null}

      <DataGrid<TimelineEvent>
        mode="server"
        fetchPage={fetchPage}
        columns={COLUMNS}
        getRowId={(row) => row.event_id}
        viewId="timeline-events"
        height={460}
        initialViewport={initialViewport}
        ariaLabel="Timeline events"
        emptyMessage={
          backendError
            ? "Timeline unavailable - see the message above."
            : "No events in this window."
        }
        onOpenRow={(row) => openContext(row, contextSeconds)}
      />

      {selected ? (
        <aside data-testid="timeline-context" className="tl-context">
          <h3>
            ±{contextSeconds}s around {formatEventTs(selected.ts)}{" "}
            <small>({selected.ts_desc ?? selected.event_id})</small>
          </h3>
          <label>
            Window
            <select
              data-testid="timeline-context-window"
              value={contextSeconds}
              onChange={(event) => openContext(selected, Number(event.target.value))}
            >
              {[30, 60, 300, 900, 3600].map((seconds) => (
                <option key={seconds} value={seconds}>
                  ±{seconds}s
                </option>
              ))}
            </select>
          </label>
          {contextBusy ? (
            <p data-testid="timeline-context-loading">Loading context…</p>
          ) : (
            <table className="tl-context-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Family</th>
                  <th>User</th>
                  <th>Artifact</th>
                </tr>
              </thead>
              <tbody>
                {(contextRows ?? []).map((row) => (
                  <tr key={row.event_id}>
                    <td>{formatEventTs(row.ts)}</td>
                    <td>{row.family}</td>
                    <td>{row.user || "-"}</td>
                    <td>{row.artifact}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </aside>
      ) : null}
    </section>
  );
}
