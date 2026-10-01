/**
 * Timeline lanes + events, migrated to the kit (WO-U8a).
 *
 * The gain beyond the port: **every lane is on one scale**. The old page drew
 * each family's bars from its own first bucket, so a mark at 03:00 sat at a
 * different pixel in a lane that started at 09:00 the previous day, and a
 * brush meant different instants per lane. Lanes that cannot be read across
 * are decoration, not a timeline. The stack is now U6's `TimeLanes` over a
 * range spanning every bucket in every lane, so a mark at one instant lines up
 * vertically and one brush means one instant range for the whole stack.
 *
 * A consequence worth naming: U6's model is one tone per lane, so the old
 * per-bucket severity colouring is gone from the bars. Peak severity is carried
 * on the lane's tone and its label, and per-event severity still shows in the
 * event list below - the bars never encoded which event was which anyway.
 *
 * The brush is now a real instant range instead of two indices into a
 * per-lane hour array, which is what let the two disagree.
 *
 * Kit: PageHeader + Panel + EmptyState + Button + Field/Input + Badge.
 * Styles in a CSS module; zero inline style objects. The A10 queryable events
 * grid is unchanged as the second tab.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  api,
  type HitInterpretation,
  type N4Hit,
  type TimelineLaneEntry,
} from "../api/client";
import { pickHitColumns } from "../lib/hitColumns";
import VirtualTable, { type Column } from "../components/VirtualTable";
import TimelineEventsGrid from "../components/TimelineEventsGrid";
import { useCase } from "../context/CaseContext";
import {
  Badge,
  Button,
  EmptyState,
  Field,
  Input,
  PageHeader,
  Panel,
  TimeLanes,
  parseUtc,
  type HistogramBucket,
  type LaneSeries,
  type TimeRange,
} from "@/ui";
import styles from "./Timeline.module.css";

const SEVERITIES = ["", "medium", "high", "critical"] as const;

/** Rank 0 is the most severe, so a severity floor is a ">" comparison. */
const SEV_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

/** The lane's peak severity, which is what the bars are coloured by. */
function peakSeverity(lane: TimelineLaneEntry): string {
  let best = "";
  for (const severity of Object.values(lane.buckets_sev || {})) {
    const value = String(severity || "").toLowerCase();
    if (value && !["low", "informational"].includes(value)) {
      if (!best || (SEV_RANK[value] ?? 9) < (SEV_RANK[best] ?? 9)) best = value;
    }
  }
  return best;
}

export default function Timeline() {
  const { activeCase } = useCase();
  const navigate = useNavigate();

  const [lanes, setLanes] = useState<TimelineLaneEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [defaultedNeedles, setDefaultedNeedles] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [rebuilding, setRebuilding] = useState(false);
  const [tab, setTab] = useState<"lanes" | "events">("lanes");

  // The brush is an instant range - the same thing for every lane.
  const [brush, setBrush] = useState<TimeRange | null>(null);
  const [selectedLane, setSelectedLane] = useState<string | null>(null);

  const [events, setEvents] = useState<N4Hit[]>([]);
  const [eventCount, setEventCount] = useState(0);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventError, setEventError] = useState("");
  const [filterText, setFilterText] = useState("");
  const [minSev, setMinSev] = useState("");

  const [selected, setSelected] = useState<N4Hit | null>(null);
  const [interp, setInterp] = useState<HitInterpretation | null>(null);
  const [interpLoading, setInterpLoading] = useState(false);

  const caseKey = activeCase || "";
  const laneFrameRef = useRef<HTMLDivElement | null>(null);
  const [laneWidth, setLaneWidth] = useState(960);

  const loadLanes = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await api.timelineLanes({});
      setLanes(response.families || []);
      setTotal(response.total);
      setDefaultedNeedles(response.default_needles || 0);
    } catch (exc) {
      setError((exc as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadLanes();
  }, [activeCase, loadLanes]);

  // The lane stack needs a real width; jsdom has no layout engine, so the
  // default stands until a ResizeObserver reports otherwise.
  useEffect(() => {
    const node = laneFrameRef.current;
    if (!node || typeof ResizeObserver === "undefined") return undefined;
    const observer = new ResizeObserver((entries) => {
      const next = Math.round(entries[0]?.contentRect?.width ?? 0);
      if (next > 0) setLaneWidth(next);
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  // Restore the view per case. Instants, not hour indices.
  useEffect(() => {
    if (!caseKey) return;
    try {
      const saved = JSON.parse(localStorage.getItem(`tl:${caseKey}`) || "{}");
      if (saved.lane) setSelectedLane(saved.lane);
      if (saved.filter) setFilterText(saved.filter);
      if (saved.minSev) setMinSev(saved.minSev);
      const start = parseUtc(saved.startIso);
      const end = parseUtc(saved.endIso);
      if (start && end) setBrush({ start, end });
    } catch {
      /* a corrupt saved view must not break the page */
    }
  }, [caseKey]);

  useEffect(() => {
    if (!caseKey) return;
    localStorage.setItem(
      `tl:${caseKey}`,
      JSON.stringify({
        lane: selectedLane,
        startIso: brush?.start.toISOString() ?? "",
        endIso: brush?.end.toISOString() ?? "",
        filter: filterText,
        minSev,
      }),
    );
  }, [caseKey, selectedLane, brush, filterText, minSev]);

  /**
   * The shared scale: the span that covers every bucket in every lane. This is
   * the whole point - one range, so marks line up and a brush means one span.
   */
  const series = useMemo<LaneSeries[]>(
    () =>
      lanes.map((lane) => {
        const buckets: HistogramBucket[] = Object.entries(lane.buckets || {})
          .map(([hour, count]) => {
            const at = parseUtc(hour);
            return at ? { t: at.getTime(), count } : null;
          })
          .filter((bucket): bucket is HistogramBucket => bucket !== null)
          .sort((a, b) => a.t - b.t);
        const severity = peakSeverity(lane);
        return {
          id: lane.family,
          label: severity ? `${lane.family} (max ${severity})` : lane.family,
          buckets,
          tone: severity,
        };
      }),
    [lanes],
  );

  const sharedRange = useMemo<TimeRange | null>(() => {
    const times = series.flatMap((lane) => lane.buckets.map((bucket) => bucket.t));
    if (times.length === 0) return null;
    return {
      start: new Date(Math.min(...times)),
      end: new Date(Math.max(...times) + 3600_000),
    };
  }, [series]);

  const totalEvents = useMemo(
    () => series.reduce((sum, lane) => sum + lane.buckets.reduce((s, b) => s + b.count, 0), 0),
    [series],
  );

  // Reload the event list when the lane or the brushed range changes.
  useEffect(() => {
    if (!selectedLane && !brush) {
      setEvents([]);
      setEventCount(0);
      return;
    }
    setEventsLoading(true);
    setEventError("");
    api.search({
      family: selectedLane || undefined,
      start: brush?.start.toISOString(),
      end: brush?.end.toISOString(),
      limit: 200,
      offset: 0,
      default_needles: true,
    })
      .then((response) => {
        setEvents(response.hits);
        setEventCount(response.count);
      })
      .catch((exc) => setEventError((exc as Error).message))
      .finally(() => setEventsLoading(false));
  }, [selectedLane, brush?.start.toISOString(), brush?.end.toISOString(), activeCase]);

  const openEvent = useCallback(async (hit: N4Hit) => {
    setSelected(hit);
    setInterp(null);
    setInterpLoading(true);
    try {
      setInterp(await api.hitInterpret(hit));
    } catch {
      setInterp(null);
    } finally {
      setInterpLoading(false);
    }
  }, []);

  const sendToExplore = () => {
    const params = new URLSearchParams();
    if (brush) {
      params.set("start", brush.start.toISOString());
      params.set("end", brush.end.toISOString());
    }
    if (selectedLane) params.set("family", selectedLane);
    navigate(`/case/${encodeURIComponent(caseKey)}/explore?${params.toString()}`);
  };

  const typeColumns = useMemo(() => pickHitColumns(events), [events]);

  const eventColumns = useMemo<Column<N4Hit>[]>(
    () => [
      {
        key: "sev",
        header: "",
        width: 26,
        render: (hit) => {
          const severity = String(
            hit.fields?.Severity ?? hit.fields?.severity ?? "",
          ).toLowerCase();
          if (!severity) return null;
          return (
            <span
              title={`severity ${severity}`}
              className={styles.sevDot}
              data-sev={severity}
            />
          );
        },
      },
      {
        key: "time",
        header: "Time",
        width: 150,
        render: (hit) => {
          const raw =
            hit.fields?.Timestamp ||
            hit.fields?.TimeCreated ||
            hit.fields?.timestamp ||
            "";
          const match = /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?)/.exec(
            raw || hit.text || "",
          );
          return (
            <span className={styles.cellMono}>
              {match ? match[1] : "—"}
            </span>
          );
        },
      },
      {
        key: "family",
        header: "Family",
        width: 90,
        render: (hit) => (
          <span className={styles.cellMono}>{hit.family}</span>
        ),
      },
      {
        key: "host",
        header: "Host",
        width: 130,
        render: (hit) => (
          <span className={styles.cellMono}>{hit.host || "—"}</span>
        ),
      },
      ...typeColumns.map((fieldName) => ({
        key: `field-${fieldName}`,
        header: fieldName,
        width: fieldName.toLowerCase().includes("message") ? undefined : 150,
        render: (hit: N4Hit) => (
          <span className={styles.cellTruncate}>
            {hit.fields?.[fieldName] ?? ""}
          </span>
        ),
      })),
      {
        key: "source",
        header: "Source",
        width: 150,
        render: (hit) => (
          <span className={styles.cellSource}>
            {hit.file}:{hit.line}
          </span>
        ),
      },
    ],
    [typeColumns],
  );

  const visibleEvents = useMemo(() => {
    const floor = SEV_RANK[minSev] ?? -1;
    const needle = filterText.trim().toLowerCase();
    return events.filter((hit) => {
      if (minSev) {
        const severity = String(
          hit.fields?.Severity ?? hit.fields?.severity ?? "",
        ).toLowerCase();
        // An unlabelled row is not a low-severity row: showing it under a
        // severity floor would assert something the evidence does not say.
        if (!severity || (SEV_RANK[severity] ?? 9) > floor) return false;
      }
      if (!needle) return true;
      const blob =
        `${hit.family} ${hit.host || ""} ${hit.terms || ""} ${hit.text || ""} ` +
        Object.values(hit.fields || {}).join(" ")
      return blob.toLowerCase().includes(needle);
    });
  }, [events, filterText, minSev]);

  const rebuildTimeline = async () => {
    setRebuilding(true);
    try {
      await api.timelineRebuild();
      await loadLanes();
    } catch (exc) {
      setError((exc as Error).message);
    } finally {
      setRebuilding(false);
    }
  };

  return (
    <div className={styles.page}>
      <PageHeader
        title="Timeline"
        subtitle={
          loading
            ? "Loading…"
            : `${totalEvents.toLocaleString()} bucketed events across ${total.toLocaleString()} hits`
        }
        stageCode="N7"
        actions={
          <div className={styles.eventBar}>
            <Button size="sm" onClick={rebuildTimeline} disabled={rebuilding}>
              {rebuilding ? "Rebuilding…" : "Rebuild timeline.json"}
            </Button>
          </div>
        }
      />

      <nav className={styles.tabs} role="tablist" aria-label="Timeline view">
        <button
          type="button"
          role="tab"
          aria-selected={tab === "lanes"}
          data-testid="timeline-tab-lanes"
          className={tab === "lanes" ? `${styles.tab} ${styles.tabActive}` : styles.tab}
          onClick={() => setTab("lanes")}
        >
          Lanes
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === "events"}
          data-testid="timeline-tab-events"
          className={tab === "events" ? `${styles.tab} ${styles.tabActive}` : styles.tab}
          onClick={() => setTab("events")}
        >
          Events
        </button>
      </nav>

      {error ? (
        <div role="alert" className="error-banner">
          {error}
        </div>
      ) : null}

      {tab === "events" ? (
        <TimelineEventsGrid caseId={caseKey} />
      ) : (
        <>
          {defaultedNeedles > 0 ? (
            <p className={styles.note}>
              Showing rows matched by the case&apos;s needle vocabulary (
              {defaultedNeedles} needles — full-run scan or playbook terms for this
              case&apos;s families). Use Explore for arbitrary queries.
            </p>
          ) : null}

          {brush ? (
            <div className={styles.brushBar} data-testid="timeline-brush">
              <span>
                Brushed {brush.start.toISOString()} → {brush.end.toISOString()}
              </span>
              <Button size="sm" onClick={() => setBrush(null)}>
                Clear
              </Button>
              <Button variant="primary" size="sm" onClick={sendToExplore}>
                Search in Explore →
              </Button>
            </div>
          ) : null}

          {sharedRange ? (
            <>
              <div ref={laneFrameRef} className={styles.laneFrame}>
                <TimeLanes
                  lanes={series}
                  range={sharedRange}
                  width={laneWidth}
                  selectedLaneId={selectedLane}
                  onSelectLane={(id) =>
                    setSelectedLane((current) => (current === id ? null : id))
                  }
                  onRangeChange={setBrush}
                  ariaLabel="Timeline lanes on one shared UTC scale"
                />
              </div>
              <p className={styles.laneCaption} data-testid="timeline-lane-caption">
                Every lane is drawn against the same UTC range
                ({sharedRange.start.toISOString()} → {sharedRange.end.toISOString()}),
                so a mark at one instant lines up across the stack and a brush
                means the same span everywhere.
              </p>
            </>
          ) : (
            <EmptyState
              title="No timeline data"
              hint="Run the N2 processing lane and query evidence to populate the timeline lanes."
            />
          )}

          <Panel
            title={`Events${
              selectedLane ? ` — ${selectedLane}` : ""
            }${brush ? " — brushed range" : ""} (${eventCount.toLocaleString()})`}
            actions={
              <div className={styles.eventBar}>
                <div className={styles.sevPicker}>
                  {SEVERITIES.map((severity) => (
                    <button
                      key={severity || "all"}
                      type="button"
                      data-testid={`timeline-sev-${severity || "all"}`}
                      className={
                        minSev === severity
                          ? `${styles.sevButton} ${styles.sevActive}`
                          : styles.sevButton
                      }
                      data-sev={severity || "all"}
                      onClick={() => setMinSev(severity)}
                      title={severity ? `Show ${severity}+ severity only` : "Show all severities"}
                    >
                      {severity ? `${severity}+` : "all"}
                    </button>
                  ))}
                </div>
                <Field label="Filter events">
                  {({ id }) => (
                    <Input
                      id={id}
                      value={filterText}
                      onChange={(event) => setFilterText(event.target.value)}
                      placeholder="text contains…"
                    />
                  )}
                </Field>
              </div>
            }
          >
            {eventsLoading ? (
              <div className="loading">Loading events…</div>
            ) : eventError ? (
              <div role="alert" className="error-banner">
                {eventError}
              </div>
            ) : visibleEvents.length === 0 ? (
              <EmptyState
                title="No events in this view"
                hint="Choose a lane, or brush a range across the lanes above."
              />
            ) : (
              <>
                {filterText || minSev ? (
                  <p className={styles.note}>
                    {visibleEvents.length.toLocaleString()} shown of{" "}
                    {eventCount.toLocaleString()}
                  </p>
                ) : null}
                <VirtualTable
                  rows={visibleEvents}
                  columns={eventColumns}
                  rowKey={(hit, index) => `${hit.family}:${hit.file}:${hit.line}:${index}`}
                  maxHeight="45vh"
                  onRowClick={openEvent}
                />
                {selected ? (
                  <div className={styles.interp} data-testid="timeline-interpretation">
                    <Badge>{selected.family}</Badge>{" "}
                    <code>{selected.file}:{selected.line}</code>
                    {interpLoading ? (
                      <p>Interpreting…</p>
                    ) : interp ? (
                      <>
                        {interp.meaning ? <p>{interp.meaning}</p> : null}
                        {interp.look_for?.length ? (
                          <div className={styles.interpSection}>
                            <strong>Look for</strong>
                            <ul className={styles.interpList}>
                              {interp.look_for.slice(0, 6).map((item, index) => (
                                <li key={index}>{item}</li>
                              ))}
                            </ul>
                          </div>
                        ) : null}
                        {interp.corroborate?.length ? (
                          <div className={styles.interpSection}>
                            <strong>Corroborate</strong>
                            <ul className={styles.interpList}>
                              {interp.corroborate.slice(0, 5).map((item, index) => (
                                <li key={index}>{item}</li>
                              ))}
                            </ul>
                          </div>
                        ) : null}
                      </>
                    ) : (
                      <p>
                        No interpretation for this row. Interpretation is advisory —
                        it is never examiner-approved.
                      </p>
                    )}
                  </div>
                ) : null}
              </>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
