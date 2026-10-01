/**
 * Explore (N4), migrated to the kit (WO-U8a).
 *
 * The result list is a table and the hit explanation is a Drawer. A cell
 * click opens the row. It does not rotate the needle — that only happens
 * from a suggestion chip or the drawer's search control.
 */
import { useState, useEffect, useCallback, useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type N4Hit, type HistogramResponse, type PlaybookSuggestion, type HitInterpretation } from "../api/client";
import { useCase } from "../context/CaseContext";
import { allHitColumns } from "../lib/hitColumns";
import Histogram from "../components/Histogram";
import {
  Badge,
  Button,
  Drawer,
  EmptyState,
  Input,
  PageHeader,
  Panel,
} from "@/ui";
import styles from "./Explore.module.css";

const PAGE_SIZE = 200;

const normalizeInterp = (r: HitInterpretation): HitInterpretation => ({
  meaning: r?.meaning || "",
  learn: r?.learn
    ? {
        headline: r.learn.headline || "",
        why_matters: r.learn.why_matters || [],
        technique: r.learn.technique || [],
        watch_out: r.learn.watch_out || [],
        sources: r.learn.sources || [],
      }
    : undefined,
  skills: (r?.skills || []).map((s) => ({
    ...s,
    mitre: s.mitre || [],
    matched_steps: s.matched_steps || [],
  })),
  techniques: r?.techniques || [],
  look_for: r?.look_for || [],
  corroborate: r?.corroborate || [],
  next_queries: r?.next_queries || [],
  pivots: r?.pivots || [],
  negative: r?.negative || [],
  caveats: r?.caveats || [],
  confidence_rules: r?.confidence_rules || {},
  det: r?.det,
  methodology: r?.methodology,
  sources: r?.sources || [],
  error: r?.error,
});

const hasInterpContent = (i: HitInterpretation): boolean =>
  !!(
    i.meaning ||
    i.skills.length ||
    i.look_for.length ||
    i.next_queries.length ||
    i.corroborate.length ||
    i.pivots.length ||
    i.negative.length ||
    i.caveats.length ||
    i.methodology ||
    (i.learn && i.learn.why_matters.length)
  );

interface SearchOverrides {
  needles?: string;
  family?: string;
  host?: string;
  start?: string;
  end?: string;
}

const sourceLabel = (s?: string) =>
  s === "mitre" ? "ATT&CK" : s === "sigma" ? "Sigma" : s === "overlay" ? "yours" : "playbook";

function queryString(values: {
  needles: string;
  family: string;
  host: string;
  start: string;
  end: string;
}): string {
  const next = new URLSearchParams();
  if (values.needles) next.set("needles", values.needles);
  if (values.family) next.set("family", values.family);
  if (values.host) next.set("host", values.host);
  if (values.start) next.set("start", values.start);
  if (values.end) next.set("end", values.end);
  return next.toString();
}

export default function Explore() {
  const { activeCase } = useCase();
  const [searchParams, setSearchParams] = useSearchParams();
  const [needles, setNeedles] = useState("");
  const [family, setFamily] = useState("");
  const [hostFilter, setHostFilter] = useState("");
  const [hits, setHits] = useState<N4Hit[]>([]);
  const [count, setCount] = useState(0);
  const [countLowerBound, setCountLowerBound] = useState(false);
  const [countExact, setCountExact] = useState(false);
  const [capReasons, setCapReasons] = useState<string[]>([]);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [familyAgg, setFamilyAgg] = useState<Record<string, number>>({});
  const [hostAgg, setHostAgg] = useState<Record<string, number>>({});
  const [bookmarked, setBookmarked] = useState<Set<string>>(new Set());
  const [bookmarkIds, setBookmarkIds] = useState<Map<string, string>>(new Map());
  const [bookmarking, setBookmarking] = useState(false);
  const [bookmarkNote, setBookmarkNote] = useState("");
  const [histogram, setHistogram] = useState<Record<string, number>>({});
  const [showHistogram, setShowHistogram] = useState(true);
  const [playbookSuggestions, setPlaybookSuggestions] = useState<PlaybookSuggestion[]>([]);
  const [showPlaybookHelp, setShowPlaybookHelp] = useState(false);
  const [feedbackMsg, setFeedbackMsg] = useState("");
  const [timeRange, setTimeRange] = useState<{ start: string; end: string }>({ start: "", end: "" });
  const [visibleFields, setVisibleFields] = useState<string[]>([]);
  const [showColPicker, setShowColPicker] = useState(false);
  const [selected, setSelected] = useState<N4Hit | null>(null);
  const [interp, setInterp] = useState<HitInterpretation | null>(null);
  const [interpLoading, setInterpLoading] = useState(false);
  const [interpReady, setInterpReady] = useState(false);
  const reqIdRef = useRef(0);
  const skipUrlEffect = useRef(false);

  useEffect(() => {
    setHits([]);
    setCount(0);
    setSelected(null);
    setInterp(null);
    setInterpReady(false);
    api.aggregate({ group_by: "family" })
      .then((r) => setFamilyAgg(r.buckets || {}))
      .catch((e) => setError(`Facet load failed: ${(e as Error).message}`));
    api.aggregate({ group_by: "host" })
      .then((r) => setHostAgg(r.buckets || {}))
      .catch(() => setHostAgg({}));
    api.workbench()
      .then((r) => {
        const ids = new Set<string>();
        const idMap = new Map<string, string>();
        for (const b of r.bookmarks) {
          const k = `${b.family}:${b.file}:${b.line}`;
          ids.add(k);
          idMap.set(k, b.id);
        }
        setBookmarked(ids);
        setBookmarkIds(idMap);
      })
      .catch((e) => setError(`Bookmark state load failed: ${(e as Error).message}`));
  }, [activeCase]);

  useEffect(() => {
    const fams = Object.keys(familyAgg).join(",");
    api.playbookNeedles(fams || undefined)
      .then((r) => setPlaybookSuggestions(r.suggestions || []))
      .catch((e) => setError(`Needle suggestions load failed: ${(e as Error).message}`));
  }, [familyAgg]);

  const needleFeedback = async (
    pb: PlaybookSuggestion,
    verdict: "accept" | "reject" | "promote",
  ) => {
    try {
      const fam = Object.keys(familyAgg)[0] || "";
      await api.needleFeedback({
        needles: pb.needles,
        family: fam,
        source: pb.source || "playbook",
        verdict,
      });
      setFeedbackMsg(`${verdict === "promote" ? "★ promoted" : verdict}: ${pb.playbook}`);
      if (verdict === "promote") {
        const r = await api.playbookNeedles(Object.keys(familyAgg).join(",") || undefined);
        setPlaybookSuggestions(r.suggestions || []);
      }
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const doSearch = useCallback(async (
    targetOffset: number,
    overrides: SearchOverrides = {},
    fromUrl = false,
  ) => {
    const reqId = ++reqIdRef.current;
    setLoading(true);
    setHits([]);
    setError("");
    const needleValue = overrides.needles !== undefined ? overrides.needles : needles;
    const famValue = overrides.family !== undefined ? overrides.family : family;
    const hostValue = overrides.host !== undefined ? overrides.host : hostFilter;
    const startValue = overrides.start !== undefined ? overrides.start : timeRange.start;
    const endValue = overrides.end !== undefined ? overrides.end : timeRange.end;
    if (!fromUrl) {
      const next = queryString({
        needles: needleValue,
        family: famValue,
        host: hostValue,
        start: startValue,
        end: endValue,
      });
      if (next !== searchParams.toString()) {
        skipUrlEffect.current = true;
        setSearchParams(new URLSearchParams(next), { replace: true });
      }
    }
    try {
      const [searchResult, histResult] = await Promise.all([
        api.search({
          needles: needleValue || undefined,
          family: famValue || undefined,
          host: hostValue || undefined,
          start: startValue || undefined,
          end: endValue || undefined,
          limit: PAGE_SIZE,
          offset: targetOffset,
        }),
        api.histogram({
          needles: needleValue || undefined,
          family: famValue || undefined,
          start: startValue || undefined,
          end: endValue || undefined,
        }).catch(() => ({ buckets: {}, count: 0 }) as HistogramResponse),
      ]);
      if (reqIdRef.current !== reqId) return;
      setHits(searchResult.hits);
      setCount(searchResult.count);
      setCountLowerBound(Boolean(searchResult.count_lower_bound));
      setCountExact(Boolean(searchResult.count_exact));
      setCapReasons(searchResult.capped_reasons || []);
      setOffset(targetOffset);
      setHistogram(histResult.buckets || {});
      const all = allHitColumns(searchResult.hits);
      setVisibleFields((prev) => {
        const stillValid = prev.filter((f) => all.includes(f));
        return stillValid.length > 0 ? stillValid : all.slice(0, 6);
      });
    } catch (e) {
      if (reqIdRef.current !== reqId) return;
      setError((e as Error).message);
      setHits([]);
      setHistogram({});
    } finally {
      if (reqIdRef.current === reqId) setLoading(false);
    }
  }, [needles, family, hostFilter, timeRange, activeCase, searchParams, setSearchParams]);

  useEffect(() => {
    if (skipUrlEffect.current) {
      skipUrlEffect.current = false;
      return;
    }
    const start = searchParams.get("start");
    const end = searchParams.get("end");
    const fam = searchParams.get("family");
    const host = searchParams.get("host");
    const n = searchParams.get("needles");
    if (start === null && end === null && fam === null && host === null && n === null) return;
    setFamily(fam || "");
    setHostFilter(host || "");
    setNeedles(n || "");
    setTimeRange({ start: start || "", end: end || "" });
    setSelected(null);
    doSearch(0, {
      needles: n || "",
      family: fam || "",
      host: host || "",
      start: start || "",
      end: end || "",
    }, true);
    // doSearch identity changes when the box changes; this effect is the URL.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams, activeCase]);

  const search = (resetOffset = true) => {
    doSearch(resetOffset ? 0 : offset);
  };

  const toggleFamilyChip = (fam: string) => {
    const newFam = family === fam ? "" : fam;
    setFamily(newFam);
    doSearch(0, { family: newFam });
  };

  const toggleHostChip = (host: string) => {
    const newHost = hostFilter === host ? "" : host;
    setHostFilter(newHost);
    doSearch(0, { host: newHost });
  };

  const hitKey = (hit: N4Hit) => `${hit.family}:${hit.file}:${hit.line}`;

  const toggleBookmark = (hit: N4Hit) => {
    const key = hitKey(hit);
    const next = new Set(bookmarked);
    if (next.has(key)) {
      const bid = bookmarkIds.get(key);
      if (bid) {
        api.workbenchRemove(bid)
          .catch((e) => setError(`Bookmark remove failed: ${(e as Error).message}`));
      }
      next.delete(key);
      setBookmarkIds((m) => { const n = new Map(m); n.delete(key); return n; });
    } else {
      api.workbenchAdd(hit)
        .then((r) => {
          if (r.bookmark_id) {
            setBookmarkIds((m) => new Map(m).set(key, r.bookmark_id!));
          }
        })
        .catch((e) => setError(`Bookmark add failed: ${(e as Error).message}`));
      next.add(key);
    }
    setBookmarked(next);
  };

  const bookmarkAll = async () => {
    setBookmarking(true);
    setBookmarkNote("");
    try {
      const r = await api.workbenchAddMany({
        needles: needles || undefined,
        family: family || undefined,
        host: hostFilter || undefined,
        start: timeRange.start || undefined,
        end: timeRange.end || undefined,
      });
      setBookmarkNote(
        `Bookmarked ${r.added} hit${r.added === 1 ? "" : "s"}` +
          (r.skipped ? ` (${r.skipped} already saved)` : "") +
          (r.truncated ? ` — capped at 5000 of ${r.matched.toLocaleString()} matched` : "") +
          ` — workbench holds ${r.total}`,
      );
      const wb = await api.workbench();
      const ids = new Set<string>();
      const idMap = new Map<string, string>();
      for (const b of wb.bookmarks) {
        const k = `${b.family}:${b.file}:${b.line}`;
        ids.add(k);
        idMap.set(k, b.id);
      }
      setBookmarked(ids);
      setBookmarkIds(idMap);
    } catch (e) {
      setError(`Bookmark all failed: ${(e as Error).message}`);
    } finally {
      setBookmarking(false);
    }
  };

  const pages = Math.ceil(count / PAGE_SIZE);
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;
  const familyEntries = Object.entries(familyAgg).sort((a, b) => b[1] - a[1]);
  const hostEntries = Object.entries(hostAgg)
    .filter(([k]) => k && k !== "(unknown host)")
    .sort((a, b) => b[1] - a[1]);
  const allFields = allHitColumns(hits);

  const pivotOnValue = (value: string) => {
    const v = value.trim();
    if (!v) return;
    setNeedles(v);
    setSelected(null);
    doSearch(0, { needles: v });
  };

  useEffect(() => {
    if (!selected) {
      setInterp(null);
      setInterpLoading(false);
      setInterpReady(false);
      return;
    }
    let stale = false;
    setInterp(null);
    setInterpLoading(true);
    setInterpReady(false);
    api.hitInterpret(selected)
      .then((r) => { if (!stale) setInterp(normalizeInterp(r)); })
      .catch(() => { if (!stale) setInterp(null); })
      .finally(() => { if (!stale) { setInterpLoading(false); setInterpReady(true); } });
    return () => { stale = true; };
  }, [selected]);

  const moveField = (fieldName: string, delta: number) => {
    setVisibleFields((prev) => {
      const i = prev.indexOf(fieldName);
      const j = i + delta;
      if (i < 0 || j < 0 || j >= prev.length) return prev;
      const next = [...prev];
      [next[i], next[j]] = [next[j], next[i]];
      return next;
    });
  };

  const exportAll = () => {
    const p = new URLSearchParams();
    if (activeCase) p.set("case_id", activeCase);
    if (needles) p.set("needles", needles);
    if (family) p.set("family", family);
    if (hostFilter) p.set("host", hostFilter);
    if (timeRange.start) p.set("start", timeRange.start);
    if (timeRange.end) p.set("end", timeRange.end);
    p.set("format", "csv");
    window.open(`/portal/api/case/export?${p.toString()}`, "_blank");
  };

  const hitTitle = countLowerBound
    ? `Hits (≥${count.toLocaleString()}${count > PAGE_SIZE ? ` — page ${currentPage}/${pages}` : ""})`
    : `Hits (${count.toLocaleString()}${count > PAGE_SIZE ? ` — page ${currentPage}/${pages}` : ""})`;

  return (
    <div className={styles.page}>
      <PageHeader title="Explore" subtitle="Search the active case index" stageCode="N4" />
      {error ? <div role="alert" className="error-banner">{error}</div> : null}

      {(timeRange.start || timeRange.end) ? (
        <Panel
          title={`Time filter: ${timeRange.start || "…"} → ${timeRange.end || "…"}`}
          actions={(
            <Button
              size="sm"
              onClick={() => { setTimeRange({ start: "", end: "" }); doSearch(0, { start: "", end: "" }); }}
            >
              Clear time filter
            </Button>
          )}
        >
          <span className={styles.hint}>From the timeline brush or a briefing link.</span>
        </Panel>
      ) : null}

      <Panel>
        <div className={styles.searchRow}>
          <div className={styles.needleField}>
            <Input
              aria-label="Needles"
              placeholder="Needles (e.g. sdelete, powershell, 1102)"
              value={needles}
              onChange={(e) => setNeedles(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && search()}
            />
          </div>
          <div className={styles.familyField}>
            <Input
              aria-label="Family"
              placeholder="Family"
              value={family}
              onChange={(e) => setFamily(e.target.value)}
              list="family-list"
            />
          </div>
          <datalist id="family-list">
            {familyEntries.map(([key, cnt]) => (
              <option key={key} value={key}>{key} ({cnt})</option>
            ))}
          </datalist>
          <Button variant="primary" onClick={() => search()}>Search</Button>
        </div>

        <p className={styles.hint}>
          <strong>Needles</strong> are search terms — IOCs, technique names, file names, event IDs —
          that the N4 query engine searches for across parsed evidence.
          Clicking a briefing chip, field value, or suggested needle replaces this box —
          it always shows exactly what was last searched.
          {" "}
          <Button size="sm" variant="ghost" onClick={() => setShowPlaybookHelp(!showPlaybookHelp)}>
            {showPlaybookHelp ? "Hide suggestions" : `Show playbook suggestions (${playbookSuggestions.length})`}
          </Button>
        </p>

        {showPlaybookHelp && playbookSuggestions.length > 0 ? (
          <div className={styles.suggestions}>
            <div className={styles.kicker}>Suggested Needles — Playbooks · MITRE ATT&CK · Sigma · Yours</div>
            {feedbackMsg ? <div className={styles.feedback}>{feedbackMsg}</div> : null}
            {playbookSuggestions.slice(0, 8).map((pb) => (
              <div key={pb.slug} className={styles.playbook}>
                <div className={styles.playbookTitle}>
                  <span className={styles.source} data-source={pb.source || "playbook"}>
                    <Badge>{sourceLabel(pb.source)}</Badge>
                  </span>
                  {pb.playbook}
                </div>
                <div className={styles.chipRow}>
                  {[
                    ...(pb.strong_needles || []),
                    ...pb.needles.filter((n) => !(pb.strong_needles || []).includes(n)),
                  ].slice(0, 10).map((n) => (
                    <Button
                      key={n}
                      size="sm"
                      className={(pb.strong_needles || []).includes(n) ? styles.needleStrong : undefined}
                      title={(pb.strong_needles || []).includes(n) ? "high-signal" : undefined}
                      onClick={() => { setNeedles(n); doSearch(0, { needles: n }); }}
                    >
                      {n}
                    </Button>
                  ))}
                </div>
                <div className={styles.chipRow}>
                  <Button size="sm" onClick={() => needleFeedback(pb, "accept")} title="Mark this suggestion as useful">used</Button>
                  <Button size="sm" onClick={() => needleFeedback(pb, "reject")} title="Reject this suggestion">reject</Button>
                  <Button size="sm" onClick={() => needleFeedback(pb, "promote")} title="Promote to my local overlay (never the repo)">promote</Button>
                </div>
                {pb.caveats.length > 0 ? <div className={styles.caveat}>{pb.caveats[0]}</div> : null}
              </div>
            ))}
          </div>
        ) : null}

        {familyEntries.length > 0 ? (
          <div className={styles.chipRow}>
            <span className={styles.kicker}>Family</span>
            {familyEntries.slice(0, 20).map(([key, cnt]) => (
              <Button
                key={key}
                size="sm"
                className={family === key ? styles.chipOn : undefined}
                aria-pressed={family === key}
                onClick={() => toggleFamilyChip(key)}
              >
                {key} ({cnt})
              </Button>
            ))}
          </div>
        ) : null}

        {hostEntries.length > 0 ? (
          <div className={styles.chipRow}>
            <span className={styles.kicker}>Host</span>
            {hostEntries.slice(0, 12).map(([key, cnt]) => (
              <Button
                key={key}
                size="sm"
                className={hostFilter === key ? styles.chipOn : undefined}
                aria-pressed={hostFilter === key}
                onClick={() => toggleHostChip(key)}
              >
                {key} ({cnt})
              </Button>
            ))}
          </div>
        ) : null}
      </Panel>

      {showHistogram && Object.keys(histogram).length > 0 ? (
        <Panel
          title="Event timeline"
          actions={<Button size="sm" onClick={() => setShowHistogram(false)}>Hide</Button>}
        >
          <Histogram buckets={histogram} />
        </Panel>
      ) : null}

      <Panel
        title={hitTitle}
        actions={(
          <div className={styles.actions}>
            {allFields.length > 0 ? (
              <Button size="sm" onClick={() => setShowColPicker((v) => !v)}>
                Columns ({visibleFields.length}/{allFields.length})
              </Button>
            ) : null}
            {count > 0 ? (
              <Button size="sm" title="Download EVERY matching row as CSV — no result caps" onClick={exportAll}>
                Export all
              </Button>
            ) : null}
            {count > 0 ? (
              <Button
                size="sm"
                disabled={bookmarking || loading}
                title="Bookmark EVERY hit matching the current search — the full result set, not just this page"
                onClick={bookmarkAll}
              >
                {bookmarking ? "Bookmarking…" : `Bookmark all ${count.toLocaleString()}`}
              </Button>
            ) : null}
            <Button size="sm" disabled={offset === 0 || loading} onClick={() => doSearch(Math.max(0, offset - PAGE_SIZE))}>Prev</Button>
            <Button size="sm" disabled={offset + PAGE_SIZE >= count || loading} onClick={() => doSearch(offset + PAGE_SIZE)}>Next</Button>
          </div>
        )}
      >
        {countLowerBound ? (
          <p className={styles.bound} title={capReasons.join("; ") || "a cap was reached"}>
            lower bound{capReasons.length > 0 ? ` — ${capReasons.join("; ")}` : ""}
          </p>
        ) : null}
        {countExact && count > PAGE_SIZE ? (
          <p className={styles.exact}>exact total — Export all for every row</p>
        ) : null}
        {bookmarkNote ? (
          <p className={styles.note}>
            {bookmarkNote} — <Link to="/workbench">open Workbench</Link>
          </p>
        ) : null}

        {showColPicker && allFields.length > 0 ? (
          <div className={styles.suggestions}>
            <div className={styles.kicker}>Parsed fields — check to show</div>
            <div className={styles.chipRow}>
              {allFields.map((f) => {
                const on = visibleFields.includes(f);
                return (
                  <span key={f} className={styles.chipRow}>
                    <Button
                      size="sm"
                      className={on ? styles.chipOn : undefined}
                      aria-pressed={on}
                      onClick={() => setVisibleFields((prev) => (on ? prev.filter((x) => x !== f) : [...prev, f]))}
                    >
                      {f}
                    </Button>
                    {on ? (
                      <>
                        <Button size="sm" title="Move left" onClick={() => moveField(f, -1)}>◀</Button>
                        <Button size="sm" title="Move right" onClick={() => moveField(f, 1)}>▶</Button>
                      </>
                    ) : null}
                  </span>
                );
              })}
            </div>
          </div>
        ) : null}

        {loading ? (
          <p className={styles.loading}>Searching...</p>
        ) : hits.length === 0 ? (
          <EmptyState
            title="No hits"
            hint={activeCase
              ? "Enter needles above and click Search. If the index is empty, register evidence and run the N2 processing lane first."
              : "No active case — Explore searches the active case's N3 index."}
            action={!activeCase ? <Link to="/case-setup">Go to Case Setup (N1)</Link> : undefined}
          />
        ) : (
          <div className={styles.scroller}>
            <table className={styles.results}>
              <thead>
                <tr>
                  <th>Saved</th>
                  <th>Family</th>
                  <th>Host</th>
                  {visibleFields.map((fieldName) => <th key={fieldName}>{fieldName}</th>)}
                  <th>Source</th>
                  <th>Terms</th>
                </tr>
              </thead>
              <tbody>
                {hits.map((hit, index) => {
                  const on = bookmarked.has(hitKey(hit));
                  return (
                    <tr key={`${hit.family}:${hit.file}:${hit.line}:${index}`} onClick={() => setSelected(hit)}>
                      <td>
                        <button
                          type="button"
                          className={styles.star}
                          data-on={on ? "true" : "false"}
                          aria-pressed={on}
                          aria-label={on ? "Remove bookmark" : "Bookmark hit"}
                          onClick={(e) => { e.stopPropagation(); toggleBookmark(hit); }}
                        >
                          {on ? "★" : "☆"}
                        </button>
                      </td>
                      <td className={styles.mono}>{hit.family}</td>
                      <td className={`${styles.mono} ${styles.muted}`}>{hit.host || "—"}</td>
                      {visibleFields.map((fieldName) => (
                        <td key={fieldName} className={styles.cell}>{hit.fields?.[fieldName] ?? ""}</td>
                      ))}
                      <td className={styles.muted}>{hit.file}:{hit.line}</td>
                      <td className={`${styles.mono} ${styles.muted}`}>{hit.terms}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Drawer
        open={Boolean(selected)}
        onOpenChange={(next) => { if (!next) setSelected(null); }}
        title={selected ? `Hit detail — ${selected.family} · ${selected.host || "unknown host"}` : "Hit detail"}
        width={640}
      >
        {selected ? (
          <HitDetail
            hit={selected}
            interp={interp}
            interpLoading={interpLoading}
            interpReady={interpReady}
            onPivot={pivotOnValue}
            onRunQuery={(q) => { setNeedles(q); setSelected(null); doSearch(0, { needles: q }); }}
          />
        ) : null}
      </Drawer>
    </div>
  );
}

function HitDetail({
  hit,
  interp,
  interpLoading,
  interpReady,
  onPivot,
  onRunQuery,
}: {
  hit: N4Hit;
  interp: HitInterpretation | null;
  interpLoading: boolean;
  interpReady: boolean;
  onPivot: (value: string) => void;
  onRunQuery: (query: string) => void;
}) {
  return (
    <div>
      <p className={styles.hint}>{hit.file}:{hit.line} · terms: {hit.terms || "—"}</p>
      {interpLoading ? <p className={styles.hint}>Interpreting…</p> : null}
      {!interpLoading && interpReady && !interp ? (
        <div className={`${styles.interp} ${styles.interpMuted}`}>
          Interpretation unavailable for this row — the source fields are below;
          use search on a value to keep digging.
        </div>
      ) : null}
      {interp ? (
        <div className={styles.interp}>
          {!hasInterpContent(interp) ? (
            <p className={styles.hint}>
              No skill procedure covers this row yet — use search on a
              field value below or open the source file for context.
            </p>
          ) : null}
          {interp.meaning ? <p>{interp.meaning}</p> : null}
          {interp.learn && interp.learn.why_matters.length > 0 ? (
            <div className={styles.learn}>
              <strong>Why this matters:</strong> {interp.learn.headline}
              <ul>
                {interp.learn.why_matters.slice(0, 3).map((w, wi) => <li key={wi}>{w}</li>)}
              </ul>
            </div>
          ) : null}
          {interp.skills.length > 0 ? (
            <div className={styles.badgeRow}>
              {interp.skills.map((s) => (
                <Badge key={s.name}>{s.name}{s.mitre.length ? ` · ${s.mitre.join(",")}` : ""}</Badge>
              ))}
            </div>
          ) : null}
          {interp.det && interp.det.length > 0 ? (
            <div className={styles.badgeRow}>
              {interp.det.map((d) => (
                <Badge key={d.id}>{d.name}</Badge>
              ))}
            </div>
          ) : null}
          {interp.look_for.length > 0 ? (
            <div className={styles.block}>
              <strong>Check next:</strong>
              <ul className={styles.checkList}>{interp.look_for.map((lf, i) => <li key={i}>{lf}</li>)}</ul>
            </div>
          ) : null}
          {interp.next_queries.length > 0 ? (
            <div className={styles.block}>
              <strong>Run:</strong>{" "}
              {interp.next_queries.map((q) => (
                <Button key={q} size="sm" title="Search this query" onClick={() => onRunQuery(q)}>
                  {q.length > 40 ? `${q.slice(0, 40)}…` : q}
                </Button>
              ))}
            </div>
          ) : null}
          {interp.pivots.length > 0 ? (
            <p className={styles.block}><strong>Pivot on:</strong> <span className={styles.mono}>{interp.pivots.join(", ")}</span></p>
          ) : null}
          {interp.corroborate.length > 0 ? (
            <div className={styles.block}>
              <strong>Corroborate:</strong>
              <ul className={styles.checkList}>{interp.corroborate.map((c, i) => <li key={i}>{c}</li>)}</ul>
            </div>
          ) : null}
          {interp.negative.length > 0 ? (
            <p className={`${styles.block} ${styles.muted}`}><strong>If absent:</strong> {interp.negative.join(" ")}</p>
          ) : null}
          {interp.caveats.length > 0 ? (
            <div className={styles.caveat}>{interp.caveats.map((c, i) => <div key={i}>{c}</div>)}</div>
          ) : null}
          {interp.methodology ? (
            <details className={styles.method}>
              <summary title="Text excerpt retrieved from the knowledge base — not generated by an LLM">
                Methodology (KB retrieval — not LLM-generated)
              </summary>
              <div>{interp.methodology}</div>
            </details>
          ) : null}
        </div>
      ) : null}

      {hit.fields && Object.keys(hit.fields).length > 0 ? (
        <table className={styles.fields}>
          <tbody>
            {Object.entries(hit.fields).map(([k, v]) => (
              <tr key={k}>
                <td className={styles.fieldName}>{k}</td>
                <td className={styles.fieldValue}>
                  {v}
                  {v ? (
                    <Button
                      size="sm"
                      title={`Search this value (rotates the needle to "${v.slice(0, 60)}")`}
                      onClick={() => onPivot(v)}
                    >
                      search
                    </Button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <pre className={styles.raw}>{hit.text}</pre>
      )}
    </div>
  );
}
