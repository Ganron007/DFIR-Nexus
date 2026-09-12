import { useState, useEffect, useCallback, useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type N4Hit, type HistogramResponse, type PlaybookSuggestion, type HitInterpretation } from "../api/client";
import { useCase } from "../context/CaseContext";
import { allHitColumns } from "../lib/hitColumns";
import VirtualTable, { type Column } from "../components/VirtualTable";
import Histogram from "../components/Histogram";

const PAGE_SIZE = 200;

// WP 4j.5: interpretation payloads can arrive partial (older backend, RAG
// failure, family-less row) — fill defaults so the drawer never dereferences
// an undefined list, and distinguish "no interpretation" from "still loading".
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

export default function Explore() {
  const { activeCase } = useCase();
  const [searchParams] = useSearchParams();
  const [needles, setNeedles] = useState("");
  const [family, setFamily] = useState("");
  const [hostFilter, setHostFilter] = useState("");
  const [hits, setHits] = useState<N4Hit[]>([]);
  const [count, setCount] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [familyAgg, setFamilyAgg] = useState<Record<string, number>>({});
  const [hostAgg, setHostAgg] = useState<Record<string, number>>({});
  const [bookmarked, setBookmarked] = useState<Set<string>>(new Set());
  const [histogram, setHistogram] = useState<Record<string, number>>({});
  const [showHistogram, setShowHistogram] = useState(true);
  const [playbookSuggestions, setPlaybookSuggestions] = useState<PlaybookSuggestion[]>([]);
  const [showPlaybookHelp, setShowPlaybookHelp] = useState(false);
  const [feedbackMsg, setFeedbackMsg] = useState("");
  const [timeRange, setTimeRange] = useState<{ start: string; end: string }>({ start: "", end: "" });
  // WP 4i.3: full-field rendering — column picker, sorting, detail drawer, pivot
  const [visibleFields, setVisibleFields] = useState<string[]>([]);
  const [showColPicker, setShowColPicker] = useState(false);
  const [sortKey, setSortKey] = useState("");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [selected, setSelected] = useState<N4Hit | null>(null);
  // WP 4j.1: hit interpretation — meaning + what to check next, from skills/playbooks/RAG
  const [interp, setInterp] = useState<HitInterpretation | null>(null);
  const [interpLoading, setInterpLoading] = useState(false);
  const [interpReady, setInterpReady] = useState(false);
  const reqIdRef = useRef(0);

  // Load family/host aggregates and workbench bookmarks on mount
  useEffect(() => {
    api.aggregate({ group_by: "family" })
      .then((r) => setFamilyAgg(r.buckets || {}))
      .catch((e) => setError(`Facet load failed: ${(e as Error).message}`));
    api.aggregate({ group_by: "host" })
      .then((r) => setHostAgg(r.buckets || {}))
      .catch(() => setHostAgg({}));
    api.workbench()
      .then((r) => {
        const ids = new Set(r.bookmarks.map((b) => b.id));
        setBookmarked(ids);
      })
      .catch((e) => setError(`Bookmark state load failed: ${(e as Error).message}`));
  }, [activeCase]);

  // Phase 4g: suggestions are case-aware — static playbooks PLUS ATT&CK packs
  // matched to the evidence families actually present, refreshing when the
  // family aggregate changes.
  useEffect(() => {
    const fams = Object.keys(familyAgg).join(",");
    api.playbookNeedles(fams || undefined)
      .then((r) => setPlaybookSuggestions(r.suggestions || []))
      .catch((e) => setError(`Needle suggestions load failed: ${(e as Error).message}`));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [familyAgg]);

  const needleFeedback = async (
    pb: PlaybookSuggestion,
    verdict: "accept" | "reject" | "promote",
  ) => {
    try {
      const family = Object.keys(familyAgg)[0] || "";
      await api.needleFeedback({
        needles: pb.needles,
        family,
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

  const sourceLabel = (s?: string) =>
    s === "mitre" ? "ATT&CK" : s === "sigma" ? "Sigma" : s === "overlay" ? "yours" : "playbook";
  const sourceColor = (s?: string) =>
    s === "mitre"
      ? "var(--purple)"
      : s === "sigma"
        ? "var(--orange)"
        : s === "overlay"
          ? "var(--success)"
          : undefined;

  // WP 4b.10: Read URL params from Timeline brush navigation / Briefing pivots.
  // Any single param (incl. a needles-only link) re-arms the search; values are
  // passed to doSearch explicitly so the fetch never sees stale state.
  useEffect(() => {
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
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  // Explicit overrides beat component state — callers that just changed a value
  // pass it here instead of relying on a setTimeout against a stale closure.
  interface SearchOverrides {
    needles?: string;
    family?: string;
    host?: string;
    start?: string;
    end?: string;
  }

  const doSearch = useCallback(async (targetOffset: number, overrides: SearchOverrides = {}) => {
    const reqId = ++reqIdRef.current;
    setLoading(true);
    setError("");
    const needleValue = overrides.needles !== undefined ? overrides.needles : needles;
    const famValue = overrides.family !== undefined ? overrides.family : family;
    const hostValue = overrides.host !== undefined ? overrides.host : hostFilter;
    const startValue = overrides.start !== undefined ? overrides.start : timeRange.start;
    const endValue = overrides.end !== undefined ? overrides.end : timeRange.end;
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
          family: famValue || undefined,
          start: startValue || undefined,
          end: endValue || undefined,
        }).catch(() => ({ buckets: {}, count: 0 }) as HistogramResponse),
      ]);
      if (reqIdRef.current !== reqId) return;
      setHits(searchResult.hits);
      setCount(searchResult.count);
      setOffset(targetOffset);
      setHistogram(histResult.buckets || {});
      // WP 4i.3: default visible columns = first 6 fields (priority-ordered);
      // the picker can show every parsed field. Keep prior selection if still valid.
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
  }, [needles, family, hostFilter, timeRange, activeCase]);

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

  const toggleBookmark = (hit: N4Hit) => {
    const key = `${hit.family}:${hit.file}:${hit.line}`;
    const next = new Set(bookmarked);
    if (next.has(key)) {
      api.workbenchRemove(key)
        .catch((e) => setError(`Bookmark remove failed: ${(e as Error).message}`));
      next.delete(key);
    } else {
      api.workbenchAdd(hit)
        .catch((e) => setError(`Bookmark add failed: ${(e as Error).message}`));
      next.add(key);
    }
    setBookmarked(next);
  };

  const pages = Math.ceil(count / PAGE_SIZE);
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  const familyEntries = Object.entries(familyAgg).sort((a, b) => b[1] - a[1]);
  const hostEntries = Object.entries(hostAgg)
    .filter(([k]) => k && k !== "(unknown host)")
    .sort((a, b) => b[1] - a[1]);

  // WP 4i.3: all parsed fields present in this hit set (priority-ordered)
  const allFields = allHitColumns(hits);

  // WP 4i.3: click a field value → rotate the active needle to that value.
  // The needle box shows exactly what is being searched; clicking a new value
  // replaces it rather than piling terms into an unmatchable string.
  const pivotOnValue = (value: string) => {
    const v = value.trim();
    if (!v) return;
    setNeedles(v);
    setSelected(null);
    doSearch(0, { needles: v });
  };

  // WP 4j.1: fetch interpretation when a hit is selected for the drawer
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

  // WP 4i.3: client-side sort of the current page
  const sortedHits = (() => {
    if (!sortKey) return hits;
    const val = (h: N4Hit): string => {
      if (sortKey === "family") return h.family || "";
      if (sortKey === "host") return h.host || "";
      if (sortKey === "file") return `${h.file}:${h.line}`;
      if (sortKey === "terms") return h.terms || "";
      return h.fields?.[sortKey] ?? "";
    };
    const sorted = [...hits].sort((a, b) => val(a).localeCompare(val(b), undefined, { numeric: true }));
    return sortDir === "desc" ? sorted.reverse() : sorted;
  })();

  const onSort = (key: string) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  // WP 4i.3: type-aware columns — visible subset of ALL parsed fields;
  // every cell is clickable to pivot on that value
  const typeColumns: Column<N4Hit>[] = visibleFields.map((fieldName) => ({
    key: fieldName,
    header: fieldName,
    width: fieldName.toLowerCase().includes("message") || fieldName.toLowerCase().includes("text") || fieldName.toLowerCase().includes("commandline") ? undefined : 150,
    render: (h: N4Hit) => {
      const v = h.fields?.[fieldName] ?? "";
      return (
        <span
          style={{ fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", display: "block", whiteSpace: "nowrap", cursor: v ? "pointer" : undefined }}
          title={v ? `${v}\n(click to pivot)` : ""}
          onClick={(e) => {
            if (!v) return;
            e.stopPropagation();
            pivotOnValue(v);
          }}
        >
          {v}
        </span>
      );
    },
  }));

  const columns: Column<N4Hit>[] = [
    {
      key: "bookmark",
      header: "★",
      width: 30,
      render: (h) => {
        const key = `${h.family}:${h.file}:${h.line}`;
        return (
          <button
            onClick={(e) => { e.stopPropagation(); toggleBookmark(h); }}
            style={{
              background: "none",
              border: "none",
              cursor: "pointer",
              color: bookmarked.has(key) ? "var(--warning)" : "var(--text-muted)",
              fontSize: 14,
              padding: 0,
            }}
          >
            {bookmarked.has(key) ? "★" : "☆"}
          </button>
        );
      },
    },
    {
      key: "family",
      header: "Family",
      width: 100,
      render: (h) => <span style={{ fontFamily: "monospace", fontSize: 11 }}>{h.family}</span>,
    },
    {
      key: "host",
      header: "Host",
      width: 90,
      render: (h) => (
        <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--text-secondary)" }}>
          {h.host || "—"}
        </span>
      ),
    },
    ...typeColumns,
    {
      key: "file",
      header: "Source",
      width: 170,
      render: (h) => (
        <span style={{ fontSize: 10, overflow: "hidden", textOverflow: "ellipsis", display: "block", whiteSpace: "nowrap", color: "var(--text-muted)" }}>
          {h.file}:{h.line}
        </span>
      ),
    },
    {
      key: "terms",
      header: "Terms",
      width: 110,
      render: (h) => <span style={{ fontSize: 10, fontFamily: "monospace", color: "var(--text-muted)" }}>{h.terms}</span>,
    },
  ];

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Explore</h2>
      {error && <div className="error-banner">{error}</div>}

      {/* WP 4b.10: Active time-range filter from Timeline brush */}
      {(timeRange.start || timeRange.end) && (
        <div className="card" style={{ padding: "8px 12px", marginBottom: 8 }}>
          <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
            Time filter: <strong>{timeRange.start || "…"}</strong> → <strong>{timeRange.end || "…"}</strong>
          </span>
          <button
            className="btn btn-sm"
            style={{ marginLeft: 12 }}
            onClick={() => { setTimeRange({ start: "", end: "" }); doSearch(0, { start: "", end: "" }); }}
          >
            Clear time filter
          </button>
        </div>
      )}

      {/* Search bar */}
      <div className="card">
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          <input
            placeholder="Needles (e.g. sdelete, powershell, 1102)"
            value={needles}
            onChange={(e) => setNeedles(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && search()}
            style={{ flex: 1 }}
          />
          <input
            placeholder="Family"
            value={family}
            onChange={(e) => setFamily(e.target.value)}
            style={{ width: 120 }}
            list="family-list"
          />
          <datalist id="family-list">
            {familyEntries.map(([key, cnt]) => (
              <option key={key} value={key}>{key} ({cnt})</option>
            ))}
          </datalist>
          <button className="btn btn-primary" onClick={() => search()}>Search</button>
        </div>

        {/* WP 4b.5: Needle explanation */}
        <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 8 }}>
          <strong>Needles</strong> are search terms — IOCs, technique names, file names, event IDs —
          that the N4 query engine searches for across parsed evidence.
          Clicking a briefing chip, field value, or suggested needle replaces this box —
          it always shows exactly what was last searched.
          {" "}
          <button
            onClick={() => setShowPlaybookHelp(!showPlaybookHelp)}
            style={{ background: "none", border: "none", color: "var(--accent)", cursor: "pointer", fontSize: 12 }}
          >
            {showPlaybookHelp ? "Hide suggestions" : `Show playbook suggestions (${playbookSuggestions.length})`}
          </button>
        </div>

        {/* WP 4b.5: Playbook needle suggestions */}
        {showPlaybookHelp && playbookSuggestions.length > 0 && (
          <div style={{ marginTop: 8, padding: 12, background: "var(--bg-tertiary)", borderRadius: 8 }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8, textTransform: "uppercase" }}>
              Suggested Needles — Playbooks · MITRE ATT&CK · Sigma · Yours
            </div>
            {feedbackMsg && (
              <div style={{ fontSize: 11, color: "var(--success)", marginBottom: 8 }}>{feedbackMsg}</div>
            )}
            {playbookSuggestions.slice(0, 8).map((pb) => (
              <div key={pb.slug} style={{ marginBottom: 8 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 4 }}>
                  <span
                    className="badge draft"
                    style={{
                      fontSize: 9,
                      marginRight: 6,
                      background: pb.source === "mitre" ? "rgba(163,113,247,0.15)" : undefined,
                      color: sourceColor(pb.source),
                    }}
                  >
                    {sourceLabel(pb.source)}
                  </span>
                  {pb.playbook}
                </div>
                <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                  {[
                    ...(pb.strong_needles || []),
                    ...pb.needles.filter((n) => !(pb.strong_needles || []).includes(n)),
                  ]
                    .slice(0, 10)
                    .map((n) => (
                      <button
                        key={n}
                        className="btn btn-sm"
                        style={{
                          fontFamily: "monospace",
                          fontSize: 11,
                          padding: "2px 8px",
                          borderColor: (pb.strong_needles || []).includes(n) ? "var(--accent)" : undefined,
                        }}
                        title={(pb.strong_needles || []).includes(n) ? "high-signal" : ""}
                        onClick={() => { setNeedles(n); doSearch(0, { needles: n }); }}
                      >
                        {n}
                      </button>
                    ))}
                </div>
                <div style={{ display: "flex", gap: 6, marginTop: 4 }}>
                  <button className="btn btn-sm" style={{ fontSize: 10 }} onClick={() => needleFeedback(pb, "accept")} title="Mark this suggestion as useful">
                    ✓ used
                  </button>
                  <button className="btn btn-sm" style={{ fontSize: 10 }} onClick={() => needleFeedback(pb, "reject")} title="Reject this suggestion">
                    ✗ reject
                  </button>
                  <button className="btn btn-sm" style={{ fontSize: 10 }} onClick={() => needleFeedback(pb, "promote")} title="Promote to my local overlay (never the repo)">
                    ★ promote
                  </button>
                </div>
                {pb.caveats.length > 0 && (
                  <div style={{ fontSize: 10, color: "var(--warning)", marginTop: 4 }}>
                    ⚠ {pb.caveats[0]}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Family facet chips */}
        {familyEntries.length > 0 && (
          <div style={{ marginBottom: 8 }}>
            <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", marginRight: 8 }}>Family:</span>
            {familyEntries.slice(0, 20).map(([key, cnt]) => (
              <button
                key={key}
                className="btn btn-sm"
                onClick={() => toggleFamilyChip(key)}
                style={{
                  margin: 2,
                  borderColor: family === key ? "var(--accent)" : undefined,
                  background: family === key ? "rgba(47,129,247,0.15)" : undefined,
                }}
              >
                {key} ({cnt})
              </button>
            ))}
          </div>
        )}

        {/* WP 4d.2: Host facet chips */}
        {hostEntries.length > 0 && (
          <div style={{ marginBottom: 8 }}>
            <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", marginRight: 8 }}>Host:</span>
            {hostEntries.slice(0, 12).map(([key, cnt]) => (
              <button
                key={key}
                className="btn btn-sm"
                onClick={() => toggleHostChip(key)}
                style={{
                  margin: 2,
                  borderColor: hostFilter === key ? "var(--accent)" : undefined,
                  background: hostFilter === key ? "rgba(47,129,247,0.15)" : undefined,
                }}
              >
                {key} ({cnt})
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Histogram */}
      {showHistogram && Object.keys(histogram).length > 0 && (
        <div className="card">
          <div className="card-header">
            <span className="card-title">Event Timeline</span>
            <button className="btn btn-sm" onClick={() => setShowHistogram(false)}>Hide</button>
          </div>
          <Histogram buckets={histogram} />
        </div>
      )}

      {/* Hits table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            Hits ({count.toLocaleString()}{count > PAGE_SIZE && ` — page ${currentPage}/${pages}`})
          </span>
          <div style={{ display: "flex", gap: 8 }}>
            {/* WP 4i.3: column picker — examiner chooses which parsed fields show */}
            {allFields.length > 0 && (
              <button className="btn btn-sm" onClick={() => setShowColPicker((v) => !v)}>
                Columns ({visibleFields.length}/{allFields.length})
              </button>
            )}
            <button
              className="btn btn-sm"
              disabled={offset === 0 || loading}
              onClick={() => doSearch(Math.max(0, offset - PAGE_SIZE))}
            >
              Prev
            </button>
            <button
              className="btn btn-sm"
              disabled={offset + PAGE_SIZE >= count || loading}
              onClick={() => doSearch(offset + PAGE_SIZE)}
            >
              Next
            </button>
          </div>
        </div>

        {/* WP 4i.3: column picker panel */}
        {showColPicker && allFields.length > 0 && (
          <div style={{ padding: "8px 12px", background: "var(--bg-tertiary)", borderRadius: 6, marginBottom: 8 }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase" }}>
              Parsed fields — check to show; arrows reorder
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {allFields.map((f) => {
                const on = visibleFields.includes(f);
                return (
                  <span key={f} style={{ display: "inline-flex", alignItems: "center", gap: 2 }}>
                    <button
                      className="btn btn-sm"
                      style={{
                        fontFamily: "monospace",
                        fontSize: 11,
                        borderColor: on ? "var(--accent)" : undefined,
                        background: on ? "rgba(47,129,247,0.15)" : undefined,
                      }}
                      onClick={() =>
                        setVisibleFields((prev) =>
                          on ? prev.filter((x) => x !== f) : [...prev, f],
                        )
                      }
                    >
                      {f}
                    </button>
                    {on && (
                      <>
                        <button
                          className="btn btn-sm"
                          style={{ padding: "0 4px", fontSize: 10 }}
                          title="Move left"
                          onClick={() =>
                            setVisibleFields((prev) => {
                              const i = prev.indexOf(f);
                              if (i <= 0) return prev;
                              const next = [...prev];
                              [next[i - 1], next[i]] = [next[i], next[i - 1]];
                              return next;
                            })
                          }
                        >
                          ◀
                        </button>
                        <button
                          className="btn btn-sm"
                          style={{ padding: "0 4px", fontSize: 10 }}
                          title="Move right"
                          onClick={() =>
                            setVisibleFields((prev) => {
                              const i = prev.indexOf(f);
                              if (i < 0 || i >= prev.length - 1) return prev;
                              const next = [...prev];
                              [next[i + 1], next[i]] = [next[i], next[i + 1]];
                              return next;
                            })
                          }
                        >
                          ▶
                        </button>
                      </>
                    )}
                  </span>
                );
              })}
            </div>
          </div>
        )}

        {loading ? (
          <div className="loading">Searching...</div>
        ) : hits.length === 0 ? (
          <div className="empty-state">
            <h3>No hits</h3>
            {!activeCase ? (
              <>
                <p>No active case — Explore searches the active case's N3 index.</p>
                <Link to="/case-setup" className="btn btn-primary" style={{ marginTop: 12, display: "inline-block" }}>
                  Go to Case Setup (N1)
                </Link>
              </>
            ) : (
              <>
                <p>Enter needles above and click Search.</p>
                <p style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  If the index is empty, register evidence and run the N2 processing lane first (Case Setup, steps 2 and 4).
                </p>
              </>
            )}
          </div>
        ) : (
          <VirtualTable
            rows={sortedHits}
            columns={columns}
            rowKey={(h, i) => `${h.family}:${h.file}:${h.line}:${i}`}
            maxHeight="60vh"
            sortKey={sortKey}
            sortDir={sortDir}
            onSort={onSort}
            onRowClick={(h) => setSelected(h)}
          />
        )}
      </div>

      {/* WP 4i.3: hit detail drawer — every parsed field + raw row + provenance */}
      {selected && (
        <div className="card" style={{ position: "sticky", bottom: 0, maxHeight: "45vh", overflowY: "auto" }}>
          <div className="card-header">
            <span className="card-title">
              Hit detail — {selected.family} · {selected.host || "unknown host"}
            </span>
            <button className="btn btn-sm" onClick={() => setSelected(null)}>Close</button>
          </div>
          <div style={{ padding: "8px 12px" }}>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
              {selected.file}:{selected.line} · terms: {selected.terms || "—"}
            </div>

            {/* WP 4j.1: what this means + what to check next. The panel always
                resolves — a row with no skill coverage gets an honest note
                instead of a silent gap. */}
            {interpLoading && (
              <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8 }}>
                Interpreting…
              </div>
            )}
            {!interpLoading && interpReady && !interp && (
              <div style={{
                marginBottom: 10, padding: "8px 10px", fontSize: 11,
                background: "var(--bg-tertiary)", borderRadius: 6,
                borderLeft: "3px solid var(--text-muted)", color: "var(--text-muted)",
              }}>
                Interpretation unavailable for this row — the source fields are below;
                pivot on a value to keep digging.
              </div>
            )}
            {interp && (
              <div style={{
                marginBottom: 10, padding: "8px 10px",
                background: "var(--bg-tertiary)", borderRadius: 6,
                borderLeft: "3px solid var(--accent)",
              }}>
                {!hasInterpContent(interp) && (
                  <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                    No skill procedure covers this row yet — pivot on a field value
                    below or open the source file for context.
                  </div>
                )}
                {interp.meaning && (
                  <div style={{ fontSize: 12, marginBottom: 6 }}>{interp.meaning}</div>
                )}
                {interp.learn && interp.learn.why_matters.length > 0 && (
                  <div style={{
                    fontSize: 11, marginBottom: 6, padding: "6px 8px",
                    background: "var(--bg-tertiary)", borderRadius: 4,
                  }}>
                    <strong style={{ color: "var(--text-secondary)" }}>Why this matters:</strong>{" "}
                    <span>{interp.learn.headline}</span>
                    <ul style={{ margin: "2px 0 0 16px", padding: 0, color: "var(--text-muted)" }}>
                      {interp.learn.why_matters.slice(0, 3).map((w, wi) => <li key={wi}>{w}</li>)}
                    </ul>
                  </div>
                )}
                {interp.skills.length > 0 && (
                  <div style={{ marginBottom: 6, display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {interp.skills.map((s) => (
                      <span key={s.name} className="badge draft" style={{ fontSize: 9 }}
                            title={s.title}>
                        {s.name}{s.mitre.length ? ` · ${s.mitre.join(",")}` : ""}
                      </span>
                    ))}
                  </div>
                )}
                {interp.look_for.length > 0 && (
                  <div style={{ fontSize: 11, marginBottom: 4 }}>
                    <strong style={{ color: "var(--text-secondary)" }}>Check next:</strong>
                    <ul style={{ margin: "2px 0 0 16px", padding: 0 }}>
                      {interp.look_for.map((lf, i) => <li key={i}>{lf}</li>)}
                    </ul>
                  </div>
                )}
                {interp.next_queries.length > 0 && (
                  <div style={{ fontSize: 11, marginBottom: 4 }}>
                    <strong style={{ color: "var(--text-secondary)" }}>Run:</strong>{" "}
                    {interp.next_queries.map((q) => (
                      <button key={q} className="btn btn-sm"
                              style={{ fontFamily: "monospace", fontSize: 10, marginRight: 4 }}
                              title="Search this query"
                              onClick={() => { setNeedles(q); setSelected(null); doSearch(0, { needles: q }); }}>
                        {q.length > 40 ? q.slice(0, 40) + "…" : q}
                      </button>
                    ))}
                  </div>
                )}
                {interp.pivots.length > 0 && (
                  <div style={{ fontSize: 11, marginBottom: 4 }}>
                    <strong style={{ color: "var(--text-secondary)" }}>Pivot on:</strong>{" "}
                    <span style={{ fontFamily: "monospace" }}>{interp.pivots.join(", ")}</span>
                  </div>
                )}
                {interp.corroborate.length > 0 && (
                  <div style={{ fontSize: 11, marginBottom: 4 }}>
                    <strong style={{ color: "var(--text-secondary)" }}>Corroborate:</strong>
                    <ul style={{ margin: "2px 0 0 16px", padding: 0 }}>
                      {interp.corroborate.map((c, i) => <li key={i}>{c}</li>)}
                    </ul>
                  </div>
                )}
                {interp.negative.length > 0 && (
                  <div style={{ fontSize: 11, marginBottom: 4, color: "var(--text-muted)" }}>
                    <strong>If absent:</strong> {interp.negative.join(" ")}
                  </div>
                )}
                {interp.caveats.length > 0 && (
                  <div style={{ fontSize: 10, color: "var(--warning)" }}>
                    {interp.caveats.map((c, i) => <div key={i}>⚠ {c}</div>)}
                  </div>
                )}
                {interp.methodology && (
                  <details style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
                    <summary style={{ cursor: "pointer" }} title="Text excerpt retrieved from the knowledge base — not generated by an LLM">
                      Methodology (KB retrieval — not LLM-generated)
                    </summary>
                    <div style={{ whiteSpace: "pre-wrap", marginTop: 4 }}>{interp.methodology}</div>
                  </details>
                )}
              </div>
            )}

            {selected.fields && Object.keys(selected.fields).length > 0 ? (
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <tbody>
                  {Object.entries(selected.fields).map(([k, v]) => (
                    <tr key={k} style={{ borderBottom: "1px solid var(--border)" }}>
                      <td style={{ padding: "4px 8px", fontFamily: "monospace", fontSize: 11, color: "var(--text-muted)", width: 200, verticalAlign: "top" }}>
                        {k}
                      </td>
                      <td style={{ padding: "4px 8px", fontSize: 11, wordBreak: "break-all" }}>
                        <span
                          style={{ cursor: "pointer" }}
                          title="click to pivot"
                          onClick={() => pivotOnValue(v)}
                        >
                          {v}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <pre style={{ fontSize: 11, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{selected.text}</pre>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
