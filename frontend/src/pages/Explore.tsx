import { useState, useEffect, useCallback, useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type N4Hit, type HistogramResponse, type PlaybookSuggestion } from "../api/client";
import { useCase } from "../context/CaseContext";
import { pickHitColumns } from "../lib/hitColumns";
import VirtualTable, { type Column } from "../components/VirtualTable";
import Histogram from "../components/Histogram";

const PAGE_SIZE = 200;

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
  const [timeRange, setTimeRange] = useState<{ start: string; end: string }>({ start: "", end: "" });
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
    // WP 4b.5: Load playbook needle suggestions
    api.playbookNeedles()
      .then((r) => setPlaybookSuggestions(r.suggestions || []))
      .catch((e) => setError(`Playbook suggestions load failed: ${(e as Error).message}`));
  }, []);

  // WP 4b.10: Read URL params from Timeline brush navigation
  useEffect(() => {
    const start = searchParams.get("start");
    const end = searchParams.get("end");
    const fam = searchParams.get("family");
    const host = searchParams.get("host");
    if (fam) setFamily(fam);
    if (host) setHostFilter(host);
    if (start || end || fam || host) {
      const n = searchParams.get("needles") || "";
      setNeedles(n);
      setTimeRange({ start: start || "", end: end || "" });
      setTimeout(() => doSearch(0, fam || undefined), 100);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const doSearch = useCallback(async (targetOffset: number, fam?: string, host?: string) => {
    const reqId = ++reqIdRef.current;
    setLoading(true);
    setError("");
    const famValue = fam !== undefined ? fam : family;
    const hostValue = host !== undefined ? host : hostFilter;
    try {
      const [searchResult, histResult] = await Promise.all([
        api.search({
          needles: needles || undefined,
          family: famValue || undefined,
          host: hostValue || undefined,
          start: timeRange.start || undefined,
          end: timeRange.end || undefined,
          limit: PAGE_SIZE,
          offset: targetOffset,
        }),
        api.histogram({
          family: famValue || undefined,
          start: timeRange.start || undefined,
          end: timeRange.end || undefined,
        }).catch(() => ({ buckets: {}, count: 0 }) as HistogramResponse),
      ]);
      if (reqIdRef.current !== reqId) return;
      setHits(searchResult.hits);
      setCount(searchResult.count);
      setOffset(targetOffset);
      setHistogram(histResult.buckets || {});
    } catch (e) {
      if (reqIdRef.current !== reqId) return;
      setError((e as Error).message);
      setHits([]);
      setHistogram({});
    } finally {
      if (reqIdRef.current === reqId) setLoading(false);
    }
  }, [needles, family, hostFilter, timeRange]);

  const search = (resetOffset = true) => {
    doSearch(resetOffset ? 0 : offset);
  };

  const toggleFamilyChip = (fam: string) => {
    const newFam = family === fam ? "" : fam;
    setFamily(newFam);
    doSearch(0, newFam);
  };

  const toggleHostChip = (host: string) => {
    const newHost = hostFilter === host ? "" : host;
    setHostFilter(newHost);
    doSearch(0, family, newHost);
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

  // WP 4d.1: type-aware columns recomputed for the current page of hits
  const typeColumns: Column<N4Hit>[] = pickHitColumns(hits).map((fieldName) => ({
    key: `field-${fieldName}`,
    header: fieldName,
    width: fieldName.toLowerCase().includes("message") || fieldName.toLowerCase().includes("text") ? undefined : 150,
    render: (h: N4Hit) => (
      <span style={{ fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", display: "block", whiteSpace: "nowrap" }}>
        {h.fields?.[fieldName] ?? ""}
      </span>
    ),
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
            onClick={() => { setTimeRange({ start: "", end: "" }); setTimeout(() => search(), 50); }}
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
              Playbook-Suggested Needles
            </div>
            {playbookSuggestions.slice(0, 6).map((pb) => (
              <div key={pb.slug} style={{ marginBottom: 8 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-secondary)", marginBottom: 4 }}>
                  {pb.playbook}
                </div>
                <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                  {pb.needles.slice(0, 10).map((n) => (
                    <button
                      key={n}
                      className="btn btn-sm"
                      style={{ fontFamily: "monospace", fontSize: 11, padding: "2px 8px" }}
                      onClick={() => {
                        setNeedles(n);
                        setTimeout(() => search(), 50);
                      }}
                    >
                      {n}
                    </button>
                  ))}
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
            rows={hits}
            columns={columns}
            rowKey={(h, i) => `${h.family}:${h.file}:${h.line}:${i}`}
            maxHeight="60vh"
          />
        )}
      </div>
    </div>
  );
}
