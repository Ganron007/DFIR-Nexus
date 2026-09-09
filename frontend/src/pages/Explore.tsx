import { useState, useEffect, useCallback, useRef } from "react";
import { api, type N4Hit, type HistogramResponse } from "../api/client";
import VirtualTable, { type Column } from "../components/VirtualTable";
import Histogram from "../components/Histogram";

const PAGE_SIZE = 200;

export default function Explore() {
  const [needles, setNeedles] = useState("");
  const [family, setFamily] = useState("");
  const [hits, setHits] = useState<N4Hit[]>([]);
  const [count, setCount] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [familyAgg, setFamilyAgg] = useState<Record<string, number>>({});
  const [bookmarked, setBookmarked] = useState<Set<string>>(new Set());
  const [histogram, setHistogram] = useState<Record<string, number>>({});
  const [showHistogram, setShowHistogram] = useState(true);
  const reqIdRef = useRef(0);

  // Load family aggregates and workbench bookmarks on mount
  useEffect(() => {
    api.aggregate({ group_by: "family" })
      .then((r) => setFamilyAgg(r.buckets || {}))
      .catch(() => {});
    api.workbench()
      .then((r) => {
        const ids = new Set(r.bookmarks.map((b) => b.id));
        setBookmarked(ids);
      })
      .catch(() => {});
  }, []);

  const doSearch = useCallback(async (targetOffset: number, fam?: string) => {
    const reqId = ++reqIdRef.current;
    setLoading(true);
    setError("");
    const famValue = fam !== undefined ? fam : family;
    try {
      const [searchResult, histResult] = await Promise.all([
        api.search({
          needles: needles || undefined,
          family: famValue || undefined,
          limit: PAGE_SIZE,
          offset: targetOffset,
        }),
        api.histogram({ family: famValue || undefined }).catch(() => ({ buckets: {}, count: 0 }) as HistogramResponse),
      ]);
      // Ignore stale responses
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
  }, [needles, family]);

  const search = (resetOffset = true) => {
    doSearch(resetOffset ? 0 : offset);
  };

  const toggleFamilyChip = (fam: string) => {
    const newFam = family === fam ? "" : fam;
    setFamily(newFam);
    doSearch(0, newFam);
  };

  const toggleBookmark = (hit: N4Hit) => {
    const key = `${hit.family}:${hit.file}:${hit.line}`;
    const next = new Set(bookmarked);
    if (next.has(key)) {
      // Find the bookmark ID from the workbench
      api.workbenchRemove(key).catch(() => {});
      next.delete(key);
    } else {
      api.workbenchAdd(hit).catch(() => {});
      next.add(key);
    }
    setBookmarked(next);
  };

  const pages = Math.ceil(count / PAGE_SIZE);
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

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
      width: 120,
      render: (h) => <span style={{ fontFamily: "monospace", fontSize: 11 }}>{h.family}</span>,
    },
    {
      key: "file",
      header: "File",
      width: 200,
      render: (h) => (
        <span style={{ fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", display: "block", whiteSpace: "nowrap" }}>
          {h.file}:{h.line}
        </span>
      ),
    },
    {
      key: "terms",
      header: "Terms",
      width: 150,
      render: (h) => <span style={{ fontSize: 11, fontFamily: "monospace" }}>{h.terms}</span>,
    },
    {
      key: "text",
      header: "Row",
      render: (h) => (
        <span style={{ fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", display: "block", whiteSpace: "nowrap" }}>
          {h.text}
        </span>
      ),
    },
  ];

  const familyEntries = Object.entries(familyAgg).sort((a, b) => b[1] - a[1]);

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Explore</h2>
      {error && <div className="error-banner">{error}</div>}

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
            <p>Enter needles above and click Search.</p>
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
