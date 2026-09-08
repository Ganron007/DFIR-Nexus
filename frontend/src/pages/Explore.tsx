import { useState, useEffect, useCallback } from "react";
import { api, type ExploreHit, type AggregateResponse } from "../api/client";
import VirtualTable, { type Column } from "../components/VirtualTable";
import Histogram, { type HistogramBucket } from "../components/Histogram";

const PAGE_SIZE = 200; // larger pages for virtualization

export default function Explore() {
  const [needles, setNeedles] = useState("");
  const [family, setFamily] = useState("");
  const [host, setHost] = useState("");
  const [hits, setHits] = useState<ExploreHit[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [aggregates, setAggregates] = useState<Record<string, AggregateResponse>>({});
  const [bookmarked, setBookmarked] = useState<Set<string>>(new Set());
  const [histogram, setHistogram] = useState<HistogramBucket[]>([]);
  const [showHistogram, setShowHistogram] = useState(true);

  const search = useCallback(async (resetOffset = true) => {
    setLoading(true);
    setError("");
    const off = resetOffset ? 0 : offset;
    try {
      const [searchResult, histResult] = await Promise.all([
        api.search({
          needles: needles || undefined,
          family: family || undefined,
          host: host || undefined,
          limit: PAGE_SIZE,
          offset: off,
        }),
        api.histogram({ family: family || undefined }).catch(() => ({ buckets: [] })),
      ]);
      setHits(searchResult.hits);
      setTotal(searchResult.total);
      if (resetOffset) setOffset(0);
      setHistogram(histResult.buckets || []);
    } catch (e) {
      setError((e as Error).message);
      setHits([]);
      setHistogram([]);
    } finally {
      setLoading(false);
    }
  }, [needles, family, host, offset]);

  useEffect(() => {
    Promise.all([
      api.aggregate("family").catch(() => ({ field: "family", buckets: [] })),
      api.aggregate("host").catch(() => ({ field: "host", buckets: [] })),
    ]).then(([fam, host]) => {
      setAggregates({ family: fam, host });
    });
  }, []);

  const toggleBookmark = (hit: ExploreHit) => {
    const key = `${hit.audit_id}:${hit.line_no || 0}`;
    const next = new Set(bookmarked);
    if (next.has(key)) {
      api.workbenchRemove(key).catch(() => {});
      next.delete(key);
    } else {
      api.workbenchAdd(hit).catch(() => {});
      next.add(key);
    }
    setBookmarked(next);
  };

  const pages = Math.ceil(total / PAGE_SIZE);
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  const columns: Column<ExploreHit>[] = [
    {
      key: "bookmark",
      header: "★",
      width: 30,
      render: (h) => {
        const key = `${h.audit_id}:${h.line_no || 0}`;
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
      key: "host",
      header: "Host",
      width: 100,
      render: (h) => <span style={{ fontSize: 11 }}>{h.host}</span>,
    },
    {
      key: "timestamp",
      header: "Timestamp",
      width: 160,
      render: (h) => <span style={{ fontSize: 11, whiteSpace: "nowrap" }}>{h.timestamp}</span>,
    },
    {
      key: "line",
      header: "Line",
      render: (h) => (
        <span style={{ fontSize: 11, overflow: "hidden", textOverflow: "ellipsis", display: "block", whiteSpace: "nowrap" }}>
          {h.line}
        </span>
      ),
    },
  ];

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Explore</h2>
      {error && <div className="error-banner">{error}</div>}

      {/* Search bar */}
      <div className="card">
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          <input
            placeholder="Needles (e.g. sdelete | powershell -enc | 1102)"
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
            {aggregates.family?.buckets.map((b) => (
              <option key={b.key} value={b.key}>{b.key} ({b.count})</option>
            ))}
          </datalist>
          <input
            placeholder="Host"
            value={host}
            onChange={(e) => setHost(e.target.value)}
            style={{ width: 120 }}
            list="host-list"
          />
          <datalist id="host-list">
            {aggregates.host?.buckets.map((b) => (
              <option key={b.key} value={b.key}>{b.key} ({b.count})</option>
            ))}
          </datalist>
          <button className="btn btn-primary" onClick={() => search()}>Search</button>
        </div>

        {/* Family facet chips */}
        {aggregates.family && aggregates.family.buckets.length > 0 && (
          <div style={{ marginBottom: 8 }}>
            <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", marginRight: 8 }}>Family:</span>
            {aggregates.family.buckets.slice(0, 20).map((b) => (
              <button
                key={b.key}
                className="btn btn-sm"
                onClick={() => { setFamily(family === b.key ? "" : b.key); }}
                style={{
                  margin: 2,
                  borderColor: family === b.key ? "var(--accent)" : undefined,
                  background: family === b.key ? "rgba(47,129,247,0.15)" : undefined,
                }}
              >
                {b.key} ({b.count})
              </button>
            ))}
          </div>
        )}

        {/* Host facet chips */}
        {aggregates.host && aggregates.host.buckets.length > 0 && (
          <div>
            <span style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", marginRight: 8 }}>Host:</span>
            {aggregates.host.buckets.slice(0, 10).map((b) => (
              <button
                key={b.key}
                className="btn btn-sm"
                onClick={() => { setHost(host === b.key ? "" : b.key); }}
                style={{
                  margin: 2,
                  borderColor: host === b.key ? "var(--accent)" : undefined,
                  background: host === b.key ? "rgba(47,129,247,0.15)" : undefined,
                }}
              >
                {b.key} ({b.count})
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Histogram */}
      {showHistogram && histogram.length > 0 && (
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
            Hits ({total.toLocaleString()}{total > PAGE_SIZE && ` — page ${currentPage}/${pages}`})
          </span>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              className="btn btn-sm"
              disabled={offset === 0 || loading}
              onClick={() => { setOffset(Math.max(0, offset - PAGE_SIZE)); search(false); }}
            >
              Prev
            </button>
            <button
              className="btn btn-sm"
              disabled={offset + PAGE_SIZE >= total || loading}
              onClick={() => { setOffset(offset + PAGE_SIZE); search(false); }}
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
            rowKey={(h, i) => `${h.audit_id}:${h.line_no || i}`}
            maxHeight="60vh"
          />
        )}
      </div>
    </div>
  );
}
