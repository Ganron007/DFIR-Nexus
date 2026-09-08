import { useState, useEffect, useCallback } from "react";
import { api, type ExploreHit, type AggregateResponse } from "../api/client";

const PAGE_SIZE = 50;

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

  const search = useCallback(async (resetOffset = true) => {
    setLoading(true);
    setError("");
    const off = resetOffset ? 0 : offset;
    try {
      const r = await api.search({
        needles: needles || undefined,
        family: family || undefined,
        host: host || undefined,
        limit: PAGE_SIZE,
        offset: off,
      });
      setHits(r.hits);
      setTotal(r.total);
      if (resetOffset) setOffset(0);
    } catch (e) {
      setError((e as Error).message);
      setHits([]);
    } finally {
      setLoading(false);
    }
  }, [needles, family, host, offset]);

  useEffect(() => {
    // Load family aggregates on mount
    api.aggregate("family")
      .then((r) => setAggregates((p) => ({ ...p, family: r })))
      .catch(() => {});
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

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>Explore</h2>
      {error && <div className="error-banner">{error}</div>}
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
          />
          <button className="btn btn-primary" onClick={() => search()}>
            Search
          </button>
        </div>
        {aggregates.family && (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
            {aggregates.family.buckets.slice(0, 15).map((b) => (
              <button
                key={b.key}
                className="btn btn-sm"
                onClick={() => { setFamily(b.key); search(); }}
                style={family === b.key ? { borderColor: "var(--accent)" } : {}}
              >
                {b.key} ({b.count})
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title">
            Hits ({total}{total > PAGE_SIZE && ` — page ${currentPage}/${pages}`})
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
          <div style={{ overflowX: "auto", maxHeight: "60vh", overflowY: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th style={{ width: 30 }}>★</th>
                  <th>Family</th>
                  <th>Host</th>
                  <th>Timestamp</th>
                  <th>Line</th>
                </tr>
              </thead>
              <tbody>
                {hits.map((h, i) => {
                  const key = `${h.audit_id}:${h.line_no || 0}`;
                  return (
                    <tr key={i}>
                      <td>
                        <button
                          onClick={() => toggleBookmark(h)}
                          style={{
                            background: "none",
                            border: "none",
                            cursor: "pointer",
                            color: bookmarked.has(key) ? "var(--warning)" : "var(--text-muted)",
                            fontSize: 14,
                          }}
                        >
                          {bookmarked.has(key) ? "★" : "☆"}
                        </button>
                      </td>
                      <td style={{ fontFamily: "monospace", fontSize: 11 }}>{h.family}</td>
                      <td style={{ fontSize: 11 }}>{h.host}</td>
                      <td style={{ fontSize: 11, whiteSpace: "nowrap" }}>{h.timestamp}</td>
                      <td style={{ fontSize: 11, maxWidth: 600, overflow: "hidden", textOverflow: "ellipsis" }}>
                        {h.line}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
