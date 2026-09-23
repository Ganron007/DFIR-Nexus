/**
 * Live run feed (WP 4j.5d, extended): renders the pipeline stage journal and
 * the per-tool lane entries as one chronological log — timestamps, coloured
 * status, the exact command, duration and output file — plus a "Running:"
 * header for the job executing right now. Shared by Case Setup (step 4) and
 * the Evidence page so the feed is visible wherever processing is watched.
 */
import type { PipelineStageLine, PipelineStatusResponse } from "../api/client";

function fmtTs(ts?: string): string {
  if (!ts) return "";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString([], { hour12: false });
}

function statusColor(status?: string): string {
  const s = (status || "").toUpperCase();
  if (s === "OK" || s === "DONE" || s === "COMPLETE") return "var(--success)";
  if (s === "RUNNING") return "var(--accent)";
  if (s === "ERROR" || s === "FAIL") return "var(--danger)";
  if (s === "SKIP") return "var(--warning)";
  return "var(--text-muted)";
}

function baseName(path?: string): string {
  if (!path) return "";
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

export default function LiveRunFeed({
  stages,
  progress,
  maxHeight = 280,
  maxLines = 120,
}: {
  stages: PipelineStageLine[];
  progress?: PipelineStatusResponse["progress"];
  maxHeight?: number;
  maxLines?: number;
}) {
  const lines = (stages || []).slice(-maxLines);
  const running = progress?.running;
  return (
    <div>
      {running?.tool && (
        <div style={{ fontSize: 12, marginBottom: 6 }}>
          <span style={{ color: "var(--accent)", fontWeight: 600 }}>
            Running: {running.tool}
            {running.host ? ` (${running.host})` : ""}
          </span>
          {running.command && (
            <div
              style={{
                fontFamily: "monospace",
                fontSize: 11,
                color: "var(--text-muted)",
                overflowWrap: "anywhere",
              }}
              title={running.command}
            >
              {running.command}
            </div>
          )}
        </div>
      )}
      <div
        style={{
          maxHeight,
          overflowY: "auto",
          display: "flex",
          flexDirection: "column",
          gap: 3,
          fontFamily: "monospace",
          fontSize: 11,
          lineHeight: 1.45,
        }}
      >
        {lines.length === 0 && (
          <span style={{ color: "var(--text-muted)" }}>Waiting for the first event…</span>
        )}
        {lines.map((st, i) => {
          const label = st.tool || st.stage || "?";
          const color = statusColor(st.status);
          const dur = typeof st.duration_s === "number" ? `${st.duration_s}s` : "";
          const out = baseName(st.output);
          const extra = [dur, out].filter(Boolean).join(" → ");
          const detail = [st.detail, st.reason].filter(Boolean).join(" — ");
          const ts = fmtTs(st.ts);
          return (
            <span key={`${st.ts || ""}-${st.tool || st.stage || i}-${i}`} style={{ color }}>
              {ts && <span style={{ color: "var(--text-muted)" }}>{ts} </span>}
              [{label}] {st.status || ""}
              {extra ? ` — ${extra}` : ""}
              {detail ? ` — ${detail}` : ""}
              {st.command && !out && (
                <span
                  style={{
                    display: "block",
                    color: "var(--text-muted)",
                    paddingLeft: 16,
                    overflowWrap: "anywhere",
                  }}
                  title={st.command}
                >
                  {st.command}
                </span>
              )}
            </span>
          );
        })}
      </div>
    </div>
  );
}
