"""N7 chronology + I3 merge — host query hits and importer events, one timeline."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from nexus.ingest.schemas import Artifact, ArtifactSource
from nexus.langgraph.query_pack import _DATE_RE, load_case_intake, parse_intake_window

_HOST_RE = re.compile(
    r"\b((?:[a-z0-9][a-z0-9-]{0,24}\.)+(?:local|lan|corp|internal|com|net|org))\b",
    re.I,
)


def _parse_ts(text: str) -> str | None:
    m = _DATE_RE.search(text or "")
    if not m:
        return None
    if m.group(2):
        return f"{m.group(1)}T{m.group(2)}Z"
    return f"{m.group(1)}T00:00:00Z"


def _in_window(ts: str | None, start: datetime | None, end: datetime | None) -> bool:
    if start is None or end is None or not ts:
        return True
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return True
    if d.tzinfo is None:
        from datetime import UTC
        d = d.replace(tzinfo=UTC)
    return start <= d <= end


def hits_to_events(hits: list[dict[str, str]], source: str = "n4") -> list[dict[str, Any]]:
    from nexus.integration.evidence_table import evidence_rows_from_n4_hits

    events: list[dict[str, Any]] = []
    for h in hits:
        text = h.get("text") or ""
        ts = _parse_ts(text)
        host = ""
        hm = _HOST_RE.search(text)
        if hm:
            host = hm.group(1)
        fam = h.get("family") or "n4"
        terms = h.get("terms") or ""
        rows = evidence_rows_from_n4_hits([h], limit=1)
        art = (rows[0].get("artifact") if rows else "") or ""
        if art and art not in {"—", terms}:
            desc = f"{fam} [{terms}]: {art}"
        elif rows and rows[0].get("detail"):
            desc = f"{fam} [{terms}]: {str(rows[0].get('detail'))[:120]}"
        else:
            desc = f"{fam} [{terms}]: {text[:120]}"
        sev = ""
        try:
            from nexus.langgraph.mode1 import _severity_from_hits

            sev = _severity_from_hits([h]) if h.get("fields") else ""
        except Exception:
            sev = ""
        events.append({
            "timestamp": ts or "",
            "host": host,
            "description": desc[:240],
            "source": source,
            "family": fam,
            "file": h.get("file") or "",
            "line": h.get("line") or "",
            "terms": terms,
            # Structured matched needles: a term containing a comma cannot be
            # split into phantom terms by the event merge (EH-8).
            "terms_list": list(h.get("terms_list") or []),
            "artifact": art[:160] if art else "",
            "severity": sev,
        })
    return events


def artifacts_to_events(
    artifacts: list[Artifact],
    source: str = "i1",
    store_lines: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Imported artifacts as timeline events.

    ``store_lines`` (parallel to ``artifacts``) stamps the ingest-store loc so
    the same row arriving both here and as an N4 hit merges into ONE event
    instead of appearing twice.
    """
    events: list[dict[str, Any]] = []
    for idx, a in enumerate(artifacts):
        if a.source == ArtifactSource.GENERIC_JSONL:
            continue
        ts = a.timestamp.isoformat() if a.timestamp else ""
        desc = a.description or a.process_name or a.file_path or a.artifact_type.value
        if store_lines is not None and idx < len(store_lines):
            loc_file = "ingest/artifacts.jsonl"
            loc_line: Any = store_lines[idx]
        else:
            loc_file = a.file_path or ""
            loc_line = ""
        events.append({
            "timestamp": ts,
            "host": a.host or "",
            "description": str(desc)[:240],
            "source": f"{source}:{a.source.value}",
            "family": a.artifact_type.value,
            "file": loc_file,
            "line": str(loc_line) if loc_line != "" else "",
            "terms": ", ".join(a.technique_ids[:4]),
            "terms_list": list(a.technique_ids[:4]),
            "source_ip": a.source_ip or "",
            "dest_ip": a.dest_ip or "",
            # EH-7: provenance — this timestamp is the INGEST time, not the
            # event's own (the source timestamp was unparseable).
            "ts_synthesized": bool(getattr(a, "ts_synthesized", False)),
            "ts_year_assumed": bool(getattr(a, "ts_year_assumed", False)),
        })
    return events


def merge_events(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Tuple keys: string separators can collide (a '|'/':' inside a filename or
    # description used to merge two distinct events). EH-8.
    seen: dict[tuple, int] = {}
    out: list[dict[str, Any]] = []
    for group in groups:
        for ev in group:
            # (file, line) identifies the underlying artifact row — the same
            # row matched by two needles is ONE event (union the terms),
            # not two. Fall back to the content key for rows without loc.
            has_loc = bool(ev.get("file") and ev.get("line"))
            key: tuple = (
                ("loc", str(ev.get("file") or ""), str(ev.get("line") or ""))
                if has_loc
                else (
                    "content",
                    str(ev.get("timestamp") or ""),
                    str(ev.get("description") or "")[:120],
                    str(ev.get("source") or ""),
                    str(ev.get("file") or ""),
                )
            )
            if key in seen:
                prev = out[seen[key]]
                # Union matched needles + fill any fields the first event
                # lacked. Structured lists are unioned first so a term with a
                # comma never splits (EH-8); the display string follows.
                def _terms_of(event: dict[str, Any]) -> set[str]:
                    listed = event.get("terms_list")
                    if isinstance(listed, list) and listed:
                        return {str(t).strip() for t in listed if str(t).strip()}
                    return {
                        t.strip()
                        for t in str(event.get("terms") or "").split(",")
                        if t.strip()
                    }

                union = _terms_of(prev) | _terms_of(ev)
                if union:
                    prev["terms_list"] = sorted(union)
                    prev["terms"] = ", ".join(sorted(union))
                for k in ("severity", "host", "timestamp", "artifact", "note"):
                    if not prev.get(k) and ev.get(k):
                        prev[k] = ev[k]
                continue
            seen[key] = len(out)
            out.append(ev)
    out.sort(key=lambda e: (e.get("timestamp") or "9999", e.get("source") or "", e.get("file") or ""))
    return out


def load_ingest_artifacts(case_dir: Path) -> list[Artifact]:
    return [a for _n, a in load_ingest_artifacts_with_lines(case_dir)]


def load_ingest_artifacts_with_lines(case_dir: Path) -> list[tuple[int, Artifact]]:
    """(store line number, artifact) pairs — loc for timeline dedupe."""
    path = Path(case_dir) / "ingest" / "artifacts.jsonl"
    if not path.is_file():
        return []
    arts: list[tuple[int, Artifact]] = []
    for n, line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            arts.append((n, Artifact.from_dict(json.loads(line))))
        except Exception:
            continue
    return arts


def _artifact_key(d: dict) -> tuple:
    """Content key so re-ingesting the same evidence does not duplicate rows.

    Includes ports/protocol/user/file_path AND a hash of the raw record: two
    genuinely different events (same ts/IP pair, different URL/uid) must not
    collapse, and events whose timestamp was synthesized at parse time must
    still key stably across runs.
    """
    import hashlib

    raw = d.get("raw")
    raw_hash = ""
    if raw not in (None, "", {}):
        raw_hash = hashlib.sha1(
            str(raw).encode("utf-8", "replace")
        ).hexdigest()[:16]
    parts: tuple = (
        d.get("source"),
        d.get("artifact_type"),
        # With a raw record the hash IS the identity — parse-time synthesized
        # timestamps must not make the same row look new on every re-ingest.
        None if raw_hash else d.get("timestamp"),
        d.get("src_ip") or d.get("source_ip"),
        d.get("source_port"),
        d.get("dest_ip"),
        d.get("dest_port"),
        d.get("protocol"),
        d.get("user"),
        d.get("file_path"),
        d.get("process_name"),
        str(d.get("description") or d.get("details") or "")[:160],
        raw_hash,
    )
    return parts


def append_ingest_artifacts(case_dir: Path, artifacts: list[Artifact]) -> Path:
    """Append artifacts to the case ingest store, deduped by content key.

    Reprocessing the same network log must not double the store — keys are
    compared against the existing ``artifacts.jsonl`` before appending.
    """
    dest_dir = Path(case_dir) / "ingest"
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / "artifacts.jsonl"
    existing: set[str] = set()
    if path.is_file():
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        existing.add(_artifact_key(json.loads(line)))
                    except (json.JSONDecodeError, TypeError):
                        continue
        except OSError:
            existing = set()
    rows: list[str] = []
    for a in artifacts:
        d = a.to_dict()
        key = _artifact_key(d)
        if key in existing:
            continue
        existing.add(key)
        rows.append(json.dumps(d, default=str))
    if rows:
        with path.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(rows) + "\n")
    return path


def _ingest_limit() -> int:
    """Bound on artifacts stored per ingested file (env-configurable).

    ``NEXUS_INGEST_MAX_ARTIFACTS=0`` means unlimited (a bare ``0`` used to be
    clamped to 1 — silently storing a single row).
    """
    import os

    try:
        raw = int(os.environ.get("NEXUS_INGEST_MAX_ARTIFACTS", "20000"))
    except ValueError:
        raw = 20000
    if raw <= 0:
        return 2**31 - 1
    return raw


def ingest_into_case(
    path: Path,
    case_dir: Path,
    limit: int = 0,
    source: str | None = None,
) -> dict[str, Any]:
    """I1 ingest a file onto the case, then I3-ready artifact store."""
    from nexus.ingest.detect import resolve_ingest_source
    from nexus.ingest.registry import get_registry

    path = Path(path)
    resolved, err = resolve_ingest_source(path, source)
    if err:
        return {"success": False, "error": err, "artifacts": 0, "path": str(path)}
    if resolved is None:
        return {
            "success": False,
            "error": f"Could not detect format for {path.name}",
            "artifacts": 0,
            "path": str(path),
        }
    cap = limit if limit > 0 else _ingest_limit()
    result = get_registry().import_path(path, source=resolved, limit=cap)
    arts = list(result.artifacts or [])
    if arts:
        append_ingest_artifacts(case_dir, arts)
    capped = len(arts) >= cap
    return {
        "success": result.success,
        "source": result.source.value,
        "artifacts": len(arts),
        "artifacts_total": len(arts),
        "artifacts_capped": capped,
        "errors": result.errors[:5],
        "path": str(path),
    }


def _bookmark_events(case_dir: Path) -> list[dict[str, Any]]:
    """Workbench bookmarks → timeline events (source ``workbench``).

    Bookmarks are the examiner's flagged rows — they belong on the timeline
    the moment they're starred, pre-approval. Rows also matched by needles
    dedupe onto the richer n4 event via the file:line key; the examiner's
    note is carried across in the merge. Fields are re-attached so severity
    survives even though workbench.json strips them.
    """
    try:
        from nexus.case.workbench import load_bookmarks

        bookmarks = load_bookmarks(case_dir)
    except Exception:
        return []
    if not bookmarks:
        return []
    hits = [
        {
            "family": str(b.get("family") or ""),
            "file": str(b.get("file") or ""),
            "line": str(b.get("line") or ""),
            "text": str(b.get("text") or ""),
            "terms": "",
        }
        for b in bookmarks if isinstance(b, dict)
    ]
    try:
        from nexus.langgraph.query_pack import attach_hit_fields

        hits = attach_hit_fields(case_dir, hits)
    except Exception:
        pass
    events = hits_to_events(hits, source="workbench")
    for ev, b in zip(events, bookmarks, strict=False):
        if b.get("note"):
            ev["note"] = str(b["note"])[:200]
        if b.get("time") and not ev.get("timestamp"):
            ev["timestamp"] = str(b["time"])
        ev["status"] = "UNREVIEWED"  # bookmarked, pre-approval
    return events


def _finding_evidence_events(case_dir: Path) -> list[dict[str, Any]]:
    """Staged/approved findings' evidence rows → timeline events.

    The finding's own severity stamps the row; source tags it back to the
    finding so the timeline shows why the row matters.
    """
    events: list[dict[str, Any]] = []
    fp = case_dir / "findings.json"
    if not fp.is_file():
        return events
    try:
        findings = json.loads(fp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return events
    for f in findings if isinstance(findings, list) else []:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id") or "")
        fsev = str(f.get("severity") or "")
        for row in (f.get("evidence") or [])[:20]:
            if not isinstance(row, dict):
                continue
            loc = str(row.get("loc") or "")
            rfile, _, rline = loc.partition(":")
            if not rfile:
                rfile = str(row.get("artifact") or "")
            fam = str(row.get("source") or "").split("/")[0]
            events.append({
                "timestamp": str(row.get("time") or ""),
                "host": str(f.get("host") or ""),
                "description": str(row.get("detail") or f.get("title") or "")[:240],
                "status": str(f.get("status") or "DRAFT"),
                "source": f"finding:{fid}" if fid else "finding",
                "family": fam,
                "file": rfile,
                "line": rline,
                "terms": "",
                "severity": fsev,
            })
    return events


def rebuild_case_timeline(
    case_dir: Path,
    hits: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """N7: N4 hits + I1 artifacts + finding evidence + ledger events.

    Ledger events (T-* entries written by record_timeline_event / evidence
    registration) are MERGED back in — never dropped by a rebuild.
    """
    case_dir = Path(case_dir)
    intake = load_case_intake(case_dir)
    window = parse_intake_window(intake)
    start, end = window
    if hits is None:
        from nexus.langgraph.query_pack import (
            collect_playbook_query_terms,
            collect_query_terms,
            n4_hits,
        )

        terms = collect_query_terms(intake)
        if not terms:
            # Portal-created cases have no intake terms — fall back to the
            # needles a Mode 1 full-run actually scanned, so the timeline
            # still populates from real investigation work.
            run_path = case_dir / "analysis" / "mode1_full_run.json"
            try:
                rec = json.loads(run_path.read_text(encoding="utf-8"))
                terms = [str(t) for t in (rec.get("needles") or []) if str(t).strip()]
            except (OSError, json.JSONDecodeError, AttributeError):
                terms = []
        hits, _backend = n4_hits(
            case_dir, terms, window, priority_terms=collect_playbook_query_terms(intake),
        )
        try:
            from nexus.langgraph.query_pack import attach_hit_fields

            hits = attach_hit_fields(case_dir, hits)
        except Exception:
            pass  # fields absent → severity stays unset, timeline still builds
    # Ledger events already staged in timeline.json (evidence registration,
    # examiner notes, finding-linked events) must survive a rebuild.
    ledger_events: list[dict[str, Any]] = []
    tl_path = case_dir / "timeline.json"
    if tl_path.is_file():
        try:
            existing = json.loads(tl_path.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                existing = existing.get("events", [])
            ledger_events = [
                e for e in existing
                if isinstance(e, dict) and (e.get("id") or e.get("event_type"))
            ]
        except (OSError, json.JSONDecodeError):
            pass
    host_events = hits_to_events(hits or [])
    ingest_pairs = load_ingest_artifacts_with_lines(case_dir)
    ingest_events = artifacts_to_events(
        [a for _n, a in ingest_pairs],
        store_lines=[n for n, _a in ingest_pairs],
    )
    merged = merge_events(
        ledger_events,
        _finding_evidence_events(case_dir),
        host_events,
        _bookmark_events(case_dir),
        ingest_events,
    )
    # Window scopes host telemetry; ledger events (id/event_type — evidence
    # registration, examiner notes) are case activity and always kept.
    scoped = [
        e for e in merged
        if (e.get("id") or e.get("event_type"))
        or _in_window(e.get("timestamp") or None, start, end)
    ]
    tl_path = case_dir / "timeline.json"
    tl_path.write_text(json.dumps(scoped, indent=2), encoding="utf-8")
    analysis = case_dir / "analysis"
    analysis.mkdir(parents=True, exist_ok=True)
    lines = [
        "# N7 chronology\n",
        "Host N4 hits merged with I1 importer events. Empty timestamp = keyword hit without a date.\n",
        f"Events: {len(scoped)}\n",
    ]
    for ev in scoped[:200]:
        ts = ev.get("timestamp") or "(no ts)"
        lines.append(f"- `{ts}` [{ev.get('source')}] {ev.get('description')}")
    extra_i1 = [
        e for e in scoped[200:]
        if str(e.get("source") or "").lower().startswith("i1")
    ]
    if extra_i1:
        lines.append("\n## Import/ingest (I1)\n")
        for ev in extra_i1[:40]:
            ts = ev.get("timestamp") or "(no ts)"
            lines.append(f"- `{ts}` [{ev.get('source')}] {ev.get('description')}")
    (analysis / "chronology.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return scoped
