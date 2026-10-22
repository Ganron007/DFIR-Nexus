"""N7 chronology + I3 merge — host query hits and importer events, one timeline."""

from __future__ import annotations

import contextlib
import csv
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.case.locks import lock_case_writes
from nexus.ingest.schemas import Artifact, ArtifactSource
from nexus.langgraph.evidence_rows import row_time
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


def _hit_flag(hit: dict[str, Any], flag: str, text: str) -> bool:
    fields = hit.get("fields")
    if isinstance(fields, dict) and str(fields.get(flag) or "").lower() in (
        "true", "1", "yes",
    ):
        return True
    return f"{flag}=true" in str(text or "")


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
        rows = evidence_rows_from_n4_hits([h])
        art = (rows[0].get("artifact") if rows else "") or ""
        if art and art not in {"—", terms}:
            desc = f"{fam} [{terms}]: {art}"
        elif rows and rows[0].get("detail"):
            desc = f"{fam} [{terms}]: {rows[0].get('detail')}"
        else:
            desc = f"{fam} [{terms}]: {text}"
        sev = ""
        try:
            from nexus.modes.llm_desk import _severity_from_hits

            sev = _severity_from_hits([h]) if h.get("fields") else ""
        except Exception:
            sev = ""
        events.append({
            "timestamp": ts or "",
            "host": host,
            "description": desc,
            "source": source,
            "family": fam,
            "file": h.get("file") or "",
            "line": h.get("line") or "",
            "terms": terms,
            # Structured matched needles: a term containing a comma cannot be
            # split into phantom terms by the event merge (EH-8).
            "terms_list": list(h.get("terms_list") or []),
            "artifact": art,
            "severity": sev,
            # EH-7 flags come from the enriched fields/text of the hit.
            "ts_synthesized": _hit_flag(h, "ts_synthesized", text),
            "ts_year_assumed": _hit_flag(h, "ts_year_assumed", text),
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
            "description": str(desc),
            "source": f"{source}:{a.source.value}",
            "family": a.artifact_type.value,
            "file": loc_file,
            "line": str(loc_line) if loc_line != "" else "",
            "terms": ", ".join(a.technique_ids),
            "terms_list": list(a.technique_ids),
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
                    str(ev.get("description") or ""),
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
                # Merge honesty flags — the ingest-projection event may arrive
                # after the hit event for the same row (first-wins preserved
                # everything else, and the flags were lost).
                for flag in ("ts_synthesized", "ts_year_assumed"):
                    if ev.get(flag) and not prev.get(flag):
                        prev[flag] = True
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
        str(d.get("description") or d.get("details") or ""),
        raw_hash,
    )
    return parts


#: The dedupe keys of each store, kept between appends (path -> (mtime_ns, size, keys)). Re-reading the
#: whole store on every append made an import quadratic: one volume of files is thousands of appends.
#: The cache is trusted only while the file's size and mtime still match what the last append left.
_STORE_KEYS: dict[str, tuple[int, int, set[tuple]]] = {}


def _store_keys(path: Path) -> set[tuple]:
    """The content keys already in ``artifacts.jsonl``: read once, then kept up to date."""
    cache_key = str(path)
    try:
        st = path.stat()
    except OSError:
        _STORE_KEYS.pop(cache_key, None)
        return set()
    cached = _STORE_KEYS.get(cache_key)
    if cached and (cached[0], cached[1]) == (st.st_mtime_ns, st.st_size):
        return cached[2]
    keys: set[tuple] = set()
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    keys.add(_artifact_key(json.loads(line)))
                except (json.JSONDecodeError, TypeError):
                    continue
    except OSError:
        return set()
    return keys


def append_ingest_artifacts(case_dir: Path, artifacts: list[Artifact]) -> Path:
    """Append artifacts to the case ingest store, deduped by content key.

    Reprocessing the same network log must not double the store. Keys are compared against the keys
    already in ``artifacts.jsonl``; they are read once and kept, not re-read on every append.
    """
    dest_dir = Path(case_dir) / "ingest"
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / "artifacts.jsonl"
    existing = _store_keys(path)
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
    # The keys now match the file. Remember the signature the append left, so the next call reuses them.
    try:
        st = path.stat()
        _STORE_KEYS[str(path)] = (st.st_mtime_ns, st.st_size, existing)
    except OSError:
        _STORE_KEYS.pop(str(path), None)
    return path


def anchor_assumed_years(case_dir: Path) -> dict[str, Any]:
    """Give a yearless time (RFC 3164 syslog) the year of the case's own dated evidence (D262).

    The importer gives such a time the current year and flags it ``ts_year_assumed``. On sample S03 a mail
    server's and a firewall's syslog read 2026-07-12 beside the BIND queries and packets of 2016-07-12, so no time
    window held the three together. After the importer pass, each assumed row takes the year that puts its month,
    day and time inside the span of the case's dated rows (a month either side), the nearest to their middle when
    more than one does; the examiner's window, when set, is that span. The row stays flagged and says where its
    year came from. With no dated row, or no year that fits, the row is left as it was.
    """
    from datetime import timedelta

    path = Path(case_dir) / "ingest" / "artifacts.jsonl"
    if not path.is_file():
        return {"anchored": 0, "unresolved": 0}
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue

    def _flag(d: dict, key: str) -> bool:
        return str(d.get(key) or "").lower() in ("true", "1", "yes")

    def _dt(d: dict) -> datetime | None:
        try:
            got = datetime.fromisoformat(str(d.get("timestamp") or "").replace("Z", "+00:00"))
        except ValueError:
            return None
        return got if got.tzinfo else got.replace(tzinfo=UTC)

    assumed = [d for d in rows if _flag(d, "ts_year_assumed") and not d.get("ts_year_from")]
    if not assumed:
        return {"anchored": 0, "unresolved": 0}
    span: tuple[datetime, datetime] | None = None
    basis = ""
    try:
        start, end = parse_intake_window(load_case_intake(Path(case_dir)))
        if start and end:
            span, basis = (start, end), "the examiner's window"
    except Exception:  # noqa: BLE001 - the window is optional
        span = None
    if span is None:
        dated = sorted(t for d in rows if not _flag(d, "ts_year_assumed") and not _flag(d, "ts_synthesized")
                       for t in [_dt(d)] if t is not None)
        if not dated:
            return {"anchored": 0, "unresolved": len(assumed)}
        span, basis = (dated[0], dated[-1]), "the case's dated rows"
    low, high = span[0] - timedelta(days=31), span[1] + timedelta(days=31)
    middle = span[0] + (span[1] - span[0]) / 2
    anchored = unresolved = 0
    for d in assumed:
        t = _dt(d)
        if t is None:
            unresolved += 1
            continue
        fits = []
        for year in range(span[0].year - 1, span[1].year + 2):
            try:
                candidate = t.replace(year=year)
            except ValueError:  # 29 February in a year without one
                continue
            if low <= candidate <= high:
                fits.append(candidate)
        if not fits:
            unresolved += 1
            continue
        best = min(fits, key=lambda c: abs(c - middle))
        d["timestamp"] = best.isoformat()
        d["ts_year_from"] = f"{basis} {span[0].date()}..{span[1].date()}"
        anchored += 1
    if anchored:
        tmp = path.with_suffix(".jsonl.tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            fh.write("\n".join(json.dumps(d, default=str) for d in rows) + "\n")
        os.replace(tmp, path)
        _STORE_KEYS.pop(str(path), None)
    return {"anchored": anchored, "unresolved": unresolved, "basis": basis}


_GZIP_MAGIC = b"\x1f\x8b"


def gunzipped_working_copy(path: Path, case_dir: Path) -> Path | None:
    """A decompressed working copy of a gzipped file, or None when the file is not gzip (D275).

    Cloud and log exports arrive gzipped: sample S07's CloudTrail records and VPC flow logs are 3,900 ``.gz``
    files, which no importer read (detection returned "no importer" for any ``.gz`` but a Zeek log). The copy is
    the inner file, under the case's ingest ``_staged`` folder (never indexed as rows of its own), so every importer
    reads it as it reads any file; the original stays where it is and the import names it.
    """
    import gzip
    import hashlib
    import shutil

    try:
        with path.open("rb") as fh:
            if fh.read(2) != _GZIP_MAGIC:
                return None
    except OSError:
        return None
    name = path.name
    lowered = name.lower()
    if lowered.endswith(".tgz"):
        name = name[:-4] + ".tar"
    elif lowered.endswith(".gz"):
        name = name[:-3]
    digest = hashlib.sha1(str(path.resolve()).encode("utf-8", "replace")).hexdigest()[:12]
    dest = Path(case_dir) / "ingest" / "_staged" / "gunzip" / digest / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    with gzip.open(path, "rb") as src, part.open("wb") as out:
        shutil.copyfileobj(src, out, 1 << 20)
    os.replace(part, dest)
    return dest


@lock_case_writes(case_arg=1)
def _placed_tool_csv(path: Path, case_dir: Path) -> tuple[str, Path, int] | None:
    """A tool's CSV the examiner already ran, placed for the index as that tool's output (D283, 2026-10-18).

    EvtxECmd, MFTECmd, PECmd or RECmd output is indexed as its family from ``ingest/<family>/``, the copy that
    registering the CSV on its own makes. A CSV inside a registered folder was read again as generic rows (sample
    S09: 626,255 rows under no family) or failed on an importer the family does not have. Returns the family, the
    placed copy and its row count, or None when the CSV is no known tool's.
    """
    from nexus.ingest.fingerprint import place_recognized_csv

    if path.suffix.lower() != ".csv":
        return None
    dest = place_recognized_csv(path, case_dir / "ingest")
    if dest is None:
        return None
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    with dest.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
        rows = max(sum(1 for _ in csv.reader(fh)) - 1, 0)
    return dest.parent.name, dest, rows


def ingest_into_case(
    path: Path,
    case_dir: Path,
    source: str | None = None,
    audit: bool = True,
) -> dict[str, Any]:
    """I1 ingest a file onto the case, then I3-ready artifact store.

    ``audit=True`` writes a case-scoped ``ingest_auto`` audit entry so the
    imported family is LINKABLE by findings (EH-9). Callers that already
    audit the run (CLI, MCP ingest_auto) pass ``audit=False`` to avoid a
    duplicate entry.
    """
    from nexus.ingest.detect import resolve_ingest_source
    from nexus.ingest.registry import get_registry

    original = Path(path)
    try:
        working = gunzipped_working_copy(original, Path(case_dir))
    except (OSError, EOFError) as exc:
        return {"success": False, "error": f"gzip: {exc}", "artifacts": 0, "path": str(original)}
    path = working or original
    if source is None:
        placed = _placed_tool_csv(path, Path(case_dir))
        if placed is not None:
            family, dest, rows = placed
            if audit:
                with contextlib.suppress(Exception):
                    from nexus.audit import AuditWriter

                    AuditWriter("nexus", audit_dir=Path(case_dir) / "audit").log(
                        tool="ingest_auto",
                        params={"path": str(original), "source": "",
                                **({"working_copy": str(working)} if working else {})},
                        result_summary={"success": True, "artifacts": rows, "source": family,
                                        "placed_at": str(dest)},
                        source="pipeline",
                        input_files=[str(original)],
                    )
            return {"success": True, "source": family, "artifacts": rows, "artifacts_total": rows,
                    "artifacts_capped": False, "errors": [], "placed_at": str(dest), "path": str(original)}
    resolved, err = resolve_ingest_source(path, source)
    if err:
        return {"success": False, "error": err, "artifacts": 0, "path": str(original)}
    if resolved is None:
        return {
            "success": False,
            "error": f"Could not detect format for {original.name}",
            "artifacts": 0,
            "path": str(original),
        }
    stored = 0
    import_context: dict[str, Any] = {}
    if getattr(resolved, "value", resolved) == "scheduled_tasks":
        from nexus.ingest.windows_timezones import record_case_host_timezones

        import_context["host_timezones"] = record_case_host_timezones(Path(case_dir))

    def _store(batch: list[Any]) -> None:
        nonlocal stored
        append_ingest_artifacts(case_dir, batch)
        stored += len(batch)

    result = get_registry().import_path(
        path,
        source=resolved,
        on_batch=_store,
        context=import_context,
    )
    if audit:
        with contextlib.suppress(Exception):
            from nexus.audit import AuditWriter

            AuditWriter("nexus", audit_dir=Path(case_dir) / "audit").log(
                tool="ingest_auto",
                params={"path": str(original), "source": source or "",
                        **({"working_copy": str(working)} if working else {})},
                result_summary={
                    "success": result.success,
                    "artifacts": result.parsed_lines,
                    "source": result.source.value,
                    "persisted": bool(stored),
                },
                source="pipeline",
                input_files=[str(original)],
            )
    return {
        "success": result.success,
        "source": result.source.value,
        "artifacts": result.parsed_lines,
        "artifacts_total": result.parsed_lines,
        "artifacts_capped": False,
        "errors": result.errors,
        "path": str(original),
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
        if row_time(b) and not ev.get("timestamp"):
            ev["timestamp"] = row_time(b)
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
        for row in (f.get("evidence") or []):
            if not isinstance(row, dict):
                continue
            loc = str(row.get("loc") or "")
            rfile, _, rline = loc.partition(":")
            if not rfile:
                rfile = str(row.get("artifact") or "")
            fam = str(row.get("source") or "").split("/")[0]
            events.append({
                "timestamp": row_time(row),
                "host": str(f.get("host") or ""),
                "description": str(row.get("detail") or f.get("title") or ""),
                "status": str(f.get("status") or "DRAFT"),
                "source": f"finding:{fid}" if fid else "finding",
                "family": fam,
                "file": rfile,
                "line": rline,
                "terms": "",
                "severity": fsev,
            })
    return events


@lock_case_writes
def rebuild_case_timeline(
    case_dir: Path,
    hits: list[dict[str, str]] | None = None,
    run_id: str = "",
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
        from nexus.langgraph.query_pack import attach_hit_fields, n4_hits

        terms, priority_terms = timeline_query_plan(case_dir, intake)
        hits, _backend = n4_hits(
            case_dir, terms, window, priority_terms=priority_terms,
            run_id=run_id,
        )
        with contextlib.suppress(Exception):
            hits = attach_hit_fields(case_dir, hits, run_id=run_id)
            # Fields absent → severity stays unset; the timeline still builds.
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
    from nexus.case.outputs import _atomic_write_json as _atomic

    _atomic(tl_path, scoped)
    analysis = case_dir / "analysis"
    analysis.mkdir(parents=True, exist_ok=True)
    lines = [
        "# N7 chronology\n",
        "Host N4 hits merged with I1 importer events. Empty timestamp = keyword hit without a date.\n",
        f"Events: {len(scoped)}\n",
    ]
    for ev in scoped:
        ts = ev.get("timestamp") or "(no ts)"
        lines.append(f"- `{ts}` [{ev.get('source')}] {ev.get('description')}")
    (analysis / "chronology.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return scoped


def timeline_query_plan(
    case_dir: Path,
    intake: dict[str, str] | None = None,
) -> tuple[list[str], list[str]]:
    """Return the exact terms and priorities used for a timeline N4 search."""
    case_dir = Path(case_dir)
    intake = load_case_intake(case_dir) if intake is None else intake
    from nexus.langgraph.query_pack import (
        collect_playbook_query_terms,
        collect_query_terms,
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
    return terms, collect_playbook_query_terms(intake)
