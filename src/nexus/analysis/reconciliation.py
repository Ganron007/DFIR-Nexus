"""Row reconciliation — tool output records vs indexed docs (WO-3, report-only).

The single method that found most debug defects during the debug cycle: compare
a count from the tool's own output with the count the pipeline reports as
indexed. D1, D2, D13, D15, D22, D23, D30, D32, D35, D36, D53 and D55 would
each have been caught here automatically.

``delta = source_records - docs - deduped``

* ``source_records`` — the records the file itself contains. CSV/TSV via the
  ``csv`` module so a quoted newline stays one record, minus a header when the
  indexer would treat line 1 as one (same heuristic: comma/tab present and the
  file is not JSON-records). JSON/JSONL/NDJSON non-empty lines, text/log
  non-empty lines; ``.gz`` transparent. A format with no defined record count
  is ``unreconcilable`` — never a silent match.
* ``docs`` — documents this index accepted from the file.
* ``deduped`` — rows the index dropped as duplicates of an earlier row; they
  are accounted for, not a mismatch.

Phase-in: this ships **report-only** (report section + coverage/briefing
line). Flipping mismatches to block the lane gate is a separate,
operator-approved commit.

Families whose mapping is legitimately not 1 record = 1 doc must be declared
in :data:`FAMILY_OVERRIDES` with a reason. That table is the only place this
relaxation may live — nothing is skipped silently.
"""
from __future__ import annotations

import contextlib
import csv
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
FILENAME = "reconciliation.json"

#: family -> reason the mapping is legitimately not 1 record = 1 doc.
FAMILY_OVERRIDES: dict[str, str] = {}

_TABLE_SUFFIXES = {".csv", ".tsv"}
_LINE_SUFFIXES = {".jsonl", ".ndjson", ".txt", ".log"}
_JSON_SUFFIXES = {".json", ".jsonl", ".ndjson"}


def _effective_suffix(path: Path) -> str:
    name = path.name.lower()
    if name.endswith(".gz"):
        name = name[:-3]
    return Path(name).suffix


def _count_lines(path: Path) -> int:
    from nexus.langgraph.case_index import _open_text_auto

    with _open_text_auto(path) as fh:
        return sum(1 for line in fh if line.strip())


def _count_table_rows(path: Path, delimiter: str) -> int:
    import gzip

    if str(path).lower().endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as fh:
            return sum(1 for _ in csv.reader(fh, delimiter=delimiter))
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        return sum(1 for _ in csv.reader(fh, delimiter=delimiter))


def _count_json_records(path: Path) -> int | None:
    """Records a .json/.jsonl/.ndjson file contains (WO-15).

    .jsonl/.ndjson are line records, the way the indexer reads them. .json is
    **parsed**: an array counts its elements, an object (or scalar) counts 1.
    Counting the file's *lines* for .json made this check mirror the reader - a
    pretty-printed array the indexer fragmented into line-docs reconciled at
    delta 0 (D36's class), which is exactly what this check exists to catch.
    ``None`` when the JSON cannot be parsed: unreconcilable, never a silent
    match.
    """
    suffix = _effective_suffix(path)
    if suffix in (".jsonl", ".ndjson"):
        return _count_lines(path)
    from nexus.langgraph.case_index import _open_text_auto

    try:
        with _open_text_auto(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if isinstance(data, list):
        return len(data)
    return 1


def _fragmentation_line_count(path: Path) -> int | None:
    """Non-empty lines of a .json ARRAY whose element count differs (WO-15).

    A line-fragmenting index produces exactly the non-empty-line count as its
    doc count; returning it lets the reconciler name that shape instead of
    reporting a plain short count.
    """
    if _effective_suffix(path) != ".json":
        return None
    records = _count_json_records(path)
    if records is None:
        return None
    lines = _count_lines(path)
    return lines if lines != records else None


def source_record_count(path: Path) -> int | None:
    """Records the file itself contains, or ``None`` when undefined.

    The header rule mirrors the indexer (``_index_header``): when line 1 looks
    like a delimited table it is a header and is not a record. Blank lines are
    not records.
    """
    p = Path(path)
    if not p.is_file():
        return None
    suffix = _effective_suffix(p)
    if suffix in _JSON_SUFFIXES:
        return _count_json_records(p)
    from nexus.langgraph.case_index import _index_header  # parity with the indexer

    header = _index_header(p) if suffix in _TABLE_SUFFIXES or suffix in _LINE_SUFFIXES else None
    subtract = 1 if header is not None else 0
    if suffix in _TABLE_SUFFIXES:
        rows = _count_table_rows(p, "\t" if suffix == ".tsv" else ",")
    elif suffix in _LINE_SUFFIXES:
        rows = _count_lines(p)
    else:
        return None
    return max(0, rows - subtract)


def _resolved_paths(case_dir: Path) -> dict[str, tuple[Path | None, str | None]]:
    """Map index keys (``file`` values) back to real paths + families.

    Uses the same resolver as the indexer (``iter_extraction_files``), so a
    renamed/removed root shows up as ``missing`` rather than a false match.
    """
    out: dict[str, tuple[Path | None, str | None]] = {}
    with contextlib.suppress(Exception):
        from nexus.langgraph.case_index import _index_rel
        from nexus.langgraph.query_pack import iter_extraction_files

        for path, root, fam in iter_extraction_files(case_dir):
            out[_index_rel(path, root)] = (path, fam)
    ingest = case_dir / "ingest" / "artifacts.jsonl"
    if ingest.is_file():
        out.setdefault("ingest/artifacts.jsonl", (ingest, "ingest"))
    return out


def _classify(
    family: str | None, source: int | None, docs: int, deduped: int
) -> tuple[str, int | None, str, str]:
    """Return ``(status, delta, note, override_reason)`` for one file."""
    if source is None:
        return "unreconcilable", None, "no record count defined for this format", ""
    delta = source - docs - deduped
    override = FAMILY_OVERRIDES.get(str(family or ""))
    if override:
        return "override", delta, "", override
    if delta == 0:
        return "match", delta, "", ""
    note = ""
    if delta < 0:
        note = (
            "the index holds more docs than the file has records "
            "(quoted newlines fragmented, or a stale index)"
        )
    return "mismatch", delta, note, ""


def reconcile_case(case_dir: Path | str) -> dict[str, Any]:
    """Compare every indexed file's record count with its doc count.

    Reads ``analysis/es_index.json`` (``file_counts``, written by the indexer),
    counts each file's records, and writes ``analysis/reconciliation.json``.
    Report-only: nothing here blocks a lane or a gate.
    """
    case_dir = Path(case_dir)
    analysis = case_dir / "analysis"
    meta_path = analysis / "es_index.json"
    meta: dict[str, Any] = {}
    meta_mtime = 0.0
    if meta_path.is_file():
        with contextlib.suppress(OSError, ValueError):
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            meta_mtime = meta_path.stat().st_mtime
    counts = meta.get("file_counts") or {}
    paths = _resolved_paths(case_dir)

    files: list[dict[str, Any]] = []
    for rel in sorted(counts):
        entry = counts.get(rel) or {}
        docs = int(entry.get("docs") or 0)
        deduped = int(entry.get("deduped") or 0)
        path, family = paths.get(rel, (None, None))
        if path is None:
            files.append({
                "file": rel, "family": family, "docs": docs, "deduped": deduped,
                "source_records": None, "delta": None, "status": "missing",
                "note": "indexed file no longer resolves on disk",
            })
            continue
        source = source_record_count(path)
        status, delta, note, override = _classify(family, source, docs, deduped)
        if status == "mismatch":
            frag = _fragmentation_line_count(path)
            if frag is not None and docs == frag:
                status = "fragmented"
                note = (
                    f"{docs} doc(s) look like line fragments of a json array "
                    f"with {source} element(s) - index the file as records, "
                    f"not lines (D36 class)"
                )
        row: dict[str, Any] = {
            "file": rel, "family": family, "docs": docs, "deduped": deduped,
            "source_records": source, "delta": delta, "status": status,
        }
        if note:
            row["note"] = note
        if override:
            row["override_reason"] = override
        files.append(row)

    totals = {
        "files": len(files),
        "match": sum(1 for f in files if f["status"] == "match"),
        "mismatch": sum(1 for f in files if f["status"] == "mismatch"),
        "fragmented": sum(1 for f in files if f["status"] == "fragmented"),
        "override": sum(1 for f in files if f["status"] == "override"),
        "unreconcilable": sum(1 for f in files if f["status"] == "unreconcilable"),
        "missing": sum(1 for f in files if f["status"] == "missing"),
        "source_records": sum(int(f["source_records"] or 0) for f in files),
        "docs": sum(int(f["docs"] or 0) for f in files),
        "deduped": sum(int(f["deduped"] or 0) for f in files),
    }
    out: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "case_id": case_dir.name,
        "generated_at": datetime.now(UTC).isoformat(),
        "report_only": True,
        "file_counts_present": bool(counts),
        "index_meta_mtime": meta_mtime,
        "index_meta_docs": meta.get("docs"),
        "files": files,
        "totals": totals,
        "overrides": dict(FAMILY_OVERRIDES),
    }
    if not counts:
        out["note"] = (
            "no per-file counts in analysis/es_index.json — re-index the case "
            "to enable row reconciliation"
        )
    analysis.mkdir(parents=True, exist_ok=True)
    tmp = analysis / f"{FILENAME}.tmp"
    tmp.write_text(json.dumps(out, indent=2, sort_keys=True, default=str), encoding="utf-8")
    os.replace(tmp, analysis / FILENAME)
    return out


def load_or_reconcile(case_dir: Path | str) -> dict[str, Any]:
    """Reuse the persisted result when it matches the current index meta."""
    case_dir = Path(case_dir)
    path = case_dir / "analysis" / FILENAME
    meta_path = case_dir / "analysis" / "es_index.json"
    if path.is_file():
        with contextlib.suppress(OSError, ValueError):
            data = json.loads(path.read_text(encoding="utf-8"))
            current = meta_path.stat().st_mtime if meta_path.is_file() else 0.0
            if isinstance(data, dict) and data.get("index_meta_mtime") == current:
                data["cached"] = True
                return data
    return reconcile_case(case_dir)


def summary_line(rec: dict[str, Any]) -> str:
    """One line for coverage/briefing surfaces. Never claims more than it did."""
    if not rec.get("file_counts_present"):
        return (
            "Row reconciliation: not available — the index has no per-file "
            "counts yet (re-index to enable)"
        )
    t = rec.get("totals") or {}
    return (
        f"Row reconciliation: {t.get('match', 0)}/{t.get('files', 0)} file(s) match "
        f"({t.get('mismatch', 0)} mismatch, {t.get('fragmented', 0)} fragmented, "
        f"{t.get('override', 0)} overridden, "
        f"{t.get('unreconcilable', 0)} unreconcilable, {t.get('missing', 0)} missing) "
        "— report-only"
    )


def render_reconciliation_markdown(rec: dict[str, Any], *, limit: int = 25) -> str:
    """Report section. Only mismatches are tabulated; the rest is counted."""
    if not rec:
        return ""
    lines = ["## Row reconciliation", "", summary_line(rec), ""]
    mismatches = [
        f for f in rec.get("files") or ()
        if f.get("status") in ("mismatch", "fragmented")
    ]
    if mismatches:
        lines += ["| File | family | source | docs | deduped | delta |",
                  "|---|---|---|---|---|---|"]
        for f in mismatches[:limit]:
            lines.append(
                f"| {f.get('file')} | {f.get('family') or '-'} | {f.get('source_records')} "
                f"| {f.get('docs')} | {f.get('deduped')} | {f.get('delta')} |"
            )
        if len(mismatches) > limit:
            lines.append(f"| ... | {len(mismatches) - limit} more | | | | |")
    elif (rec.get("totals") or {}).get("files"):
        lines.append("No mismatches.")
    lines.append("")
    return "\n".join(lines)
