"""N7 chronology + I3 merge — host query hits and importer events, one timeline."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from nexus.langgraph.query_pack import _DATE_RE, load_case_intake, parse_window
from nexus.ingest.schemas import Artifact


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
    events: list[dict[str, Any]] = []
    for h in hits:
        text = h.get("text") or ""
        ts = _parse_ts(text)
        events.append({
            "timestamp": ts or "",
            "host": "",
            "description": text[:240],
            "source": source,
            "family": h.get("family") or "",
            "file": h.get("file") or "",
            "line": h.get("line") or "",
            "terms": h.get("terms") or "",
        })
    return events


def artifacts_to_events(artifacts: list[Artifact], source: str = "i1") -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for a in artifacts:
        ts = a.timestamp.isoformat() if a.timestamp else ""
        desc = a.description or a.process_name or a.file_path or a.artifact_type.value
        events.append({
            "timestamp": ts,
            "host": a.host or "",
            "description": str(desc)[:240],
            "source": f"{source}:{a.source.value}",
            "family": a.artifact_type.value,
            "file": a.file_path or "",
            "line": "",
            "terms": ",".join(a.technique_ids[:4]),
            "source_ip": a.source_ip or "",
            "dest_ip": a.dest_ip or "",
        })
    return events


def merge_events(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for group in groups:
        for ev in group:
            key = "|".join([
                str(ev.get("timestamp") or ""),
                str(ev.get("description") or "")[:120],
                str(ev.get("source") or ""),
                str(ev.get("file") or ""),
            ])
            if key in seen:
                continue
            seen.add(key)
            out.append(ev)
    out.sort(key=lambda e: (e.get("timestamp") or "9999", e.get("source") or "", e.get("file") or ""))
    return out


def load_ingest_artifacts(case_dir: Path) -> list[Artifact]:
    path = Path(case_dir) / "ingest" / "artifacts.jsonl"
    if not path.is_file():
        return []
    arts: list[Artifact] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            arts.append(Artifact.from_dict(json.loads(line)))
        except Exception:
            continue
    return arts


def append_ingest_artifacts(case_dir: Path, artifacts: list[Artifact]) -> Path:
    dest_dir = Path(case_dir) / "ingest"
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / "artifacts.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        for a in artifacts:
            fh.write(json.dumps(a.to_dict(), default=str) + "\n")
    return path


def ingest_into_case(path: Path, case_dir: Path, limit: int = 400) -> dict[str, Any]:
    """I1 ingest a file onto the case, then I3-ready artifact store."""
    from nexus.ingest.detect import detect_format
    from nexus.ingest.registry import get_registry

    path = Path(path)
    source = detect_format(path)
    if source is None:
        return {"success": False, "error": f"Could not detect format for {path.name}", "artifacts": 0}
    result = get_registry().import_path(path, source=source)
    arts = list(result.artifacts or [])[:limit]
    if arts:
        append_ingest_artifacts(case_dir, arts)
    return {
        "success": result.success,
        "source": result.source.value,
        "artifacts": len(arts),
        "errors": result.errors[:5],
        "path": str(path),
    }


def rebuild_case_timeline(
    case_dir: Path,
    hits: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """N7: N4 hits + I1 artifacts, window-scoped, written to timeline.json."""
    case_dir = Path(case_dir)
    intake = load_case_intake(case_dir)
    window = parse_window(" ".join(filter(None, [intake.get("window", ""), intake.get("question", "")])))
    start, end = window
    if hits is None:
        from nexus.langgraph.query_pack import (
            collect_playbook_query_terms,
            collect_query_terms,
            n4_hits,
        )

        terms = collect_query_terms(intake)
        hits, _backend = n4_hits(
            case_dir, terms, window, priority_terms=collect_playbook_query_terms(intake),
        )
    host_events = hits_to_events(hits or [])
    ingest_events = artifacts_to_events(load_ingest_artifacts(case_dir))
    merged = merge_events(host_events, ingest_events)
    scoped = [e for e in merged if _in_window(e.get("timestamp") or None, start, end)]
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
