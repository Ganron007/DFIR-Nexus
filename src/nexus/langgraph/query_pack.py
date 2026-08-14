"""N4 query pack — filter parsed CSVs/txt by intake window + playbook terms.

First N3 backend (no cluster). Interpret reads hits, not file heads.
Does not hardcode case plots: terms come from playbook YAML + intake tokens.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from nexus.integration.evidence_table import evidence_rows_from_n4_hits

_MAX_HITS_PER_FILE = 40
_MAX_HITS_TOTAL = 400
_MAX_LINE = 480
_MAX_MD = 60000
_DATE_RE = re.compile(r"\b(20\d{2}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}:\d{2}))?")
_EXE_RE = re.compile(r"\b[\w.-]+\.exe\b", re.I)
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\\:-]{2,}")
_STOP = frozenset(
    {
        "the", "and", "for", "from", "with", "what", "this", "that", "host",
        "activity", "supports", "refutes", "insider", "misuse", "data",
        "staging", "external", "compromise", "hypothesis", "interpret",
        "windows", "artifacts", "automated", "investigation", "via",
        "langgraph", "pipeline", "examiner", "supplied", "evidence",
        "timestamps", "win", "user", "profiles", "both", "lenses",
        "authorized", "threat", "or", "not", "invent", "name",
        "insider-threat",
    }
)
_FAMILY_HINTS = (
    "pecmd", "prefetch", "jlecmd", "lecmd", "sbecmd", "rbcmd", "srum",
    "srumecmd", "recmd", "hayabusa", "evtx", "mftecmd", "amcache",
    "appcompat", "wxtcmd", "bits", "vol", "fls", "setupapi",
)
_SCAN_FIRST = (
    "userassist", "wordwheel", "recentdocs", "opensave",
    "rbcmd", "srum", "jlecmd", "lecmd", "wxtcmd", "pecmd", "recmd",
)
_SKIP_SUFFIXES = ("_stdout.txt", "_stderr.txt", "_meta.json")
_MAX_COLLECT_PER_FILE = 200
_USB_TERMS = frozenset({"usbstor", "mountpoints2"})
_CLOUD_TERMS = frozenset({"googledrive", "drivefs", "my drive"})
# High-volume in host CSVs; keep some hits but never ahead of wipe/PST/C2 terms.
_WEAK_TERMS = frozenset({
    "onedrive", "recycle.bin", "$recycle", "removable", "setupapi",
    "winrar", "rar.exe", "7z.exe", "compact.exe", "winrar.exe",
})


def _scan_prio(path: Path) -> tuple:
    n = str(path).lower()
    for i, hint in enumerate(_SCAN_FIRST):
        if hint in n:
            return (i, n)
    return (40, n)


def load_case_intake(case_dir: Path) -> dict[str, str]:
    """Intake from CASE.yaml (nested ``intake`` plus a few top-level keys)."""
    import yaml

    meta_path = Path(case_dir) / "CASE.yaml"
    if not meta_path.is_file():
        return {}
    try:
        loaded = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    if not isinstance(loaded, dict):
        return {}
    out: dict[str, str] = {}
    nested = loaded.get("intake")
    if isinstance(nested, dict):
        for k, v in nested.items():
            if v is not None and str(v).strip():
                out[str(k)] = str(v).strip()
    for k in ("question", "window", "subjects", "hypothesis", "playbooks", "notes"):
        if k not in out and loaded.get(k):
            out[k] = str(loaded[k]).strip()
    return out


def parse_window(text: str) -> tuple[datetime | None, datetime | None]:
    """Parse YYYY-MM-DD (optional time) from intake. Unparseable → no filter."""
    dates = list(_DATE_RE.finditer(text or ""))
    if not dates:
        return None, None

    def _dt(m: re.Match[str], end_of_day: bool = False) -> datetime:
        d = datetime.strptime(m.group(1), "%Y-%m-%d").replace(tzinfo=UTC)
        if m.group(2):
            hh, mm, ss = (int(x) for x in m.group(2).split(":"))
            return d.replace(hour=hh, minute=mm, second=ss)
        if end_of_day:
            return d + timedelta(days=1) - timedelta(microseconds=1)
        return d

    start = _dt(dates[0])
    end = _dt(dates[-1], end_of_day=True) if len(dates) > 1 else _dt(dates[0], end_of_day=True)
    if end < start:
        start, end = end, start
    return start, end


def _playbook_terms(playbook_ids: list[str]) -> list[str]:
    from nexus.knowledge.loader import get_playbook

    terms: list[str] = []
    for name in playbook_ids:
        pb = get_playbook(name)
        if not isinstance(pb, dict):
            continue
        raw = pb.get("query_terms") or []
        if isinstance(raw, list):
            terms.extend(str(t).strip() for t in raw if str(t).strip())
        blob = yaml_dump_values(pb)
        terms.extend(_EXE_RE.findall(blob))
    return terms


def yaml_dump_values(obj: Any) -> str:
    if isinstance(obj, dict):
        return " ".join(yaml_dump_values(v) for v in obj.values())
    if isinstance(obj, list):
        return " ".join(yaml_dump_values(v) for v in obj)
    return str(obj or "")


def _dedupe(terms: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for t in terms:
        key = t.lower()
        if not str(t).strip() or key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out


def _parse_needles(raw: str) -> list[str]:
    """Comma/semicolon examiner or agent needles (not free-prose)."""
    return [t.strip() for t in (raw or "").replace(";", ",").split(",") if t.strip()]


def collect_playbook_query_terms(intake: dict[str, str] | None) -> list[str]:
    from nexus.langgraph.case_intake import extra_playbook_names

    return _dedupe(_playbook_terms(extra_playbook_names(intake or {})))


def collect_query_terms(intake: dict[str, str] | None) -> list[str]:
    intake = intake or {}
    terms: list[str] = []
    terms.extend(collect_playbook_query_terms(intake))
    # notes/description are methodology, not search needles (paths, tool names).
    terms.extend(_parse_needles(intake.get("query_extra", "")))
    blob = " ".join(
        intake.get(k, "")
        for k in ("question", "subjects", "hypothesis")
    )
    for tok in _TOKEN_RE.findall(blob):
        low = tok.lower()
        if low in _STOP or len(low) < 4:
            continue
        if low.startswith("20") and len(low) == 10:
            continue
        if "/" in tok or "\\" in tok or "http" in low:
            continue
        terms.append(tok)
    return _dedupe(terms)


def _row_in_window(line: str, start: datetime | None, end: datetime | None) -> bool:
    if start is None or end is None:
        return True
    found = False
    for m in _DATE_RE.finditer(line):
        found = True
        try:
            d = datetime.strptime(m.group(1), "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            continue
        if m.group(2):
            hh, mm, ss = (int(x) for x in m.group(2).split(":"))
            d = d.replace(hour=hh, minute=mm, second=ss)
        if start <= d <= end:
            return True
    return not found  # keyword hit with no timestamp still kept


def _family(path: Path, root: Path) -> str:
    rel = str(path.relative_to(root)).replace("\\", "/").lower()
    for hint in _FAMILY_HINTS:
        if hint in rel:
            return hint
    return path.parent.name.lower() or "other"


def _strong_set(terms: list[str]) -> set[str]:
    return {
        t.lower()
        for t in terms
        if t.strip()
        and t.lower() not in _WEAK_TERMS
        and t.lower() not in _USB_TERMS
    }


def _hit_rank(matched: list[str], strong: set[str]) -> int:
    """0 wipe/PST/C2, 1 cloud copy, 2 USB ids, 3 generic onedrive/recycle."""
    core = strong - _CLOUD_TERMS
    if any(t in core for t in matched):
        return 0
    if any(t in _CLOUD_TERMS for t in matched):
        return 1
    if any(t in _USB_TERMS for t in matched):
        return 2
    return 3


def _hits_from_file(
    path: Path,
    root: Path,
    fam: str,
    needles: list[str],
    strong: set[str],
    start: datetime | None,
    end: datetime | None,
) -> list[dict[str, str]]:
    """Keep strong-term rows even when noisier matches appear first in the file."""
    raw: list[tuple[int, int, list[str], str]] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, start=1):
            if i == 1 and ("," in line or "\t" in line):
                continue
            low = line.lower()
            matched = [t for t in needles if t in low]
            if not matched:
                continue
            if not _row_in_window(line, start, end):
                continue
            pri = _hit_rank(matched, strong)
            raw.append((pri, i, matched, line.strip()[:_MAX_LINE]))
            if len(raw) >= _MAX_COLLECT_PER_FILE:
                break
    raw.sort(key=lambda row: (row[0], row[1]))
    hits: list[dict[str, str]] = []
    for _pri, i, matched, text in raw[:_MAX_HITS_PER_FILE]:
        hits.append({
            "family": fam,
            "file": str(path.relative_to(root)),
            "line": str(i),
            "terms": ",".join(matched[:6]),
            "text": text,
        })
    return hits


def iter_extraction_files(case_dir: Path) -> list[tuple[Path, Path, str]]:
    """Registered-case processed outputs only (never Evidence-files/)."""
    case_dir = Path(case_dir)
    out: list[tuple[Path, Path, str]] = []
    roots = [
        case_dir / "extractions",
        case_dir / "sift" / "extractions",
        case_dir / "ingest",
    ]
    for root in roots:
        if not root.is_dir():
            continue
        files: list[Path] = []
        pats = ("*.csv", "*.txt", "*.json", "*.jsonl")
        if root.name == "ingest":
            pats = ("*.csv", "*.txt", "*.json", "*.jsonl", "*.log")
        for pat in pats:
            files.extend(root.rglob(pat))
        for path in sorted(set(files), key=_scan_prio):
            if path.name.startswith("_"):
                continue
            if path.name.endswith(_SKIP_SUFFIXES):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > 80 * 1024 * 1024:
                continue
            out.append((path, root, _family(path, root)))
    return out


def finalize_hits(
    hits: list[dict[str, str]],
    terms: list[str],
    priority_terms: list[str] | None = None,
) -> list[dict[str, str]]:
    """Same ranking/cap used by the CSV pack and the Elasticsearch backend."""
    strong = _strong_set(priority_terms if priority_terms is not None else terms)
    ranked = sorted(hits, key=lambda h: (
        _hit_rank([t.strip() for t in h.get("terms", "").split(",") if t.strip()], strong),
        h.get("family") or "",
        h.get("file") or "",
        int(h.get("line") or 0),
    ))
    return ranked[:_MAX_HITS_TOTAL]


def n4_hits(
    case_dir: Path,
    terms: list[str],
    window: tuple[datetime | None, datetime | None],
    priority_terms: list[str] | None = None,
    backend: str | None = None,
) -> tuple[list[dict[str, str]], str]:
    """One query API: Elasticsearch when reachable+indexed, else CSV pack."""
    import os

    choice = (backend or os.environ.get("NEXUS_N4_BACKEND") or "auto").strip().lower()
    if choice in {"es", "elasticsearch", "auto"}:
        try:
            from nexus.langgraph.case_index import IndexMissing, es_available, query_index

            if choice != "auto" or es_available():
                return query_index(case_dir, terms, window, priority_terms), "elasticsearch"
        except IndexMissing:
            if choice != "auto":
                raise
        except Exception:
            if choice not in {"auto", ""}:
                raise
    return scan_extractions(case_dir, terms, window, priority_terms), "csv"


def extras_gap_notes(case_dir: Path, intake: dict[str, str] | None = None) -> list[str]:
    """Honest N2 extra-parser status until the examiner gates them on."""
    intake = intake if intake is not None else load_case_intake(case_dir)
    raw = (intake.get("extras") or "").replace(";", ",")
    requested = {p.strip().lower() for p in raw.split(",") if p.strip()}
    known = {
        "chrome_profiles": "Chrome/Edge Profile* History (beyond Default)",
        "drivefs": "Google Drive File Stream logs/DB",
        "email": "PST/OST mailbox copy",
        "usb_serial": "USBSTOR serial parse from setupapi",
    }
    ext = Path(case_dir) / "extractions"
    present = {
        "chrome_profiles": (ext / "sqlecmd").is_dir() and any(
            "profile" in p.name.lower() for p in (ext / "sqlecmd").rglob("*")
        ),
        "drivefs": (ext / "drivefs").is_dir(),
        "email": (ext / "email").is_dir(),
        "usb_serial": (ext / "usb").is_dir(),
    }
    lines: list[str] = []
    for key, label in known.items():
        if key in requested and present.get(key):
            lines.append(f"- `{key}` ran ({label})")
        elif key in requested:
            lines.append(f"- `{key}` requested — artifact not present or parser did not produce output ({label})")
        else:
            lines.append(f"- `{key}` not requested — {label} not run (Default browser History / setupapi copy may still exist)")
    return lines


def scan_extractions(
    case_dir: Path,
    terms: list[str],
    window: tuple[datetime | None, datetime | None],
    priority_terms: list[str] | None = None,
) -> list[dict[str, str]]:
    case_dir = Path(case_dir)
    needles = [t.lower() for t in terms if t.strip()]
    strong = _strong_set(priority_terms if priority_terms is not None else terms)
    start, end = window
    hits: list[dict[str, str]] = []
    if not needles:
        return hits

    for path, root, fam in iter_extraction_files(case_dir):
        try:
            hits.extend(
                _hits_from_file(path, root, fam, needles, strong, start, end)
            )
        except OSError:
            continue
    return finalize_hits(hits, terms, priority_terms)


def build_query_pack_markdown(
    case_dir: Path,
    ledger: list[dict[str, Any]] | None = None,
    intake: dict[str, str] | None = None,
) -> str:
    case_dir = Path(case_dir)
    intake = intake if intake is not None else load_case_intake(case_dir)
    terms = collect_query_terms(intake)
    pb_terms = collect_playbook_query_terms(intake)
    win_text = " ".join(filter(None, [intake.get("window", ""), intake.get("question", "")]))
    window = parse_window(win_text)
    hits, backend = n4_hits(case_dir, terms, window, priority_terms=pb_terms)

    if ledger is None:
        lp = case_dir / "extractions" / "_tool_lane_ledger.json"
        ledger = []
        if lp.is_file():
            import json
            try:
                ledger = json.loads(lp.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                ledger = []

    families = sorted({h["family"] for h in hits})
    ok_ledger = [r for r in (ledger or []) if str(r.get("status") or "").upper() == "OK"]
    parts: list[str] = [
        "# N4 query pack (hits for interpretation)\n",
        "Facts for N5 come from **hits below**, not CSV heads. "
        "Empty hits + OK ledger = INSUFFICIENT rows, not a coverage gap.\n",
        "## Intake\n",
        f"- question: {intake.get('question') or '(none)'}",
        f"- window: {intake.get('window') or '(none)'} "
        f"(parsed={window[0].isoformat() if window[0] else 'none'} … "
        f"{window[1].isoformat() if window[1] else 'none'})",
        f"- playbooks: {intake.get('playbooks') or '(none)'}",
        f"- terms ({len(terms)}): {', '.join(terms[:40])}"
        + (" …" if len(terms) > 40 else ""),
        f"- backend: `{backend}` (elasticsearch when NEXUS_ES_URL is up and this case is indexed; else CSV pack)",
        "",
        f"## Ledger OK rows: {len(ok_ledger)} / {len(ledger or [])}\n",
        f"## Hit families ({len(families)}): {', '.join(families) or '(none)'}\n",
    ]
    parts.extend(["## N2 extras", ""])
    parts.extend(extras_gap_notes(case_dir, intake))
    parts.append("")
    parts.append(f"## Hits ({len(hits)}, cap {_MAX_HITS_TOTAL})\n")
    if not hits:
        parts.append(
            "_No rows matched query terms. Do not invent findings. "
            "Do not call this a coverage gap if the ledger is OK._\n"
        )
    else:
        current = ""
        for h in hits:
            loc = f"{h['file']}:{h['line']}"
            if h["family"] != current:
                current = h["family"]
                parts.append(f"### family `{current}`\n")
            parts.append(f"- `{loc}` terms=`{h['terms']}`\n  `{h['text']}`")
        parts.append("")

    md = "\n".join(parts)
    if len(md) > _MAX_MD:
        md = md[:_MAX_MD] + "\n\n_(query pack truncated)_\n"
    return md


_FAMILY_TO_TOOL = {
    "pecmd": "pecmd",
    "prefetch": "pecmd",
    "amcache": "amcacheparser",
    "appcompat": "appcompatcacheparser",
    "recmd": "recmd",
    "rbcmd": "rbcmd",
    "jlecmd": "jlecmd",
    "lecmd": "lecmd",
    "srum": "srumecmd",
    "srumecmd": "srumecmd",
    "sbecmd": "sbecmd",
    "wxtcmd": "wxtcmd",
    "hayabusa": "hayabusa",
    "evtx": "evtxecmd",
    "mftecmd": "mftecmd",
    "bits": "bitsparser",
    "vol": "vol",
    "setupapi": "setupapi",
}

# One finding per claim (first match wins for overlapping cloud/recycle keys).
_N4_CLAIMS: tuple[tuple[str, str], ...] = (
    ("sdelete", "sdelete wipe / secure-delete on host"),
    (".pst", "PST / Outlook mailbox files accessed or staged"),
    ("my drive", "Google Drive (G:\\My Drive) copy"),
    ("googledrive", "Google Drive copy"),
    ("drivefs", "Google Drive File Stream"),
    ("usbstor", "USB / USBSTOR activity"),
    ("mountpoints2", "Removable volume / MountPoints2"),
    ("recycle.bin", "Recycle Bin staging"),
    ("$recycle", "Recycle Bin staging"),
    ("mimikatz", "credential-dump tooling on host"),
    ("psexec", "PsExec / remote service exec"),
)


def _audits_for_families(ledger: list[dict[str, Any]], families: set[str]) -> list[str]:
    want = {_FAMILY_TO_TOOL.get(f, f).lower() for f in families}
    want |= {f.lower() for f in families}
    out: list[str] = []
    for row in ledger or []:
        if row.get("status") != "OK" or not row.get("audit_id"):
            continue
        tool = str(row.get("tool") or "").lower()
        if any(w in tool or tool in w for w in want):
            aid = str(row["audit_id"])
            if aid not in out:
                out.append(aid)
        if len(out) >= 8:
            break
    if out:
        return out
    for row in ledger or []:
        if row.get("status") == "OK" and row.get("audit_id"):
            out.append(str(row["audit_id"]))
        if len(out) >= 3:
            break
    return out


def n4_finding_candidates(
    case_dir: Path,
    ledger: list[dict[str, Any]] | None = None,
    intake: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Deterministic N5 salvage: one finding per N4 claim cluster, quoting hits.

    Used when the LLM emits no parseable findings JSON. Never 'parser completed OK'.
    """
    case_dir = Path(case_dir)
    intake = intake if intake is not None else load_case_intake(case_dir)
    terms = collect_query_terms(intake)
    pb_terms = collect_playbook_query_terms(intake)
    win_text = " ".join(filter(None, [intake.get("window", ""), intake.get("question", "")]))
    window = parse_window(win_text)
    hits, _backend = n4_hits(case_dir, terms, window, priority_terms=pb_terms)
    if not hits:
        return []

    emitted_keys: set[str] = set()
    out: list[dict[str, Any]] = []
    skip_if = {
        "googledrive": "my drive",
        "drivefs": "my drive",
        "$recycle": "recycle.bin",
        "mountpoints2": "usbstor",
    }

    for needle, title in _N4_CLAIMS:
        if skip_if.get(needle) in emitted_keys:
            continue
        clustered = []
        for h in hits:
            matched = [t.strip().lower() for t in (h.get("terms") or "").split(",") if t.strip()]
            blob = f"{h.get('text', '')} {h.get('terms', '')}".lower()
            if needle in blob or needle in matched:
                clustered.append(h)
        if not clustered:
            continue
        families = {str(h.get("family") or "other") for h in clustered}
        quotes = []
        ev_rows = evidence_rows_from_n4_hits(clustered, limit=8)
        for h in clustered[:5]:
            loc = f"{h.get('file')}:{h.get('line')}"
            quotes.append(f"{loc} terms={h.get('terms')}: {h.get('text', '')[:280]}")
        aids = _audits_for_families(ledger or [], families)
        fam_s = ", ".join(sorted(families))
        out.append({
            "title": title[:200],
            "observation": (
                f"N4 query-pack hits ({len(clustered)} rows, families: {fam_s}):\n"
                + "\n".join(quotes)
            )[:8000],
            "interpretation": (
                "These are filtered parser rows, not CSV heads. "
                "Insider / data-staging lens: the rows are consistent with local "
                "wipe, mailbox/cloud copy, or removable-media use. "
                "External-compromise lens: these host rows do not show remote "
                "access tooling or an implant. Missing families mean no matching "
                "row in this pack, not a coverage gap."
            ),
            "confidence": "HIGH" if len(families) >= 3 else "MEDIUM",
            "confidence_justification": (
                f"FD-001: {len(clustered)} N4 hits across {fam_s}; "
                f"audit_ids from matching OK ledger tools."
            )[:2000],
            "host": str(intake.get("host") or "rocba")[:200],
            "type": "finding",
            "audit_ids": aids,
            "artifacts": [{"audit_id": a, "type": "audit"} for a in aids[:10]],
            "evidence": ev_rows,
            "attack_ids": ["T1485"] if needle == "sdelete" else (
                ["T1074.001"] if needle in {".pst", "my drive", "googledrive", "drivefs"} else []
            ),
        })
        emitted_keys.add(needle)
        if len(out) >= 8:
            break
    return out


def write_query_pack(
    case_dir: Path,
    ledger: list[dict[str, Any]] | None = None,
    intake: dict[str, str] | None = None,
) -> Path:
    case_dir = Path(case_dir)
    out_dir = case_dir / "analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "query_pack.md"
    path.write_text(
        build_query_pack_markdown(case_dir, ledger, intake),
        encoding="utf-8",
    )
    try:
        from nexus.langgraph.timeline_merge import rebuild_case_timeline

        rebuild_case_timeline(case_dir)
    except Exception:
        pass
    return path


def run_ad_hoc_query(
    case_dir: Path,
    extra_needles: list[str] | None = None,
    persist: bool = False,
    backend: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Examiner/agent N4 search over processed outputs (never invents rows)."""
    case_dir = Path(case_dir)
    extras = [t for t in (extra_needles or []) if str(t).strip()]
    intake = dict(load_case_intake(case_dir))
    if extras:
        merged = _dedupe(_parse_needles(intake.get("query_extra", "")) + extras)
        if persist:
            from nexus.langgraph.case_intake import persist_case_intake

            persist_case_intake(case_dir, {"query_extra": ",".join(merged)})
            intake = load_case_intake(case_dir)
        else:
            intake["query_extra"] = ",".join(merged)
    terms = collect_query_terms(intake)
    pb_terms = collect_playbook_query_terms(intake)
    win_text = " ".join(filter(None, [intake.get("window", ""), intake.get("question", "")]))
    window = parse_window(win_text)
    hits, used = n4_hits(case_dir, terms, window, priority_terms=pb_terms, backend=backend)
    if persist:
        write_query_pack(case_dir, intake=intake)
    cap = max(1, min(int(limit or 50), _MAX_HITS_TOTAL))
    return {
        "backend": used,
        "terms": terms,
        "count": len(hits),
        "hits": hits[:cap],
        "persisted": persist,
        "empty": not hits,
    }
