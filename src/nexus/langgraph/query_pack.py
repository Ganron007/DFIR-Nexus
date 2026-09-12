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
# Full-row index/scan of small CSVs. Hayabusa/USN live above this;
# N4 still needle-scans them up to _MAX_FILTERED_SCAN_BYTES.
_MAX_FULL_SCAN_BYTES = 80 * 1024 * 1024
_MAX_FILTERED_SCAN_BYTES = 400 * 1024 * 1024
_MAX_FILES_PER_FAMILY = 120
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
        # Collection / IR narrative in the question is not a search needle.
        "disk", "memory", "security", "admin", "incident", "formally",
        "called", "after", "alerts", "collected", "hired", "complete",
        "scoping", "evidenced", "several", "days", "first", "firm",
        "scope", "pack", "over",
        # IR collection / question prose — not host-artifact needles.
        "attacker", "velociraptor", "kansa", "f-response", "fresponse",
        "hunts", "sweep", "analyst", "intrusion", "anti-malware",
        "antimailware", "response", "collection",
    }
)
_FAMILY_HINTS = (
    "hayabusa", "suzaku", "chainsaw", "evtxecmd", "evtx", "pecmd", "prefetch", "jlecmd", "lecmd",
    "sbecmd", "rbcmd", "srum", "srumecmd", "recmd", "mftecmd", "amcache",
    "appcompat", "wxtcmd", "bits", "vol", "fls", "setupapi", "bmc-tools",
    "plaso", "log2timeline", "psort",
)
_SCAN_FIRST = (
    "hayabusa", "suzaku", "chainsaw", "evtxecmd", "evtx", "pecmd", "prefetch", "amcache",
    "appcompat", "recmd", "mftecmd-usn", "usn",
    "userassist", "wordwheel", "recentdocs", "opensave",
    "rbcmd", "srum", "jlecmd", "lecmd", "wxtcmd",
)
_SKIP_SUFFIXES = ("_stdout.txt", "_stderr.txt", "_meta.json")
_MAX_COLLECT_PER_FILE = 200
_USB_TERMS = frozenset({"usbstor", "mountpoints2"})
_CLOUD_TERMS = frozenset({"googledrive", "drivefs", "my drive"})
# High-volume in host CSVs; keep some hits but never ahead of wipe/PST/C2 terms.
_WEAK_TERMS = frozenset({
    "onedrive", "recycle.bin", "$recycle", "removable", "setupapi",
    "winrar", "rar.exe", "7z.exe", "compact.exe", "winrar.exe",
    # Common LOLBins — keep some hits, never ahead of wipe/C2/wevtutil.
    "rundll32", "schtasks", "certutil", "wscript", "cscript",
    "bitsadmin", "mshta", "regsvr32", "wmic", "winrm", "termsrv",
    # Generic protocol/channel substrings from playbook terms — they match
    # huge row volumes (URLs, channel names, paths) and must not outrank
    # specific indicators like sdelete/mimikatz.
    "http", "dns", "tls", "sum", "cl", "mft", "txt", "sysmon", "defender",
    # 2-digit Task Scheduler / RDP event IDs — also match counts and sizes.
    "21", "22", "23", "24", "25",
    # Volatility/memory + browser generic terms from memory_forensics /
    # browser_forensics playbooks — plugin-ish but high-volume substrings.
    "modules", "strings", "handles", "consoles", "cmdline", "netstat",
    "history", "downloads", "cookies", "secure", "messages", "received",
    "attachment", "edge", "uac", "fls",
    # Generic question/playbook vocabulary (WP 4g-G) — matches almost every
    # row. Structural identifiers (hashes, IPs, domains, paths, event IDs)
    # still count as strong via _is_structurally_strong.
    "security", "audit", "event", "events", "log", "logs", "file", "files",
    "system", "windows", "user", "users", "process", "processes", "network",
    "local", "domain", "activity", "record", "records", "report", "data",
    "investigate", "analysis", "artifact", "artifacts", "evidence",
    "suspicious", "detected", "possible", "unknown", "update", "backup",
    "service", "services", "driver", "drivers", "admin", "administrator",
})
_NUMERIC_TERM = re.compile(r"^\d{1,5}$")
_needle_rx: dict[str, re.Pattern[str]] = {}

# Structural identifiers are strong regardless of the weak list above.
_STRONG_RX: tuple[re.Pattern[str], ...] = (
    re.compile(r"^[a-f0-9]{8,}$"),                       # hash / hex fragment
    re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),            # IPv4
    re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$"),        # domain / dotted host
    re.compile(r"\.(?:exe|dll|ps1|bat|vbs|js|lnk|pst|ost|zip|7z|rar|evtx|pf|sqlite)$"),
    re.compile(r"[\\/]"),                                 # path-ish
    re.compile(r"^\d{3,5}$"),                             # event id
)


def _is_structurally_strong(term: str) -> bool:
    t = (term or "").strip().lower()
    return bool(t) and any(rx.search(t) for rx in _STRONG_RX)


def needle_in_text(low: str, term: str) -> bool:
    """Match a search term in a lowercased parser row.

    Short numeric event IDs (``1102``, ``7045``) must not match inside
    hashes, UUIDs, or file sizes (``f1102060``, ``704501``, ``cc1149ff``).
    Other terms stay substring (``sdelete`` in ``sdelete.exe``).
    """
    t = (term or "").strip().lower()
    if not t or not low:
        return False
    if _NUMERIC_TERM.fullmatch(t):
        rx = _needle_rx.get(t)
        if rx is None:
            rx = re.compile(rf"(?<![0-9a-f]){re.escape(t)}(?![0-9a-f])")
            _needle_rx[t] = rx
        return rx.search(low) is not None
    return t in low


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


def parse_intake_window(intake: dict[str, str] | None) -> tuple[datetime | None, datetime | None]:
    """Prefer ``intake.window``. Do not let dates inside the question clip it."""
    intake = intake or {}
    dedicated = parse_window(intake.get("window") or "")
    if dedicated[0] is not None:
        return dedicated
    return parse_window(intake.get("question") or "")


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


def _family_matched_playbooks(families: set[str] | list[str] | None) -> list[dict]:
    """Playbooks whose query_terms/name/description mention any given family."""
    from nexus.knowledge.loader import get_playbook, list_playbook_slugs

    fams = {str(f).lower() for f in (families or []) if str(f).strip()}
    if not fams:
        return []
    out: list[dict] = []
    for slug in list_playbook_slugs():
        pb = get_playbook(slug)
        if not isinstance(pb, dict):
            continue
        # Explicit family declaration wins (Phase 4g-D tiering): robust matching
        # for playbooks whose query_terms don't literally contain the family.
        declared = pb.get("families")
        if isinstance(declared, list) and declared:
            if any(f in {str(d).lower() for d in declared} for f in fams):
                out.append(pb)
            continue
        terms = pb.get("query_terms") or []
        term_lower = (
            {str(t).lower() for t in terms} if isinstance(terms, list) else set()
        )
        blob = (
            str(pb.get("name", "")) + " " + str(pb.get("description", ""))
        ).lower()
        if any(f in term_lower or f in blob for f in fams):
            out.append(pb)
    return out


def playbook_terms_for_families(families: set[str] | list[str] | None) -> list[str]:
    """Playbook ``query_terms`` for the given artifact families (WP 4g-A).

    Family-matched against each playbook's terms and name/description, so
    expanding the playbook YAML expands Mode 1's starting vocabulary.
    """
    out: list[str] = []
    for pb in _family_matched_playbooks(families):
        terms = pb.get("query_terms") or []
        if isinstance(terms, list):
            out.extend(str(t).strip() for t in terms if str(t).strip())
    return _dedupe(out)


def playbook_techniques_for_families(families: set[str] | list[str] | None) -> list[str]:
    """MITRE technique ids declared by playbooks matched to those families."""
    out: list[str] = []
    for pb in _family_matched_playbooks(families):
        mitre = pb.get("mitre") or []
        if isinstance(mitre, list):
            out.extend(str(t).strip() for t in mitre if str(t).strip())
    return _dedupe(out)


def playbook_strong_terms_for_families(families: set[str] | list[str] | None) -> list[str]:
    """High-signal ``query_terms_strong`` from playbooks matched to families."""
    out: list[str] = []
    for pb in _family_matched_playbooks(families):
        strong = pb.get("query_terms_strong") or []
        if isinstance(strong, list):
            out.extend(str(t).strip() for t in strong if str(t).strip())
    return _dedupe(out)


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
            try:
                d = d.replace(hour=hh, minute=mm, second=ss)
            except ValueError:
                continue
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
        and (
            _is_structurally_strong(t)
            or (t.lower() not in _WEAK_TERMS and t.lower() not in _USB_TERMS)
        )
    }


def _hit_rank(matched: list[str], strong: set[str]) -> int:
    """0 wipe/PST/C2, 1 cloud copy, 2 USB ids, 3 generic onedrive/recycle."""
    core = strong - _CLOUD_TERMS
    low = [t.strip().lower() for t in matched if t.strip()]
    if any(t in core for t in low):
        return 0
    if any(t in _CLOUD_TERMS for t in low):
        return 1
    if any(t in _USB_TERMS for t in low):
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
    query: Any | None = None,
) -> list[dict[str, str]]:
    """Keep strong-term rows even when noisier matches appear first in the file."""
    raw: list[tuple[int, int, list[str], str]] = []
    strong_n = 0
    weak_n = 0
    with path.open(encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, start=1):
            if i == 1 and ("," in line or "\t" in line):
                continue
            low = line.lower()
            if query is not None:
                from nexus.langgraph.query_dsl import row_matches

                ok, matched = row_matches(
                    query, line_lower=low, family=fam, file_rel=str(path.relative_to(root))
                )
                if not ok:
                    continue
                matched = matched[:6]
            else:
                matched = [t for t in needles if needle_in_text(low, t)]
                if not matched:
                    continue
            if not _row_in_window(line, start, end):
                continue
            pri = _hit_rank(matched, strong)
            if pri == 0:
                if strong_n >= _MAX_COLLECT_PER_FILE:
                    continue
                strong_n += 1
            else:
                if weak_n >= _MAX_COLLECT_PER_FILE:
                    continue
                weak_n += 1
            raw.append((pri, i, matched, line.strip()[:_MAX_LINE]))
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


def iter_extraction_files(
    case_dir: Path,
    *,
    max_bytes: int | None = None,
    max_files_per_family: int | None = None,
) -> list[tuple[Path, Path, str]]:
    """Registered-case processed outputs only (never Evidence-files/)."""
    case_dir = Path(case_dir)
    cap = _MAX_FULL_SCAN_BYTES if max_bytes is None else max_bytes
    file_cap = _MAX_FILES_PER_FAMILY if max_files_per_family is None else max_files_per_family
    out: list[tuple[Path, Path, str]] = []
    fam_files: dict[str, int] = {}
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    extractions = resolve_tools_extractions(case_dir)
    tools_run_dir = extractions.parent
    roots = [
        extractions,
        tools_run_dir / "sift" / "extractions",
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
            # I1 dump — processing-time JSON, not a host parser CSV. N7 reads it
            # via load_ingest_artifacts; scanning it as N4 text matches UUIDs.
            if path.name.lower() == "artifacts.jsonl":
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > cap:
                continue
            fam = _family(path, root)
            n = fam_files.get(fam, 0)
            if n >= file_cap:
                continue
            fam_files[fam] = n + 1
            out.append((path, root, fam))
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
    query: Any | None = None,
) -> tuple[list[dict[str, str]], str]:
    """One query API: Elasticsearch when reachable+indexed, else CSV pack.

    ``query`` is an optional parsed query_dsl.ParsedQuery adding boolean /
    field-filter / regex semantics. The ES backend translates it to a bool
    query; the CSV backend evaluates it per row.
    """
    import os

    choice = (backend or os.environ.get("NEXUS_N4_BACKEND") or "auto").strip().lower()
    if choice in {"es", "elasticsearch", "auto"}:
        try:
            from nexus.langgraph.case_index import IndexMissing, es_available, query_index

            if choice != "auto" or es_available():
                return query_index(case_dir, terms, window, priority_terms, query=query), "elasticsearch"
        except IndexMissing:
            if choice != "auto":
                raise
        except Exception:
            if choice not in {"auto", ""}:
                raise
    return scan_extractions(case_dir, terms, window, priority_terms, query=query), "csv"


# ---------------------------------------------------------------------------
# WP 4d.1 — type-aware hit enrichment: parsed CSV fields + best-effort host
# ---------------------------------------------------------------------------

_HOST_RE = re.compile(
    r"(?:^|[\",;\s|])(?:computer(?:\s*name)?|host(?:name)?)\"?\s*[:=,]\s*\"?([A-Za-z0-9][A-Za-z0-9.-]{1,30})",
    re.I,
)
_UNC_RE = re.compile(r"\\\\([A-Za-z0-9][A-Za-z0-9.-]{1,30})\\")
_MAX_FIELDS = 24
_MAX_FIELD_VALUE = 160
_header_cache: dict[str, list[str]] = {}


def _split_csv_row(text: str) -> list[str]:
    """Best-effort CSV row split (handles quoted commas)."""
    import csv

    try:
        return next(csv.reader([text]))
    except (StopIteration, csv.Error):
        return [p.strip() for p in text.split(",")]


def _host_from_text(text: str) -> str:
    """Best-effort hostname from a hit row (Computer column or \\\\UNC path)."""
    m = _HOST_RE.search(text)
    if m:
        return m.group(1).rstrip(".").lower()
    m = _UNC_RE.search(text)
    if m:
        return m.group(1).lower()
    return ""


def _host_from_fields(fields: dict[str, str]) -> str:
    for key in ("Computer", "ComputerName", "Host", "Hostname", "HostName", "SourceHost"):
        v = fields.get(key, "").strip()
        if v:
            return v.split(".")[0].lower()
    return ""


def _header_for_file(root: Path, file_rel: str) -> list[str]:
    """Read (and cache) the CSV header line of a source file."""
    if file_rel in _header_cache:
        return _header_cache[file_rel]
    header: list[str] = []
    p = root / file_rel
    if file_rel and p.is_file():
        try:
            with p.open(encoding="utf-8", errors="replace") as fh:
                first = fh.readline().strip()
            if first:
                import csv as _csv

                header = next(_csv.reader([first]), [])
                header = [h.strip().lstrip("\ufeff").strip('"') for h in header]
        except OSError:
            header = []
    _header_cache[file_rel] = header
    return header


def attach_hit_fields(case_dir: Path, hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """WP 4d.1: attach parsed ``fields`` (CSV header -> value) and a
    best-effort ``host`` to each hit so the UI can render type-aware
    columns instead of raw text rows.

    Headers are read once per source file (line 1, cached process-wide).
    Rows are split with the csv reader so quoted commas survive. ES and
    CSV backends share the same hit shape, so this works for both.
    """
    case_dir = Path(case_dir)
    if not hits:
        return hits
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    root = resolve_tools_extractions(case_dir)
    out: list[dict[str, Any]] = []
    for h in hits:
        row = dict(h)
        fields: dict[str, str] = {}
        file_rel = str(h.get("file") or "")
        p = root / file_rel if file_rel else None
        if p is not None and p.is_file():
            if file_rel not in _header_cache:
                try:
                    with p.open(encoding="utf-8", errors="replace") as fh:
                        first = fh.readline().strip()
                    _header_cache[file_rel] = (
                        [c.strip().lstrip("\ufeff").strip('"') for c in _split_csv_row(first)] if first else []
                    )
                except OSError:
                    _header_cache[file_rel] = []
            header = _header_cache[file_rel]
            values = _split_csv_row(h.get("text", ""))
            for name, val in list(zip(header, values, strict=False))[:_MAX_FIELDS]:
                v = str(val).strip()[:_MAX_FIELD_VALUE]
                if v:
                    fields[name] = v
        host = next((v for v in (fields.get(k, "") for k in ("Computer", "ComputerName", "Host", "Hostname")) if v), "")
        if not host:
            m = _HOST_RE.search(h.get("text", "")) or _UNC_RE.search(h.get("text", ""))
            host = (m.group(1) if m else "").rstrip(".").lower()
        row["fields"] = fields
        row["host"] = host
        out.append(row)
    return out


def n4_query(
    case_dir: Path,
    query_text: str,
    window: tuple[datetime | None, datetime | None] | None = None,
    limit: int = 80,
    offset: int = 0,
    backend: str | None = None,
) -> dict[str, Any]:
    """DSL entry point: parse -> N4 -> hits + total count (pagination-ready).

    Returns {query, backend, count, offset, hits, empty} or {error}.
    """
    from nexus.langgraph.query_dsl import QuerySyntaxError, parse_query

    try:
        parsed = parse_query(query_text)
    except QuerySyntaxError as exc:
        return {"error": str(exc), "query": query_text}

    case_dir = Path(case_dir)
    intake = load_case_intake(case_dir)
    if window is None:
        window = parse_intake_window(intake)
    pb_terms = collect_playbook_query_terms(intake)
    dsl_terms = parsed.all_needles()
    terms = list(dict.fromkeys(dsl_terms + collect_query_terms(intake)))
    all_hits, backend_used = n4_hits(
        case_dir,
        terms,
        window,
        priority_terms=list(dict.fromkeys(pb_terms + dsl_terms)),
        backend=backend,
        query=parsed if not parsed.is_empty() else None,
    )
    total = len(all_hits)
    page = all_hits[max(0, offset):max(0, offset) + max(1, min(int(limit or 80), _MAX_HITS_TOTAL))]
    return {
        "query": parsed.describe(),
        "backend": backend_used,
        "count": total,
        "offset": max(0, offset),
        "hits": page,
        "empty": not all_hits,
    }


def n4_aggregate(
    case_dir: Path,
    query_text: str = "",
    group_by: str = "family",
    window: tuple[datetime | None, datetime | None] | None = None,
) -> dict[str, Any]:
    """Count hits grouped by family / hour / day (caps: _MAX_HITS_TOTAL)."""

    from nexus.langgraph.query_dsl import QuerySyntaxError, parse_query

    if group_by not in ("family", "hour", "day", "file", "host"):
        return {"error": f"unknown group_by: {group_by}"}
    try:
        parsed = parse_query(query_text)
    except QuerySyntaxError as exc:
        return {"error": str(exc)}

    case_dir = Path(case_dir)
    intake = load_case_intake(case_dir)
    if window is None:
        window = parse_intake_window(intake)
    dsl_terms = parsed.all_needles()
    terms = collect_query_terms(intake)
    pb_terms = collect_playbook_query_terms(intake)
    merged = list(dict.fromkeys(dsl_terms + terms))
    # Always pass the parsed query — an EMPTY query is a match-all, which is
    # exactly what a facet aggregate wants: cases without intake query terms
    # (or a fresh Explore load) still get real family/host buckets instead of
    # an empty rail.
    all_hits, _ = n4_hits(
        case_dir,
        merged,
        window,
        priority_terms=list(dict.fromkeys(pb_terms + dsl_terms)),
        query=parsed,
    )

    buckets: dict[str, int] = {}
    for h in all_hits:
        if group_by == "family":
            key = h.get("family") or "other"
        elif group_by == "host":
            m = _HOST_RE.search(h.get("text", "")) or _UNC_RE.search(h.get("text", ""))
            key = (m.group(1).rstrip(".").lower() if m else "") or "(unknown host)"
        elif group_by in ("hour", "day"):
            m = _DATE_RE.search(h.get("text", ""))
            key = m.group(1) if m else "(no timestamp)"
            if group_by == "hour" and m and m.group(2):
                key = f"{m.group(1)}T{m.group(2)[:2]}:00"
        else:
            key = h.get("file") or "?"
        buckets[key] = buckets.get(key, 0) + 1
    return {
        "group_by": group_by,
        "buckets": dict(sorted(buckets.items(), key=lambda kv: -kv[1])),
        "total": len(all_hits),
    }


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
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    ext = resolve_tools_extractions(Path(case_dir))
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
    query: Any | None = None,
) -> list[dict[str, str]]:
    """Scan parsed CSVs. ``query`` (query_dsl.ParsedQuery) adds boolean /
    field-filter / regex semantics on top of the plain needle list."""
    case_dir = Path(case_dir)
    needles = [t.lower() for t in terms if t.strip()]
    strong = _strong_set(priority_terms if priority_terms is not None else terms)
    start, end = window
    hits: list[dict[str, str]] = []
    if not needles and query is None:
        return hits

    for path, root, fam in iter_extraction_files(
        case_dir, max_bytes=_MAX_FILTERED_SCAN_BYTES,
    ):
        try:
            hits.extend(
                _hits_from_file(path, root, fam, needles, strong, start, end, query=query)
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
    window = parse_intake_window(intake)
    hits, backend = n4_hits(case_dir, terms, window, priority_terms=pb_terms)

    if ledger is None:
        from nexus.langgraph.pipeline_runs import resolve_tools_extractions

        lp = resolve_tools_extractions(case_dir) / "_tool_lane_ledger.json"
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
    ("wevtutil", "event-log clearing / wevtutil"),
    ("1102", "Security log cleared (Event ID 1102)"),
    ("dataoverwrite", "USN DataOverwrite on logs or hives"),
    ("encodedcommand", "PowerShell EncodedCommand"),
    ("psexec", "PsExec / remote service exec"),
    ("psexesvc", "PsExec service install"),
    ("mimikatz", "credential-dump tooling on host"),
    ("lsass", "LSASS access / dump indicators"),
    ("rundll32", "rundll32 execution"),
    ("schtasks", "scheduled task creation"),
    ("bitsadmin", "BITS transfer / persistence"),
    (".pst", "PST / Outlook mailbox files accessed or staged"),
    ("my drive", "Google Drive (G:\\My Drive) copy"),
    ("googledrive", "Google Drive copy"),
    ("drivefs", "Google Drive File Stream"),
    ("usbstor", "USB / USBSTOR activity"),
    ("mountpoints2", "Removable volume / MountPoints2"),
    ("recycle.bin", "Recycle Bin staging"),
    ("$recycle", "Recycle Bin staging"),
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


def _is_process_dump_hit(h: dict[str, str]) -> bool:
    """True when the row is I1 processing JSON, not a host parser CSV."""
    f = str(h.get("file") or "").replace("\\", "/").lower()
    fam = str(h.get("family") or "").lower()
    text = str(h.get("text") or "").lower()
    if f.endswith("artifacts.jsonl") or "/artifacts.jsonl" in f:
        return True
    return bool(fam == "ingest" and "generic_jsonl" in text)


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
    window = parse_intake_window(intake)
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
        "psexesvc": "psexec",
        "1102": "wevtutil",
    }

    for needle, title in _N4_CLAIMS:
        if skip_if.get(needle) in emitted_keys:
            continue
        clustered = []
        for h in hits:
            if _is_process_dump_hit(h):
                continue
            matched = [t.strip().lower() for t in (h.get("terms") or "").split(",") if t.strip()]
            text_l = str(h.get("text") or "").lower()
            if needle in matched or needle_in_text(text_l, needle):
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
        if needle == "sdelete":
            attack_ids = ["T1485"]
        elif needle in {"wevtutil", "1102", "dataoverwrite"}:
            attack_ids = ["T1070.001"]
        elif needle == "encodedcommand":
            attack_ids = ["T1059.001"]
        elif needle in {"psexec", "psexesvc"}:
            attack_ids = ["T1569.002"]
        elif needle in {"mimikatz", "lsass"}:
            attack_ids = ["T1003"]
        elif needle in {".pst", "my drive", "googledrive", "drivefs"}:
            attack_ids = ["T1074.001"]
        else:
            attack_ids = []
        out.append({
            "title": title[:200],
            "observation": (
                f"N4 query-pack hits ({len(clustered)} rows, families: {fam_s}):\n"
                + "\n".join(quotes)
            )[:8000],
            "interpretation": (
                "These are filtered parser rows for this claim, not CSV heads. "
                "IR collection tools (Velociraptor, F-Response, Kansa) in the "
                "same pack are not C2 unless the row shows attacker-controlled "
                "use. Missing other claims mean no matching row, not a coverage gap."
            ),
            "confidence": "HIGH" if len(families) >= 3 else "MEDIUM",
            "confidence_justification": (
                f"FD-001: {len(clustered)} N4 hits across {fam_s}; "
                f"audit_ids from matching OK ledger tools."
            )[:2000],
            "host": str(intake.get("host") or "")[:200],
            "type": "finding",
            "audit_ids": aids,
            "artifacts": [{"audit_id": a, "type": "audit"} for a in aids[:10]],
            "evidence": ev_rows,
            "attack_ids": attack_ids,
        })
        emitted_keys.add(needle)
        if len(out) >= 10:
            break
    return out


def write_query_pack(
    case_dir: Path,
    ledger: list[dict[str, Any]] | None = None,
    intake: dict[str, str] | None = None,
    output_dir: Path | None = None,
) -> Path:
    case_dir = Path(case_dir)
    out_dir = Path(output_dir) if output_dir else case_dir / "analysis"
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
    window = parse_intake_window(intake)
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
