"""N4 query pack — filter parsed CSVs/txt by intake window + playbook terms.

First N3 backend (no cluster). Interpret reads hits, not file heads.
Does not hardcode case plots: terms come from playbook YAML + intake tokens.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from nexus.integration.evidence_table import evidence_rows_from_n4_hits
from nexus.langgraph.audit_linkage import _FAMILY_TO_TOOL, linked_audit_ids
from nexus.langgraph.path_sanitize import (
    sanitize_field_map,
    sanitize_row_text,
)

_MAX_LINE = 4000
_MAX_MD = 60000
# Full-row index/scan of small CSVs. Hayabusa/USN live above this;
# N4 still needle-scans them up to _MAX_FILTERED_SCAN_BYTES.
def _env_mb(name: str, default_mb: int) -> int:
    """MB-valued env knob; 0 means UNLIMITED (EH-11: no silent evidence loss)."""
    import os

    try:
        value = int(os.environ.get(name, "") or default_mb)
    except ValueError:
        value = default_mb
    return max(0, value) * 1024 * 1024

def _env_int(name: str, default: int) -> int:
    """Count-valued env knob (result caps). EH-12: retunable, defaults kept."""
    import os

    try:
        value = int(os.environ.get(name, "") or default)
    except ValueError:
        value = default
    return max(0, value)

log = logging.getLogger(__name__)

# EH-12: every result cap is now operator-tunable; 0 = unlimited. The
# defaults stay modest for interactive search — report/export paths
# use the exhaustive `iter_all_hits`, never these caps, so no evidence
# is sidelined. Caps that do trigger are reported by _cap_reasons.
_MAX_HITS_PER_FILE = _env_int("NEXUS_N4_HITS_PER_FILE", 40)
_MAX_HITS_TOTAL = _env_int("NEXUS_N4_MAX_HITS", 400)



# 0 = index/scan everything. Operators who need a guard set NEXUS_SCAN_MAX_FILE_MB
# / NEXUS_N4_MAX_FILE_MB; the old 80MB/400MB skips silently dropped evidence.
_MAX_FULL_SCAN_BYTES = _env_mb("NEXUS_SCAN_MAX_FILE_MB", 0)
_MAX_FILTERED_SCAN_BYTES = _env_mb("NEXUS_N4_MAX_FILE_MB", 0)
_MAX_FILES_PER_FAMILY = _env_int("NEXUS_N4_FILES_PER_FAMILY", 120)
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
_MAX_COLLECT_PER_FILE = _env_int("NEXUS_N4_COLLECT_PER_FILE", 200)
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


def _open_text(path: Path):
    """Open a text file, transparently decompressing .gz (EH-11)."""
    if str(path).lower().endswith(".gz"):
        import gzip

        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open(encoding="utf-8", errors="replace")


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


# Entity/schema vocabulary that must never become a needle: type labels like
# "domain_user" are how the extractor classifies rows, not strings the host
# emits. Paths are machine-local (C:\STUDY\Github\...) and match every path in
# every row — they belong in the file column, not in the signal map.
_NEEDLE_NOISE = frozenset({
    "domain_user", "windows_path", "posix_path", "process_name", "service_name",
    "ipv4", "ipv6", "url", "domain", "hostname", "username", "account",
    "sha256", "sha1", "md5", "imphash", "file_path", "path", "user", "host",
})


def is_needle_like(term: str) -> bool:
    """Vocabulary hygiene for AUTO-generated needles (playbook/ATT&CK/Sigma/intake).

    Rejects paths, entity-type labels, bare numbers and over-long strings.
    Examiner-typed searches are NOT filtered by this — Explore keeps its
    existing semantics; this only guards what the scan proposes on its own.
    """
    t = str(term or "").strip()
    if len(t) < 3 or len(t) > 64:
        return False
    if "\\" in t or "/" in t or ":" in t:
        return False
    if t.lower() in _NEEDLE_NOISE:
        return False
    # Event IDs (4624/7045/1102) are first-class needles; stray short numbers
    # ("21", "123") are row noise and stay out.
    if t.isdigit():
        return len(t) >= 4
    return True


def persistable_needles(terms: list[str]) -> list[str]:
    """Needles allowed to become permanent ``CASE.yaml`` intake values.

    The portal persists Explore/ask needles into ``intake.query_extra``; once
    written they appear in every later scan. Paths and entity-type labels must
    never become permanent needles (live report 2026-09-23: the case folder
    path was persisted and surfaced as scan needles).
    """
    return _dedupe([t for t in terms if is_needle_like(t)])


def _parse_needles(raw: str) -> list[str]:
    """Examiner or agent needles (not free-prose).

    Newline-separated values are the current format and preserve commas
    inside a needle (e.g. a quoted phrase); legacy comma/semicolon values
    persisted before EH-8 still parse.
    """
    text = raw or ""
    if "\n" in text:
        return [t.strip() for t in text.splitlines() if t.strip()]
    return [t.strip() for t in text.replace(";", ",").split(",") if t.strip()]


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
    match_all: bool = False,
    case_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """Keep strong-term rows even when noisier matches appear first in the file.

    Returns ``(hits, capped)`` — ``capped`` is True when this file had more
    matching rows than the collect/per-file caps allowed through, so callers
    can mark its counts as lower bounds instead of exact.
    """
    raw: list[tuple[int, int, list[str], str]] = []
    strong_n = 0
    weak_n = 0
    skipped_cap = 0
    header = _header_for_file(root, str(path.relative_to(root)).replace("\\", "/"))
    from nexus.langgraph.case_index import _row_fields

    with _open_text(path) as fh:
        for i, line in enumerate(fh, start=1):
            if i == 1 and ("," in line or "\t" in line):
                continue
            raw_fields = _row_fields(line, header) if header else None
            # Source/provenance columns carry the machine path the parser read:
            # replace them outright, then normalize remaining machine prefixes.
            line = sanitize_row_text(line, raw_fields, case_dir, family=fam)
            low = line.lower()
            if query is not None:
                from nexus.langgraph.query_dsl import row_matches

                row_fields = (
                    sanitize_field_map(raw_fields, case_dir, family=fam)
                    if raw_fields else None
                )
                ok, matched = row_matches(
                    query, line_lower=low, family=fam, file_rel=str(path.relative_to(root)),
                    row_fields=row_fields,
                )
                if not ok:
                    continue
                matched = matched[:6]
            else:
                matched = [t for t in needles if needle_in_text(low, t)]
                if not matched:
                    if not match_all:
                        continue
                    matched = ["*"]
            if not _row_in_window(line, start, end):
                continue
            pri = _hit_rank(matched, strong)
            if pri == 0:
                if strong_n >= _MAX_COLLECT_PER_FILE:
                    skipped_cap += 1
                    continue
                strong_n += 1
            else:
                if weak_n >= _MAX_COLLECT_PER_FILE:
                    skipped_cap += 1
                    continue
                weak_n += 1
            raw.append((pri, i, matched, line.strip()[:_MAX_LINE]))
    raw.sort(key=lambda row: (row[0], row[1]))
    kept = raw[:_MAX_HITS_PER_FILE]
    capped = skipped_cap > 0 or len(raw) > _MAX_HITS_PER_FILE
    hits: list[dict[str, Any]] = [
        {
            "family": fam,
            "file": str(path.relative_to(root)).replace("\\", "/"),
            "line": str(i),
            "terms": ",".join(matched[:6]),
            "terms_list": matched[:6],
            "text": text,
        }
        for _pri, i, matched, text in kept
    ]
    return hits, capped


def render_ingest_row(d: dict[str, Any], max_len: int = _MAX_LINE) -> str:
    """Compact, N4-indexable text for one imported artifact.

    Deliberately excludes ids/UUIDs and processing metadata — the raw store
    line is noisy; this is the searchable projection (same text on ES + CSV).
    """
    parts = [
        str(d.get("timestamp") or ""),
        str(d.get("source") or ""),
        str(d.get("artifact_type") or ""),
        str(d.get("severity") or ""),
        f"host={d.get('host')}" if d.get("host") else "",
        f"user={d.get('user')}" if d.get("user") else "",
        f"src={d.get('source_ip')}:{d.get('source_port')}" if d.get("source_ip") else "",
        f"dst={d.get('dest_ip')}:{d.get('dest_port')}" if d.get("dest_ip") else "",
        str(d.get("description") or d.get("details") or d.get("rule") or ""),
        " ".join(str(t) for t in (d.get("technique_ids") or [])),
        " ".join(str(i) for i in (d.get("iocs") or [])),
        # EH-7: searchable/visible marker so nobody reads ingest time as
        # event time in the evidence rows themselves.
        "ts_synthesized=true" if d.get("ts_synthesized") else "",
        "ts_year_assumed=true" if d.get("ts_year_assumed") else "",
    ]
    return " ".join(p for p in parts if p).strip()[:max_len]


def iter_ingest_records(case_dir: Path):
    """Yield (line_no, family, searchable text, ts, record) per artifact.

    Generator (EH-11): a million-row imported store must not be materialized
    as a list just to scan it.
    """
    path = Path(case_dir) / "ingest" / "artifacts.jsonl"
    if not path.is_file():
        return
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(d, dict):
                    continue
                fam = str(d.get("source") or "ingest").strip().lower() or "ingest"
                yield (n, fam, render_ingest_row(d), str(d.get("timestamp") or ""), d)
    except OSError:
        return


def iter_ingest_rows(case_dir: Path):
    """Yield (line_no, family, searchable text, ts) per imported artifact."""
    for n, fam, text, ts, _rec in iter_ingest_records(case_dir):
        yield (n, fam, text, ts)


def _hits_from_ingest(
    case_dir: Path,
    needles: list[str],
    strong: set[str],
    start: datetime | None,
    end: datetime | None,
    query: Any | None = None,
    match_all: bool = False,
    stats: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """Same matching semantics as ``_hits_from_file`` over the artifact store.

    Carries ``terms_list`` (EH-8) and records the collect cap so a 20k-row
    network log cannot lower-bound every count silently.
    """
    hits: list[dict[str, Any]] = []
    strong_n = 0
    weak_n = 0
    skipped_cap = 0
    for line_no, fam, text, _ts, record in iter_ingest_records(case_dir):
        text = sanitize_row_text(text, record, case_dir, family=fam)
        low = text.lower()
        if query is not None:
            from nexus.langgraph.query_dsl import row_matches

            row_fields = sanitize_field_map(
                {
                    str(k): str(v) for k, v in (record or {}).items()
                    if v not in (None, "", [], {})
                },
                case_dir,
                family=fam,
            )
            ok, matched = row_matches(
                query, line_lower=low, family=fam, file_rel="ingest/artifacts.jsonl",
                row_fields=row_fields,
            )
            if not ok:
                continue
            matched = matched[:6]
        else:
            matched = [t for t in needles if needle_in_text(low, t)]
            if not matched:
                if not match_all:
                    continue
                matched = ["*"]
        if not _row_in_window(text, start, end):
            continue
        pri = _hit_rank(matched, strong)
        if pri == 0:
            if strong_n >= _MAX_COLLECT_PER_FILE:
                skipped_cap += 1
                continue
            strong_n += 1
        else:
            if weak_n >= _MAX_COLLECT_PER_FILE:
                skipped_cap += 1
                continue
            weak_n += 1
        hits.append({
            "family": fam,
            "file": "ingest/artifacts.jsonl",
            "line": str(line_no),
            "terms": ",".join(matched[:6]),
            "terms_list": matched[:6],
            "text": text,
        })
    if stats is not None:
        stats["ingest_capped"] = bool(skipped_cap)
    return hits


def iter_extraction_files(
    case_dir: Path,
    *,
    max_bytes: int | None = None,
    max_files_per_family: int | None = None,
    stats: dict[str, Any] | None = None,
) -> list[tuple[Path, Path, str]]:
    """Registered-case processed outputs only (never Evidence-files/).

    ``stats`` (optional out-param) records coverage honesty: how many files
    were eligible, scanned, or skipped because of the size / per-family caps —
    a skipped file must never later read as "no hits".
    """
    case_dir = Path(case_dir)
    # 0/None = UNLIMITED (EH-11): the old default silently skipped evidence.
    cap = _MAX_FULL_SCAN_BYTES if max_bytes is None else max_bytes
    if cap is not None and cap <= 0:
        cap = 0
    file_cap = _MAX_FILES_PER_FAMILY if max_files_per_family is None else max_files_per_family
    out: list[tuple[Path, Path, str]] = []
    fam_files: dict[str, int] = {}
    if stats is not None:
        stats.setdefault("files_total", 0)
        stats.setdefault("files_scanned", 0)
        stats.setdefault("files_skipped_size", 0)
        stats.setdefault("files_skipped_family_cap", 0)
        stats.setdefault("families_capped", [])
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
        # 4k.4: `.log` covers Zeek/Suricata/app logs pulled from SIFT too —
        # indexing everything means these must not be silently skipped.
        pats = (
            "*.csv", "*.txt", "*.json", "*.jsonl", "*.log",
            "*.csv.gz", "*.txt.gz", "*.json.gz", "*.jsonl.gz", "*.log.gz",
        )
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
            if stats is not None:
                stats["files_total"] += 1
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if cap and size > cap:
                if stats is not None:
                    stats["files_skipped_size"] += 1
                continue
            fam = _family(path, root)
            n = fam_files.get(fam, 0)
            if n >= file_cap:
                if stats is not None:
                    stats["files_skipped_family_cap"] += 1
                    capped = stats["families_capped"]
                    if fam not in capped:
                        capped.append(fam)
                continue
            fam_files[fam] = n + 1
            out.append((path, root, fam))
            if stats is not None:
                stats["files_scanned"] += 1
    return out


def finalize_hits(
    hits: list[dict[str, Any]],
    terms: list[str],
    priority_terms: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Same ranking/cap used by the CSV pack and the Elasticsearch backend."""
    strong = _strong_set(priority_terms if priority_terms is not None else terms)

    def _rank(h: dict[str, Any]) -> int:
        matched = h.get("terms_list")
        if not isinstance(matched, list):
            matched = [t.strip() for t in str(h.get("terms") or "").split(",")]
        return _hit_rank([str(t).strip() for t in matched if str(t).strip()], strong)

    ranked = sorted(hits, key=lambda h: (
        _rank(h),
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
    match_all: bool = False,
    stats: dict[str, Any] | None = None,
    catalog: dict[str, Any] | None = None,
) -> tuple[list[dict[str, str]], str]:
    """One query API: Elasticsearch when reachable+indexed, else CSV pack.

    ``query`` is an optional parsed query_dsl.ParsedQuery adding boolean /
    field-filter / regex semantics. The ES backend translates it to a bool
    query; the CSV backend evaluates it per row. ``match_all`` returns all
    in-window hits when there are no terms/query.

    ``stats`` (optional out-param) records term coverage — how many needle
    terms were requested vs actually queried and any that could not be
    queried. Retrieval must never present an unqueried needle as 0 hits.
    """
    import os

    def _csv_stats(fallback_reason: str = "") -> None:
        if stats is None:
            return
        requested = len([t for t in terms if str(t).strip()])
        stats.clear()
        stats.update({
            "mode": "csv",
            "terms_requested": requested,
            "terms_queried": requested,
            "terms_failed": [],
            "chunk_queries": 0,
            "chunks_split": 0,
            "backend": "csv",
            "fallback_reason": fallback_reason,
        })

    from nexus.langgraph.query_dsl import QuerySyntaxError

    choice = (backend or os.environ.get("NEXUS_N4_BACKEND") or "auto").strip().lower()
    fallback_reason = ""
    if choice in {"es", "elasticsearch", "auto"}:
        try:
            from nexus.langgraph.case_index import IndexMissing, es_available, query_index

            if choice != "auto" or es_available():
                result = query_index(
                    case_dir, terms, window, priority_terms,
                    query=query, match_all=match_all, stats=stats,
                    catalog=catalog,
                )
                if stats is not None:
                    stats["backend"] = "elasticsearch"
                    stats["fallback_reason"] = ""
                return result, "elasticsearch"
        except IndexMissing as exc:
            if choice != "auto":
                raise
            fallback_reason = f"index missing ({exc})"
        except QuerySyntaxError:
            # A malformed/unknown-field query is a USER error, not backend
            # unreachability — never silently rerun it on the CSV pack.
            raise
        except Exception as exc:  # noqa: BLE001 — auto mode degrades to CSV
            if choice not in {"auto", ""}:
                raise
            fallback_reason = f"{type(exc).__name__}: {exc}"
            # EH-13: a silent backend switch is an evidence-integrity risk —
            # make it loud and carry the reason into every consumer's stats.
            log.warning("N4 ES query failed — CSV fallback: %s", fallback_reason)
        if not fallback_reason:
            fallback_reason = (
                "NEXUS_ES_URL unset"
                if not (os.environ.get("NEXUS_ES_URL") or "").strip()
                else "Elasticsearch unreachable or index missing"
            )
    else:
        fallback_reason = f"backend forced to {choice!r}"
    _csv_stats(fallback_reason)
    return scan_extractions(
        case_dir, terms, window, priority_terms, query=query, match_all=match_all,
        stats=stats, catalog=catalog,
    ), "csv"


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
# line_no -> parsed record per ingest store, keyed by path+mtime. The hit
# enricher used to re-open and linearly scan artifacts.jsonl for EVERY hit
# (O(hits × store)); one cached pass makes it O(store) (EH-10).
_ingest_line_cache: dict[str, dict[int, dict[str, Any]]] = {}


def _ingest_records_by_line(store: Path) -> dict[int, dict[str, Any]]:
    """Parsed record per line for one ingest store (mtime-cached, bounded)."""
    try:
        key = f"{store}:{store.stat().st_mtime_ns}"
    except OSError:
        return {}
    cached = _ingest_line_cache.get(key)
    if cached is not None:
        return cached
    rows: dict[int, dict[str, Any]] = {}
    try:
        with store.open(encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(d, dict):
                    rows[i] = d
    except OSError:
        rows = {}
    _ingest_line_cache[key] = rows
    if len(_ingest_line_cache) > 4:
        _ingest_line_cache.pop(next(iter(_ingest_line_cache)))
    return rows


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
    """CSV header line of a source file (path+mtime keyed, gz-aware).

    Keying by mtime prevents one case's identical relative filename from
    leaking its columns into another case in a long-running server.
    """
    header: list[str] = []
    p = root / file_rel
    if file_rel and p.is_file():
        try:
            key = f"{p.resolve()}:{p.stat().st_mtime_ns}"
        except OSError:
            key = str(p)
        if key in _header_cache:
            return _header_cache[key]
        try:
            with _open_text(p) as fh:
                first = fh.readline().strip()
            if first:
                import csv as _csv

                header = next(_csv.reader([first]), [])
                header = [h.strip().lstrip("\ufeff").strip('"') for h in header]
        except OSError:
            header = []
        _header_cache[key] = header
        return header
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

    tools_root = resolve_tools_extractions(case_dir)
    # Hits can come from the tools run, the SIFT mirror, or the ingest store —
    # resolve the source file against every candidate root.
    candidate_roots = [tools_root, tools_root.parent / "sift" / "extractions", case_dir]
    out: list[dict[str, Any]] = []
    for h in hits:
        row = dict(h)
        fields: dict[str, str] = {}
        file_rel = str(h.get("file") or "")
        p = None
        if file_rel:
            for candidate_root in candidate_roots:
                candidate = candidate_root / file_rel
                if candidate.is_file():
                    p = candidate
                    break
        if file_rel.startswith("ingest/"):
            # Imported-artifact row — project the store line into typed fields
            # (network events get source_ip/dest_ip/proto/severity in the UI).
            store = case_dir / file_rel
            record: dict[str, Any] | None = None
            try:
                line_no = int(h.get("line") or 0)
                record = _ingest_records_by_line(store).get(line_no)
            except (OSError, ValueError):
                record = None
            if isinstance(record, dict):
                for key in (
                    "source", "artifact_type", "severity", "timestamp", "host",
                    "user", "source_ip", "source_port", "dest_ip", "dest_port",
                    "protocol", "description", "rule",
                    "ts_synthesized", "ts_year_assumed",
                ):
                    value = record.get(key)
                    if value not in (None, "", []):
                        fields[key] = str(value)[:_MAX_FIELD_VALUE]
                for list_key in ("technique_ids", "iocs"):
                    values = record.get(list_key)
                    if values:
                        fields[list_key] = ",".join(str(v) for v in values)[:_MAX_FIELD_VALUE]
        elif p is not None:
            # Header cache is keyed by the resolved path + mtime — a relative
            # name alone lets one case's header leak into another.
            try:
                cache_key = f"{p}:{p.stat().st_mtime_ns}"
            except OSError:
                cache_key = str(p)
            if cache_key not in _header_cache:
                try:
                    with p.open(encoding="utf-8", errors="replace") as fh:
                        first = fh.readline().strip()
                    _header_cache[cache_key] = (
                        [c.strip().lstrip("\ufeff").strip('"') for c in _split_csv_row(first)] if first else []
                    )
                except OSError:
                    _header_cache[cache_key] = []
            header = _header_cache[cache_key]
            values = _split_csv_row(h.get("text", ""))
            for name, val in list(zip(header, values, strict=False))[:_MAX_FIELDS]:
                v = str(val).strip()[:_MAX_FIELD_VALUE]
                if v:
                    fields[name] = v
        host = next(
            (
                v
                for v in (
                    fields.get(k, "")
                    for k in ("Computer", "ComputerName", "Host", "Hostname", "host")
                )
                if v
            ),
            "",
        )
        if not host:
            m = _HOST_RE.search(h.get("text", "")) or _UNC_RE.search(h.get("text", ""))
            host = (m.group(1) if m else "").rstrip(".").lower()
        row["fields"] = sanitize_field_map(
            fields, case_dir, family=str(h.get("family") or "")
        )
        # Never clobber an envelope host the backend already resolved
        # (ES schema-v2 hits carry `host`; CSV rows often don't).
        row["host"] = host or str(h.get("host") or "")
        out.append(row)
    return out


def _cap_reasons(stats: dict[str, Any]) -> list[str]:
    """Human-readable lower-bound reasons from a coverage stats dict."""
    reasons: list[str] = []
    if stats.get("hits_capped"):
        reasons.append("result cap")
    if stats.get("files_capped"):
        reasons.append(f"{stats['files_capped']} capped file(s)")
    if stats.get("ingest_capped"):
        reasons.append("imported-evidence collect cap")
    if stats.get("files_skipped_size"):
        reasons.append(f"{stats['files_skipped_size']} oversized file(s)")
    if stats.get("files_skipped_family_cap"):
        reasons.append(f"{stats['files_skipped_family_cap']} file(s) over the family cap")
    if stats.get("terms_failed"):
        reasons.append(f"{len(stats['terms_failed'])} unqueried needle(s)")
    return reasons


def n4_query(
    case_dir: Path,
    query_text: str,
    window: tuple[datetime | None, datetime | None] | None = None,
    limit: int = 80,
    offset: int = 0,
    backend: str | None = None,
    match_all: bool = False,
) -> dict[str, Any]:
    """DSL entry point: parse -> N4 -> hits + total count (pagination-ready).

    Returns {query, backend, count, offset, hits, empty} or {error}.
    ``match_all`` makes an empty query scan every in-window row instead of
    falling back to intake terms only.
    """
    from nexus.langgraph.query_dsl import QuerySyntaxError, parse_query

    try:
        from nexus.langgraph.field_catalog import case_field_catalog

        _catalog = case_field_catalog(case_dir)
        parsed = parse_query(query_text, catalog=_catalog)
    except QuerySyntaxError as exc:
        return {"error": str(exc), "query": query_text}
    except Exception:  # noqa: BLE001 — catalog failure must not block queries
        _catalog = None
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
    do_match_all = bool(match_all) and parsed.is_empty()
    terms = [] if do_match_all else list(dict.fromkeys(dsl_terms + collect_query_terms(intake)))
    stats: dict[str, Any] = {}
    try:
        all_hits, backend_used = n4_hits(
            case_dir,
            terms,
            window,
            priority_terms=list(dict.fromkeys(pb_terms + dsl_terms)),
            backend=backend,
            query=parsed if not parsed.is_empty() else None,
            match_all=do_match_all,
            stats=stats,
            catalog=_catalog,
        )
    except QuerySyntaxError as exc:
        return {"error": str(exc), "query": parsed.describe()}
    total = len(all_hits)
    page = all_hits[max(0, offset):max(0, offset) + max(1, min(int(limit or 80), _MAX_HITS_TOTAL))]
    cap_reasons = _cap_reasons(stats)
    exact_info: dict[str, Any] | None = None
    if cap_reasons:
        # EH-12: the rendered page may be capped, but the total shown to the
        # examiner must be exact — one cheap `_count` / one CSV pass.
        with contextlib.suppress(Exception):
            info = count_hits(
                case_dir, terms, window,
                priority_terms=list(dict.fromkeys(pb_terms + dsl_terms)),
                query=parsed if not parsed.is_empty() else None,
                match_all=do_match_all,
                backend=backend,
                catalog=_catalog,
            )
            if info.get("exact"):
                exact_info = info
    return {
        "query": parsed.describe(),
        "backend": backend_used,
        "count": int(exact_info["count"]) if exact_info else total,
        "count_exact": bool(exact_info),
        "count_lower_bound": bool(cap_reasons) and exact_info is None,
        "offset": max(0, offset),
        "hits": page,
        "empty": not all_hits,
        "stats": stats,
        "capped_reasons": cap_reasons,
    }


def n4_sample(
    case_dir: Path,
    family: str = "",
    field: str = "",
    value: str = "",
    n: int = 12,
    window: tuple[datetime | None, datetime | None] | None = None,
) -> dict[str, Any]:
    """Representative raw rows for a family/field value, spread across time.

    The digest gives aggregates; this pulls the raw texture (Mode 2/3): the
    LLM asks for N rows of a family (optionally where ``field == value``) and
    gets them evenly spaced over the matched timeline instead of the first N
    (which would bias to one burst). Read-only; rows are context, findings
    still cite the audit trail.
    """
    case_dir = Path(case_dir)
    count = max(1, min(int(n or 12), 60))
    intake = load_case_intake(case_dir)
    if window is None:
        window = parse_intake_window(intake)
    needle = str(value or "").strip()
    terms = [needle] if needle else list(collect_query_terms(intake))
    all_hits, backend_used = n4_hits(
        case_dir,
        terms,
        window,
        priority_terms=[needle] if needle else [],
    )

    _ENVELOPE_ALIASES = {
        "event": "event_id", "eventid": "event_id",
        "timestamp": "ts", "time": "ts",
    }

    def _value_for(hit: dict[str, Any], fname: str) -> str:
        key = _ENVELOPE_ALIASES.get(fname.lower(), fname)
        raw = hit.get(key)
        if raw not in (None, ""):
            return str(raw)
        fields = hit.get("fields") or {}
        if isinstance(fields, dict):
            for fk, fv in fields.items():
                if str(fk).lower() in (fname.lower(), key.lower()) and fv not in (None, ""):
                    return str(fv)
        return ""

    family_hits = [
        h for h in all_hits
        if isinstance(h, dict) and (not family or str(h.get("family") or "") == family)
    ]
    if field:
        # Parsed columns are attached per-file (header cached) so the field
        # filter behaves identically on the ES and CSV backends — envelope
        # keys (host/user/event_id/ts) match directly, parsed columns via
        # attach; `event` aliases `event_id`.
        with contextlib.suppress(Exception):
            family_hits = attach_hit_fields(case_dir, family_hits)
        low_needle = needle.lower()
        candidates = []
        for h in family_hits:
            value = _value_for(h, field)
            if needle:
                if value.lower() == low_needle:
                    candidates.append(h)
            elif value:
                candidates.append(h)
    else:
        candidates = family_hits
    matched = len(candidates)

    step = max(1, matched // count)
    picked = candidates[::step][:count] if candidates else []
    return {
        "family": family,
        "field": field,
        "value": needle,
        "backend": backend_used,
        "matched": matched,
        "sampled": len(picked),
        "spread_every": step,
        "hits": picked,
        "empty": not picked,
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
    match_all: bool = False,
    stats: dict[str, Any] | None = None,
    catalog: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """Scan parsed CSVs. ``query`` (query_dsl.ParsedQuery) adds boolean /
    field-filter / regex semantics on top of the plain needle list.
    ``match_all`` returns every in-window row when there are no terms/query."""
    case_dir = Path(case_dir)
    needles = [t.lower() for t in terms if t.strip()]
    strong = _strong_set(priority_terms if priority_terms is not None else terms)
    start, end = window
    hits: list[dict[str, str]] = []
    if not needles and query is None and not match_all:
        return hits

    files_capped = 0
    for path, root, fam in iter_extraction_files(
        case_dir, max_bytes=_MAX_FILTERED_SCAN_BYTES, stats=stats,
    ):
        try:
            file_hits, capped = _hits_from_file(
                path, root, fam, needles, strong, start, end,
                query=query, match_all=match_all, case_dir=case_dir,
            )
        except OSError:
            if stats is not None:
                stats["files_unreadable"] = int(stats.get("files_unreadable", 0)) + 1
            continue
        if capped:
            files_capped += 1
        hits.extend(file_hits)
    # Imported non-host evidence (network/cloud/TI) lives in the case artifact
    # store — same searchable projection as the ES backend (parity).
    hits.extend(
        _hits_from_ingest(
            case_dir, needles, strong, start, end,
            query=query, match_all=match_all, stats=stats,
        )
    )
    if stats is not None:
        stats["files_capped"] = files_capped
        stats["hits_collected"] = len(hits)
    final = finalize_hits(hits, terms, priority_terms)
    if stats is not None:
        stats["hits_returned"] = len(final)
        stats["hits_capped"] = bool(
            len(final) >= _MAX_HITS_TOTAL and len(hits) > _MAX_HITS_TOTAL
        )
    return final


def _pick_backend(case_dir: Path, backend: str | None = None) -> str:
    """Resolve 'elasticsearch' | 'csv' without querying (EH-12)."""
    import os

    choice = (backend or os.environ.get("NEXUS_N4_BACKEND") or "auto").strip().lower()
    if choice in {"csv", "local", "offline"}:
        return "csv"
    if choice in {"es", "elasticsearch"}:
        return "elasticsearch"
    try:
        from nexus.langgraph.case_index import _client, es_available, index_name

        if not es_available():
            return "csv"
        with _client() as client:
            if client.head(f"/{index_name(Path(case_dir).name)}").status_code == 200:
                return "elasticsearch"
    except Exception:  # noqa: BLE001 — auto mode degrades to CSV
        pass
    return "csv"


def _case_dir_for_root(root: Path) -> Path:
    """Case dir for an extraction root (…/extractions, …/sift/extractions, …/ingest)."""
    if root.parent.name == "sift" and len(root.parents) > 1:
        return root.parents[1]
    return root.parent


def _iter_matching_rows(
    path: Path,
    root: Path,
    fam: str,
    needles: list[str],
    start: datetime | None,
    end: datetime | None,
    query: Any | None = None,
    match_all: bool = False,
    header: list[str] | None = None,
):
    """Yield (line_no, matched_terms, text) for EVERY matching row (EH-12).

    No caps — the exhaustive enumeration behind exports/appendices. Rows come
    in file order; deterministic and streamable for arbitrarily large CSVs.
    """
    rel = str(path.relative_to(root)).replace("\\", "/")
    case_dir = _case_dir_for_root(root)
    from nexus.langgraph.case_index import _row_fields

    with _open_text(path) as fh:
        for i, line in enumerate(fh, start=1):
            if i == 1 and ("," in line or "\t" in line):
                continue
            raw_fields = _row_fields(line, header) if header else None
            # Source/provenance columns carry the machine path the parser read:
            # replace them outright, then normalize remaining machine prefixes.
            line = sanitize_row_text(line, raw_fields, case_dir, family=fam)
            low = line.lower()
            if query is not None:
                from nexus.langgraph.query_dsl import row_matches

                row_fields = (
                    sanitize_field_map(raw_fields, case_dir, family=fam)
                    if raw_fields else None
                )
                ok, matched = row_matches(
                    query, line_lower=low, family=fam, file_rel=rel,
                    row_fields=row_fields,
                )
                if not ok:
                    continue
                matched = matched[:6]
            else:
                matched = [t for t in needles if needle_in_text(low, t)]
                if not matched:
                    if not match_all:
                        continue
                    matched = ["*"]
            if not _row_in_window(line, start, end):
                continue
            yield i, matched, line.strip()[:_MAX_LINE]


def iter_extraction_hits(
    case_dir: Path,
    needles: list[str],
    start: datetime | None,
    end: datetime | None,
    query: Any | None = None,
    match_all: bool = False,
    stats: dict[str, Any] | None = None,
):
    """Stream every matching parsed-CSV row (no caps) — EH-12 CSV path."""
    case_dir = Path(case_dir)
    file_stats: dict[str, Any] = {}
    for path, root, fam in iter_extraction_files(
        case_dir, max_bytes=_MAX_FILTERED_SCAN_BYTES, stats=file_stats,
    ):
        try:
            rel = str(path.relative_to(root)).replace("\\", "/")
            header = None
            if query is not None and getattr(query, "filters", None):
                header = _header_for_file(root, rel)
            for i, matched, text in _iter_matching_rows(
                path, root, fam, needles, start, end,
                query=query, match_all=match_all, header=header,
            ):
                yield {
                    "family": fam,
                    "file": rel,
                    "line": str(i),
                    "terms": ",".join(matched[:6]),
                    "terms_list": matched[:6],
                    "text": text,
                }
        except OSError:
            file_stats["files_unreadable"] = int(file_stats.get("files_unreadable", 0)) + 1
    if stats is not None:
        stats.update(file_stats)
        stats["backend"] = "csv"
        stats["exhaustive"] = True


def iter_ingest_hits(
    case_dir: Path,
    needles: list[str],
    start: datetime | None,
    end: datetime | None,
    query: Any | None = None,
    match_all: bool = False,
    stats: dict[str, Any] | None = None,
):
    """Stream every matching imported-evidence row (no caps) — EH-12."""
    for line_no, fam, text, _ts, record in iter_ingest_records(case_dir):
        text = sanitize_row_text(text, record, case_dir, family=fam)
        low = text.lower()
        if query is not None:
            from nexus.langgraph.query_dsl import row_matches

            row_fields = sanitize_field_map(
                {
                    str(k): str(v) for k, v in (record or {}).items()
                    if v not in (None, "", [], {})
                },
                case_dir,
                family=fam,
            )
            ok, matched = row_matches(
                query, line_lower=low, family=fam, file_rel="ingest/artifacts.jsonl",
                row_fields=row_fields,
            )
            if not ok:
                continue
            matched = matched[:6]
        else:
            matched = [t for t in needles if needle_in_text(low, t)]
            if not matched:
                if not match_all:
                    continue
                matched = ["*"]
        if not _row_in_window(text, start, end):
            continue
        yield {
            "family": fam,
            "file": "ingest/artifacts.jsonl",
            "line": str(line_no),
            "terms": ",".join(matched[:6]),
            "terms_list": matched[:6],
            "text": text,
        }
    if stats is not None:
        stats["backend"] = "csv"
        stats["exhaustive"] = True


def iter_all_hits(
    case_dir: Path,
    terms: list[str],
    window: tuple[datetime | None, datetime | None],
    priority_terms: list[str] | None = None,
    query: Any | None = None,
    match_all: bool = False,
    backend: str | None = None,
    catalog: dict[str, Any] | None = None,
):
    """Stream EVERY matching hit across the chosen backend (EH-12).

    This is the no-caps enumeration used by report appendices and the export
    endpoint. It yields in backend order (ES `_doc` / CSV file order) and never
    truncates. An ES error after streaming starts propagates — an export must
    not silently switch backends mid-file (EH-13).
    """
    case_dir = Path(case_dir)
    needles = [t.lower() for t in terms if t.strip()]
    start, end = window or (None, None)
    if not needles and query is None and not match_all:
        return
    if _pick_backend(case_dir, backend) == "elasticsearch":
        from nexus.langgraph.case_index import iter_index_hits

        yield from iter_index_hits(
            case_dir, terms, window,
            priority_terms=priority_terms, query=query, match_all=match_all,
            catalog=catalog,
        )
        return
    yield from iter_extraction_hits(
        case_dir, needles, start, end, query=query, match_all=match_all
    )
    yield from iter_ingest_hits(
        case_dir, needles, start, end, query=query, match_all=match_all
    )


def count_hits(
    case_dir: Path,
    terms: list[str],
    window: tuple[datetime | None, datetime | None],
    priority_terms: list[str] | None = None,
    query: Any | None = None,
    match_all: bool = False,
    backend: str | None = None,
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Exact matched-row count (EH-12). Returns {count, backend, exact}.

    ES uses `_count` (cheap even at 10M docs); CSV streams one pass without
    keeping rows. A failed ES count in auto mode degrades to the CSV count.
    """
    import os

    case_dir = Path(case_dir)
    explicit = (backend or os.environ.get("NEXUS_N4_BACKEND") or "auto").strip().lower()
    if _pick_backend(case_dir, backend) == "elasticsearch":
        try:
            from nexus.langgraph.case_index import count_index

            cstats: dict[str, Any] = {}
            n, exact = count_index(
                case_dir, terms, window,
                priority_terms=priority_terms, query=query, match_all=match_all,
                stats=cstats, catalog=catalog,
            )
            return {"count": n, "backend": "elasticsearch", "exact": exact}
        except Exception as exc:  # noqa: BLE001
            if explicit not in {"auto", ""}:
                raise
            log.warning("ES count failed — CSV count fallback: %s", exc)
    n = sum(1 for _ in iter_all_hits(
        case_dir, terms, window,
        priority_terms=priority_terms, query=query, match_all=match_all,
        backend="csv",
    ))
    return {"count": n, "backend": "csv", "exact": True}


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
    pack_stats: dict[str, Any] = {}
    hits, backend = n4_hits(
        case_dir, terms, window, priority_terms=pb_terms, stats=pack_stats
    )

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
    cap_reasons = _cap_reasons(pack_stats)
    parts.append(
        "Scan coverage: "
        f"{pack_stats.get('terms_queried', len(terms))}/{pack_stats.get('terms_requested', len(terms))} terms; "
        f"files {pack_stats.get('files_scanned', 0)}/{pack_stats.get('files_total', 0)}; "
        f"backend `{backend}`\n"
    )
    if cap_reasons:
        parts.append(
            "\n> WARNING: hit counts below are LOWER BOUNDS — "
            + "; ".join(cap_reasons)
            + ". Do not treat them as exact.\n"
        )
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


# family -> producing tool: single source of truth lives in audit_linkage
# (EH-9), imported at the top of this module.

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
    """Ledger-only strict linkage (legacy helper).

    EH-9: exact tool match against the family's producing tool — and NO
    "first OK audit id of any tool" fallback. Callers with a case_dir should
    prefer ``audit_linkage.linked_audit_ids`` (which also reads the audit log
    and output-file tokens).
    """
    want = {_FAMILY_TO_TOOL.get(f, f).lower() for f in families}
    want |= {f.lower() for f in families}
    out: list[str] = []
    for row in ledger or []:
        if row.get("status") != "OK" or not row.get("audit_id"):
            continue
        tool = str(row.get("tool") or "").lower()
        if tool in want or any(
            tool.startswith(w) and len(w) >= 4 for w in want
        ):
            aid = str(row["audit_id"])
            if aid not in out:
                out.append(aid)
        if len(out) >= 8:
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
        aids = linked_audit_ids(
            case_dir,
            families,
            files=[h.get("file") for h in clustered if h.get("file")],
            ledger=ledger,
        )
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
    query_override: str = "",
) -> dict[str, Any]:
    """Examiner/agent N4 search over processed outputs (never invents rows).

    ``query_override`` (WP 4j.11) runs one complete DSL query verbatim instead
    of merging extra needles with intake vocabulary — a structured query from
    the LLM (or examiner) takes precedence.
    """
    case_dir = Path(case_dir)
    query_override = (query_override or "").strip()
    if query_override:
        from nexus.langgraph.query_dsl import parse_query

        _catalog = None
        try:
            from nexus.langgraph.field_catalog import case_field_catalog

            _catalog = case_field_catalog(case_dir)
        except Exception:  # noqa: BLE001 — catalog is best-effort
            _catalog = None
        parsed = parse_query(query_override, catalog=_catalog)
        if not parsed.is_empty():
            intake = dict(load_case_intake(case_dir))
            window = parse_intake_window(intake)
            hits, used = n4_hits(
                case_dir,
                parsed.all_needles(),
                window,
                priority_terms=parsed.all_needles(),
                query=parsed,
                backend=backend,
            )
            cap = max(1, min(int(limit or 50), _MAX_HITS_TOTAL))
            return {
                "backend": used,
                "terms": parsed.all_needles(),
                "count": len(hits),
                "hits": hits[:cap],
                "persisted": False,
                "empty": not hits,
                "query": query_override,
            }
    extras = [t for t in (extra_needles or []) if str(t).strip()]
    intake = dict(load_case_intake(case_dir))
    if extras:
        merged = _dedupe(_parse_needles(intake.get("query_extra", "")) + extras)
        if persist:
            from nexus.langgraph.case_intake import persist_case_intake

            persist_case_intake(
                case_dir, {"query_extra": "\n".join(merged) + ("\n" if merged else "")}
            )
            intake = load_case_intake(case_dir)
        else:
            intake["query_extra"] = "\n".join(merged) + ("\n" if merged else "")
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
