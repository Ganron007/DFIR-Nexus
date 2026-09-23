"""Normalize analyst-machine paths in DERIVED text — never in raw evidence.

Tool outputs record the absolute path of the file the parser read on *this*
machine (EvtxECmd ``SourceFile``, JLECmd/LECmd inputs, RECmd ``--csv`` source
names, RegRipper headers, ...). That is honest provenance, but it is
machine-local noise for search and review:

- every needle/entity scan over such a row sees ``C:\\STUDY\\Github\\...``;
- findings and reports would cite the analysis host's directory layout.

This module rewrites those machine-owned prefixes (case store, cases root,
registered evidence sources, repo/dev tree, home, temp) to stable placeholders
(``<case>``, ``<cases>``, ``<evidence>``, ``<repo>``, ``<home>``, ``<tmp>``,
``<staging>``) **in the derived index/scan text only**. Raw evidence files are
never modified, and paths that belong to the evidence itself
(``C:\\Windows\\System32\\...``, ``C:\\Users\\fredr\\...``) are preserved
byte-for-byte. Source/provenance columns (``SourceFile`` etc.) are replaced
outright with ``<source>``. JSON-escaped (doubled-backslash) and forward-slash
forms are matched too.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path

# Longest prefix wins so nested roots collapse to the most specific label.
_LABEL_CASE = "<case>"
_LABEL_CASES = "<cases>"
_LABEL_EVIDENCE = "<evidence>"
_LABEL_REPO = "<repo>"
_LABEL_TMP = "<tmp>"
_LABEL_HOME = "<home>"
_LABEL_STAGING = "<staging>"

# Columns that hold the file the parser READ on the analysis host — machine
# routing metadata, never evidence content. Values in these columns are
# replaced with ``<source>`` regardless of which root they live under (so an
# ``I:\`` or ``D:\`` evidence mount cannot leak either).
SOURCE_PATH_COLUMNS = frozenset({
    "sourcefile",
    "sourcefilename",
    "sourcename",
    "sourcedirectory",
    "inputfile",
    "inputdirectory",
    "plugindetailfile",
})

# Family-scoped source columns: only provenance in THAT tool's schema.
FAMILY_SOURCE_COLUMNS: dict[str, frozenset[str]] = {
    "recmd": frozenset({"hivepath", "hivefile"}),
    "chainsaw": frozenset({"path"}),
    "hindsight": frozenset({"profile"}),
    "regripper": frozenset({"hive"}),
}

# Machine-owned prefixes that are host-independent patterns rather than
# resolved roots (SIFT/remote runs, case store on any host). Evidence-internal
# POSIX paths (/home/fredr/..., /var/log/...) never match these.
_ANALYST_STAGING_RE = re.compile(
    r"(?i)(?:file://)?/home/[^/\s\"',;]+/nexus-es-mapping"
)
_ANALYST_CACHE_RE = re.compile(
    r"(?i)(?:file://)?/home/[^/\s\"',;]+/\.cache(?=[/\\]|$)"
)
_NEXUS_HOME_RE = re.compile(
    r"(?i)(?:file://)?/home/[^/\s\"',;]+(?=/+\.nexus(?:[/\\]|$))"
)
_NEXUS_CASE_RE = re.compile(r"(?i)([/\\]{1,2})\.nexus\1cases\1[^/\\\s\"',;]+")


def _is_source_column(family: str, key: str) -> bool:
    k = str(key or "").strip().lstrip("\ufeff").lower()
    if k in SOURCE_PATH_COLUMNS:
        return True
    return k in FAMILY_SOURCE_COLUMNS.get(str(family or "").lower(), frozenset())


@lru_cache(maxsize=1)
def _repo_root() -> Path | None:
    """Repo root when running from a source checkout (editable install)."""
    try:
        candidate = Path(__file__).resolve().parents[3]
    except IndexError:  # pragma: no cover - defensive
        return None
    return candidate if (candidate / "src" / "nexus").is_dir() else None


def evidence_sources(case_dir: Path | None) -> list[Path]:
    """Directories the case's evidence was registered from (best-effort)."""
    if not case_dir:
        return []
    try:
        raw = (Path(case_dir) / "evidence.json").read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, ValueError):
        return []
    rows = data if isinstance(data, list) else (data.get("evidence") or [])
    if not isinstance(rows, list):
        return []
    out: list[Path] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        src = str(row.get("source") or row.get("path") or "").strip()
        if not src:
            continue
        p = Path(src)
        out.append(p if p.is_dir() else p.parent)
    return out


def _build_machine_roots(case_dir: Path | None) -> list[tuple[str, str]]:
    roots: list[tuple[Path, str]] = []
    if case_dir:
        case = Path(case_dir)
        roots.append((case, _LABEL_CASE))
        roots.append((case.parent, _LABEL_CASES))
        roots.extend((src, _LABEL_EVIDENCE) for src in evidence_sources(case))
    repo = _repo_root()
    if repo is not None:
        roots.append((repo, _LABEL_REPO))
        # Containing dev directories: 8.3 short paths and tool banners
        # (C:\...\Github\CAF47A~1\DFIR-N~1\...) never reproduce the long root,
        # so the parent/grandparent checkouts are masked as the same `<repo>`.
        roots.append((repo.parent, _LABEL_REPO))
        roots.append((repo.parent.parent, _LABEL_REPO))
    roots.append((Path.home(), _LABEL_HOME))
    tmp = os.environ.get("TEMP") or ""
    if tmp:
        roots.append((Path(tmp), _LABEL_TMP))

    pairs: list[tuple[str, str]] = []
    for root, label in roots:
        try:
            text = str(root.resolve()).rstrip("\\/")
        except OSError:  # pragma: no cover - defensive
            continue
        # Never rewrite a drive/filesystem root ("C:", "/") — that would mangle
        # genuine evidence paths like C:\Windows\...
        if len(text) >= 4 and ":" not in text[2:] and text.count(":") <= 1:
            pairs.append((text, label))
    pairs.sort(key=lambda item: len(item[0]), reverse=True)
    return pairs


@lru_cache(maxsize=64)
def _cached_roots(
    case_str: str, ev_mtime_ns: int, ev_size: int
) -> tuple[tuple[str, str], ...]:
    return tuple(_build_machine_roots(Path(case_str) if case_str else None))


def machine_roots(case_dir: Path | None = None) -> list[tuple[str, str]]:
    """(normalized prefix, label) pairs, longest first, refusing root paths.

    Cached on the case path plus the evidence registry's mtime/size so per-row
    scans do not re-read ``evidence.json``; a new registration invalidates.
    """
    case_str = str(Path(case_dir).resolve()) if case_dir else ""
    mtime_ns = 0
    size = 0
    if case_str:
        try:
            st = (Path(case_str) / "evidence.json").stat()
            mtime_ns, size = st.st_mtime_ns, st.st_size
        except OSError:
            pass
    return list(_cached_roots(case_str, mtime_ns, size))


@lru_cache(maxsize=256)
def _prefix_variants(prefix: str) -> tuple[tuple[str, str], ...]:
    """Prefix as (normal, JSON-escaped, forward-slash) variants with lowers."""
    variants = [prefix]
    if "\\" in prefix:
        escaped = prefix.replace("\\", "\\\\")
        if escaped not in variants:
            variants.append(escaped)
        forward = prefix.replace("\\", "/")
        if forward not in variants:
            variants.append(forward)
    return tuple((v, v.lower()) for v in variants)


def sanitize_machine_paths(
    text: str,
    case_dir: Path | None = None,
    roots: list[tuple[str, str]] | None = None,
) -> str:
    """Replace machine-owned path prefixes with stable placeholders."""
    if not text:
        return text
    if not any(ch in text for ch in ("\\", "/", ":")):
        return text  # fast path: nothing path-like
    pairs = roots if roots is not None else machine_roots(case_dir)
    if not pairs:
        return text
    out = text
    low = out.lower()
    for prefix, label in pairs:
        replaced = False
        for variant, vlow in _prefix_variants(prefix):
            if variant in out or vlow in low:
                out = re.sub(re.escape(variant), label, out, flags=re.IGNORECASE)
                replaced = True
        if replaced:
            low = out.lower()
    # Host-independent machine patterns: case store on any host, SIFT/remote
    # staging and symbol cache. Order matters — the home prefix is consumed
    # first, then the case store collapses to a single <case> badge.
    out = _ANALYST_STAGING_RE.sub(_LABEL_STAGING, out)
    out = _ANALYST_CACHE_RE.sub(_LABEL_HOME, out)
    out = _NEXUS_HOME_RE.sub(_LABEL_HOME, out)
    out = _NEXUS_CASE_RE.sub(_LABEL_CASE, out)
    return out


def sanitize_row_text(
    line: str,
    fields: dict[str, str] | None = None,
    case_dir: Path | None = None,
    roots: list[tuple[str, str]] | None = None,
    family: str = "",
) -> str:
    """Sanitize one raw row: source columns → ``<source>``, rest → placeholders.

    The raw row string is the searchable projection of a CSV line; the value it
    carries for a source/provenance column is machine routing metadata, so the
    column value is replaced outright (no root matching — an ``I:\\`` or
    ``/mnt/...`` evidence source cannot leak either).
    """
    text = str(line or "")
    for key, value in (fields or {}).items():
        raw = str(value or "").strip()
        if raw and _is_source_column(family, key):
            text = text.replace(raw, "<source>")
    return sanitize_machine_paths(text, case_dir, roots)


def sanitize_field_map(
    fields: dict[str, str] | None,
    case_dir: Path | None = None,
    roots: list[tuple[str, str]] | None = None,
    family: str = "",
) -> dict[str, str]:
    """Sanitize every value in a parsed CSV field map (index/scan parity)."""
    if not fields:
        return {}
    out: dict[str, str] = {}
    for k, v in fields.items():
        if _is_source_column(family, str(k)):
            out[str(k)] = "<source>" if str(v or "").strip() else str(v or "")
        else:
            out[str(k)] = sanitize_machine_paths(str(v), case_dir, roots)
    return out
