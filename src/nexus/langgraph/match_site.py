"""Mode 1 match-site awareness — what a keyword hit landed on.

Mode 1 is keyword search (patterns/sequences are Mode 3). But a keyword only
means something when it lands in evidence *content* with a token boundary:

- ``sdelete64.exe`` on a command line: a real hit (signal).
- ``cipher`` inside ``CipherData``: embedded in an identifier — not a hit.
- ``325`` inside a timestamp (``13:25:46``) or matching an EventId cell: a fact
  about the evidence ("there are N events with id 325"), not suspicious
  behaviour.
- ``winlogon`` matching a Provider/Channel label: infrastructure, not action.

Every match is therefore classified per column (family-aware) and per token
shape. The scan keeps its keyword semantics; only counting/ranking/staging
gain the awareness.

Classes per column:
  content    -> token-boundary hit counts as a signal hit
  structure  -> labels/enumerations (Provider, Level, Rule, Description) => fact
  numeric    -> ids/counters/ports => exact value only => fact
  timestamp  -> never counted
  provenance -> machine source path (already sanitized) => skipped
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

_DATA = Path(__file__).resolve().parent.parent / "data"
_CLASSES_PATH = _DATA / "schema" / "column_classes.yaml"
_REGISTRY_PATH = _DATA / "schema" / "field_registry.yaml"

_NUMERIC_TERM = re.compile(r"^\d+$")
_BOUNDARY_RX: dict[str, re.Pattern[str]] = {}
_NUMERIC_RX: dict[str, re.Pattern[str]] = {}
_MAX_SITES = 12

_NUMERIC_TYPES = frozenset({"long", "integer", "short", "byte", "double", "float"})
_TIMESTAMP_TYPES = frozenset({"date", "timestamp", "date_nanos"})


def _norm(name: str) -> str:
    return str(name or "").strip().lstrip("\ufeff").lower()


def _file_sig(path: str) -> tuple[int, int]:
    try:
        st = Path(path).stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return (0, 0)


@lru_cache(maxsize=8)
def _classes_cached(path: str, mtime_ns: int, size: int) -> dict[str, frozenset[str]]:
    import yaml

    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}
    out: dict[str, frozenset[str]] = {}
    for key in ("content", "structure", "id_like"):
        rows = data.get(key) or []
        out[key] = frozenset(
            _norm(r) for r in rows if isinstance(r, (str, int, float)) and str(r).strip()
        )
    return out


@lru_cache(maxsize=8)
def _registry_cached(path: str, mtime_ns: int, size: int) -> dict[str, str]:
    import yaml

    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}
    out: dict[str, str] = {}
    for name, meta in (data.get("columns") or {}).items():
        if isinstance(meta, dict):
            out[_norm(name)] = str(meta.get("type") or "").lower()
    return out


def _classes() -> dict[str, frozenset[str]]:
    return _classes_cached(
        str(_CLASSES_PATH), *_file_sig(str(_CLASSES_PATH))
    )


def _registry_types() -> dict[str, str]:
    return _registry_cached(
        str(_REGISTRY_PATH), *_file_sig(str(_REGISTRY_PATH))
    )


def column_class(family: str, name: str) -> str:
    """Match-site class for one column of one family."""
    n = _norm(name)
    if not n:
        return "content"
    from nexus.langgraph.path_sanitize import _is_source_column

    if _is_source_column(family, n):
        return "provenance"
    cls = _classes()
    if n in cls.get("content", frozenset()):
        return "content"
    if n in cls.get("structure", frozenset()):
        return "structure"
    if n in cls.get("id_like", frozenset()):
        return "numeric"
    column_type = _registry_types().get(n, "")
    if column_type in _NUMERIC_TYPES:
        return "numeric"
    if column_type in _TIMESTAMP_TYPES:
        return "timestamp"
    return "content"


def token_boundary_match(value: str, term: str) -> bool:
    """Alpha term at a token boundary: ``sdelete`` hits ``sdelete64.exe``,
    ``cipher`` does not hit ``CipherData``."""
    v = str(value or "").lower()
    t = str(term or "").strip().lower()
    if not v or not t:
        return False
    rx = _BOUNDARY_RX.get(t)
    if rx is None:
        rx = re.compile(rf"(?<![a-z0-9_]){re.escape(t)}(?![a-z_])")
        _BOUNDARY_RX[t] = rx
    return bool(rx.search(v))


def numeric_in_text(value: str, term: str) -> bool:
    """Numeric term as a standalone token (never inside hashes/UUIDs)."""
    v = str(value or "").lower()
    t = str(term or "").strip().lower()
    if not v or not t:
        return False
    rx = _NUMERIC_RX.get(t)
    if rx is None:
        rx = re.compile(rf"(?<![0-9a-f]){re.escape(t)}(?![0-9a-f])")
        _NUMERIC_RX[t] = rx
    return bool(rx.search(v))


def _num_equal(value: str, term: str) -> bool:
    v = str(value or "").strip()
    if not v:
        return False
    if v == term:
        return True
    try:
        return float(v) == float(term)
    except ValueError:
        return False


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(item.strip())
    return out


def classify_matched_terms(
    family: str,
    fields: dict[str, Any] | None,
    text: str,
    matched: list[str],
) -> dict[str, Any]:
    """Classify already-matched needle terms against their match site.

    Returns ``signal`` (content, token-boundary), ``facts`` (id/label columns),
    ``weak`` (embedded / numeric-in-text / no-column numerics) and ``sites``
    (term/field/class/kind detail, capped). Only terms the caller already
    matched are classified — this stays cheap.
    """
    empty: dict[str, Any] = {"signal": [], "facts": [], "weak": [], "sites": []}
    terms = [str(t).strip() for t in (matched or []) if str(t).strip()]
    if not terms:
        return empty

    items = [
        (str(k), str(v))
        for k, v in (fields or {}).items()
        if str(v or "").strip()
    ]
    signal: list[str] = []
    facts: list[str] = []
    weak: list[str] = []
    sites: list[dict[str, str]] = []

    def _site(term: str, field: str, cls: str, kind: str) -> None:
        if len(sites) < _MAX_SITES:
            sites.append({"term": term, "field": field, "class": cls, "kind": kind})

    for term in terms:
        if term == "*":
            signal.append("*")
            continue
        low_t = term.lower()
        numeric = bool(_NUMERIC_TERM.fullmatch(low_t))
        is_signal = False

        if items:
            term_found = False
            for name, value in items:
                cls = column_class(family, name)
                if cls == "provenance":
                    continue
                v_low = value.lower()
                if numeric:
                    if cls == "numeric" and _num_equal(value, low_t):
                        facts.append(term)
                        _site(term, name, cls, "value")
                        term_found = True
                    elif cls == "content" and numeric_in_text(v_low, low_t):
                        weak.append(term)
                        _site(term, name, cls, "in-text")
                        term_found = True
                    # timestamps and embedded identifier fragments: not counted
                elif cls in {"numeric", "timestamp"}:
                    if low_t in v_low:
                        weak.append(term)
                        _site(term, name, cls, "in-text")
                        term_found = True
                elif token_boundary_match(v_low, low_t):
                    if cls == "content":
                        signal.append(term)
                        _site(term, name, cls, "token")
                        is_signal = True
                        term_found = True
                        break
                    facts.append(term)
                    _site(term, name, cls, "label")
                    term_found = True
                elif low_t in v_low:
                    weak.append(term)
                    _site(term, name, cls, "embedded")
                    term_found = True
            if not numeric and not term_found and token_boundary_match(text, low_t):
                # The row matched, but no single field carries the term: split
                # or malformed CSV rows (comma needles survive the round trip).
                # Numerics never take this path — timestamps/ids stay protected.
                signal.append(term)
                _site(term, "", "content", "token")
                is_signal = True
        else:
            # Headerless rows: no column to attribute. Alpha terms keep the
            # token-boundary rule; numerics cannot be confirmed as a field
            # value, so they are reported weak (never a signal).
            if numeric:
                weak.append(term)
            elif token_boundary_match(text, low_t):
                signal.append(term)
                is_signal = True
            elif low_t in str(text or "").lower():
                weak.append(term)
        if is_signal and term not in signal:
            signal.append(term)

    sig_keys = {s.strip().lower() for s in signal if s.strip()}
    facts = [t for t in facts if t.strip().lower() not in sig_keys]
    weak = [t for t in weak if t.strip().lower() not in sig_keys]
    keep_terms = sig_keys | {t.strip().lower() for t in facts} | {
        t.strip().lower() for t in weak
    }
    sites = [s for s in sites if str(s.get("term") or "").strip().lower() in keep_terms]
    return {
        "signal": _dedupe(signal),
        "facts": _dedupe(facts),
        "weak": _dedupe(weak),
        "sites": sites,
    }
