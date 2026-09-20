"""N4 query DSL — boolean terms, field filters, regex for examiner queries.

Grammar (operators case-insensitive, terms space-separated):

    sdelete                          bare term  -> any-of group
    sdelete OR cipher                any-of union
    sdelete AND host:WS01            conjunction (must also match)
    sdelete NOT setup.exe            exclusion
    family:evtx event:4624 file:mft  field filters
    "faulting application"           quoted phrase (substring, case-insensitive)
    regex:sdelete.*\\.exe            regex mode for the whole row text

Row matches iff:
    (no or_terms OR any or_term matches)
    AND every and_term matches
    AND no not_term matches
    AND every field filter passes
    AND (regex is None OR regex matches the row text)

Fields: family (exact, case-insensitive), file (substring of the relative
path), host / user / event (substring of the row text — CSV rows are not
column-parsed).

ReDoS guard: regex length capped; nested-quantifier patterns rejected.
"""

from __future__ import annotations

import fnmatch
import re
from datetime import datetime
from typing import Any

_FIELDS = frozenset({"family", "host", "user", "event", "file"})
_TS_FIELDS = frozenset({"ts", "time", "timestamp", "date", "after", "before"})
# 4k.6: any other identifier becomes a TYPED catalog filter — never a text
# term. URL schemes and single-letter drive tokens stay plain terms.
_FILTER_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{1,63}$")
_URL_SCHEMES = frozenset({"http", "https", "ftp", "ftps", "ws", "wss", "s3", "gs", "tcp", "udp"})
# Core envelope columns are typed-filterable too (host:=WS01, eventid:>=4688).
_CORE_TYPED: dict[str, tuple[str, str]] = {
    "family": ("family", "keyword"),
    "file": ("file", "keyword"),
    "host": ("host", "keyword"),
    "user": ("user", "keyword"),
    "event": ("event_id", "keyword"),
    "eventid": ("event_id", "keyword"),
    "event_id": ("event_id", "keyword"),
    "line": ("line", "long"),
    "computer": ("host", "keyword"),
    "machine": ("host", "keyword"),
}
_NUMERIC_TYPES = frozenset({
    "long", "integer", "short", "byte", "double", "float", "half_float",
    "scaled_float", "unsigned_long",
})
_DATE_TYPES = frozenset({"date", "date_nanos"})
_MAX_OR = 24
_MAX_AND = 12
_MAX_NOT = 12
_MAX_REGEX = 120

_TOKEN_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*:"[^"]*"|"[^"]*"|\S+')
# Reject nested quantifiers like (a+)+ or (ab*){2,} — classic ReDoS shapes.
_DANGEROUS_RE = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")


class QuerySyntaxError(ValueError):
    """Malformed N4 query."""


class ParsedQuery:
    """Structured N4 query: any-of / must / must-not terms + field filters."""

    __slots__ = (
        "or_terms", "and_terms", "not_terms", "fields", "regex",
        "ts_start", "ts_end", "filters",
    )

    def __init__(self) -> None:
        self.or_terms: list[str] = []
        self.and_terms: list[str] = []
        self.not_terms: list[str] = []
        self.fields: dict[str, str] = {}
        self.regex: re.Pattern[str] | None = None
        self.ts_start: datetime | None = None
        self.ts_end: datetime | None = None
        # Typed catalog filters: {name, resolved, type, op, value|values|lo|hi}
        self.filters: list[dict[str, Any]] = []

    def is_empty(self) -> bool:
        return not (
            self.or_terms or self.and_terms or self.not_terms
            or self.fields or self.regex or self.ts_start or self.ts_end
            or self.filters
        )

    def all_needles(self) -> list[str]:
        """OR + AND terms, deduped case-insensitively, order preserved."""
        seen: dict[str, None] = {}
        for t in self.or_terms + self.and_terms:
            seen.setdefault(t.lower(), None)
        return list(seen)

    def describe(self) -> str:
        parts: list[str] = []
        if self.or_terms:
            parts.append("any(" + ", ".join(self.or_terms) + ")")
        if self.and_terms:
            parts.append("all(" + ",".join(self.and_terms) + ")")
        if self.not_terms:
            parts.append("not(" + ",".join(self.not_terms) + ")")
        for k in sorted(self.fields):
            parts.append(f"{k}:{self.fields[k]}")
        if self.ts_start or self.ts_end:
            lo = self.ts_start.isoformat() if self.ts_start else ""
            hi = self.ts_end.isoformat() if self.ts_end else ""
            parts.append(f"ts:{lo}..{hi}")
        for f in self.filters:
            op = f.get("op") or "contains"
            if op == "exists":
                parts.append(f"exists:{f.get('value')}")
            elif op == "in":
                parts.append(f"{f['name']}:in:({','.join(f.get('values') or [])})")
            elif op == "range":
                parts.append(f"{f['name']}:{f.get('lo') or ''}..{f.get('hi') or ''}")
            elif op == "contains":
                parts.append(f"{f['name']}:{f.get('value')}")
            else:
                parts.append(f"{f['name']}:{op}:{f.get('value')}")
        if self.regex:
            parts.append(f"regex({self.regex.pattern})")
        return " ".join(parts) if parts else "(match all)"


def parse_query(text: str, catalog: dict[str, Any] | None = None) -> ParsedQuery:
    """Parse the N4 query DSL.

    ``catalog`` (``field_catalog.case_field_catalog``) enables hard errors:
    an identifier-shaped ``name:value`` that is not a catalog column raises
    ``QuerySyntaxError`` instead of silently becoming a text term. Without a
    catalog the filter is accepted and the executor validates it.
    """
    q = ParsedQuery()
    raw = (text or "").strip()
    if not raw:
        return q
    # ``field:in:(a, b)`` — collapse spaces inside the list so the tokenizer
    # keeps it as ONE token (a stray "b)" used to leak into or_terms).
    raw = re.sub(
        r":in:\s*\(([^)]*)\)",
        lambda m: ":in:(" + ",".join(p for p in m.group(1).replace(" ", "").split(",") if p) + ")",
        raw,
        flags=re.IGNORECASE,
    )

    pending: str | None = None
    for tok in _TOKEN_RE.findall(raw):
        low = tok.lower()
        if not tok.startswith('"') and low in ("and", "or", "not"):
            pending = low if low in ("and", "not") else None
            continue
        if not tok.startswith('"') and low.startswith("regex:"):
            _set_regex(q, tok[6:].strip().strip('"'))
            continue
        _add_term(q, tok, pending, catalog)

    if len(q.or_terms) > _MAX_OR:
        raise QuerySyntaxError(f"too many OR terms (max {_MAX_OR})")
    if len(q.and_terms) > _MAX_AND:
        raise QuerySyntaxError(f"too many AND terms (max {_MAX_AND})")
    if len(q.not_terms) > _MAX_NOT:
        raise QuerySyntaxError(f"too many NOT terms (max {_MAX_NOT})")
    return q


def _set_regex(q: ParsedQuery, pattern: str) -> None:
    if q.regex is not None:
        raise QuerySyntaxError("only one regex: term is allowed")
    if not pattern:
        raise QuerySyntaxError("regex: requires a pattern")
    if len(pattern) > _MAX_REGEX:
        raise QuerySyntaxError(f"regex longer than {_MAX_REGEX} chars")
    if _DANGEROUS_RE.search(pattern):
        raise QuerySyntaxError("regex rejected: nested quantifier (ReDoS guard)")
    try:
        q.regex = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise QuerySyntaxError(f"invalid regex: {exc}") from None


def _set_ts_range(q: ParsedQuery, field: str, value: str) -> None:
    """Typed time filter: ts:>=X, ts:<=X, ts:A..B, ts:DATE, after:X, before:X."""
    from nexus.langgraph.timestamps import parse_time_value

    raw = value.strip()
    op = ""
    for candidate in (">=", "<=", ">", "<"):
        if raw.startswith(candidate):
            op = candidate
            raw = raw[len(candidate):].strip()
            break
    low = raw.lower()
    if low in ("", "*", "any"):
        return

    def _parsed(text: str) -> dict:
        got = parse_time_value(text)
        if got is None:
            raise QuerySyntaxError(f"unparseable timestamp in ts filter: {text!r}")
        return got

    if op or field in ("after", "before"):
        got = _parsed(raw)
        dt = got["dt"]
        if field == "before" or op == "<":
            q.ts_end = dt
        elif field == "after" or op == ">" or op == ">=":
            q.ts_start = dt
        else:  # op == "<="
            q.ts_end = dt
        return
    if ".." in raw:
        lo_raw, _, hi_raw = raw.partition("..")
        if lo_raw.strip():
            q.ts_start = _parsed(lo_raw.strip())["dt"]
        if hi_raw.strip():
            q.ts_end = _parsed(hi_raw.strip())["dt"]
        return
    got = _parsed(raw)
    dt = got["dt"]
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        from datetime import timedelta

        q.ts_start = dt
        q.ts_end = dt + timedelta(days=1) - timedelta(seconds=1)
    else:
        q.ts_start = dt
        q.ts_end = dt


_OPS = ("!=", ">=", "<=", "=", ">", "<")


def _looks_typed_op(value: str) -> bool:
    v = str(value or "")
    return (
        v[:2] in ("!=", ">=", "<=")
        or v[:1] in ("=", ">", "<")
        or v.lower().startswith("in:")
        or ".." in v
    )


def _parse_filter_value(value: str) -> tuple[str, dict[str, Any]]:
    """Operator + payload for a typed filter value."""
    raw = str(value or "").strip()
    for op in _OPS:
        if raw.startswith(op):
            inner = raw[len(op):].strip()
            if op == "!=":
                return "ne", {"value": inner}
            if op == "=":
                return "eq", {"value": inner}
            if op == ">=":
                return "gte", {"value": inner}
            if op == "<=":
                return "lte", {"value": inner}
            if op == ">":
                return "gt", {"value": inner}
            return "lt", {"value": inner}
    low = raw.lower()
    if low.startswith("in:"):
        inner = raw[3:].strip()
        if inner.startswith("(") and inner.endswith(")"):
            inner = inner[1:-1]
        values = [v.strip().strip('"') for v in inner.split(",") if v.strip()]
        if not values:
            raise QuerySyntaxError("in:(...) needs at least one value")
        return "in", {"values": values}
    if ".." in raw:
        lo, _, hi = raw.partition("..")
        lo, hi = lo.strip(), hi.strip()
        if not lo and not hi:
            raise QuerySyntaxError("range needs at least one bound (a..b)")
        return "range", {"lo": lo, "hi": hi}
    return "contains", {"value": raw}


def _maybe_filter(q: ParsedQuery, name_raw: str, value: str,
                  catalog: dict[str, Any] | None) -> bool:
    """Identifier-shaped ``name:value`` → typed filter (or hard error)."""
    name = str(name_raw or "").strip()
    if not name or not value:
        return False
    low = name.lower()
    if low in _URL_SCHEMES:  # http://host — a term, not a field
        return False
    if low == "exists":
        target = value.strip()
        if not target:
            return False
        if catalog and target.lower() not in catalog and target.lower() not in _CORE_TYPED:
            from nexus.langgraph.field_catalog import suggest_field

            hints = suggest_field(catalog, target)
            raise QuerySyntaxError(
                f"exists: unknown field {target!r}"
                + (f" — did you mean {', '.join(hints)}?" if hints else "")
            )
        q.filters.append({"name": "exists", "resolved": target, "type": "",
                          "op": "exists", "value": target})
        return True
    if len(name) < 2 or not _FILTER_NAME_RE.match(name):
        return False
    if value.startswith("//"):  # URL path
        return False
    entry = None
    if catalog:
        from nexus.langgraph.field_catalog import resolve_field

        entry = resolve_field(catalog, low)
    if entry is None and low in _CORE_TYPED:
        target, core_type = _CORE_TYPED[low]
        entry = {"name": target, "type": core_type, "has_kw": False,
                 "path": target, "core": True}
    op, payload = _parse_filter_value(value)
    if catalog and entry is None and op == "contains":
        from nexus.langgraph.field_catalog import suggest_field

        hints = suggest_field(catalog, low)
        raise QuerySyntaxError(
            f"unknown field {name!r}"
            + (f" — did you mean {', '.join(hints)}?" if hints else "")
        )
    resolved = (entry or {}).get("name", name)
    q.filters.append({
        "name": low,
        "resolved": resolved,
        "type": (entry or {}).get("type", ""),
        "path": (entry or {}).get("path") or f"fields.{resolved}",
        "has_kw": bool((entry or {}).get("has_kw", True)),
        "op": op,
        **payload,
    })
    return True


def _field_lookup(fields: dict[str, str], name: str) -> str | None:
    low = str(name or "").lower()
    for key, val in (fields or {}).items():
        if str(key).lower() == low:
            return str(val)
    return None


def _as_number(value: str) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _filter_matches(f: dict[str, Any], row_fields: dict[str, str]) -> bool:
    """CSV parity for one typed filter (missing column → clause false)."""
    op = f.get("op") or "contains"
    if op == "exists":
        val = _field_lookup(row_fields, str(f.get("resolved") or f.get("value") or ""))
        return val not in (None, "")
    raw = _field_lookup(row_fields, str(f.get("resolved") or f.get("name") or ""))
    if raw is None:
        return False
    low = raw.strip().lower()
    if op == "contains":
        needle = str(f.get("value") or "").lower()
        if "*" in needle or "?" in needle:
            return fnmatch.fnmatchcase(low, needle)
        return needle in low
    if op == "eq":
        return low == str(f.get("value") or "").lower()
    if op == "ne":
        return low != str(f.get("value") or "").lower()
    if op == "in":
        want = {str(v).strip().lower() for v in (f.get("values") or [])}
        return low in want
    # numeric / date comparisons
    def _cmp(left: Any, right: Any) -> tuple[Any, Any] | None:
        ln, rn = _as_number(str(left)), _as_number(str(right))
        if ln is None or rn is None:
            from nexus.langgraph.timestamps import parse_time_value

            g1, g2 = parse_time_value(str(left)), parse_time_value(str(right))
            if g1 is None or g2 is None:
                return None
            ln, rn = g1["dt"], g2["dt"]
        return ln, rn

    if op in ("gt", "gte", "lt", "lte"):
        pair = _cmp(raw, f.get("value"))
        if pair is None:
            return False
        ln, rn = pair
        return {
            "gt": ln > rn, "gte": ln >= rn, "lt": ln < rn, "lte": ln <= rn,
        }[op]
    if op == "range":
        lo, hi = f.get("lo"), f.get("hi")
        if lo in (None, "") and hi in (None, ""):
            return False
        if lo not in (None, ""):
            pair = _cmp(raw, lo)
            if pair is None or pair[0] < pair[1]:
                return False
        if hi not in (None, ""):
            pair = _cmp(raw, hi)
            if pair is None or pair[0] > pair[1]:
                return False
        return True
    return False


def _add_term(q: ParsedQuery, tok: str, pending: str | None,
              catalog: dict[str, Any] | None = None) -> None:
    term = tok.strip()
    # Quoted phrases lose their literal quotes so matching works on row text.
    if len(term) >= 2 and term.startswith('"') and term.endswith('"'):
        term = term[1:-1].strip()
    if not term or (len(term) < 2 and not term.isdigit()):
        return
    if not term.startswith('"') and ":" in term:
        field, _, value = term.partition(":")
        value = value.strip().strip('"').strip()
        low_field = field.lower()
        if low_field in _URL_SCHEMES or value.startswith("//"):
            pass  # URL, not a field (http://, smb://)
        else:
            if low_field in _TS_FIELDS and value:
                _set_ts_range(q, low_field, value)
                return
            if (
                value and _looks_typed_op(value)
                and _maybe_filter(q, field, value, catalog)
            ):
                return
            if low_field in _FIELDS and value:
                q.fields[low_field] = value.lower()
                return
            if _maybe_filter(q, field, value, catalog):
                return
    bucket = (
        q.and_terms if pending == "and"
        else q.not_terms if pending == "not"
        else q.or_terms
    )
    if term.lower() not in {x.lower() for x in q.or_terms + q.and_terms + q.not_terms}:
        bucket.append(term)


def _term_in(term: str, line_lower: str) -> bool:
    """Numeric terms use hex-boundary matching (1102 must not match a hash);
    everything else stays substring. Kept for external callers/tests."""
    from nexus.langgraph.query_pack import needle_in_text

    return needle_in_text(line_lower, term)


def _row_dt(row_ts: str, line_lower: str) -> datetime | None:
    from nexus.langgraph.timestamps import parse_time_value

    got = parse_time_value(row_ts or "") if row_ts else None
    if got is None:
        got = parse_time_value(line_lower or "")
    return got["dt"] if got else None


def row_matches(
    q: ParsedQuery,
    *,
    line_lower: str,
    family: str = "",
    file_rel: str = "",
    extra_text: str = "",
    row_ts: str = "",
    row_fields: dict[str, str] | None = None,
) -> tuple[bool, list[str]]:
    """Evaluate a parsed query against one row.

    ``line_lower`` must already be lowercased. ``extra_text`` is optional
    additional searchable text (schema-v2 parsed ``fields.*`` values) so terms
    that live in structured columns match even when the raw line is compact.
    Returns ``(matched, matched_or_terms)``. An empty query matches
    everything. Numeric terms use the same hex-boundary guard as plain N4
    needles so event IDs never match inside hashes or UUIDs.
    """
    from nexus.langgraph.query_pack import needle_in_text

    hay = line_lower if not extra_text else f"{line_lower}\n{extra_text.lower()}"
    if q.filters:
        # Typed catalog filters need parsed columns; a row without them can
        # only fail the clause (loud, never a silent pass).
        if not row_fields:
            return False, []
        for f in q.filters:
            if not _filter_matches(f, row_fields):
                return False, []
    if q.ts_start is not None or q.ts_end is not None:
        # Explicit time filter: a row with no parseable time cannot match —
        # excluding it silently would be a lie; callers count these separately.
        dt = _row_dt(row_ts, line_lower)
        if dt is None:
            return False, []
        if q.ts_start is not None and dt < q.ts_start:
            return False, []
        if q.ts_end is not None and dt > q.ts_end:
            return False, []
    if q.regex is not None and not q.regex.search(hay):
        return False, []
    if q.or_terms and not any(needle_in_text(hay, t) for t in q.or_terms):
        return False, []
    for t in q.and_terms:
        if not needle_in_text(hay, t):
            return False, []
    for t in q.not_terms:
        if needle_in_text(hay, t):
            return False, []
    for fname, fvalue in q.fields.items():
        if fname == "family" and family.lower() != fvalue:
            return False, []
        if fname == "file" and fvalue not in file_rel.lower():
            return False, []
        if fname in ("host", "user", "event") and fvalue not in hay:
            return False, []

    matched = [t for t in q.all_needles() if needle_in_text(hay, t)]
    return True, matched


def validate_or_degrade(query: str) -> dict[str, Any]:
    """WP 4j.11 validation wall — parse an LLM-emitted query or degrade it.

    Returns ``{"query", "dsl", "fallback", "reason"}``: a parseable query
    passes through verbatim (``dsl`` flags whether it used fields/AND/NOT/
    regex); a parse failure degrades to bare terms — never a silent wrong
    query. Shared by both entry points (mode1 ``nl_to_needles`` and the
    Mode 2 proposal wall).
    """
    q = (query or "").strip()
    try:
        parsed = parse_query(q)
        if parsed.is_empty():
            return {"query": q, "dsl": False, "fallback": True,
                    "reason": "empty parse"}
        structured = bool(parsed.fields or parsed.regex or parsed.and_terms
                          or parsed.not_terms or parsed.filters)
        return {"query": q, "dsl": structured, "fallback": False}
    except QuerySyntaxError:
        bare: list[str] = []
        for token in _TOKEN_RE.findall(q):
            low = token.lower()
            if low in ("and", "or", "not"):
                continue
            if ":" in token:
                name, _, value = token.partition(":")
                if name.lower() in _FIELDS or name.lower() == "regex":
                    token = value
            bare.extend(re.findall(r"[A-Za-z0-9_.\\-]{2,}", token))
        seen: dict[str, None] = {}
        for token in bare:
            seen.setdefault(token, None)
        return {"query": " ".join(list(seen)[:8]), "dsl": False,
                "fallback": True, "reason": "query failed N4 parse — bare terms used"}


def _validate_dsl(query: str) -> dict[str, Any]:  # noqa: F811 — moved alias
    return validate_or_degrade(query)
