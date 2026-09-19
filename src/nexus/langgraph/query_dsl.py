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

import re
from datetime import datetime
from typing import Any

_FIELDS = frozenset({"family", "host", "user", "event", "file"})
_TS_FIELDS = frozenset({"ts", "time", "timestamp", "date", "after", "before"})
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
        "ts_start", "ts_end",
    )

    def __init__(self) -> None:
        self.or_terms: list[str] = []
        self.and_terms: list[str] = []
        self.not_terms: list[str] = []
        self.fields: dict[str, str] = {}
        self.regex: re.Pattern[str] | None = None
        self.ts_start: datetime | None = None
        self.ts_end: datetime | None = None

    def is_empty(self) -> bool:
        return not (
            self.or_terms or self.and_terms or self.not_terms
            or self.fields or self.regex or self.ts_start or self.ts_end
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
        if self.regex:
            parts.append(f"regex({self.regex.pattern})")
        return " ".join(parts) if parts else "(match all)"


def parse_query(text: str) -> ParsedQuery:
    """Parse the N4 query DSL. Raises QuerySyntaxError on a bad regex."""
    q = ParsedQuery()
    raw = (text or "").strip()
    if not raw:
        return q

    pending: str | None = None
    for tok in _TOKEN_RE.findall(raw):
        low = tok.lower()
        if not tok.startswith('"') and low in ("and", "or", "not"):
            pending = low if low in ("and", "not") else None
            continue
        if not tok.startswith('"') and low.startswith("regex:"):
            _set_regex(q, tok[6:].strip().strip('"'))
            continue
        _add_term(q, tok, pending)

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


def _add_term(q: ParsedQuery, tok: str, pending: str | None) -> None:
    term = tok.strip()
    # Quoted phrases lose their literal quotes so matching works on row text.
    if len(term) >= 2 and term.startswith('"') and term.endswith('"'):
        term = term[1:-1].strip()
    if not term or (len(term) < 2 and not term.isdigit()):
        return
    if not term.startswith('"') and ":" in term:
        field, _, value = term.partition(":")
        value = value.strip().strip('"').strip()
        if field.lower() in _TS_FIELDS and value:
            _set_ts_range(q, field.lower(), value)
            return
        if field.lower() in _FIELDS and value:
            q.fields[field.lower()] = value.lower()
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
        structured = bool(parsed.fields or parsed.regex or
                          parsed.and_terms or parsed.not_terms)
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
