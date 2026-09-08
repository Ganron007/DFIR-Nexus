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

_FIELDS = frozenset({"family", "host", "user", "event", "file"})
_MAX_OR = 24
_MAX_AND = 12
_MAX_NOT = 12
_MAX_REGEX = 120

_TOKEN_RE = re.compile(r'"[^"]*"|\S+')
# Reject nested quantifiers like (a+)+ or (ab*){2,} — classic ReDoS shapes.
_DANGEROUS_RE = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")


class QuerySyntaxError(ValueError):
    """Malformed N4 query."""


class ParsedQuery:
    """Structured N4 query: any-of / must / must-not terms + field filters."""

    __slots__ = ("or_terms", "and_terms", "not_terms", "fields", "regex")

    def __init__(self) -> None:
        self.or_terms: list[str] = []
        self.and_terms: list[str] = []
        self.not_terms: list[str] = []
        self.fields: dict[str, str] = {}
        self.regex: re.Pattern[str] | None = None

    def is_empty(self) -> bool:
        return not (
            self.or_terms or self.and_terms or self.not_terms
            or self.fields or self.regex
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
        if self.regex:
            parts.append(f"regex({self.regex.pattern})")
        return " ".join(parts) if parts else "(match all)"


def parse_query(text: str) -> ParsedQuery:
    """Parse the N4 query DSL. Raises QuerySyntaxError on a bad regex."""
    q = ParsedQuery()
    raw = (text or "").strip()
    if not raw:
        return q

    if raw.lower().startswith("regex:"):
        pattern = raw[6:].strip()
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
        return q

    pending: str | None = None
    for tok in _TOKEN_RE.findall(raw):
        low = tok.lower()
        if not tok.startswith('"') and low in ("and", "or", "not"):
            pending = low if low in ("and", "not") else None
            continue
        _add_term(q, tok, pending)

    if len(q.or_terms) > _MAX_OR:
        raise QuerySyntaxError(f"too many OR terms (max {_MAX_OR})")
    if len(q.and_terms) > _MAX_AND:
        raise QuerySyntaxError(f"too many AND terms (max {_MAX_AND})")
    if len(q.not_terms) > _MAX_NOT:
        raise QuerySyntaxError(f"too many NOT terms (max {_MAX_NOT})")
    return q


def _add_term(q: ParsedQuery, tok: str, pending: str | None) -> None:
    term = tok.strip()
    # Quoted phrases lose their literal quotes so matching works on row text.
    if len(term) >= 2 and term.startswith('"') and term.endswith('"'):
        term = term[1:-1].strip()
    if not term or (len(term) < 2 and not term.isdigit()):
        return
    if not term.startswith('"') and ":" in term:
        field, _, value = term.partition(":")
        if field.lower() in _FIELDS and value.strip():
            q.fields[field.lower()] = value.strip().lower()
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


def row_matches(
    q: ParsedQuery,
    *,
    line_lower: str,
    family: str = "",
    file_rel: str = "",
) -> tuple[bool, list[str]]:
    """Evaluate a parsed query against one row.

    ``line_lower`` must already be lowercased. Returns
    ``(matched, matched_or_terms)``. An empty query matches everything.
    Numeric terms use the same hex-boundary guard as plain N4 needles so
    event IDs never match inside hashes or UUIDs.
    """
    from nexus.langgraph.query_pack import needle_in_text

    if q.regex is not None and not q.regex.search(line_lower):
        return False, []
    if q.or_terms and not any(needle_in_text(line_lower, t) for t in q.or_terms):
        return False, []
    for t in q.and_terms:
        if not needle_in_text(line_lower, t):
            return False, []
    for t in q.not_terms:
        if needle_in_text(line_lower, t):
            return False, []
    for fname, fvalue in q.fields.items():
        if fname == "family" and family.lower() != fvalue:
            return False, []
        if fname == "file" and fvalue not in file_rel.lower():
            return False, []
        if fname in ("host", "user", "event") and fvalue not in line_lower:
            return False, []
    from nexus.langgraph.query_pack import needle_in_text

    matched = [t for t in q.all_needles() if needle_in_text(line_lower, t)]
    return True, matched
