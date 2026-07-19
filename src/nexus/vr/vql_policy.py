"""Ad-hoc VQL safety policy for live Velociraptor endpoints."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

ENV_ALLOW_ADHOC = "NEXUS_VR_ALLOW_ADHOC_VQL"


class VQLPolicyError(ValueError):
    """Raised when ad-hoc VQL violates the live-mode policy."""


def adhoc_vql_allowed(*, live_mode: bool) -> bool:
    if not live_mode:
        return True
    return os.environ.get(ENV_ALLOW_ADHOC, "").strip().lower() in {"1", "true", "yes"}


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str


_TOKEN_RE = re.compile(
    r"""
    (?P<whitespace>\s+)
    |(?P<comment>/(?:/[^\n]*|--[^\n]*)|/\*[\s\S]*?\*/)
    |(?P<string>'(?:''|[^'])*'|"(?:""|[^"])*")
    |(?P<number>\d+(?:\.\d+)?)
    |(?P<operator><=|>=|<>|!=|=|<|>|,|\.|\(|\)|\*|/|%|\+|-)
    |(?P<keyword>\b(?i:SELECT|FROM|WHERE|LIMIT|AND|OR|NOT|IN|LIKE|IS|NULL|TRUE|FALSE)\b)
    |(?P<identifier>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)
    |(?P<bad>.)
    """,
    re.VERBOSE,
)

_FORBIDDEN_KEYWORDS = frozenset({
    "DELETE", "DROP", "INSERT", "UPDATE", "LET", "EXEC", "SYSTEM", "UPLOAD",
    "EXECVE", "OSQUERY", "WMI", "PSLIST", "NETSTAT", "REGISTRY", "FILE",
})


def _tokenize(vql: str) -> tuple[list[_Token], list[str]]:
    tokens: list[_Token] = []
    comments: list[str] = []
    for match in _TOKEN_RE.finditer(vql):
        kind = match.lastgroup
        value = match.group()
        if kind is None:
            continue
        if kind == "whitespace":
            continue
        if kind == "comment":
            comments.append(value)
            continue
        if kind == "bad":
            raise VQLPolicyError(f"Unexpected character in VQL: {value!r}")
        tokens.append(_Token(kind=kind, value=value))
    return tokens, comments


def _normalize_keyword(value: str) -> str:
    return value.upper()


def validate_adhoc_vql(
    vql: str,
    *,
    live_mode: bool,
    allowed_artifacts: set[str] | None = None,
) -> str:
    text = (vql or "").strip()
    if not text:
        raise VQLPolicyError("Empty VQL query")
    if not live_mode:
        return text
    if not adhoc_vql_allowed(live_mode=True):
        raise VQLPolicyError(
            f"Ad-hoc VQL is disabled in live mode. Use vr_collect_artifact / vr_run_hunt "
            f"or set {ENV_ALLOW_ADHOC}=1 for constrained Artifact.* SELECT queries."
        )

    tokens, comments = _tokenize(text)
    if not tokens:
        raise VQLPolicyError("Empty VQL query after removing comments")

    upper_values = {_normalize_keyword(t.value) for t in tokens if t.kind == "keyword"}
    upper_values.update({_normalize_keyword(t.value) for t in tokens if t.kind == "identifier"})
    for comment in comments:
        upper_comment = comment.upper()
        for word in _FORBIDDEN_KEYWORDS:
            if word in upper_comment:
                upper_values.add(word)
    forbidden = upper_values & _FORBIDDEN_KEYWORDS
    if forbidden:
        raise VQLPolicyError(f"Ad-hoc VQL contains forbidden keywords: {sorted(forbidden)}")

    if len(tokens) < 4:
        raise VQLPolicyError("Live ad-hoc VQL is too short")

    def expect(idx: int, kind: str, value: str | None = None) -> int:
        if idx >= len(tokens):
            raise VQLPolicyError(f"Unexpected end of VQL, expected {kind}")
        tok = tokens[idx]
        if tok.kind != kind:
            raise VQLPolicyError(f"Expected {kind}, got {tok.kind} {tok.value!r}")
        if value is not None and _normalize_keyword(tok.value) != value:
            raise VQLPolicyError(f"Expected {value!r}, got {tok.value!r}")
        return idx + 1

    idx = expect(0, "keyword", "SELECT")
    idx = expect(idx, "operator", "*")
    idx = expect(idx, "keyword", "FROM")

    if idx >= len(tokens) or tokens[idx].kind != "identifier":
        raise VQLPolicyError("Live ad-hoc VQL must SELECT FROM an Artifact")
    artifact_ref = tokens[idx].value
    idx += 1

    if not artifact_ref.startswith("Artifact."):
        raise VQLPolicyError("Live ad-hoc VQL must SELECT FROM Artifact.<Name>")
    artifact_name = artifact_ref[len("Artifact."):]
    if not artifact_name or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", artifact_name):
        raise VQLPolicyError(f"Invalid artifact name: {artifact_name}")

    if allowed_artifacts is not None and artifact_name not in allowed_artifacts:
        raise VQLPolicyError(f"Artifact not in catalog: {artifact_name}")

    if idx < len(tokens) and tokens[idx].kind == "operator" and tokens[idx].value == "(":
        idx += 1
        paren_depth = 1
        while idx < len(tokens) and paren_depth > 0:
            tok = tokens[idx]
            if tok.kind == "operator":
                if tok.value == "(":
                    paren_depth += 1
                elif tok.value == ")":
                    paren_depth -= 1
            idx += 1
        if paren_depth != 0:
            raise VQLPolicyError("Unclosed parenthesis in artifact arguments")

    if idx < len(tokens) and tokens[idx].kind == "keyword" and _normalize_keyword(tokens[idx].value) == "WHERE":
        idx += 1
        if idx >= len(tokens):
            raise VQLPolicyError("WHERE clause requires a condition")
        where_tokens: list[_Token] = []
        while idx < len(tokens) and not (
            tokens[idx].kind == "keyword" and _normalize_keyword(tokens[idx].value) == "LIMIT"
        ):
            where_tokens.append(tokens[idx])
            idx += 1
        _validate_where_clause(where_tokens)

    if idx < len(tokens):
        idx = expect(idx, "keyword", "LIMIT")
        idx = expect(idx, "number")
        if idx < len(tokens):
            raise VQLPolicyError("Unexpected tokens after LIMIT")

    return text


def _validate_where_clause(tokens: list[_Token]) -> None:
    if not tokens:
        raise VQLPolicyError("WHERE clause is empty")
    allowed_ops = {"=", "<", ">", "<=", ">=", "<>", "!=", "AND", "OR", "NOT", "IN", "LIKE", "IS"}
    allowed_char_ops = {"=", "<", ">", "!", "%", "+", "-", "/", "*"}
    for tok in tokens:
        kind = tok.kind
        value = tok.value
        if kind in ("identifier", "string", "number"):
            continue
        if kind == "keyword" and _normalize_keyword(value) in allowed_ops:
            continue
        if kind == "operator" and value in ("(", ")", ","):
            continue
        if kind == "operator" and all(ch in allowed_char_ops for ch in value):
            continue
        raise VQLPolicyError(f"Disallowed token in WHERE clause: {value!r}")
