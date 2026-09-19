"""Audit-id ↔ evidence linkage (EH-9).

FD-001 requires findings to cite ``audit_id``s from real tool calls, but until
this module the *relationship* between a cited call and the finding was never
checked. Family→tool matching was two-way substring against the tool name, and
on no match the staging paths attached the first 3 OK audit ids of ANY tool.
Findings could therefore cite existent-but-unrelated audits and pass FD-001
mechanically.

This module builds an explicit linkage map:

    audit_id -> {tokens}

Tokens come from the two authoritative sources the case already has:

  * the tool-lane ledger (``_tool_lane_ledger.json``): tool name, output-file
    basenames + parent directory names, mapped parser families;
  * the case audit log (``audit/*.jsonl``): tool name, scalar param values
    (``path``/``source``/``family``/``file``), ``input_files`` basenames, and
    ``result_summary.source`` (the detector's family for ingest runs).

``linked_audit_ids(case_dir, families, files)`` returns only the audit ids
whose tokens intersect the finding's families/files — and **returns [] when
nothing matches**. No fallback: a finding with no linked audit id is exactly
the finding FD-001 is supposed to stop.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# family -> parser/ingest tool that produces it (single source of truth;
# query_pack re-exports this for backward compatibility).
_FAMILY_TO_TOOL: dict[str, str] = {
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
    "evtxecmd": "evtxecmd",
    "chainsaw": "chainsaw",
    "mftecmd": "mftecmd",
    "bits": "bitsparser",
    "vol": "vol",
    "volatility": "vol",
    "setupapi": "setupapi",
    # imported (non-host) evidence: the detector's source IS the family
    "suricata": "ingest_auto",
    "zeek": "ingest_auto",
    "wireshark": "ingest_auto",
    "pcap": "ingest_auto",
    "netflow": "ingest_auto",
    "nfdump": "ingest_auto",
    "syslog": "ingest_auto",
    "splunk": "ingest_auto",
    "elastic": "ingest_auto",
    "security_onion": "ingest_auto",
    "wazuh": "ingest_auto",
    "socrates": "ingest_auto",
    "cloudtrail": "ingest_auto",
    "azure": "ingest_auto",
    "m365": "ingest_auto",
    "email": "ingest_auto",
    "eml": "ingest_auto",
    "msg": "ingest_auto",
    "generic_csv": "ingest_auto",
    "generic_jsonl": "ingest_auto",
}

_TOKEN_CLEAN = re.compile(r"[^a-z0-9_.\-/\\ ]+")
_MAX_TOKENS_PER_ID = 64

# linkage cache: case_dir -> (stamp, map)
_LINKAGE_CACHE: dict[str, tuple[tuple[float, float], dict[str, set[str]]]] = {}


def _norm(token: Any) -> str:
    text = str(token or "").strip().lower().replace("\\", "/")
    text = _TOKEN_CLEAN.sub(" ", text)
    return " ".join(text.split())


def _tokens_from_value(value: Any, out: set[str]) -> None:
    """Collect useful tokens from a scalar / small structure."""
    if value in (None, "", [], {}):
        return
    if isinstance(value, dict):
        for v in value.values():
            _tokens_from_value(v, out)
        return
    if isinstance(value, (list, tuple)):
        for v in value:
            _tokens_from_value(v, out)
        return
    text = _norm(value)
    if not text:
        return
    out.add(text)
    # Paths: only the basename (+ its dotted prefix) and the immediate parent
    # are useful linkage tokens. Drive letters and shared root segments
    # ("d", "evidence", "cases") used to false-link every audit under the
    # same evidence root to every finding (EH-9 re-audit).
    if "/" in text:
        parts = [p for p in text.split("/") if p]
        if parts:
            base = parts[-1]
            out.add(base)
            if "." in base:
                out.add(base.split(".")[0])
            if len(parts) > 1:
                parent = parts[-2]
                out.add(parent)
                if parent in _TOOL_FAMILIES or parent in _FAMILY_TO_TOOL:
                    for fam_token in family_tokens(parent):
                        out.add(fam_token)
    else:
        # dotted prefixes for bare filenames ("eve.json" -> "eve")
        if "." in text:
            out.add(text.split(".")[0])


# Tools that produce several families (the detector decides which). Linking
# on the tool name alone would make every ingest_auto call match every
# imported family — for these, linkage must come from the audit entry's
# recorded source / file tokens, never from the tool name.
_SHARED_TOOLS = {"ingest_auto"}

_TOOL_FAMILIES: dict[str, set[str]] = {}
for _fam, _tool in _FAMILY_TO_TOOL.items():
    _TOOL_FAMILIES.setdefault(_tool, set()).add(_fam)


def tool_tokens(tool: str) -> set[str]:
    """Tokens contributed by a tool name (families only when unambiguous).

    Ledger tool names are sometimes namespaced (``windows/pecmd``) — the last
    path segment links to the mapped family as well.
    """
    name = _norm(tool)
    if not name:
        return set()
    tokens = {name}
    bare = name.rsplit("/", 1)[-1].strip()
    if bare and bare != name:
        tokens.add(bare)
    for candidate in (name, bare):
        if candidate and candidate not in _SHARED_TOOLS:
            tokens |= _TOOL_FAMILIES.get(candidate, set())
    return tokens


def family_tokens(family: str) -> set[str]:
    """Tokens that link a family to its producing tool (both directions)."""
    fam = _norm(family)
    if not fam:
        return set()
    tokens = {fam}
    mapped = _FAMILY_TO_TOOL.get(fam)
    if mapped and mapped not in _SHARED_TOOLS:
        tokens.add(mapped)
    for other_fam, tool in _FAMILY_TO_TOOL.items():
        if tool == fam and fam not in _SHARED_TOOLS:
            tokens.add(other_fam)
    return tokens


def _ledger_path(case_dir: Path) -> Path | None:
    try:
        from nexus.langgraph.pipeline_runs import resolve_tools_extractions

        extractions = resolve_tools_extractions(case_dir)
    except Exception:  # noqa: BLE001 — linkage is best-effort on odd layouts
        return None
    for candidate in (
        extractions / "_tool_lane_ledger.json",
        extractions.parent / "ledger" / "_tool_lane_ledger.json",
    ):
        if candidate.is_file():
            return candidate
    return None


def _linkage_stamp(case_dir: Path) -> tuple[float, float]:
    ledger = _ledger_path(case_dir)
    ledger_mtime = ledger.stat().st_mtime_ns if ledger else 0.0
    audit_mtime = 0.0
    audit_dir = case_dir / "audit"
    if audit_dir.is_dir():
        try:
            for path in audit_dir.glob("*.jsonl"):
                audit_mtime = max(audit_mtime, path.stat().st_mtime_ns)
        except OSError:
            pass
    return (float(ledger_mtime), float(audit_mtime))


def linkage_map(
    case_dir: Path,
    ledger: list[dict[str, Any]] | None = None,
) -> dict[str, set[str]]:
    """``audit_id -> tokens`` for one case (mtime-cached).

    ``ledger`` lets a caller that already holds the tool-lane ledger rows use
    them instead of re-reading the file (in-memory rows are not cached).
    """
    case_dir = Path(case_dir)
    use_cache = ledger is None
    if use_cache:
        stamp = _linkage_stamp(case_dir)
        cached = _LINKAGE_CACHE.get(str(case_dir))
        if cached and cached[0] == stamp:
            return cached[1]
    else:
        stamp = (0.0, 0.0)

    linkage: dict[str, set[str]] = {}

    def add(audit_id: str, tokens: set[str]) -> None:
        if not audit_id:
            return
        bucket = linkage.setdefault(str(audit_id), set())
        # sorted so the 64-token cap is deterministic (family/tool tokens
        # sort early; set-iteration order used to drop them randomly).
        for token in sorted(t for t in tokens if t):
            if len(bucket) < _MAX_TOKENS_PER_ID:
                bucket.add(token)

    # 1) tool-lane ledger (caller override wins)
    rows_override = ledger
    ledger_file = _ledger_path(case_dir)
    rows: list[Any] = list(rows_override or [])
    if not rows and ledger_file:
        try:
            loaded = json.loads(ledger_file.read_text(encoding="utf-8"))
            rows = loaded if isinstance(loaded, list) else []
        except (OSError, ValueError):
            rows = []
    if rows:
        for row in rows:
            aid = row.get("audit_id")
            if not aid:
                continue
            tokens: set[str] = set()
            tool = _norm(row.get("tool"))
            if tool:
                tokens |= tool_tokens(tool)
            for out_file in row.get("output_files") or []:
                path = out_file.get("path") if isinstance(out_file, dict) else out_file
                _tokens_from_value(path, tokens)
            _tokens_from_value(row.get("purpose"), tokens)
            for arg in row.get("argv") or []:
                _tokens_from_value(arg, tokens)
            add(aid, tokens)

    # 2) case audit log (MCP tools, CLI ingest, bridged SIFT rows)
    audit_dir = case_dir / "audit"
    if audit_dir.is_dir():
        try:
            audit_files = sorted(audit_dir.glob("*.jsonl"))
        except OSError:
            audit_files = []
        for jsonl in audit_files:
            try:
                with jsonl.open(encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        aid = entry.get("audit_id")
                        if not aid:
                            continue
                        tokens = set()
                        tool = _norm(entry.get("tool"))
                        if tool:
                            tokens |= tool_tokens(tool)
                        _tokens_from_value(entry.get("params"), tokens)
                        _tokens_from_value(entry.get("result_summary"), tokens)
                        for f in entry.get("input_files") or []:
                            _tokens_from_value(f, tokens)
                        add(aid, tokens)
            except OSError:
                continue

    if use_cache:
        _LINKAGE_CACHE[str(case_dir)] = (stamp, linkage)
        if len(_LINKAGE_CACHE) > 8:
            _LINKAGE_CACHE.pop(next(iter(_LINKAGE_CACHE)))
    return linkage


def scope_tokens(families: Any = (), files: Any = ()) -> set[str]:
    """Wanted tokens for a finding's families + evidence files."""
    wanted: set[str] = set()
    for fam in families or ():
        wanted |= family_tokens(fam)
        _tokens_from_value(fam, wanted)
    for path in files or ():
        _tokens_from_value(path, wanted)
    return wanted


def linked_audit_ids(
    case_dir: Path,
    families: Any = (),
    files: Any = (),
    limit: int = 8,
    ledger: list[dict[str, Any]] | None = None,
) -> list[str]:
    """Audit ids whose linkage tokens intersect these families/files.

    Returns ``[]`` when nothing is linked — there is deliberately NO
    "first OK audit id of any tool" fallback (EH-9).
    """
    wanted = scope_tokens(families, files)
    if not wanted:
        return []
    linkage = linkage_map(case_dir, ledger=ledger)
    strong: list[str] = []
    weak: list[str] = []
    for aid, tokens in linkage.items():
        if not tokens & wanted:
            continue
        # A family/tool token match is stronger than a path-word match.
        if tokens & wanted and any(t in wanted for t in tokens if t in _TOOL_FAMILIES):
            strong.append(aid)
        else:
            weak.append(aid)
    ordered = strong + weak
    return ordered[: max(1, int(limit))]


def is_linked(
    case_dir: Path,
    audit_id: str,
    families: Any = (),
    files: Any = (),
) -> bool:
    """True when this audit id references the finding's families/files."""
    wanted = scope_tokens(families, files)
    if not wanted or not audit_id:
        return False
    tokens = linkage_map(case_dir).get(str(audit_id))
    return bool(tokens and tokens & wanted)
