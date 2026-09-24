"""Tool binding layer — WP 4j.10 (the Mode 2/3 backbone, in-process).

The LLM never gets raw endpoints or raw ES access: it binds a fixed
**read-only allowlist** of the backbone tools and nothing else. Binding is
the enforcement point — the allowlist is structural, not advisory:

  evidence : es_fields, es_search, es_aggregate, es_sample, index_mappings,
             family_fields
  knowledge: kb_search, kb_read, kb_cite

Mutating tools (approve, case_delete, evidence_register, ...) are NOT in
any LLM allowlist — the examiner disposes (FD-002).

Calls go through the same core functions the MCP tools use, so the in-process
path and the MCP path cannot drift; every call is audit-logged.
"""
from __future__ import annotations

import contextlib
import logging
from pathlib import Path
from typing import Any

from nexus.audit import AuditWriter
from nexus.tools import evidence_index
from nexus.tools import kb as kb_tools
from nexus.tools import web as web_tools

log = logging.getLogger(__name__)

# The LLM-visible backbone. Read-only by construction — every mutating tool
# is outside every allowlist (WP 4j.10c).
MODE2_TOOL_ALLOWLIST: dict[str, str] = {
    # 4k.5.5 COMPLETE: the Mode 2/3 agent surface is ES-only. The typed DSL
    # lives in the MCP tools for Mode 1 / deterministic paths — never here.
    "es_fields": "evidence",
    "es_search": "evidence",
    "es_aggregate": "evidence",
    "es_sample": "evidence",
    "index_mappings": "evidence",
    "family_fields": "evidence",
    "kb_search": "knowledge",
    "kb_read": "knowledge",
    "kb_cite": "knowledge",
    # WP 10.53: model-facing context-engineering aliases (Option B). The
    # canonical implementations above stay exactly as audited; the alias is
    # transport only and can never map to a mutating tool.
    "es_mappings": "evidence",
    "kb_query": "knowledge",
    "sample_rows": "evidence",
    "rag_search": "knowledge",
    "run_record": "evidence",
    "ti_lookup": "intel",
    "ti_fanout": "intel",
    "ti_list_providers": "intel",
    "web_search": "web",
    "web_fetch": "web",
    "web_status": "web",
}

# Confirmed routing (WIRING-PLAN 10.53, Option B):
#   es_mappings -> es_fields   kb_query -> kb_search
#   sample_rows -> es_sample   rag_search -> forensic_rag_search core
#   run_record  -> tool-lane ledger reader (new core)
# The LLM sees the left-hand names; every alias resolves to the already
# audited canonical implementation. No mutating tool gains an alias.
TOOL_ALIASES: dict[str, str] = {
    "es_mappings": "es_fields",
    "kb_query": "kb_search",
    "sample_rows": "es_sample",
    "rag_search": "forensic_rag_search",
    "run_record": "run_record",
}

_CONTEXT_TOOL_NAMES: tuple[str, ...] = (
    "es_mappings", "es_search", "es_aggregate", "sample_rows",
    "kb_query", "rag_search", "run_record",
)

# Mode 3 agents bind the same read-only set (4j-D) — defined here so there is
# exactly one place where an agent's reachable toolset is decided.
MODE3_TOOL_ALLOWLIST: dict[str, str] = dict(MODE2_TOOL_ALLOWLIST)


def tool_contracts_block(mode: int = 2) -> str:
    """Prompt block: the backbone tools the LLM may call + their contracts.

    WP 10.53: the model-facing names are the seven context-engineering tools
    (``es_mappings`` / ``es_search`` / ``es_aggregate`` / ``kb_query`` /
    ``rag_search`` / ``run_record`` / ``sample_rows``). The canonical
    implementations and audit names remain the existing ones (Option B).
    """
    lines = [
        "You investigate through these READ-ONLY tools only (you cannot mutate case state):",
        "- es_mappings(case_id) — per-case field catalog: families, row counts, typed core fields, every parsed column. Call this first when you need to know where the data is.",
        "- es_search(case_id, query, size, sort, search_after) — allowlisted Elasticsearch query JSON (bool/term/terms/range/match/match_phrase/multi_match/wildcard/exists/prefix/match_all); exact total + next_search_after for full enumeration; use a range clause on ts for time filters and fields.<Name>/fields.<Name>.kw for parsed columns.",
        "- es_aggregate(case_id, aggs, query) — terms/date_histogram/cardinality/composite/min/max/avg; composite returns `next_after_key` for complete bucket enumeration. Use it for counts, distributions and completeness checks.",
        "- sample_rows(case_id, family, field, value, n) — representative raw rows spread over time; context, never evidence.",
        "- kb_query(query, folder, signal, limit) — examiner-curated KB procedures + citations; methodology, never evidence.",
        "- rag_search(query, top_k, source, technique, platform) — semantic methodology/detection knowledge; methodology, never evidence.",
        "- run_record(case_id) — the tool-lane ledger: which parser/tool ran, status (OK/SKIP/FAIL), reason, output file, command, audit_id. Use this before claiming evidence is absent — distinguish 'not parsed' from 'not found'.",
        "- kb_read(chunk_id) / kb_cite(chunk_id) — read/cite a KB chunk returned by kb_query.",
        "- ti_lookup(value) / ti_fanout(value) / ti_list_providers() — threat-intel context, never evidence.",
        "- web_status() / web_search(query) / web_fetch(url) — examiner-opt-in external context, never evidence.",
    ]
    return "\n".join(lines)


def _es_call(
    name: str,
    audit: AuditWriter | None = None,
    *,
    tool_label: str = "",
    **kwargs: Any,
) -> dict[str, Any]:
    """ES-native backbone call: active-case gated, audited, ES-required."""
    import time as _time

    from nexus.langgraph import es_native
    from nexus.tools.evidence_index import _resolve_active_case

    case_dir, err = _resolve_active_case(str(kwargs.pop("case_id", "") or ""))
    if err or case_dir is None:
        return {"error": err or "no active case"}
    started = _time.monotonic()
    fn = getattr(es_native, name)
    label = tool_label or name
    try:
        result = fn(str(Path(case_dir).name), **kwargs)
    except es_native.ESQueryError as exc:
        if audit is not None:
            with contextlib.suppress(Exception):
                audit.log(
                    tool=label,
                    params={"case_id": Path(case_dir).name,
                            **{k: v for k, v in kwargs.items()
                               if k in ("query", "aggs", "size", "family",
                                        "field", "value")}},
                    result_summary={"error": str(exc)[:300]},
                    elapsed_ms=round((_time.monotonic() - started) * 1000, 1),
                    extra={"canonical_tool": name} if label != name else None,
                )
        return {"error": str(exc), "case_id": Path(case_dir).name}
    aid = None
    if audit is not None:
        aid = audit.log(
            tool=label,
            params={"case_id": Path(case_dir).name,
                    **{k: v for k, v in kwargs.items() if k in ("query", "aggs", "size", "family", "field", "value")}},
            result_summary={"total": result.get("total"),
                            "returned": result.get("returned"),
                            "families": len(result.get("families") or {})},
            elapsed_ms=round((_time.monotonic() - started) * 1000, 1),
            extra={"canonical_tool": name} if label != name else None,
        )
    result.setdefault("provenance", {})
    result["provenance"] = {"audit_id": aid, "case_id": Path(case_dir).name}
    if label != name:
        result["alias"] = label
    return result


def _resolve_tool(name: str) -> str:
    """Resolve a model-facing alias to its canonical implementation (Option B)."""
    return TOOL_ALIASES.get(name, name)


def backbone_call(name: str, audit: AuditWriter | None = None, **kwargs: Any) -> dict[str, Any]:
    """Execute one allowlisted backbone tool (in-process, same core as MCP).

    ``name`` may be a canonical tool or one of the confirmed model-facing
    aliases (WIRING-PLAN 10.53). Aliases are transport only: they resolve to
    the existing audited implementations and cannot reach a mutating tool.
    """
    if name not in MODE2_TOOL_ALLOWLIST:
        raise PermissionError(
            f"tool {name!r} is not in the agent allowlist — the LLM cannot call it")
    canonical = _resolve_tool(name)
    if canonical in ("es_fields", "es_search", "es_aggregate", "es_sample"):
        return _es_call(canonical, audit=audit, tool_label=name, **kwargs)
    if name == "index_mappings" or canonical == "index_mappings":
        return evidence_index.do_index_mappings(audit=audit, **kwargs)
    if name == "family_fields" or canonical == "family_fields":
        return evidence_index.do_family_fields(audit=audit, **kwargs)
    if canonical == "kb_search":
        kwargs.setdefault("query", "")
        return kb_tools.do_kb_search(
            audit=audit, alias=name if name != canonical else "", **kwargs)
    if canonical == "forensic_rag_search":
        return _rag_call(audit=audit, alias=name, **kwargs)
    if canonical == "run_record":
        return _run_record_call(audit=audit, **kwargs)
    if name == "kb_read":
        return kb_tools.do_kb_read(audit=audit, **kwargs)
    if name == "kb_cite":
        return kb_tools.do_kb_cite(audit=audit, **kwargs)
    if name == "ti_lookup":
        return _ti_call("lookup", audit=audit, **kwargs)
    if name == "ti_fanout":
        return _ti_call("fanout", audit=audit, **kwargs)
    if name == "ti_list_providers":
        return _ti_call("providers", audit=audit, **kwargs)
    if name == "web_status":
        return web_tools.do_web_status(audit=audit)
    if name == "web_search":
        return web_tools.do_web_search(audit=audit, **kwargs)
    if name == "web_fetch":
        return web_tools.do_web_fetch(audit=audit, **kwargs)
    raise PermissionError(f"tool {name!r} has no binding")


def _ti_call(
    kind: str, audit: AuditWriter | None = None, **kwargs: Any
) -> dict[str, Any]:
    """TI router binding — mock/local by default, external only with keys."""
    from nexus.ti import create_default_router
    from nexus.ti.enrich import _run_async

    router = create_default_router()
    if kind == "providers":
        providers = [
            p.to_dict() if hasattr(p, "to_dict") else dict(getattr(p, "__dict__", {}))
            for p in router.list_providers()
        ]
        result = {"providers": providers, "mock": router.use_mock}
    else:
        value = str(kwargs.get("value") or "").strip()
        if not value:
            result = {"error": "value is required"}
        else:
            ioc_type = str(kwargs.get("ioc_type") or "").strip() or None
            if kind == "fanout":
                result = _run_async(router.fanout(value, ioc_type=ioc_type))
            else:
                providers = kwargs.get("providers")
                if isinstance(providers, str):
                    providers = [p.strip() for p in providers.split(",") if p.strip()] or None
                result = _run_async(
                    router.lookup(value, ioc_type=ioc_type, providers=providers)
                )
    if audit is not None:
        audit_id = audit.log(
            tool=f"ti_{kind}", params={"ioc_type": kwargs.get("ioc_type") or "auto"},
            result_summary={"error": result.get("error"),
                            "malicious": result.get("malicious_count")},
        )
        if audit_id:
            result = {**result, "provenance": {"audit_id": audit_id}}
    return result


def _rag_call(audit: AuditWriter | None = None, *, alias: str = "",
              **kwargs: Any) -> dict[str, Any]:
    """RAG-search binding (WP 10.53) — same core the MCP tool uses."""
    from nexus.tools.rag import do_forensic_rag_search

    result = do_forensic_rag_search(
        query=str(kwargs.get("query") or ""),
        top_k=int(kwargs.get("top_k") or 10),
        source=str(kwargs.get("source") or ""),
        source_ids=kwargs.get("source_ids"),
        technique=str(kwargs.get("technique") or ""),
        platform=str(kwargs.get("platform") or ""),
        audit=audit,
    )
    if alias:
        result = {**result, "alias": alias}
    return result


def _run_record_call(audit: AuditWriter | None = None, **kwargs: Any) -> dict[str, Any]:
    """Tool-lane ledger binding (WP 10.53) — what ran against this case."""
    return evidence_index.do_run_record(
        case_id=str(kwargs.get("case_id") or ""),
        audit=audit,
    )