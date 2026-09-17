"""Tool binding layer — WP 4j.10 (the Mode 2/3 backbone, in-process).

The LLM never gets raw endpoints or raw ES access: it binds a fixed
**read-only allowlist** of the backbone tools and nothing else. Binding is
the enforcement point — the allowlist is structural, not advisory:

  evidence : n4_query, n4_sample, n4_aggregate, index_mappings, family_fields
  knowledge: kb_search, kb_read, kb_cite

Mutating tools (approve, case_delete, evidence_register, ...) are NOT in
any LLM allowlist — the examiner disposes (FD-002).

Calls go through the same core functions the MCP tools use, so the in-process
path and the MCP path cannot drift; every call is audit-logged.
"""
from __future__ import annotations

import logging
from typing import Any

from nexus.audit import AuditWriter
from nexus.tools import evidence_index
from nexus.tools import kb as kb_tools
from nexus.tools import web as web_tools

log = logging.getLogger(__name__)

# The LLM-visible backbone. Read-only by construction — every mutating tool
# is outside every allowlist (WP 4j.10c).
MODE2_TOOL_ALLOWLIST: dict[str, str] = {
    "n4_query": "evidence",
    "n4_sample": "evidence",
    "n4_aggregate": "evidence",
    "index_mappings": "evidence",
    "family_fields": "evidence",
    "kb_search": "knowledge",
    "kb_read": "knowledge",
    "kb_cite": "knowledge",
    "ti_lookup": "intel",
    "ti_fanout": "intel",
    "ti_list_providers": "intel",
    "web_search": "web",
    "web_fetch": "web",
    "web_status": "web",
}

# Mode 3 agents bind the same read-only set (4j-D) — defined here so there is
# exactly one place where an agent's reachable toolset is decided.
MODE3_TOOL_ALLOWLIST: dict[str, str] = dict(MODE2_TOOL_ALLOWLIST)


def tool_contracts_block(mode: int = 2) -> str:
    """Prompt block: the backbone tools the LLM may call + their contracts."""
    allow = MODE2_TOOL_ALLOWLIST if mode <= 2 else MODE3_TOOL_ALLOWLIST
    lines = [
        "You investigate through these TOOLS only (read-only; you cannot mutate case state):",
        "- n4_query(case_id, dsl) — search evidence with the N4 grammar above.",
        "- n4_sample(case_id, family, field, value, n) — N representative raw rows (spread over time) for a family/field value.",
        "- n4_aggregate(case_id, dsl, field, top, bucket) — counts/top values for a field; context, never evidence.",
        "- index_mappings(case_id) — the case's families, their fields, and the DSL vocabulary.",
        "- family_fields(family) — the columns a parser family emits (query these, not guesses).",
        "- kb_search(query) / kb_read(chunk_id) / kb_cite(chunk_id) — KB procedures + citations.",
        "- ti_lookup(value) / ti_fanout(value) / ti_list_providers() — threat-intel context, never evidence.",
        "- web_status() / web_search(query) / web_fetch(url) — examiner-opt-in external context, never evidence.",
    ]
    extra = [t for t in allow if t not in MODE2_TOOL_ALLOWLIST]
    for t in extra:
        lines.append(f"- {t}")
    return "\n".join(lines)


def backbone_call(name: str, audit: AuditWriter | None = None, **kwargs: Any) -> dict[str, Any]:
    """Execute one allowlisted backbone tool (in-process, same core as MCP)."""
    if name not in MODE2_TOOL_ALLOWLIST:
        raise PermissionError(
            f"tool {name!r} is not in the agent allowlist — the LLM cannot call it")
    if name == "n4_query":
        return evidence_index.do_n4_query(audit=audit, **kwargs)
    if name == "n4_sample":
        return evidence_index.do_n4_sample(audit=audit, **kwargs)
    if name == "n4_aggregate":
        return evidence_index.do_n4_aggregate(audit=audit, **kwargs)
    if name == "index_mappings":
        return evidence_index.do_index_mappings(audit=audit, **kwargs)
    if name == "family_fields":
        return evidence_index.do_family_fields(audit=audit, **kwargs)
    if name == "kb_search":
        return kb_tools.do_kb_search(audit=audit, **kwargs)
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
