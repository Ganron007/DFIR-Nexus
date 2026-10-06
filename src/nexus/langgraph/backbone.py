"""Tool binding layer — WP 4j.10 (the Mode 2/3 backbone, in-process).

The LLM never gets raw endpoints or raw ES access: it binds a fixed
**read-only allowlist** of the backbone tools and nothing else. Binding is
the enforcement point — the allowlist is structural, not advisory:

  evidence : es_fields, es_search, es_aggregate, es_sample, index_mappings,
             family_fields
  knowledge: rag_search

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
    # WP 10.53: model-facing context-engineering aliases (Option B). The
    # canonical implementations above stay exactly as audited; the alias is
    # transport only and can never map to a mutating tool.
    "es_mappings": "evidence",
    "sample_rows": "evidence",
    "rag_search": "knowledge",
    "run_record": "evidence",
    "ti_lookup": "intel",
    "ti_fanout": "intel",
    "ti_list_providers": "intel",
    "web_search": "web",
    "web_fetch": "web",
    "web_status": "web",
    # WO-K2: the examiner toolkit as read-only loop tools. Each is audited in
    # `backbone_call` exactly like `es_search`, and every one delegates to the
    # single implementation in `analysis/examiner_checks.py` - a forked copy of a
    # baseline check would drift, and a drifted check is worse than none.
    "check_file": "evidence",
    "check_process_tree": "evidence",
    "check_service": "evidence",
    "check_hash": "evidence",
    "check_autorun": "evidence",
    "check_registry": "evidence",
    "analyze_filename_triage": "evidence",
    "check_lolbin": "evidence",
    "check_hijackable_dll": "evidence",
    "deobfuscate_command": "evidence",
    "check_driver": "evidence",
    "check_lots_domain": "evidence",
    "check_loobin": "evidence",
}

# Confirmed routing (WIRING-PLAN 10.53, Option B):
#   es_mappings -> es_fields
#   sample_rows -> es_sample   rag_search -> forensic_rag_search core
#   run_record  -> tool-lane ledger reader (new core)
# The LLM sees the left-hand names; every alias resolves to the already
# audited canonical implementation. No mutating tool gains an alias.
TOOL_ALIASES: dict[str, str] = {
    "es_mappings": "es_fields",
    "sample_rows": "es_sample",
    "rag_search": "forensic_rag_search",
    "run_record": "run_record",
}

_CONTEXT_TOOL_NAMES: tuple[str, ...] = (
    "es_mappings", "es_search", "es_aggregate", "sample_rows",
    "rag_search", "run_record",
    # WO-K2: Mode 1's loop gets the examiner toolkit too, so a hit can be
    # checked against the baseline in the same turn that raises it.
    "check_file", "check_process_tree", "check_service", "check_hash",
    "check_autorun", "check_registry", "analyze_filename_triage",
    "check_lolbin", "check_hijackable_dll", "deobfuscate_command",
    "check_driver", "check_lots_domain", "check_loobin",
)

# Mode 3 agents bind the same read-only set (4j-D) — defined here so there is
# exactly one place where an agent's reachable toolset is decided.
MODE3_TOOL_ALLOWLIST: dict[str, str] = dict(MODE2_TOOL_ALLOWLIST)


def tool_contracts_block(mode: int = 2, *, include_external: bool = True) -> str:
    """Prompt block: the backbone tools the LLM may call + their contracts.

    WP 10.53: the model-facing names are the context-engineering tools
    (``es_mappings`` / ``es_search`` / ``es_aggregate`` /
    ``rag_search`` / ``run_record`` / ``sample_rows``). The canonical
    implementations and audit names remain the existing ones (Option B).

    ``include_external=False`` (the context loop) omits TI/web tools: those
    send model-chosen values out of the process and stay outside the bounded
    loop unless the examiner explicitly enables them elsewhere.
    """
    lines = [
        "You investigate through these READ-ONLY tools only (you cannot mutate case state):",
        "- es_mappings(case_id) — per-case field catalog: families, row counts, typed core fields, every parsed column. Call this first when you need to know where the data is.",
        "- es_search(case_id, query, size, sort, search_after) — allowlisted Elasticsearch query JSON (bool/term/terms/range/match/match_phrase/multi_match/wildcard/exists/prefix/match_all); exact total + next_search_after for full enumeration; use a range clause on ts for time filters and fields.<Name>/fields.<Name>.kw for parsed columns.",
        "  FIELD CHOICE (WO-CS1): prefer ecs.* for cross-source questions "
        "(ecs.process.command_line, ecs.user.name, ecs.source.ip, ecs.file.path, "
        "ecs.registry.path, ecs.process.executable, ecs.host.name); use "
        "ecs.winlog.event_data.<Name> for Windows event fields (TargetUserName, "
        "LogonType, Image, CommandLine, ...); use fields.<tool column> for "
        "tool-specific detail. The catalog lists the ecs.* fields THIS case fills.",
        "- es_aggregate(case_id, aggs, query) — terms/date_histogram/cardinality/composite/min/max/avg; composite returns `next_after_key` for complete bucket enumeration. Use it for counts, distributions and completeness checks.",
        "- sample_rows(case_id, family, field, value, n) — representative raw rows spread over time; context, never evidence.",
        "- rag_search(query, top_k, source, technique, platform) — semantic methodology/detection knowledge; methodology, never evidence.",
        "- run_record(case_id) — the tool-lane ledger: which parser/tool ran, status (OK/SKIP/FAIL), reason, output file, command, audit_id. Use this before claiming evidence is absent — distinguish 'not parsed' from 'not found'.",
        "",
            "Examiner checks (read-only, against the triage baselines). Use one to TEST a "
            "suspicion before writing it down — a row that looks odd is not yet a finding:",
            "- check_file(path, hash) — is this path/hash in the Windows baseline? verdict "
            "EXPECTED / EXPECTED_LOLBIN / SUSPICIOUS / UNKNOWN, plus whether the filename is a "
            "known tool or a LOLBin.",
            "- check_process_tree(process_name, parent_name, path, user) — does this "
            "parent/child/path/user combination match the baseline?",
            "- check_service(service_name, binary_path) — is this service expected, and does its "
            "binary sit where the baseline says it should?",
            "- check_hash(hash_value) — baseline lookup for a file hash.",
            "- check_autorun(key_path, value_name) — is this persistence key/value expected?",
            "- check_registry(key_path, value_name, hive) — registry baseline lookup.",
            "- analyze_filename_triage(filename) — deception analysis: Unicode evasion, "
            "typosquatting, double extensions, known tools.",
            "- check_lolbin(filename) — is this a known LOLBin, and how is it abused?",
            "- check_hijackable_dll(dll_name) — is this DLL vulnerable to search-order hijacking?",
            "- deobfuscate_command(command) — decode an obfuscated command line (base64, "
            "compression, string building) and read the decoded text.",
            "- check_driver(driver_name, hash_value) — is this a known vulnerable BYOVD driver (LOLDrivers)?",
            "- check_lots_domain(domain) — is this domain a living-off-trusted-sites C2/exfil domain (LOTS)?",
            "- check_loobin(binary_name) — is this a known macOS living-off-the-land binary (LOOBin)?",
            "  CONSTRAINT (FD-004): UNKNOWN means 'not in the database', NOT suspicious — never "
            "escalate an UNKNOWN on its own, corroborate it with evidence rows. A LOLBin is "
            "legitimate-but-abusable, so a LOLBin alone is not malicious either. A check result "
            "is context for a finding, never the finding itself.",
        ]
    if include_external:
        lines.extend([
            "- ti_lookup(value) / ti_fanout(value) / ti_list_providers() — threat-intel context, never evidence.",
            "- web_status() / web_search(query) / web_fetch(url) — examiner-opt-in external context, never evidence.",
        ])
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
    audit_keys = ("query", "aggs", "size", "family", "field", "value",
                  "n", "sort", "search_after")
    try:
        result = fn(str(Path(case_dir).name), **kwargs)
    except Exception as exc:  # noqa: BLE001 — audit every failure, not just ESQueryError
        if audit is not None:
            with contextlib.suppress(Exception):
                audit.log(
                    tool=label,
                    params={"case_id": Path(case_dir).name,
                            **{k: v for k, v in kwargs.items() if k in audit_keys}},
                    result_summary={
                        "error": f"{type(exc).__name__}: {exc}"[:300],
                    },
                    elapsed_ms=round((_time.monotonic() - started) * 1000, 1),
                    extra={"canonical_tool": name} if label != name else None,
                )
        return {
            "error": f"{label} failed: {type(exc).__name__}: {exc}"[:400],
            "case_id": Path(case_dir).name,
        }
    aid = None
    if audit is not None:
        aid = audit.log(
            tool=label,
            params={"case_id": Path(case_dir).name,
                    **{k: v for k, v in kwargs.items() if k in audit_keys}},
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


#: WO-K2 examiner tools, importable without pulling the triage package.
EXAMINER_CHECK_TOOL_SET: frozenset[str] = frozenset({
    "check_file", "check_process_tree", "check_service", "check_hash",
    "check_autorun", "check_registry", "analyze_filename_triage",
    "check_lolbin", "check_hijackable_dll", "deobfuscate_command",
    "check_driver", "check_lots_domain", "check_loobin",
})

#: Argument names the examiner checks accept, for the audit record.
_EXAMINER_ARG_KEYS: frozenset[str] = frozenset({
    "path", "hash", "hash_value", "process_name", "parent_name", "user",
    "service_name", "binary_path", "key_path", "value_name", "hive",
    "os_version", "filename", "dll_name", "command",
    "driver_name", "domain", "binary_name",
})


def _open_examiner_dbs():
    """The triage baselines the examiner checks read. Read-only, always."""
    from nexus.config import settings
    from nexus.triage.db import ContextDB, KnownGoodDB

    db_dir = settings.data_root / "triage"
    known_good = context = None
    if (db_dir / "known_good.db").exists():
        known_good = KnownGoodDB(db_dir / "known_good.db", read_only=True)
        known_good.connect()
    if (db_dir / "context.db").exists():
        context = ContextDB(db_dir / "context.db", read_only=True)
        context.connect()
    return known_good, context


def _open_registry_baseline():
    """The optional registry baseline, or None when it is not installed."""
    from nexus.config import settings
    from nexus.triage.db import RegistryDB

    path = settings.data_root / "triage" / "known_good_registry.db"
    if not path.exists():
        return None
    db = RegistryDB(path, read_only=True)
    if not db.is_available():
        db.close()
        return None
    return db


def _examiner_call(
    name: str, audit: AuditWriter | None = None, **kwargs: Any
) -> dict[str, Any]:
    """Route one WO-K2 examiner check to its single implementation.

    Read-only by construction: every task in `analysis.examiner_checks` reads a
    baseline and returns a verdict. `deobfuscate_command` is the only one that
    touches no database at all.

    The call is **audited on success here**, not by `_guarded` (which only logs
    on failure) - `es_search` audits inside `_es_call` for the same reason, and
    a check with no provenance cannot be used as evidence (FD-001).
    """
    from nexus.analysis import examiner_checks as ec

    def _s(key: str) -> str:
        return str(kwargs.get(key) or "")

    if name == "deobfuscate_command":
        return ec.deobfuscate_command(command=_s("command"))
    if name == "analyze_filename_triage":
        _, context = _open_examiner_dbs()
        return ec.analyze_filename_triage(context, filename=_s("filename"))

    known_good, context = _open_examiner_dbs()
    if name == "check_file":
        return ec.check_file(known_good, context, path=_s("path"),
                             path_hash=_s("hash") or _s("hash_value"))
    if name == "check_process_tree":
        return ec.check_process_tree(
            context, process_name=_s("process_name"), parent_name=_s("parent_name"),
            path=_s("path"), user=_s("user"),
        )
    if name == "check_service":
        return ec.check_service(known_good, context, service_name=_s("service_name"),
                                binary_path=_s("binary_path"))
    if name == "check_hash":
        return ec.check_hash(known_good, context, hash_value=_s("hash_value") or _s("hash"))
    if name == "check_autorun":
        return ec.check_autorun(known_good, context, key_path=_s("key_path"),
                                value_name=_s("value_name"))
    if name == "check_registry":
        return ec.check_registry(
            _open_registry_baseline(), key_path=_s("key_path"),
            value_name=_s("value_name"), hive=_s("hive"), os_version=_s("os_version"),
        )
    if name == "check_lolbin":
        return ec.check_lolbin(context, filename=_s("filename"))
    if name == "check_hijackable_dll":
        return ec.check_hijackable_dll(context, dll_name=_s("dll_name"))
    if name == "check_driver":
        return ec.check_driver(context, driver_name=_s("driver_name"),
                               hash_value=_s("hash_value") or _s("hash"))
    if name == "check_lots_domain":
        return ec.check_lots_domain(context, domain=_s("domain"))
    if name == "check_loobin":
        return ec.check_loobin(context, binary_name=_s("binary_name"))
    raise PermissionError(f"unknown examiner check {name!r}")


def _audited_examiner_call(
    name: str, audit: AuditWriter | None, kwargs: dict[str, Any]
) -> dict[str, Any]:
    """`_examiner_call` with a success audit entry, so the call has provenance."""
    import time as _time

    started = _time.monotonic()
    result = _examiner_call(name, **kwargs)
    if audit is not None:
        with contextlib.suppress(Exception):
            verdict = str((result or {}).get("verdict") or "")
            audit.log(
                tool=name,
                params={k: str(v)[:120] for k, v in kwargs.items()
                        if k in _EXAMINER_ARG_KEYS},
                result_summary={"verdict": verdict} if verdict else {"status": "checked"},
                elapsed_ms=round((_time.monotonic() - started) * 1000, 1),
            )
    return result


def _guarded(
    name: str,
    audit: AuditWriter | None,
    fn: Any,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one binding; audit + convert any exception into a structured error.

    A failing tool call must still appear in the audit trail (otherwise the
    loop can execute a call with no provenance) and must not crash the turn.
    """
    import time as _time

    started = _time.monotonic()
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 — every failure is an observation
        if audit is not None:
            with contextlib.suppress(Exception):
                audit.log(
                    tool=name,
                    params=params or {},
                    result_summary={
                        "error": f"{type(exc).__name__}: {exc}"[:300],
                    },
                    elapsed_ms=round((_time.monotonic() - started) * 1000, 1),
                )
        return {
            "error": f"{name} failed: {type(exc).__name__}: {exc}"[:400],
        }


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
        return _guarded("index_mappings", audit,
                        lambda: evidence_index.do_index_mappings(
                            audit=audit, **kwargs),
                        params={"case_id": kwargs.get("case_id", "")})
    if name == "family_fields" or canonical == "family_fields":
        return _guarded("family_fields", audit,
                        lambda: evidence_index.do_family_fields(
                            audit=audit, **kwargs),
                        params={"family": kwargs.get("family", "")})

    if canonical == "forensic_rag_search":
        return _guarded(name, audit,
                        lambda: _rag_call(audit=audit, alias=name, **kwargs),
                        params={"query": str(kwargs.get("query") or "")[:200]})
    if canonical == "run_record":
        return _guarded(name, audit,
                        lambda: _run_record_call(audit=audit, **kwargs),
                        params={"case_id": kwargs.get("case_id", "")})
    if name in EXAMINER_CHECK_TOOL_SET:
        # WO-K2: the examiner toolkit. Audited on success (like `es_search`) so a
        # check has provenance, and read-only by construction - no task in the
        # module mutates anything.
        return _guarded(name, audit,
                        lambda: _audited_examiner_call(name, audit, kwargs),
                        params={k: str(v)[:120] for k, v in kwargs.items()
                                if k in _EXAMINER_ARG_KEYS})

    if name == "ti_lookup":
        return _guarded("ti_lookup", audit,
                        lambda: _ti_call("lookup", audit=audit, **kwargs),
                        params={"ioc_type": kwargs.get("ioc_type") or "auto"})
    if name == "ti_fanout":
        return _guarded("ti_fanout", audit,
                        lambda: _ti_call("fanout", audit=audit, **kwargs),
                        params={"ioc_type": kwargs.get("ioc_type") or "auto"})
    if name == "ti_list_providers":
        return _guarded("ti_list_providers", audit,
                        lambda: _ti_call("providers", audit=audit, **kwargs))
    if name == "web_status":
        return _guarded("web_status", audit,
                        lambda: web_tools.do_web_status(audit=audit))
    if name == "web_search":
        return _guarded("web_search", audit,
                        lambda: web_tools.do_web_search(audit=audit, **kwargs),
                        params={"query": str(kwargs.get("query") or "")[:200]})
    if name == "web_fetch":
        return _guarded("web_fetch", audit,
                        lambda: web_tools.do_web_fetch(audit=audit, **kwargs),
                        params={"url": str(kwargs.get("url") or "")[:200]})
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
            if ioc_type:
                # Accept the extractor's names (ipv4/sha256/md5/...) and fall
                # back to inference for anything the TI router does not know.
                alias = {
                    "ipv4": "ip", "ipv6": "ip", "ip_address": "ip",
                    "sha256": "hash", "sha1": "hash", "md5": "hash",
                    "file_hash": "hash",
                }.get(ioc_type.lower(), ioc_type.lower())
                from nexus.ti.schemas import IOCType

                try:
                    ioc_type = IOCType(alias).value
                except ValueError:
                    ioc_type = None
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

    source_ids = kwargs.get("source_ids")
    if isinstance(source_ids, str):
        source_ids = [source_ids] if source_ids.strip() else None
    result = do_forensic_rag_search(
        query=str(kwargs.get("query") or ""),
        top_k=int(kwargs.get("top_k") or 10),
        source=str(kwargs.get("source") or ""),
        source_ids=source_ids,
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