"""GATE-B — bounded interpret round loop (Orient → Verify → Reconcile).

Operator plan (4j-H): interpretation is **a loop**, not a single blind pass.
The same controller will back Mode 3 (4j.14–4j.19):

- **Round 0 — Orient:** the LLM reads the deterministic Case Digest (+ query
  pack) and writes hypotheses + a bounded evidence plan (queries /
  aggregations / samples, each with a *why*).
- **Rounds 1..N — Verify:** the code executes the plan through the same
  audited MCP tools the examiner uses; the LLM reads the *actual rows* and
  marks each hypothesis confirmed / refuted / unknown, optionally planning
  the next round. Early stop when nothing is left to verify.
- **Final — Reconcile:** the LLM emits ``{"findings", "dispositions"}`` with a
  hard rule: every digest item (alerts ≥ high, high-count needles) is covered
  by a finding or has a disposition, which is never staged (D193). The
  deterministic reconciliation checklist then verifies this; one bounded
  extra pass addresses anything still unanswered.

Artifacts (auditable, replayable): ``analysis/interpret_rounds/round-N.json``
+ ``summary.json``; every packed prompt persists via ``prompt_budget``.

No LLM / loop failure → the caller keeps the single-pass ReAct fallback.
"""
from __future__ import annotations

import json
import logging
import re
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.langgraph.model_json import loads_model_json
from nexus.llm.egress import egress_bound

log = logging.getLogger(__name__)

_MAX_PLAN_ITEMS = 6
_DEFAULT_ROUNDS = 3
# WP 10.53: extra read-only tools the interpret loop may call directly —
# the same audited MCP surface the examiner uses (run record + RAG).
_EXTRA_TOOL_NAMES = (
    "run_record",
    "forensic_rag_search",
)


def _resolve_rounds(state: Mapping[str, Any], case_dir: Path, explicit: int | None) -> int:
    if explicit:
        value = int(explicit)
    else:
        ctx = state.get("case_context") or {}
        raw = str(ctx.get("interpret_rounds") or "").strip()
        value = 0
        if raw.isdigit():
            value = int(raw)
        if not value:
            try:
                from nexus.case.run_options import load_run_options

                value = int(load_run_options(case_dir).get("interpret_rounds") or 0)
            except (OSError, ValueError, TypeError):
                value = 0
        if not value:
            import os

            try:
                value = int(os.environ.get("NEXUS_INTERPRET_ROUNDS") or _DEFAULT_ROUNDS)
            except ValueError:
                value = _DEFAULT_ROUNDS
    return max(1, min(int(value), 5))


def _crit_high_leads(digest: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The digest's alerts (every crit/high lead), each with a hypothesis id ``L<n>``.

    One set for Mode 1's settle rule, the reconciliation and Mode 3's agenda: the briefing's
    ``alerts_from_leads``. The id is how a verification note answers a lead (Part 12 FM-9); the
    subject used to be matched as a substring of any note's text, so wording settled a lead.
    """
    out: list[dict[str, Any]] = []
    for alert in digest.get("alerts") or []:
        if not isinstance(alert, Mapping):
            continue
        subject = str(alert.get("title") or "").strip()
        if not subject:
            continue
        out.append({
            "id": f"L{len(out) + 1}",
            "subject": subject,
            "key": str(alert.get("key") or ""),
            "kind": str(alert.get("kind") or ""),
            "level": str(alert.get("level") or "high").lower(),
            "detail": str(alert.get("detail") or "")[:200],
            "doc_ids": [str(d) for d in alert.get("doc_ids") or [] if d],
            "locs": [str(loc) for loc in alert.get("locs") or [] if loc],
        })
    return out


def _lead_hypotheses(digest: Mapping[str, Any]) -> list[dict[str, Any]]:
    """One hypothesis per crit/high alert, so every verify round answers it by its id."""
    return [{
        "id": lead["id"],
        "statement": (f"[{lead['level'].upper()}] {lead['subject']}: {lead['detail']} "
                      f"[audit_id {lead['key']}] - what its rows show (malicious, benign, or not "
                      "decidable from this evidence)"),
        "why": "a crit/high alert",
    } for lead in _crit_high_leads(digest)]


def _note_id(note: Mapping[str, Any]) -> str:
    """The hypothesis id a note answers: its leading token ("L3", "L3:", "L3 - ...")."""
    head = str(note.get("hypothesis") or "").strip().split()
    return head[0].rstrip(":.,").upper() if head else ""


def _undispositioned_crit_leads(
    digest: Mapping[str, Any],
    notes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Crit/high leads no verification note has answered by id.

    A note answers lead ``L<n>`` when its hypothesis is that id and it either states what the
    rows showed (``confirmed``/``refuted``/``partial``/``unknown`` with evidence text) or says
    why the lead cannot be decided (``refuted``/``insufficient``). A bare
    ``{"hypothesis": "L1", "status": "unknown"}`` with no evidence is not an answer (D47).
    """
    answered: set[str] = set()
    for note in notes or []:
        status = str(note.get("status") or "").strip().lower()
        evidence = str(note.get("evidence") or "").strip()
        has_rows = evidence and status in ("confirmed", "refuted", "partial", "unknown")
        if has_rows or status in ("refuted", "insufficient"):
            answered.add(_note_id(note))
    return [lead for lead in _crit_high_leads(digest) if lead["id"] not in answered]


def _replan_for_leads(leads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Plan items that read each unanswered lead's own rows, by the references it cites.

    One item per lead, capped at the plan-item limit. It used to sample rows matching the
    subject's file name as a keyword (Part 12 FM-9).
    """
    from nexus.analysis.leads import lead_rows_query

    items: list[dict[str, Any]] = []
    for lead in leads[:_MAX_PLAN_ITEMS]:
        locs = [tuple(loc.rpartition(":")[::2]) for loc in lead.get("locs") or []]
        query = lead_rows_query(list(lead.get("doc_ids") or []), [loc for loc in locs if all(loc)])
        if query is None:
            continue
        items.append({
            "kind": "es_query",
            "es": {"query": query, "size": len(lead.get("doc_ids") or []) + len(locs)},
            "why": f"crit/high alert {lead['id']} {lead['subject']!r}: the rows it stands on",
        })
    return items


def _model_record(system: str, user: str) -> str:
    """Both messages a model call receives, for the persisted context record (D174)."""
    return f"## SYSTEM MESSAGE\n\n{system}\n\n## USER MESSAGE\n\n{user}" if system else user


def _parse_json_blob(text: str) -> Any:
    """Tolerant JSON extraction: whole content, fenced blocks, or first blob."""
    if not text:
        return None
    text = text.strip()
    try:
        return loads_model_json(text)
    except (json.JSONDecodeError, ValueError):
        pass
    for match in re.finditer(r"```(?:json)?\s*(.*?)```", text, re.DOTALL):
        block = match.group(1).strip()
        try:
            return loads_model_json(block)
        except (json.JSONDecodeError, ValueError):
            continue
    start = min(
        (i for i in (text.find("["), text.find("{")) if i != -1),
        default=-1,
    )
    if start == -1:
        return None
    end = max(text.rfind("]"), text.rfind("}"))
    if end <= start:
        return None
    try:
        return loads_model_json(text[start:end + 1])
    except (json.JSONDecodeError, ValueError):
        return None


def _where_it_broke(raw: str) -> str:
    """The decoder's message and the text around it, for the corrective retry ("" when it parses) (D274)."""
    from nexus.langgraph.model_json import json_error_note

    note = json_error_note(raw)
    return f" ({note})" if note else ""


def _as_list(value: Any) -> list[Any]:
    """LLM JSON often returns an id-keyed object where a list was asked for —
    accept both, never raise."""
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return []


#: What a disposition can say about a digest item it does not make a claim about (D193).
DISPOSITION_STATUSES = ("benign", "coverage_gap", "not_examined", "refuted")


def _disposition(item: Any) -> dict[str, Any] | None:
    """One disposition of a reconcile reply, or None when it names no item."""
    if not isinstance(item, dict):
        return None
    subject = " ".join(str(item.get("item") or "").split())
    if not subject:
        return None
    status = "_".join(str(item.get("status") or "").strip().lower().replace("-", " ").split())
    audit_ids = item.get("audit_ids") or []
    if isinstance(audit_ids, str):
        audit_ids = [audit_ids]
    return {"item": subject, "status": status, "reason": " ".join(str(item.get("reason") or "").split()),
            "audit_ids": [str(a) for a in audit_ids if a]}


def _split_reconcile_reply(text: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The findings and the dispositions of a reconcile reply (D193).

    The reply is ``{"findings": [...], "dispositions": [...]}``; a bare array is findings only. A
    disposition answers for a digest item without being a claim, and is never staged. Run 5 on
    2026-10-14 had no place for one, so "zero-hit needles" and "entity census" became findings.
    """
    data = _parse_json_blob(text)
    if isinstance(data, dict) and ("findings" in data or "dispositions" in data):
        dispositions = [_disposition(d) for d in _as_list(data.get("dispositions"))]
        return ([f for f in _as_list(data.get("findings")) if isinstance(f, dict)],
                [d for d in dispositions if d])
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)], []
    return [], []


def _findings_message(findings: list[dict[str, Any]]) -> str:
    """The findings alone, as the assistant message staging parses (fenced, so a title suffices)."""
    return "```json\n" + json.dumps(findings, ensure_ascii=False, indent=1) + "\n```"


def _merge_extra_findings(found: list[dict[str, Any]], extra: list[dict[str, Any]],
                          candidates: Callable[[list[dict[str, Any]]], list[dict[str, Any]]],
                          ) -> tuple[list[dict[str, Any]], list[str]]:
    """The first pass's findings with the extra pass's applied (D255): a finding carrying `revises`: "F<n>"
    replaces first-pass finding n, any other is new. A revision that does not parse as a finding cannot
    replace one that does, so the first-pass finding stays."""
    merged = {f"F{n}": f for n, f in enumerate(found, 1)}
    revised: list[str] = []
    new: list[dict[str, Any]] = []
    for f in extra:
        f = dict(f)
        ref = str(f.pop("revises", "") or "").strip().upper()
        if ref in merged:
            if ref in revised:
                log.warning("reconcile extra pass revised %s twice; the first revision stands", ref)
            elif candidates([f]):
                merged[ref] = f
                revised.append(ref)
            continue
        new.append(f)
    return list(merged.values()) + new, revised


def _normalize_plan(data: Any) -> dict[str, list[dict[str, Any]]]:
    """Coerce an orient/verify JSON payload into bounded plan items."""
    plan: dict[str, list[dict[str, Any]]] = {"hypotheses": [], "items": []}
    if not isinstance(data, dict):
        return plan
    for h in _as_list(data.get("hypotheses"))[:6]:
        if isinstance(h, dict) and h.get("statement"):
            plan["hypotheses"].append({
                "id": str(h.get("id") or f"H{len(plan['hypotheses']) + 1}")[:12],
                "statement": str(h.get("statement"))[:400],
                "why": str(h.get("why") or "")[:200],
            })
        elif isinstance(h, str) and h.strip():
            plan["hypotheses"].append({
                "id": f"H{len(plan['hypotheses']) + 1}",
                "statement": h.strip()[:400],
                "why": "",
            })

    def _add(kind: str, entry: Any) -> None:
        if len(plan["items"]) >= _MAX_PLAN_ITEMS:
            return
        if isinstance(entry, str) and entry.strip():
            plan["items"].append({"kind": kind, "why": "", "dsl": entry.strip()})
            return
        if not isinstance(entry, dict):
            return
        if kind == "query":
            es = entry.get("es")
            if isinstance(es, dict) and es:
                plan["items"].append({"kind": "es_query", "es": es,
                                      "why": str(entry.get("why") or "")[:200]})
                return
            dsl = str(entry.get("dsl") or "").strip()
            if dsl:
                plan["items"].append({"kind": "query", "dsl": dsl,
                                      "why": str(entry.get("why") or "")[:200]})
        elif kind == "aggregate":
            aggs = entry.get("aggs")
            if isinstance(aggs, dict) and aggs:
                plan["items"].append({
                    "kind": "es_aggregate", "aggs": aggs,
                    "query": entry.get("query") if isinstance(entry.get("query"), dict) else None,
                    "why": str(entry.get("why") or "")[:200],
                })
                return
            field = str(entry.get("field") or "").strip()
            if field:
                plan["items"].append({
                    "kind": "aggregate",
                    "dsl": str(entry.get("dsl") or entry.get("query") or "").strip(),
                    "field": field,
                    "why": str(entry.get("why") or "")[:200],
                })
        elif kind == "sample":
            family = str(entry.get("family") or "").strip()
            value = str(entry.get("value") or "").strip()
            if family or value:
                try:
                    sample_n = int(entry.get("n") or 8)
                except (TypeError, ValueError):
                    sample_n = 8
                plan["items"].append({
                    "kind": "sample",
                    "family": family,
                    "field": str(entry.get("field") or "").strip(),
                    "value": value,
                    "n": max(1, min(sample_n, 20)),
                    "why": str(entry.get("why") or "")[:200],
                })
        elif kind == "tool":
            tool = str(entry.get("tool") or "").strip()
            if tool in _EXTRA_TOOL_NAMES:
                args = entry.get("args") if isinstance(entry.get("args"), dict) else {}
                plan["items"].append({
                    "kind": "tool",
                    "tool": tool,
                    "args": args,
                    "why": str(entry.get("why") or "")[:200],
                })

    # The schema-bound plan: the read loop's tool calls, run as they are written.
    for call in _as_list(data.get("tool_calls")):
        if len(plan["items"]) >= _MAX_PLAN_ITEMS:
            break
        if isinstance(call, dict) and str(call.get("tool") or "") in _PLAN_TOOLS:
            plan["items"].append({
                "kind": "read",
                "tool": str(call["tool"]),
                "args": dict(call.get("args") or {}) if isinstance(call.get("args"), dict) else {},
                "why": str(call.get("why") or "")[:200],
            })
    for kind in ("queries", "aggregations", "aggregates", "samples", "tools"):
        key_kind = {
            "queries": "query", "aggregations": "aggregate",
            "aggregates": "aggregate", "samples": "sample",
            "tools": "tool",
        }[kind]
        for entry in _as_list(data.get(kind)):
            _add(key_kind, entry)
        if len(plan["items"]) >= _MAX_PLAN_ITEMS:
            break
    return plan


def _notes_from(data: Any) -> list[dict[str, str]]:
    notes: list[dict[str, str]] = []
    if not isinstance(data, dict):
        return notes
    for n in _as_list(data.get("notes"))[:8]:
        if isinstance(n, dict):
            notes.append({
                "hypothesis": str(n.get("hypothesis") or "")[:40],
                "status": str(n.get("status") or "unknown").lower()[:20],
                "evidence": str(n.get("evidence") or "")[:500],
                "family": str(n.get("family") or "")[:80],
            })
        elif isinstance(n, str) and n.strip():
            notes.append({"hypothesis": "", "status": "unknown",
                          "evidence": n.strip()[:500], "family": ""})
    return notes


def _render_results(entries: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for i, entry in enumerate(entries, start=1):
        kind = entry.get("kind")
        why = f" — why: {entry.get('why')}" if entry.get("why") else ""
        audit = entry.get("audit_id") or ""
        header = f"### {kind} {i}{why} [audit_id {audit}]"
        lines.append(header)
        if entry.get("error"):
            lines.append(f"  ERROR: {entry['error']}")
            continue
        if kind == "es_aggregate":
            import json as _json

            try:
                rendered = _json.dumps(entry.get("aggregations") or {}, default=str)
            except (TypeError, ValueError):
                rendered = str(entry.get("aggregations"))
            lines.append(f"  aggregations: {rendered[:4000]}")
            if entry.get("next_after_key") is not None:
                lines.append(f"  next_after_key: {entry['next_after_key']}")
            continue
        if kind == "tool":
            lines.append(
                "  tool result keys: "
                + ", ".join(str(k) for k in (entry.get("result_keys") or []))
            )
            continue
        if kind == "aggregate":
            lines.append(
                f"  {entry.get('field')}: {entry.get('distinct')} distinct"
                f"{' (approximate)' if entry.get('distinct_approximate') else ''} — top: "
                + ", ".join(
                    f"{t.get('value')}({t.get('count')})"
                    for t in (entry.get("top") or [])[:12]
                )
            )
            continue
        hits = entry.get("hits") or []
        lines.append(
            f"  {entry.get('count', len(hits))} matched row(s); "
            f"this page returned {len(hits)} row(s)"
        )
        if entry.get("has_more"):
            lines.append(
                "  more rows remain; continue with "
                f"search_after={entry.get('next_search_after')!r}"
            )
        lines.extend(
            "  " + json.dumps(hit, ensure_ascii=False, sort_keys=True, default=str)
            for hit in hits
        )
    return "\n".join(lines) if lines else "(no results)"


async def _call_model(model: Any, messages: list[dict[str, str]]) -> str:
    try:
        response = await model.ainvoke(messages)
    except (AttributeError, NotImplementedError):
        import asyncio

        response = await asyncio.to_thread(model.invoke, messages)
    return str(getattr(response, "content", response))


#: The read tools a plan's queries use, in the read loop's own grammar (``tool_generation.response_schema``).
_PLAN_TOOLS = ("es_search", "es_aggregate", "run_record")


def _string_object(names: tuple[str, ...], required: tuple[str, ...]) -> dict[str, Any]:
    return {"type": "object", "properties": {n: {"type": "string"} for n in names},
            "required": list(required), "additionalProperties": False}


#: The keys each plan reply declares beside its tool calls: under strict decoding an undeclared key is not
#: generated (a real T22 orient replay under the bare tool-call schema returned one query and no hypotheses).
ORIENT_KEYS = {"hypotheses": {"type": "array", "items": _string_object(("id", "statement", "why"), ("id", "statement"))}}
VERIFY_KEYS = {"notes": {"type": "array", "items": _string_object(
    ("hypothesis", "status", "evidence", "family"), ("hypothesis", "status", "evidence"))}}


def _plan_format(model: Any, case_id: str, keys: dict[str, Any]) -> dict[str, Any] | None:
    """The schema-constrained contract for a plan reply, or None on a transport without one.

    Orient and verify write Elasticsearch query JSON. Written free-form, the orient plan failed to parse on 7 of
    24 replies before the corrective retry, and on T22 (2026-10-28) the retry failed too and the run ended: the
    model closed a query item one brace early. The read loop's tool-call grammar under the provider's strict JSON
    schema is now their contract: the plan's queries are ``tool_calls`` and the hypotheses or notes ride beside
    them. A transport without schema support keeps the free-form plan, as the read loop does.
    """
    from nexus.langgraph.context_loop import _REQUIRED_ARGS, _STRING_FIELDS_BY_TOOL, _TOOL_ARGS
    from nexus.langgraph.tool_generation import (
        generation_format,
        response_schema,
        supports_generation_schema,
    )

    if not supports_generation_schema(model):
        return None
    return generation_format(model, response_schema(
        case_id, _TOOL_ARGS, _REQUIRED_ARGS, _STRING_FIELDS_BY_TOOL, allowed_tools=_PLAN_TOOLS,
        extra_properties=keys))


async def _call_plan(model: Any, messages: list[dict[str, str]], response_format: dict[str, Any] | None) -> str:
    """One plan call, bound to its schema through the read loop's call when the transport supports it.

    A reply that breaks its schema is returned whole, for the caller's corrective retry to read.
    """
    if response_format is None:
        return await _call_model(model, messages)
    import asyncio

    from nexus.langgraph.context_loop import _call_model as call_bound

    try:
        return await asyncio.to_thread(call_bound, model, messages, response_format=response_format)
    except Exception as exc:
        text = getattr(exc, "model_response_text", None)
        if text is None:
            raise
        return str(text)


def _looks_like_findings_json(text: str) -> bool:
    """True when a reply is *shaped* like findings but did not parse to any.

    Distinguishes a formatting failure from a legitimate "no findings": the
    former carries the finding keys, the latter does not. Only the former is
    worth a corrective retry.
    """
    blob = (text or "").lower()
    if not blob.strip():
        return False
    keys = ('"title"', '"observation"', '"interpretation"', '"confidence"')
    return sum(1 for key in keys if key in blob) >= 2


def _persist_round(case_dir: Path, name: str, payload: dict[str, Any]) -> None:
    try:
        out = Path(case_dir) / "analysis" / "interpret_rounds"
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{name}.json").write_text(
            json.dumps(payload, indent=2, default=str), encoding="utf-8"
        )
    except OSError as exc:
        log.debug("round artifact write failed: %s", exc)


def _family_ledger_for_run(case_dir: Path, run_id: str) -> dict[str, Any]:
    """This run's family coverage ledger, or ``{}`` when it cannot be built.

    WO-1C item 7 (KR4 / D58): a run must account for every indexed family from
    its own execution records. Best-effort by design — a ledger failure must
    never take the interpretation down.
    """
    if not run_id:
        return {}
    try:
        from nexus.analysis.family_ledger import build_family_ledger

        return build_family_ledger(case_dir, run_id=run_id)
    except Exception as exc:  # noqa: BLE001
        log.debug("family ledger build failed for %s: %s", run_id, exc)
        return {}


def _record_loop_query(
    case_dir: Path,
    run_id: str,
    tool_name: str,
    payload: dict[str, Any],
    result: dict[str, Any],
    entry: dict[str, Any],
) -> None:
    """Persist one executed interpret query to the family ledger (WO-1C item 7).

    Only evidence queries are recorded: ``es_search`` / ``es_aggregate`` /
    ``es_sample``. The query body comes from the executed payload, the status
    and rows from the tool's own result — never from the plan.
    """
    if tool_name not in ("es_search", "es_aggregate", "es_sample"):
        return
    from nexus.analysis.family_ledger import families_read, record_query

    query = payload.get("query") if isinstance(payload.get("query"), dict) else None
    if query is None:
        family = str(payload.get("family") or "").strip()
        query = {"term": {"family": family}} if family else {"__tool__": tool_name}
    record_query(
        case_dir,
        query,
        status="FAIL" if entry.get("error") else "OK",
        rows=int(entry.get("count") or 0),
        audit_id=str(entry.get("audit_id") or ""),
        run_id=run_id,
        families=families_read(entry.get("hits")),
    )


@egress_bound
async def run_interpret_loop(
    *,
    case_dir: Path,
    case_id: str,
    model: Any,
    state: Mapping[str, Any],
    digest: dict[str, Any],
    digest_md: str,
    sections: list[tuple[int, str, str]],
    execute: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]],
    rounds: int | None = None,
    run_id: str = "",
    context_policy: str = "independent",
) -> dict[str, Any]:
    """Run the bounded interpretation loop; return messages + round log.

    ``execute`` invokes one audited evidence tool (es_search/es_sample/
    es_aggregate) and returns the parsed tool dict — the caller wires it to
    the same MCP tool bindings the examiner uses, so every row carries an
    audit_id the findings can cite (FD-001).

    ``run_id`` is this Mode 1 analysis run (WO-1C item 2): every executed
    query and every round artifact is attributed to it, so the run's family
    ledger and lineage say which run did the work.

    ``context_policy`` (WO-1C item 3) is ``independent`` by default — the loop
    sees the evidence only. ``informed`` adds the case's prior report and
    DRAFT findings as one labelled section: examiner context, never evidence.
    """
    from nexus.analysis.context_policy import (
        context_sections,
        normalize_policy,
    )
    from nexus.langgraph.prompt_budget import (
        case_window,
        log_usage,
        pack_sections,
        persist_context,
    )

    case_dir = Path(case_dir)
    rounds_total = _resolve_rounds(state, case_dir, rounds)
    ctx_window = case_window(case_dir)
    # WO-1C item 2: a Mode 1 run has an id like Modes 2 and 3. The caller
    # passes it; when it does not, one is minted here and returned so the
    # run record and the ledger agree.
    run_id = str(run_id or state.get("run_id") or "").strip()
    if not run_id:
        from uuid import uuid4

        run_id = (
            "M1-"
            + datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
            + f"-{uuid4().hex[:6]}"
        )
    intake = state.get("case_context") or {}
    intake_block = "\n".join(
        f"- {key}: {value}" for key, value in intake.items() if value
    ) or "(no examiner intake)"

    # WO-1C item 3: `informed` runs add the case's prior analysis as one
    # labelled section (examiner context, never evidence). It is added once,
    # here, so every round of this loop sees the same context — a run cannot
    # gain evidence mid-loop.
    policy = normalize_policy(context_policy or state.get("context_policy"))
    sections = [*sections, *context_sections(case_dir, policy)]

    def _packed(tag: str, extra: list[tuple[int, str, str]], system: str = "") -> str:
        base = [*extra, *sections]
        # `sections` from the caller may already start with the digest; never
        # pack it twice (double content + double budget accounting).
        if not any(name == "case_digest" for _pri, name, _text in base):
            base = [(0, "case_digest", digest_md), *base]
        packed, report = pack_sections(base, window=ctx_window)
        # The record holds both messages the model receives (D174: the system message, with the
        # skills, field sheet and query protocol, was missing from it).
        persist_context(case_dir, tag, _model_record(system, packed), report,
                        meta={"case_id": case_id, "run_id": state.get("run_id", "")})
        log_usage(tag, report)
        return packed

    from nexus.langgraph.llm_pipeline import emit_stage

    def _progress(status: str, detail: str = "") -> None:
        # A Mode 1 run is minutes of model calls; each phase says where it is (2026-10-14).
        emit_stage(dict(state), "interpret", status, detail)

    messages: list[dict[str, str]] = []
    hypotheses: list[dict[str, Any]] = []
    notes_all: list[dict[str, str]] = []
    evidence_blocks: list[str] = []

    # ── Round 0 — Orient ────────────────────────────────────────────────
    plan_format = _plan_format(model, case_id, ORIENT_KEYS)
    verify_format = _plan_format(model, case_id, VERIFY_KEYS) if plan_format else None
    if plan_format:
        plan_shape = (
            '{"hypotheses":[{"id":"H1","statement":"...","why":"..."}],'
            '"tool_calls":[{"tool":"es_search|es_aggregate|run_record","args":{"query":{"match_all":{}},"size":20},"why":"..."}]}\n'
            "RULES:\n"
            "- Max 6 tool_calls: es_search for rows, es_aggregate for counts and distributions; only "
            "families and fields that actually exist in the digest and the field sheet.\n")
        plan_keys = "hypotheses and tool_calls"
    else:
        plan_shape = (
            '{"hypotheses":[{"id":"H1","statement":"...","why":"..."}],'
            '"queries":[{"es":{"query":{"bool":{"must":[{"match":{"text":"<term>"}}]}}},"why":"..."}],'
            '"aggregates":[{"aggs":{"by_host":{"terms":{"field":"host"}}},"query":{},"why":"..."}],'
            '"samples":[{"family":"","field":"","value":"","n":8,"why":""}],'
            '"tools":[{"tool":"run_record|forensic_rag_search",'
            '"args":{},"why":"..."}]}\n'
            "RULES:\n"
            "- Max 6 query/aggregate/sample items total; only families and fields "
            "that actually exist in the digest and the field sheet.\n")
        plan_keys = "hypotheses, queries, aggregates, samples and tools"
    orient_system = (
        "You are the lead DFIR analyst orienting an evidence interpretation. "
        "You have the deterministic CASE DIGEST (everything the case holds: the "
        "alert surface, every crit/high lead with the [audit_id ...] of the call "
        "that holds its rows, the top leads, and the scope of what is NOT in "
        "evidence). Your queries fetch the rows.\n"
        "Return ONLY JSON:\n"
        + plan_shape +
        "- ES query JSON only: bool/term/terms/range/match/match_phrase/"
        "multi_match/wildcard/exists/prefix/match_all. Time filters are "
        '{"range":{"ts":{"gte":...,"lte":...}}} (ts is canonical UTC; '
        "ts_year_assumed/ts_tz_assumed mark policy assumptions). Parsed "
        "columns live under fields.<Name> (keyword subfield "
        "fields.<Name>.kw) — use es_fields data from the digest, never invent "
        "columns.\n"
        "- Hypotheses must be falsifiable from the evidence; prefer the "
        "examiner's focus if one is given.\n"
        "- No prose outside the JSON."
    )
    field_sheet = ""
    skill_block = ""
    try:
        from nexus.langgraph.field_catalog import field_sheet_block
        from nexus.langgraph.query_normalize import query_protocol_block

        sheet = field_sheet_block(case_dir)
        if sheet:
            field_sheet = "\n" + sheet + "\n"
    except Exception:  # noqa: BLE001 — a prompt extra must never break the loop
        field_sheet = ""
    # WO-R1F item 8: the skill procedures selected for this case's families reach
    # Mode 1's interpret, as they already reach Mode 2's roles (and Mode 3's seats).
    try:
        from nexus.modes.multi_role import (
            WorkOrder,
            _retrieve_skill_refs,
            _skill_procedure_block,
            attack_method_block,
        )

        families = []
        try:
            from nexus.langgraph.query_pack import _present_families

            families = _present_families(case_dir)
        except Exception:  # noqa: BLE001
            families = []
        # The procedures for what the evidence shows, not only for which parsers ran: the top
        # leads' techniques rank the skills first (Mode 3's lead seats already do this). Keyed on
        # families and the question alone, CASE-C5B04D31's credential-theft and Defender-tamper
        # leads got browser and phishing procedures (2026-10-14).
        techniques: list[str] = []
        for lead in digest.get("top_leads") or []:
            if not isinstance(lead, dict):
                continue
            for tid in lead.get("attack_ids") or []:
                if tid not in techniques:
                    techniques.append(str(tid))
        refs = _retrieve_skill_refs(
            families or None,
            [w for w in str(intake.get("question") or "").split() if len(w) > 3][:12],
            limit=8,
            techniques=techniques[:12] or None,
        )
        # IC-5: ATT&CK's method for the crit/high leads' techniques, and the hunt list of the software
        # the leads detected, as Mode 2's orders and Mode 3's lead seats get them.
        crit_techniques: list[str] = []
        software: list[str] = []
        for lead in digest.get("top_leads") or []:
            if not isinstance(lead, dict):
                continue
            if lead.get("crit_high"):
                crit_techniques += [str(t) for t in lead.get("attack_ids") or [] if str(t) not in crit_techniques]
            software += [str(s) for s in lead.get("software") or [] if str(s) not in software]
        order = WorkOrder(order_id="interpret", role="evidence", task="", skill_refs=refs or [],
                          techniques=tuple(crit_techniques), software=tuple(software))
        block = (_skill_procedure_block(order, case_dir) if refs else "") + attack_method_block(order, case_dir)
        if block:
            skill_block = "\n" + block + "\n"
    except Exception:  # noqa: BLE001
        skill_block = ""
    # Every stage that writes ES queries gets the case's columns and the query protocol. Verify
    # plans the next round's queries too; it had neither, and its rounds came back with hundreds
    # of thousands of rows (2026-10-14: 471,013 and 351,982).
    query_guidance = field_sheet + "\n" + query_protocol_block()
    orient_system = orient_system + skill_block + query_guidance
    packed = _packed("interpret-orient", [
        (1, "examiner_intake", intake_block),
    ], system=orient_system)
    _progress("orient", f"planning hypotheses and queries ({rounds_total} round(s) allowed)")
    raw = await _call_plan(model, [
        {"role": "system", "content": orient_system},
        {"role": "user", "content": packed + "\n\nProduce the plan JSON."},
    ], plan_format)
    plan_data = _parse_json_blob(raw)
    plan = _normalize_plan(plan_data)
    orient_retry = False
    if raw.strip() and not plan["hypotheses"] and not plan["items"]:
        # A reply that says something but yields no plan is a format failure, not "nothing to
        # investigate": the 2026-10-14 run got 10,011 characters back, read 0 hypotheses and 0
        # queries, skipped every round and wrote findings from nothing. Keep the reply, ask once
        # for well-formed JSON, and fail the run with the reason if the second reply is no better.
        orient_retry = True
        _persist_round(case_dir, "round-0-orient-unparsed", {"raw": raw, "chars": len(raw)})
        _progress("orient", f"the plan reply ({len(raw)} chars) did not parse; one corrective retry")
        raw = await _call_plan(model, [
            {"role": "system", "content": orient_system},
            {"role": "user", "content": (
                packed + "\n\nYour previous reply could not be read as the plan JSON"
                + _where_it_broke(raw) + f". Return ONLY one JSON object with the keys {plan_keys}. "
                "Every value must be valid JSON: no comments, no trailing commas and no '...' "
                "placeholders; close every { and [ you open.")},
        ], plan_format)
        plan_data = _parse_json_blob(raw)
        plan = _normalize_plan(plan_data)
    # Part 12 FM-9: every crit/high alert is a hypothesis with its own id, answered by id.
    hypotheses = plan["hypotheses"] + _lead_hypotheses(digest)
    _progress("orient", f"{len(hypotheses)} hypothesis(es), {len(plan['items'])} query item(s) planned")
    _persist_round(case_dir, "round-0-orient", {
        "round": 0, "kind": "orient", "hypotheses": hypotheses,
        "items": plan["items"], "raw_chars": len(raw), "raw": raw,
        "corrective_retry_used": orient_retry,
    })
    if not plan["hypotheses"] and not plan["items"]:
        raise RuntimeError(
            f"the orient reply could not be read as a plan ({len(raw)} chars"
            + (", after one corrective retry" if orient_retry else "")
            + "); see analysis/interpret_rounds/round-0-orient.json")

    def _execute_payload(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        kind = item["kind"]
        if kind == "es_query":
            es = item.get("es") or {}
            query = es.get("query") if isinstance(es.get("query"), dict) else es
            payload: dict[str, Any] = {
                "case_id": case_id, "query": query or {"match_all": {}},
                "size": es.get("size") or 50,
            }
            if isinstance(es.get("sort"), list):
                payload["sort"] = es["sort"]
            if isinstance(es.get("search_after"), list):
                payload["search_after"] = es["search_after"]
            return "es_search", payload
        if kind == "es_aggregate":
            payload = {"case_id": case_id, "aggs": item.get("aggs") or {}}
            if item.get("query"):
                payload["query"] = item["query"]
            return "es_aggregate", payload
        if kind == "sample":
            return "es_sample", {
                "case_id": case_id, "family": item.get("family") or "",
                "field": item.get("field") or "", "value": item.get("value") or "",
                "n": item.get("n") or 8,
            }
        if kind == "read":
            return str(item["tool"]), {**dict(item.get("args") or {}), "case_id": case_id}
        if kind == "tool":
            tool = str(item.get("tool") or "")
            payload = dict(item.get("args") or {})
            if tool in ("run_record",):
                payload.setdefault("case_id", case_id)
            return tool, payload
        # Legacy DSL items (older planned rounds) keep executing for replay.
        if kind == "aggregate":
            return "n4_aggregate", {
                "case_id": case_id, "dsl": item.get("dsl") or "",
                "field": item.get("field") or "host", "top": 20,
            }
        return "n4_query", {"case_id": case_id, "dsl": item.get("dsl") or ""}

    # ── Rounds 1..N — Verify ────────────────────────────────────────────
    current_items = plan["items"]
    rounds_run = 0
    stop_reason = "planned"
    for round_no in range(1, rounds_total + 1):
        if not current_items:
            stop_reason = "no_more_queries"
            break
        entries: list[dict[str, Any]] = []
        _progress(f"round {round_no}/{rounds_total}",
                  f"running {len(current_items[:_MAX_PLAN_ITEMS])} evidence query(ies)")
        for item in current_items[:_MAX_PLAN_ITEMS]:
            tool_name, payload = _execute_payload(item)
            result: dict[str, Any]
            try:
                result = await execute(tool_name, payload)
            except Exception as exc:  # noqa: BLE001 — one item must not kill the loop
                result = {"error": str(exc)}
            entry = {
                "kind": item["kind"], "why": item.get("why", ""),
                "params": {k: v for k, v in payload.items() if k != "case_id"},
                "audit_id": ((result.get("provenance") or {}).get("audit_id")
                             or result.get("audit_id") or ""),
                "error": result.get("error", ""),
                "count": result.get("total", result.get("count", result.get("matched", 0))),
                "field": result.get("field", ""),
                "distinct": result.get("distinct", 0),
                "distinct_approximate": result.get("distinct_approximate", False),
                "top": result.get("top") or result.get("ranked") or [],
                "aggregations": result.get("aggregations") or {},
                "next_after_key": result.get("next_after_key"),
                "has_more": result.get("has_more"),
                "next_search_after": result.get("next_search_after"),
                "hits": result.get("hits") or [],
                "result_keys": sorted(result.keys())[:24],
            }
            entries.append(entry)
            # WO-1C item 7 (KR4 / D58): record the query that actually ran, with
            # its outcome, so the run's family ledger is built from execution
            # records and not from the plan.
            _record_loop_query(case_dir, run_id, tool_name, payload, result, entry)
        rounds_run = round_no
        _rows = sum(e["count"] for e in entries if isinstance(e.get("count"), int))
        _errs = sum(1 for e in entries if e.get("error"))
        _progress(f"round {round_no}/{rounds_total}",
                  f"{len(entries) - _errs} ok, {_errs} error(s), {_rows} row(s); verifying")
        results_block = _render_results(entries)
        evidence_blocks.append(f"## Round {round_no} results\n{results_block}")
        _persist_round(case_dir, f"round-{round_no}-verify", {
            "round": round_no, "kind": "verify", "entries": entries,
        })

        next_key = "tool_calls" if verify_format else "next"
        verify_system = (
            f"You are verifying hypotheses against the ACTUAL rows returned by "
            f"the queries just executed (round {round_no} of up to "
            f"{rounds_total}). The rows below are the only evidence.\n"
            "Return ONLY JSON:\n"
            '{"notes":[{"hypothesis":"H1","status":"confirmed|refuted|unknown|partial",'
            '"evidence":"one sentence naming the rows (family/host/ts)","family":"..."}],'
            + ('"tool_calls":[{"tool":"es_search|es_aggregate|run_record","args":{"query":{"match_all":{}},"size":20},"why":"..."}]}\n'
               if verify_format else
               '"next":[{"es":{"query":{"bool":{"must":[{"match":{"text":"<term>"}}]}}},"why":"..."},'
               '{"tool":"run_record|forensic_rag_search","args":{},"why":"..."}]}\n')
            + f"RULES: one note per hypothesis. Plan `{next_key}` ONLY for unresolved "
            "hypotheses where new evidence could resolve them (max 4 items). "
            "If a search result says `has_more: true`, preserve its query and "
            "continue with the supplied `search_after` cursor before treating "
            f"that search as complete. If everything is settled, {next_key} = []. "
            "No prose outside the JSON."
            + query_guidance
        )
        hyps_block = "\n".join(
            f"- {h['id']}: {h['statement']}" for h in hypotheses
        ) or "(none)"
        plus_sections = [
            (0, "hypotheses", hyps_block),
            (1, "round_results", results_block),
        ]
        packed = _packed(f"interpret-verify-{round_no}", plus_sections, system=verify_system)
        raw = await _call_plan(model, [
            {"role": "system", "content": verify_system},
            {"role": "user", "content": packed + "\n\nProduce the notes JSON."},
        ], verify_format)
        data = _parse_json_blob(raw)
        verify_retry = False
        if raw.strip() and not (isinstance(data, dict) and ("notes" in data or next_key in data)):
            # Same failure as the orient reply: unreadable notes used to read as "nothing more to
            # query", so the loop settled on a round it never verified.
            verify_retry = True
            _progress(f"round {round_no}/{rounds_total}",
                      "the verification reply did not parse; one corrective retry")
            raw = await _call_plan(model, [
                {"role": "system", "content": verify_system},
                {"role": "user", "content": (
                    packed + "\n\nYour previous reply could not be read as the notes JSON"
                    + _where_it_broke(raw) + ". "
                    f"Return ONLY one JSON object with the keys notes and {next_key}. Every value must "
                    "be valid JSON: no comments, no trailing commas and no '...' placeholders; close "
                    "every { and [ you open.")},
            ], verify_format)
            data = _parse_json_blob(raw)
        if raw.strip() and not (isinstance(data, dict) and ("notes" in data or next_key in data)):
            _persist_round(case_dir, f"round-{round_no}-notes", {
                "round": round_no, "kind": "notes", "notes": [], "next": [],
                "raw": raw, "corrective_retry_used": verify_retry, "unparsed": True,
            })
            stop_reason = "verify_reply_unparsed"
            _progress(f"round {round_no}/{rounds_total}",
                      "the verification reply could not be read; the loop stops here")
            break
        notes = _notes_from(data)
        notes_all.extend(notes)
        next_list = _as_list(data.get("next")) if isinstance(data, dict) else []
        if verify_format:
            next_list = []
        next_plan = _normalize_plan({
            "queries": [
                i for i in next_list
                if isinstance(i, str)
                or (
                    isinstance(i, dict)
                    and (i.get("dsl") or i.get("query") or i.get("es")
                         or i.get("aggs"))
                )
            ],
            # One item goes to exactly ONE bucket: sample (by family) wins,
            # otherwise aggregate (aggregation shape or field) — never both.
            "aggregations": [
                i for i in next_list
                if isinstance(i, dict)
                and (i.get("aggs") or i.get("field")) and not i.get("family")
            ],
            "samples": [
                i for i in next_list
                if isinstance(i, dict) and i.get("family")
            ],
            "tools": [
                i for i in next_list
                if isinstance(i, dict) and i.get("tool")
            ],
            "tool_calls": _as_list(data.get("tool_calls")) if verify_format and isinstance(data, dict) else [],
        })
        _persist_round(case_dir, f"round-{round_no}-notes", {
            "round": round_no, "kind": "notes", "notes": notes,
            "next": next_plan["items"], "raw": raw, "corrective_retry_used": verify_retry,
        })
        # WO-R2F item 7 (D47): a round may stop `settled` only when every
        # crit/high lead has a disposition that cites its own rows — the same
        # contract Mode 3 enforces through `_dispositioned_keys`
        # (multi_agent.py:1135). Previously the loop settled the moment the
        # model planned no further queries, so a critical lead whose rows were
        # never pulled ended the round loop and the finding that followed was
        # written without any evidence for it.
        undispositioned = _undispositioned_crit_leads(digest, notes_all)
        if not next_plan["items"] and not undispositioned:
            stop_reason = "settled"
            break
        if not next_plan["items"] and round_no >= rounds_total:
            stop_reason = "rounds_exhausted"
            break
        if not next_plan["items"]:
            # The model is done planning but crit/high leads are still open.
            # Plan the evidence for them explicitly rather than letting the
            # loop die with them unverified. Nothing has settled yet, so the
            # stop reason is left to the round that ends the loop (D134).
            current_items = _replan_for_leads(undispositioned)
            _persist_round(case_dir, f"round-{round_no}-lead-replan", {
                "round": round_no, "kind": "lead_replan",
                "undispositioned": [lead["subject"] for lead in undispositioned],
                "items": current_items,
            })
            continue
        current_items = next_plan["items"]
    else:
        # Every round ran and queries were still planned: the loop was cut off, not settled.
        # The summary used to keep "planned" (or a stale "settled") here (D134).
        if current_items:
            stop_reason = "rounds_exhausted"

    evidence_block = "\n\n".join(evidence_blocks) or "(no rows returned)"
    notes_block = "\n".join(
        f"- {n['hypothesis']} → {n['status']}: {n['evidence']}" for n in notes_all
    ) or "(none)"

    # ── Final round — Reconcile + findings JSON ─────────────────────────
    findings_system = (
        "You are the lead DFIR analyst. Evidence gathering is complete; write "
        "the final findings JSON using ONLY the digest facts and the "
        "rows/notes below.\n"
        "Return ONE JSON object: {\"findings\": [...], \"dispositions\": [...]}.\n"
        "HARD RULES:\n"
        "- findings hold claims the rows support, and nothing else.\n"
        "- dispositions answer for each ALERT SURFACE item (listed with [audit_id X]) that no "
        "finding covers: {\"item\": that audit_id, \"status\": "
        + "|".join(DISPOSITION_STATUSES)
        + ", \"reason\": why, from the rows and notes, \"audit_ids\": the markers it rests "
        "on, or []}. A census, a scope note and a threat-intel verdict that no row supports are "
        "dispositions, never findings.\n"
        "- Every ALERT SURFACE item is covered by a finding or has a disposition. "
        "Silence is a failure.\n"
        # D217: with no status for "part of a finding", run d1a28c66 disposed a service install it
        # tied to the beacon as benign ("subsumed by H1 beacon"). Part 12 FM-9: coverage is by audit id,
        # never by the finding's wording.
        "- A finding covers an alert when its audit_ids include the alert's audit_id and its "
        "observation describes that activity: an alert that is part of a finding's activity is "
        "cited by that finding, never disposed. "
        "benign = the rows show legitimate activity (say which); coverage_gap = the evidence "
        "needed is not in this case; not_examined = not queried in this run; refuted = rows "
        "contradict it.\n"
        "- Absent evidence classes are SCOPE - never phrase them as "
        "'no compromise'. A search that matched nothing is not evidence of absence.\n"
        "- Each finding: title, severity (critical|high|medium|low|info, judged from "
        "the evidence), entity {\"type\",\"value\"} (the one thing it is about, "
        "e.g. {\"type\":\"event_id\",\"value\":\"1004\"}), observation, interpretation (non-empty), "
        "evidence [{time,source,artifact,detail}], attack_ids (only when "
        "justified), confidence, confidence_justification, audit_ids from "
        "the [audit_id ...] markers shown above.\n"
        "Return ONLY the JSON object. No prose."
    )
    reconcile_extra = [
        (0, "hypotheses", "\n".join(f"- {h['id']}: {h['statement']}" for h in hypotheses)),
        (1, "round_results", evidence_block),
        (2, "verification_notes", notes_block),
    ]
    _progress("reconcile", f"writing findings from {len(notes_all)} verification note(s)")
    packed = _packed("interpret-reconcile", reconcile_extra, system=findings_system)
    # Keep the packing stats so the corrective retry's persisted context carries
    # the same completeness header as every other stage.
    _, packed_report = pack_sections(
        [(0, "case_digest", digest_md), *reconcile_extra], window=ctx_window
    )
    raw_findings = await _call_model(model, [
        {"role": "system", "content": findings_system},
        {"role": "user", "content": packed + "\n\nEmit the JSON object."},
    ])

    from nexus.langgraph.case_digest import reconciliation_checklist
    from nexus.langgraph.hunt_parser import parse_hunt_candidates

    def _candidates(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return parse_hunt_candidates([{"role": "assistant", "content": _findings_message(findings)}])

    found, dispositions = _split_reconcile_reply(raw_findings)
    candidates = _candidates(found)
    # A reply that parses to zero candidates but LOOKS like findings JSON (it
    # carries the keys) is a formatting failure, not "no findings" - and it
    # discards everything this loop verified. One corrective retry, bounded to
    # one, asking only for well-formed JSON. A reply with none of the keys
    # (prose, "I could not find...") is a legitimate empty result and is NOT
    # retried.
    correct_used = False
    if not candidates and _looks_like_findings_json(raw_findings):
        correct_used = True
        log.warning("Findings reply carried findings keys but parsed to 0 — one corrective retry")
        # Keep the reply that failed to parse, so the cause can be read after the run; only the
        # corrected reply used to be kept (2026-10-14).
        _persist_round(case_dir, "findings-unparsed",
                       {"raw": raw_findings, "chars": len(raw_findings or "")})
        _progress("reconcile", "the findings reply did not parse; one corrective retry")
        try:
            persist_context(
                case_dir, "interpret-findings-corrective",
                _model_record(findings_system, packed), packed_report,
                meta={"case_id": case_id},
            )
            corrected = await _call_model(model, [
                {"role": "system", "content": findings_system},
                {
                    "role": "user",
                    "content": (
                        packed
                        + "\n\nYour previous reply could not be parsed as findings. "
                        "Return ONLY a well-formed JSON object {\"findings\": [...], "
                        "\"dispositions\": [...]}. No prose, no fence, no trailing commas. "
                        "If no claim is supportable, findings is []."
                    ),
                },
            ])
            corrected_found, corrected_dispositions = _split_reconcile_reply(corrected)
            if _candidates(corrected_found):
                raw_findings = corrected
                found, dispositions = corrected_found, corrected_dispositions
                candidates = _candidates(found)
        except Exception as exc:  # noqa: BLE001 — the retry is best-effort
            log.warning("findings corrective retry failed: %s", exc)

    checklist = reconciliation_checklist(digest, candidates, dispositions)
    unaddressed_final = checklist.get("unaddressed") or []

    # One bounded extra pass for whatever neither a finding nor a disposition answered.
    extra_text = ""
    revised: list[str] = []
    if unaddressed_final:
        _progress("reconcile",
                  f"one extra pass for {len(unaddressed_final)} unaddressed digest item(s)")
        items_block = "\n".join(
            f"- [{i.get('kind')}] {i.get('value')} [audit_id {i.get('key')}]" for i in unaddressed_final
        )
        # The same rules and finding shape as the first pass (D213): the extra pass named neither, so
        # agnes-3.0-flash returned its findings as {id, title, detail, severity} and none could stage
        # (2026-10-15: four, among them seven denied RDP logons just before the successful one).
        # The findings the first pass wrote, by id (D255): the pass was told to add only a claim "the
        # findings so far do not make" without being shown them, and restated five of seven first-pass
        # findings in new words, so each staged twice (fresh run 15d8cd92, 2026-10-16). An item that is
        # part of a written finding's activity is named in that finding's observation (D217), so the
        # pass returns that finding whole with `revises`, and it replaces the first-pass one.
        findings_block = "\n".join(
            f"- F{n}: {f.get('title')} | entity {json.dumps(f.get('entity'), ensure_ascii=False)} | "
            f"audit_ids {', '.join(str(a) for a in _as_list(f.get('audit_ids')))}: {f.get('observation') or ''}"
            for n, f in enumerate(found, 1)
        ) or "(none)"
        extra_system = (
            findings_system
            + "\nTHIS PASS: the findings listed under findings_so_far (F1, F2, ...) are written. They "
            "left the ALERT SURFACE items listed under unaddressed_items unanswered. For each "
            "item: when it is part of the activity of a finding in findings_so_far, return that finding "
            "whole, citing the item's audit_id, with \"revises\": its id; when the rows support a "
            "claim no finding in findings_so_far makes, write a new finding with no \"revises\"; "
            "otherwise give the item a disposition. Never return a finding of findings_so_far again "
            "without \"revises\", and never revise one finding twice."
        )
        extra_sections = reconcile_extra + [(0, "findings_so_far", findings_block),
                                            (0, "unaddressed_items", items_block)]
        packed_extra, report_extra = pack_sections(
            [(0, "case_digest", digest_md), *extra_sections],
            window=ctx_window,
        )
        try:
            persist_context(case_dir, "interpret-reconcile-extra",
                            _model_record(extra_system, packed_extra),
                            report_extra, meta={"case_id": case_id})
            log_usage("interpret-reconcile-extra", report_extra)
            extra_text = await _call_model(model, [
                {"role": "system", "content": extra_system},
                {"role": "user", "content": packed_extra + "\n\nEmit the JSON object."},
            ])
            extra_found, extra_dispositions = _split_reconcile_reply(extra_text)
            found, revised = _merge_extra_findings(found, extra_found, _candidates)
            dispositions = dispositions + extra_dispositions
            candidates = _candidates(found)
            checklist = reconciliation_checklist(digest, candidates, dispositions)
            unaddressed_final = checklist.get("unaddressed") or []
        except Exception as exc:  # noqa: BLE001 — extra pass is best-effort
            log.warning("reconcile extra pass failed: %s", exc)

    # The final findings reply is the one artifact that says WHY a loop that
    # confirmed its hypotheses emitted no findings - a model that answered in
    # prose, an empty array, a malformed array, or a candidate missing a key.
    # Without it `findings_emitted: 0` is unverifiable, and the caller can only
    # log "emitted no findings" and fall back (SC1, 2026-10-07: four hypotheses
    # confirmed on real evidence, 0 findings, no way to see what came back).
    _persist_round(case_dir, "findings-final", {
        "raw": raw_findings,
        "chars": len(raw_findings or ""),
        "candidates_parsed": len(candidates),
        "corrective_retry_used": correct_used,
        "reconciliation_addressed": len(checklist.get("addressed") or []),
        "extra_raw": extra_text,
        "extra_revised": revised,
    })
    from nexus.langgraph.pipeline_runs import configured_model

    _persist_round(case_dir, "summary", {
        "run_id": run_id,
        "model": configured_model(),
        "rounds_requested": rounds_total,
        "rounds_run": rounds_run,
        "stop_reason": stop_reason,
        "context_policy": policy,
        "hypotheses": hypotheses,
        "notes": notes_all,
        "findings_emitted": len(candidates),
        "dispositions": dispositions,
        "reconciliation": {
            "addressed": len(checklist.get("addressed") or []),
            "dispositioned": len(checklist.get("dispositioned") or []),
            "unaddressed": unaddressed_final,
        },
        # WO-1C item 7: the family coverage ledger this run's own queries
        # produced, so "not observed" is bounded by what actually ran.
        "family_ledger": _family_ledger_for_run(case_dir, run_id),
    })
    _progress("done", f"{rounds_run}/{rounds_total} round(s), stop {stop_reason}, "
                      f"{len(candidates)} finding candidate(s)")

    messages.append({
        "role": "assistant",
        "content": (
            f"Interpret rounds ({rounds_run}/{rounds_total}, stop: {stop_reason}). "
            f"Hypotheses: {len(hypotheses)}. Verification notes:\n{notes_block}\n\n"
            f"Evidence gathered:\n{evidence_block}"
        ),
    })
    # The findings alone: a disposition is never a candidate for staging (D193).
    messages.append({"role": "assistant", "content": _findings_message(found)})

    return {
        "run_id": run_id,
        "messages": messages,
        "rounds_requested": rounds_total,
        "rounds_run": rounds_run,
        "stop_reason": stop_reason,
        "hypotheses": hypotheses,
        "notes": notes_all,
        "findings_emitted": len(candidates),
        "dispositions": dispositions,
        "unaddressed": unaddressed_final,
        # WO-1C item 3: the policy that produced this loop, so the run record
        # and the report can always say how much prior context it saw.
        "context_policy": policy,
        "family_ledger": _family_ledger_for_run(case_dir, run_id),
    }
