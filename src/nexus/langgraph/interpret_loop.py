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
- **Final — Reconcile:** the LLM emits the findings JSON with a hard rule:
  every digest item (alerts ≥ high, high-count needles, entities, gaps) gets
  a disposition. The deterministic reconciliation checklist then verifies
  this; one bounded extra pass addresses anything still unmentioned.

Artifacts (auditable, replayable): ``analysis/interpret_rounds/round-N.json``
+ ``summary.json``; every packed prompt persists via ``prompt_budget``.

No LLM / loop failure → the caller keeps the single-pass ReAct fallback.
"""
from __future__ import annotations

import json
import logging
import re
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_MAX_PLAN_ITEMS = 6
_MAX_RESULT_ROWS = 8       # rows shown per executed item in the LLM context
_MAX_ROW_CHARS = 300
_MAX_PERSIST_ROWS = 50
_DEFAULT_ROUNDS = 3


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
                opts = json.loads(
                    (Path(case_dir) / "analysis" / "mode2_run_options.json")
                    .read_text(encoding="utf-8")
                )
                value = int(opts.get("interpret_rounds") or 0)
            except (OSError, ValueError, TypeError):
                value = 0
        if not value:
            import os

            try:
                value = int(os.environ.get("NEXUS_INTERPRET_ROUNDS") or _DEFAULT_ROUNDS)
            except ValueError:
                value = _DEFAULT_ROUNDS
    return max(1, min(int(value), 5))


def _parse_json_blob(text: str) -> Any:
    """Tolerant JSON extraction: whole content, fenced blocks, or first blob."""
    if not text:
        return None
    text = text.strip()
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    for match in re.finditer(r"```(?:json)?\s*(.*?)```", text, re.DOTALL):
        block = match.group(1).strip()
        try:
            return json.loads(block)
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
        return json.loads(text[start:end + 1])
    except (json.JSONDecodeError, ValueError):
        return None


def _normalize_plan(data: Any) -> dict[str, list[dict[str, Any]]]:
    """Coerce an orient/verify JSON payload into bounded plan items."""
    plan: dict[str, list[dict[str, Any]]] = {"hypotheses": [], "items": []}
    if not isinstance(data, dict):
        return plan
    for h in (data.get("hypotheses") or [])[:6]:
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
            dsl = str(entry.get("dsl") or entry.get("query") or "").strip()
            if dsl:
                plan["items"].append({"kind": "query", "dsl": dsl,
                                      "why": str(entry.get("why") or "")[:200]})
        elif kind == "aggregate":
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
                plan["items"].append({
                    "kind": "sample",
                    "family": family,
                    "field": str(entry.get("field") or "").strip(),
                    "value": value,
                    "n": max(1, min(int(entry.get("n") or 8), 20)),
                    "why": str(entry.get("why") or "")[:200],
                })

    for kind in ("queries", "aggregations", "aggregates", "samples"):
        key_kind = {
            "queries": "query", "aggregations": "aggregate",
            "aggregates": "aggregate", "samples": "sample",
        }[kind]
        entries = data.get(kind)
        if isinstance(entries, list):
            for entry in entries:
                _add(key_kind, entry)
        if len(plan["items"]) >= _MAX_PLAN_ITEMS:
            break
    return plan


def _notes_from(data: Any) -> list[dict[str, str]]:
    notes: list[dict[str, str]] = []
    if not isinstance(data, dict):
        return notes
    for n in (data.get("notes") or [])[:8]:
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
        lines.append(f"  {entry.get('count', len(hits))} matched row(s); showing {min(len(hits), _MAX_RESULT_ROWS)}")
        for h in hits[:_MAX_RESULT_ROWS]:
            fam = h.get("family") or ""
            ts = h.get("ts") or ""
            host = h.get("host") or ""
            text = re.sub(r"\s+", " ", str(h.get("text") or ""))[:_MAX_ROW_CHARS]
            lines.append(f"  [{fam}] {ts} {host} :: {text}")
    return "\n".join(lines) if lines else "(no results)"


async def _call_model(model: Any, messages: list[dict[str, str]]) -> str:
    try:
        response = await model.ainvoke(messages)
    except (AttributeError, NotImplementedError):
        import asyncio

        response = await asyncio.to_thread(model.invoke, messages)
    return str(getattr(response, "content", response))


def _persist_round(case_dir: Path, name: str, payload: dict[str, Any]) -> None:
    try:
        out = Path(case_dir) / "analysis" / "interpret_rounds"
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{name}.json").write_text(
            json.dumps(payload, indent=2, default=str), encoding="utf-8"
        )
    except OSError as exc:
        log.debug("round artifact write failed: %s", exc)


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
) -> dict[str, Any]:
    """Run the bounded interpretation loop; return messages + round log.

    ``execute`` invokes one audited evidence tool (n4_query/n4_sample/
    n4_aggregate) and returns the parsed tool dict — the caller wires it to
    the same MCP tool bindings the examiner uses, so every row carries an
    audit_id the findings can cite (FD-001).
    """
    from nexus.langgraph.prompt_budget import (
        log_usage,
        pack_sections,
        persist_context,
    )

    case_dir = Path(case_dir)
    rounds_total = _resolve_rounds(state, case_dir, rounds)
    intake = state.get("case_context") or {}
    intake_block = "\n".join(
        f"- {key}: {value}" for key, value in intake.items() if value
    ) or "(no examiner intake)"

    def _packed(tag: str, extra: list[tuple[int, str, str]]) -> str:
        packed, report = pack_sections(
            [(0, "case_digest", digest_md), *extra, *sections]
        )
        persist_context(case_dir, tag, packed, report,
                        meta={"case_id": case_id, "run_id": state.get("run_id", "")})
        log_usage(tag, report)
        return packed

    messages: list[dict[str, str]] = []
    hypotheses: list[dict[str, Any]] = []
    notes_all: list[dict[str, str]] = []
    evidence_blocks: list[str] = []

    # ── Round 0 — Orient ────────────────────────────────────────────────
    orient_system = (
        "You are the lead DFIR analyst orienting an evidence interpretation. "
        "You have the deterministic CASE DIGEST (everything the case holds, "
        "including 0-hit needles as negative evidence and the scope of what "
        "is NOT in evidence) and the N4 QUERY PACK of indexed rows.\n"
        "Return ONLY JSON:\n"
        '{"hypotheses":[{"id":"H1","statement":"...","why":"..."}],'
        '"queries":[{"dsl":"<N4 DSL>","why":"..."}],'
        '"aggregates":[{"field":"host|user|<column>","dsl":"","why":"..."}],'
        '"samples":[{"family":"","field":"","value":"","n":8,"why":""}]}\n'
        "RULES:\n"
        "- Max 6 query/aggregate/sample items total; only families and fields "
        "that actually exist in the digest/query pack.\n"
        "- Hypotheses must be falsifiable from the evidence; prefer the "
        "examiner's focus if one is given.\n"
        "- No prose outside the JSON."
    )
    packed = _packed("interpret-orient", [
        (1, "examiner_intake", intake_block),
    ])
    raw = await _call_model(model, [
        {"role": "system", "content": orient_system},
        {"role": "user", "content": packed + "\n\nProduce the plan JSON."},
    ])
    plan_data = _parse_json_blob(raw)
    plan = _normalize_plan(plan_data)
    hypotheses = plan["hypotheses"]
    _persist_round(case_dir, "round-0-orient", {
        "round": 0, "kind": "orient", "hypotheses": hypotheses,
        "items": plan["items"], "raw_chars": len(raw),
    })

    def _execute_payload(item: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        kind = item["kind"]
        if kind == "aggregate":
            return "n4_aggregate", {
                "case_id": case_id, "dsl": item.get("dsl") or "",
                "field": item.get("field") or "host", "top": 20,
            }
        if kind == "sample":
            return "n4_sample", {
                "case_id": case_id, "family": item.get("family") or "",
                "field": item.get("field") or "", "value": item.get("value") or "",
                "n": item.get("n") or 8,
            }
        return "n4_query", {
            "case_id": case_id, "dsl": item.get("dsl") or "", "limit": 35,
        }

    # ── Rounds 1..N — Verify ────────────────────────────────────────────
    current_items = plan["items"]
    rounds_run = 0
    stop_reason = "planned"
    for round_no in range(1, rounds_total + 1):
        if not current_items:
            stop_reason = "no_more_queries"
            break
        entries: list[dict[str, Any]] = []
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
                "count": result.get("count", result.get("matched", 0)),
                "field": result.get("field", ""),
                "distinct": result.get("distinct", 0),
                "distinct_approximate": result.get("distinct_approximate", False),
                "top": result.get("top") or result.get("ranked") or [],
                "hits": (result.get("hits") or [])[:_MAX_PERSIST_ROWS],
            }
            entries.append(entry)
        rounds_run = round_no
        results_block = _render_results(entries)
        evidence_blocks.append(f"## Round {round_no} results\n{results_block}")
        _persist_round(case_dir, f"round-{round_no}-verify", {
            "round": round_no, "kind": "verify", "entries": entries,
        })

        verify_system = (
            f"You are verifying hypotheses against the ACTUAL rows returned by "
            f"the queries just executed (round {round_no} of up to "
            f"{rounds_total}). The rows below are the only evidence.\n"
            "Return ONLY JSON:\n"
            '{"notes":[{"hypothesis":"H1","status":"confirmed|refuted|unknown|partial",'
            '"evidence":"one sentence naming the rows (family/host/ts/needle)","family":"..."}],'
            '"next":[{"dsl":"...","why":"..."}]}\n'
            "RULES: one note per hypothesis. Plan `next` ONLY for unresolved "
            "hypotheses where new evidence could resolve them (max 4 items). "
            "If everything is settled, next = []. No prose outside the JSON."
        )
        hyps_block = "\n".join(
            f"- {h['id']}: {h['statement']}" for h in hypotheses
        ) or "(none)"
        plus_sections = [
            (0, "hypotheses", hyps_block),
            (1, "round_results", results_block),
        ]
        packed = _packed(f"interpret-verify-{round_no}", plus_sections)
        raw = await _call_model(model, [
            {"role": "system", "content": verify_system},
            {"role": "user", "content": packed + "\n\nProduce the notes JSON."},
        ])
        data = _parse_json_blob(raw)
        notes = _notes_from(data)
        notes_all.extend(notes)
        next_plan = {"hypotheses": [], "items": []}
        if isinstance(data, dict) and data.get("next"):
            next_plan = _normalize_plan({"queries": data.get("next")})
            # next items may also be aggregates/samples passed as objects
            if not next_plan["items"]:
                next_plan = _normalize_plan({
                    "aggregations": data.get("next"),
                    "samples": [n for n in (data.get("next") or []) if isinstance(n, dict) and n.get("family")],
                })
        _persist_round(case_dir, f"round-{round_no}-notes", {
            "round": round_no, "kind": "notes", "notes": notes,
            "next": next_plan["items"],
        })
        if not next_plan["items"]:
            stop_reason = "settled"
            break
        current_items = next_plan["items"]

    evidence_block = "\n\n".join(evidence_blocks) or "(no rows returned)"
    notes_block = "\n".join(
        f"- {n['hypothesis']} → {n['status']}: {n['evidence']}" for n in notes_all
    ) or "(none)"

    # ── Final round — Reconcile + findings JSON ─────────────────────────
    findings_system = (
        "You are the lead DFIR analyst. Evidence gathering is complete; write "
        "the final findings JSON array using ONLY the digest facts and the "
        "rows/notes below.\n"
        "HARD RULES:\n"
        "- Every DIGEST RECONCILIATION item must be dispositioned: covered by "
        "a finding, or explicitly assessed benign with a reason, or an "
        "explicit coverage-gap item. Silence is a failure.\n"
        "- Absent evidence classes are SCOPE - never phrase them as "
        "'no compromise'.\n"
        "- Checked needles with 0 hits are negative evidence: name them in "
        "the relevant finding's observation.\n"
        "- Each finding: title, observation, interpretation (non-empty), "
        "evidence [{time,source,artifact,detail}], attack_ids (only when "
        "justified), confidence, confidence_justification, audit_ids from "
        "the [audit_id ...] markers shown above.\n"
        "Return ONLY a JSON array. No prose."
    )
    reconcile_extra = [
        (0, "hypotheses", "\n".join(f"- {h['id']}: {h['statement']}" for h in hypotheses)),
        (1, "round_results", evidence_block),
        (2, "verification_notes", notes_block),
    ]
    packed = _packed("interpret-reconcile", reconcile_extra)
    raw_findings = await _call_model(model, [
        {"role": "system", "content": findings_system},
        {"role": "user", "content": packed + "\n\nEmit the findings JSON array."},
    ])

    from nexus.langgraph.case_digest import reconciliation_checklist
    from nexus.langgraph.hunt_parser import parse_hunt_candidates

    def _candidates(text: str) -> list[dict[str, Any]]:
        return parse_hunt_candidates([{"role": "assistant", "content": text}])

    candidates = _candidates(raw_findings)
    checklist = reconciliation_checklist(digest, candidates)
    unaddressed_final = checklist.get("unaddressed") or []

    # One bounded extra pass for whatever the findings did not mention.
    extra_text = ""
    if unaddressed_final:
        items_block = "\n".join(
            f"- [{i.get('kind')}] {i.get('value')}" for i in unaddressed_final[:40]
        )
        extra_system = (
            "These digest items were not addressed by the findings so far. "
            "Emit ONLY additional findings (JSON array) that disposition each "
            "item: a real finding, 'Assessed benign: <item>' with the reason, "
            "or an explicit coverage gap. Use the digest/evidence above."
        )
        extra_sections = reconcile_extra + [(0, "unaddressed_items", items_block)]
        packed_extra, report_extra = pack_sections(
            [(0, "case_digest", digest_md), *extra_sections]
        )
        try:
            persist_context(case_dir, "interpret-reconcile-extra", packed_extra,
                            report_extra, meta={"case_id": case_id})
            log_usage("interpret-reconcile-extra", report_extra)
            extra_text = await _call_model(model, [
                {"role": "system", "content": extra_system},
                {"role": "user", "content": packed_extra + "\n\nEmit the additional findings JSON array."},
            ])
            candidates = candidates + _candidates(extra_text)
            checklist = reconciliation_checklist(digest, candidates)
            unaddressed_final = checklist.get("unaddressed") or []
        except Exception as exc:  # noqa: BLE001 — extra pass is best-effort
            log.warning("reconcile extra pass failed: %s", exc)

    _persist_round(case_dir, "summary", {
        "rounds_requested": rounds_total,
        "rounds_run": rounds_run,
        "stop_reason": stop_reason,
        "hypotheses": hypotheses,
        "notes": notes_all,
        "findings_emitted": len(candidates),
        "reconciliation": {
            "addressed": len(checklist.get("addressed") or []),
            "unaddressed": unaddressed_final,
        },
    })

    messages.append({
        "role": "assistant",
        "content": (
            f"Interpret rounds ({rounds_run}/{rounds_total}, stop: {stop_reason}). "
            f"Hypotheses: {len(hypotheses)}. Verification notes:\n{notes_block}\n\n"
            f"Evidence gathered:\n{evidence_block}"
        ),
    })
    messages.append({"role": "assistant", "content": raw_findings})
    if extra_text:
        messages.append({"role": "assistant", "content": extra_text})

    return {
        "messages": messages,
        "rounds_requested": rounds_total,
        "rounds_run": rounds_run,
        "stop_reason": stop_reason,
        "hypotheses": hypotheses,
        "notes": notes_all,
        "findings_emitted": len(candidates),
        "unaddressed": unaddressed_final,
    }
