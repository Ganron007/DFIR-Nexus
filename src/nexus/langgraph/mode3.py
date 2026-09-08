"""Mode 3 — agentic investigation with plan approval.

The agent proposes an investigation plan (extra parsers for SKIP'd
artifacts, corroboration queries) on top of the completed mandatory N2
lane. The examiner approves items in the Cockpit; only approved items
execute. Extras re-run the mandatory lane first (prior-OK reused) — the
agent can add parsers, never skip the lane. One case-file HMAC option
seals REPORT.md + findings via the same verification ledger as
per-finding approval. The agent never approves findings.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.langgraph.mode2 import corroboration_suggestions

log = logging.getLogger(__name__)

_MAX_PLAN_ITEMS = 12

log = logging.getLogger(__name__)

_KNOWN_EXTRAS = {
    "chrome_profiles": "Chrome/Edge Profile* History (beyond Default)",
    "drivefs": "Google Drive File Stream logs/DB",
    "email": "PST/OST mailbox copy",
    "usb_serial": "USBSTOR serial parse from setupapi",
}

_CORROBORATION_MAP = {
    "prefetch": ["amcache", "shimcache"],
    "amcache": ["prefetch", "shimcache"],
    "evtx": ["hayabusa", "sysmon"],
    "hayabusa": ["evtxecmd", "sysmon"],
    "usnjrnl": ["mft"],
    "lnk": ["jump_lists", "shellbags"],
    "srum": ["netstat"],
}


def _log_agent_run(case_dir: Path, entry: dict[str, Any]) -> None:
    case_dir = Path(case_dir)
    record = {"ts": datetime.now(UTC).isoformat(), **entry}
    with (case_dir / "agent_runs.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")


def _load_ledger(case_dir: Path) -> list[dict]:
    for cand in (
        Path(case_dir) / "extractions" / "_tool_lane_ledger.json",
        Path(case_dir) / "extractions" / ".parent" / "ledger" / "_tool_lane_ledger.json",
    ):
        if cand.is_file():
            try:
                data = json.loads(cand.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
            except (OSError, ValueError):
                return []
    # run-dir ledger fallback
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    extractions = resolve_tools_extractions(Path(case_dir))
    for cand in (
        extractions / "_tool_lane_ledger.json",
        extractions.parent / "ledger" / "_tool_lane_ledger.json",
    ):
        if cand.is_file():
            try:
                data = json.loads(cand.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
            except (OSError, ValueError):
                return []
    return []


def plan_extras(case_dir: Path, model: Any = None) -> dict[str, Any]:
    """Agent proposes the investigation plan (extras + corroboration queries).

    Sources: tool-lane ledger SKIPs, extras not yet requested, and FD-006
    corroboration needs from existing findings. LLM refines the rationale
    when configured. Logged to agent_runs.jsonl + chat.
    """
    from nexus.case.chat import append_chat
    from nexus.langgraph.query_pack import load_case_intake

    case_dir = Path(case_dir)
    intake = load_case_intake(case_dir)
    requested_extras = {
        p.strip().lower() for p in (intake.get("extras") or "").replace(";", ",").split(",") if p.strip()
    }

    items: list[dict[str, Any]] = []
    # 1. Known extras not yet requested
    for key, label in _KNOWN_EXTRAS.items():
        if key not in requested_extras:
            items.append({"type": "extra", "key": key, "purpose": label})

    # 2. Ledger SKIPs (real parser gaps the examiner may want to fill)
    ledger = _load_ledger(case_dir)
    for row in ledger:
        if row.get("status") == "SKIP":
            tool = str(row.get("tool") or "")
            if tool in ("(discovery)", "log2timeline", "suzaku"):
                continue
            items.append({
                "type": "tool_skip",
                "tool": tool,
                "reason": str(row.get("reason") or "")[:160],
            })

    # 3. Corroboration queries from findings (FD-006)
    queries: list[str] = []
    findings_path = case_dir / "findings.json"
    if findings_path.is_file():
        try:
            for f in json.loads(findings_path.read_text(encoding="utf-8")):
                for q in corroboration_suggestions(f):
                    if q not in queries:
                        queries.append(q)
        except (OSError, ValueError):
            pass

    rationale = (
        f"Agent plan: {len(items)} extra step(s) + {len(queries)} corroboration "
        "queries, derived from ledger SKIPs and single-source findings."
    )
    if model is not None:
        try:
            refined = _refine_rationale(model, items, queries)
            rationale = refined or rationale
        except Exception as exc:  # noqa: BLE001
            log.warning("Mode 3 plan LLM refinement failed: %s", exc)

    plan = {
        "case_id": case_dir.name,
        "items": items[:_MAX_PLAN_ITEMS],
        "queries": queries[:8],
        "rationale": rationale,
        "created_at": datetime.now(UTC).isoformat(),
    }
    _log_agent_run(case_dir, {"action": "plan", "items": len(plan["items"]), "queries": len(queries)})

    append_chat(case_dir, "llm", "mode3_plan", f"Agent plan ready: {len(plan['items'])} step(s), {len(queries)} corroboration query(ies). Awaiting examiner approval.")
    return plan


def _refine_rationale(model: Any, items: list[dict], queries: list[str]) -> str:
    prompt = (
        "You are a DFIR agent planner. Proposed steps:\n"
        + json.dumps(items, indent=1)[:1200]
        + "\nCorroboration queries: " + ", ".join(queries[:6])
        + '\nReturn ONLY JSON: {"rationale": "one sentence"}.'
    )
    response = model.invoke([{"role": "user", "content": prompt}])
    text = getattr(response, "content", str(response))
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        return ""
    try:
        return str(json.loads(text[start:end + 1]).get("rationale") or "")[:300]
    except (ValueError, KeyError):
        return ""


_PROPOSE_SYSTEM = (
    "You are a DFIR agent planner. Given proposed investigation steps, "
    "explain in one sentence why they fit the investigation. Be conservative."
)


def execute_plan(
    case_dir: Path,
    approved_extras: list[str],
    approved_queries: list[str],
) -> dict[str, Any]:
    """Execute examiner-approved plan items.

    Extras: persisted to CASE.yaml intake (next lane run picks them up;
    mandatory lane first, prior-OK reused). Queries: run immediately
    (read-only N4). Everything logged to agent_runs.jsonl + chat.
    """
    from nexus.case.chat import append_chat

    case_dir = Path(case_dir)
    valid_extras = [e for e in approved_extras if e in _KNOWN_EXTRAS]
    if valid_extras:
        from nexus.langgraph.case_intake import persist_case_intake
        from nexus.langgraph.query_pack import load_case_intake

        intake = load_case_intake(case_dir)
        existing = [e.strip() for e in (intake.get("extras") or "").split(",") if e.strip()]
        merged = list(dict.fromkeys(existing + valid_extras))
        persist_case_intake(case_dir, {"extras": ",".join(merged)})

    query_results = []
    for q in approved_queries:
        from nexus.langgraph.query_pack import n4_query

        r = n4_query(case_dir, q, limit=40)
        query_results.append({"query": q, "count": r.get("count", 0), "error": r.get("error")})

    _log_agent_run(case_dir, {
        "action": "execute_plan",
        "extras": valid_extras,
        "queries": [q.get("query") for q in query_results],
    })
    append_chat(case_dir, "llm", "mode3_executed", (
        f"Executed approved plan: extras={valid_extras or 'none'}, "
        f"queries={len(query_results)}. Re-run the tools lane to parse new extras."
    ))
    return {
        "status": "executed",
        "extras_persisted": valid_extras,
        "query_results": query_results,
        "note": "Extras parse on the next lane run (mandatory lane first, prior-OK reused).",
    }


def seal_case(case_dir: Path, examiner: str, password: str) -> dict[str, Any]:
    """Case-file HMAC (Mode 3): one signature over REPORT.md + findings.

    Uses the same PBKDF2/HMAC verification ledger as per-finding approval.
    """
    from nexus.auth import (
        SIGNING_PURPOSE,
        _load_password_entry,
        compute_hmac,
        derive_purpose_key,
        write_verification_entry,
    )

    case_dir = Path(case_dir)
    report = case_dir / "reports" / "REPORT.md"
    findings = case_dir / "findings.json"
    if not report.is_file():
        return {"error": "No REPORT.md — generate the report first (N8)"}

    entry = _load_password_entry(examiner)
    if not entry:
        return {"error": f"No password configured for {examiner}"}
    content = report.read_text(encoding="utf-8")
    key = derive_purpose_key(bytes.fromhex(entry["hash"]), SIGNING_PURPOSE)
    hmac_val = compute_hmac(key, content)
    findings_count = 0
    if findings.is_file():
        try:
            findings_count = len(json.loads(findings.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            findings_count = 0
    write_verification_entry(case_dir.name, {
        "finding_id": "CASE-FILE",
        "type": "case_file",
        "approved_by": examiner,
        "approved_at": datetime.now(UTC).isoformat(),
        "content_snapshot": content[:100000],
        "hmac": hmac_val,
        "salt": entry.get("salt", ""),
        "findings_count": findings_count,
    })
    return {"status": "SEALED", "case_id": case_dir.name, "examiner": examiner}
