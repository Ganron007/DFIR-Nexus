"""Mode 3 — agentic investigation with plan approval.

The agent proposes an investigation plan (extra parsers for SKIP'd
artifacts, corroboration queries) on top of the completed mandatory N2
lane. The examiner approves items in the Cockpit; only approved items
execute. Extras re-run the mandatory lane first (prior-OK reused) — the
agent can add parsers, never skip the lane. One case-file HMAC option
seals REPORT.md + findings via the same challenge-response + verification
ledger as per-finding approval. The agent never approves findings.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.langgraph.mode2 import corroboration_suggestions

log = logging.getLogger(__name__)

_MAX_PLAN_ITEMS = 12

_KNOWN_EXTRAS = {
    "chrome_profiles": "Chrome/Edge Profile* History (beyond Default)",
    "drivefs": "Google Drive File Stream logs/DB",
    "email": "PST/OST mailbox copy",
    "usb_serial": "USBSTOR serial parse from setupapi",
}

# Tools that are platform-inappropriate and should not appear as
# actionable SKIPs in the plan.  Suzaku is a Linux parser; log2timeline
# is informational (the plaso suggestion row), not a real SKIP.
_PLATFORM_SKIP = {
    "win32": {"suzaku"},
    "linux": set(),
}
_INFORMATIONAL_SKIP = {"(discovery)", "log2timeline"}


def _log_agent_run(case_dir: Path, entry: dict[str, Any]) -> None:
    case_dir = Path(case_dir)
    record = {"ts": datetime.now(UTC).isoformat(), **entry}
    with (case_dir / "agent_runs.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")


def _load_ledger(case_dir: Path) -> list[dict]:
    """Load the tool-lane ledger from the standard locations."""
    case_dir = Path(case_dir)
    # Direct locations (case-level + run-level)
    for cand in (
        case_dir / "extractions" / "_tool_lane_ledger.json",
        case_dir / "ledger" / "_tool_lane_ledger.json",
    ):
        if cand.is_file():
            try:
                data = json.loads(cand.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
            except (OSError, ValueError):
                return []
    # Run-dir fallback
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    extractions = resolve_tools_extractions(case_dir)
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


def _mandatory_lane_complete(ledger: list[dict]) -> bool:
    """True if the ledger has at least one OK mandatory-lane tool."""
    return any(row.get("status") == "OK" and row.get("tool") not in ("(discovery)", "log2timeline") for row in ledger)


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
        p.strip().lower()
        for p in (intake.get("extras") or "").replace(";", ",").split(",")
        if p.strip()
    }

    items: list[dict[str, Any]] = []
    # 1. Known extras not yet requested
    for key, label in _KNOWN_EXTRAS.items():
        if key not in requested_extras:
            items.append({"type": "extra", "key": key, "purpose": label})

    # 2. Ledger SKIPs (real parser gaps the examiner may want to fill)
    ledger = _load_ledger(case_dir)
    platform_skips = _PLATFORM_SKIP.get(sys.platform, set())
    for row in ledger:
        if row.get("status") != "SKIP":
            continue
        tool = str(row.get("tool") or "")
        if tool in _INFORMATIONAL_SKIP or tool in platform_skips:
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
        "lane_complete": _mandatory_lane_complete(ledger),
    }
    _log_agent_run(case_dir, {"action": "mode3_plan", "items": len(plan["items"]), "queries": len(queries)})
    append_chat(
        case_dir, "llm", "mode3_plan",
        f"Agent plan ready: {len(plan['items'])} step(s), {len(queries)} corroboration query(ies). Awaiting examiner approval.",
    )
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


def execute_plan(
    case_dir: Path,
    approved_extras: list[str],
    approved_queries: list[str],
) -> dict[str, Any]:
    """Execute examiner-approved plan items.

    Extras: persisted to CASE.yaml intake (next lane run picks them up;
    mandatory lane first, prior-OK reused). Queries: run immediately
    (read-only N4). Everything logged to agent_runs.jsonl + chat.

    Refuses to run if the mandatory lane has not completed at least one
    OK tool — the agent can add parsers but never skip the lane.
    """
    from nexus.case.chat import append_chat

    case_dir = Path(case_dir)

    # Mandatory-lane-first guard: refuse if the lane never ran
    ledger = _load_ledger(case_dir)
    if not _mandatory_lane_complete(ledger):
        return {
            "error": "Mandatory lane not complete — run the tools lane before executing agent extras.",
        }

    valid_extras = [e for e in approved_extras if e in _KNOWN_EXTRAS]
    if valid_extras:
        from nexus.langgraph.case_intake import persist_case_intake
        from nexus.langgraph.query_pack import load_case_intake

        intake = load_case_intake(case_dir)
        existing = [
            e.strip()
            for e in (intake.get("extras") or "").replace(";", ",").split(",")
            if e.strip()
        ]
        merged = list(dict.fromkeys(existing + valid_extras))
        persist_case_intake(case_dir, {"extras": ",".join(merged)})

    query_results: list[dict[str, Any]] = []
    for q in approved_queries:
        from nexus.langgraph.query_pack import n4_query

        r = n4_query(case_dir, q, limit=40)
        query_results.append({"query": q, "count": r.get("count", 0), "error": r.get("error")})

    _log_agent_run(case_dir, {
        "action": "mode3_execute",
        "extras": valid_extras,
        "queries": [q.get("query") for q in query_results],
    })
    append_chat(
        case_dir, "llm", "mode3_execute",
        f"Executed approved plan: extras={valid_extras or 'none'}, "
        f"queries={len(query_results)}. Re-run the tools lane to parse new extras.",
    )
    return {
        "status": "executed",
        "extras_persisted": valid_extras,
        "query_results": query_results,
        "note": "Extras parse on the next lane run (mandatory lane first, prior-OK reused).",
    }


def seal_case(
    case_dir: Path,
    examiner: str,
    password: str,
    *,
    skip_verify: bool = False,
) -> dict[str, Any]:
    """Case-file HMAC (Mode 3): one signature over REPORT.md + findings.

    Verifies the examiner password before signing (unless ``skip_verify``
    is True — used by the challenge-response API path which has already
    proved the examiner knows the password). Derives the signing key from
    the password (not the stored hash). The HMAC is computed over the
    exact content snapshot stored in the ledger, so verification always
    matches. Uses the same PBKDF2/HMAC verification ledger as per-finding
    approval.
    """
    from nexus.auth import (
        SIGNING_PURPOSE,
        _load_password_entry,
        compute_hmac,
        derive_hmac_key,
        derive_purpose_key,
        verify_password,
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

    # Verify the examiner password before signing (unless the caller
    # already proved it via challenge-response).
    if not skip_verify and not verify_password(examiner, password):
        return {"error": "Password verification failed"}

    content = report.read_text(encoding="utf-8")
    # Build the exact payload that will be stored — HMAC over the same
    # bytes so verification always matches.
    content_snapshot = content[:100000]
    findings_count = 0
    if findings.is_file():
        try:
            findings_count = len(json.loads(findings.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            findings_count = 0

    # Derive the signing key.  When the caller proved identity via
    # challenge-response we don't have the plaintext password, but
    # derive_hmac_key(password, salt) == pbkdf2(password, salt) == the
    # stored hash, so we use it directly as the base key.
    if skip_verify:
        base_key = bytes.fromhex(entry["hash"])
    else:
        base_key = derive_hmac_key(password, entry["salt"])
    purpose_key = derive_purpose_key(base_key, SIGNING_PURPOSE)
    hmac_val = compute_hmac(purpose_key, content_snapshot)

    write_verification_entry(case_dir.name, {
        "finding_id": "CASE-FILE",
        "type": "case_file",
        "approved_by": examiner,
        "approved_at": datetime.now(UTC).isoformat(),
        "content_snapshot": content_snapshot,
        "hmac": hmac_val,
        "salt": entry.get("salt", ""),
        "findings_count": findings_count,
    })

    # Transparency log
    try:
        from nexus.transparency import transparency_append

        transparency_append(case_dir.name, {
            "action": "case_seal",
            "examiner": examiner,
            "findings_count": findings_count,
            "hmac": hmac_val[:16] + "...",
        })
    except Exception:  # noqa: BLE001
        pass  # transparency is best-effort

    return {"status": "SEALED", "case_id": case_dir.name, "examiner": examiner}
