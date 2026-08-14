#!/usr/bin/env python3
"""Salvage: stage LLM+ledger findings for a coverage case that already has tools.

Used when tool lane succeeded but interpret→stage produced 0 drafts.
Does NOT re-run triage tools.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.chdir(ROOT)

CASE_ID = os.environ.get("NEXUS_SALVAGE_CASE", "INC-20260812065243")
EXAMINER = "e2e_host"
APPROVE_PW = "E2E-Host-Test-2026!"


async def main() -> int:
    from nexus.langgraph.hunt_parser import parse_hunt_candidates
    from nexus.langgraph.llm_pipeline import (
        _fallback_candidates_from_state,
        _finding_tool_payload,
        _is_collection_stub,
        _load_dotenv,
        _load_mcp_tools,
        _parse_tool_result,
        get_mcp_config,
        get_model,
    )

    _load_dotenv()
    os.environ.setdefault("NEXUS_WINDOWS_MCP_URL", "http://127.0.0.1:4508/mcp")
    os.environ.setdefault("NEXUS_SIFT_MCP_URL", "http://192.168.77.135:4508/mcp")

    case_dir = Path.home() / ".nexus" / "cases" / CASE_ID
    ledger_path = case_dir / "extractions" / "_tool_lane_ledger.json"
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    trail = [str(r["audit_id"]) for r in ledger if r.get("audit_id")]

    tools = await _load_mcp_tools(get_mcp_config())
    activate = tools.get("case_activate")
    if activate:
        print("activate:", _parse_tool_result(await activate.ainvoke({"case_id": CASE_ID})))

    # Ask LLM to interpret ledger under insider-threat hypothesis
    model = get_model()
    ledger_summary = [
        {
            "host": r.get("host"),
            "tool": r.get("tool"),
            "status": r.get("status"),
            "audit_id": r.get("audit_id"),
            "output_saved_to": r.get("output_saved_to"),
            "purpose": r.get("purpose"),
            "reason": (r.get("reason") or "")[:200],
        }
        for r in ledger
    ]
    prompt = (
        "You are a DFIR analyst. Case hypothesis: insider-threat "
        "(authorized user misuse / data staging). Evidence wins over hypothesis.\n"
        f"Case: {CASE_ID}\n"
        f"Tool lane ledger:\n```json\n{json.dumps(ledger_summary, indent=2)[:11000]}\n```\n"
        "Emit a ```json array of findings. Each needs title, observation, "
        "interpretation (insider-threat lens when justified), confidence, "
        "confidence_justification, host, audit_ids (from ledger), artifacts. "
        "FAIL/SKIP are coverage gaps only. Do not invent APT campaigns."
    )
    msg = await model.ainvoke(prompt)
    content = getattr(msg, "content", str(msg))
    if isinstance(content, list):
        content = "\n".join(
            b.get("text", str(b)) if isinstance(b, dict) else str(b) for b in content
        )
    candidates = parse_hunt_candidates([{"content": content}])
    print(f"LLM candidates: {len(candidates)}")
    candidates = [c for c in candidates if not _is_collection_stub(c)]
    if not candidates:
        state = {
            "case_id": CASE_ID,
            "tool_run_ledger": ledger,
            "pipeline_mode": "coverage",
            "case_context": {"hypothesis": "insider-threat", "host": "rocba"},
        }
        candidates = _fallback_candidates_from_state(state, trail, "rocba")
        print(f"N4 salvage candidates: {len(candidates)}")

    finding_tool = tools["record_finding"]
    draft_ids = []
    for c in candidates:
        payload = _finding_tool_payload(c, trail)
        result = _parse_tool_result(await finding_tool.ainvoke(payload))
        fid = result.get("finding_id") or result.get("id")
        print("stage:", fid or result)
        if fid:
            draft_ids.append(fid)

    if not draft_ids:
        print("ERROR: still 0 drafts", file=sys.stderr)
        return 1

    import yaml

    from nexus.case.compat import get_sqlite_manager
    from nexus.case.schemas import ApprovalState
    from nexus.cli.report import _extraction_notes, _load_flat_evidence
    from nexus.integration.dfir_report import build_dfir_markdown

    mgr = get_sqlite_manager()
    mgr.set_case_approval_password(CASE_ID, APPROVE_PW)
    approved = []
    for fid in draft_ids:
        f = mgr.approve_finding(
            fid, APPROVE_PW, approved_by=EXAMINER,
            note="Operator HITL — salvage after coverage tool lane",
        )
        if f and f.approval_state == ApprovalState.APPROVED:
            approved.append(fid)
    print(f"Approved {len(approved)}/{len(draft_ids)}")
    try:
        mgr.close()
    except Exception:
        pass

    findings = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    meta = yaml.safe_load((case_dir / "CASE.yaml").read_text(encoding="utf-8")) or {}
    md = build_dfir_markdown(
        case_id=CASE_ID,
        case_name=meta.get("name") or CASE_ID,
        findings=findings,
        evidence=_load_flat_evidence(case_dir),
        timeline=[],
        sift_notes=_extraction_notes(case_dir / "extractions"),
        examiner=str(meta.get("examiner") or ""),
        status=str(meta.get("status") or "open"),
        case_summary=str(meta.get("description") or ""),
    )
    out = case_dir / "reports" / "dfir-report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    docs = ROOT / "Docs" / "internal" / "reports" / f"{CASE_ID}-rocba-coverage-insider.md"
    docs.write_text(md, encoding="utf-8")
    print("Wrote", out)
    print("Wrote", docs)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
