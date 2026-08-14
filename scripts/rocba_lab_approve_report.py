#!/usr/bin/env python3
"""Lab-only: approve current DRAFTs and write this-run REPORT + D1.

Operator-authorized for Rocba test runs. Not 12-pass HITL. Not C7/C9.
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

CASE_ID = os.environ.get("NEXUS_SALVAGE_CASE", "INC-20260813122635")
EXAMINER = "e2e_host"
APPROVE_PW = "E2E-Host-Test-2026!"


async def main() -> int:
    from nexus.auth import clear_lockout
    from nexus.case.compat import get_sqlite_manager
    from nexus.case.schemas import ApprovalState
    from nexus.langgraph.llm_pipeline import generate_report

    clear_lockout(None)
    os.environ.setdefault(
        "NEXUS_REPO_CASE_ROOT",
        str(ROOT / "Docs" / "cases"),
    )

    mgr = get_sqlite_manager()
    mgr.set_case_approval_password(CASE_ID, APPROVE_PW)
    drafts = [
        f.id for f in mgr.list_findings(CASE_ID)
        if f.approval_state == ApprovalState.DRAFT
    ]
    print(f"DRAFTs: {drafts}", flush=True)
    approved: list[str] = []
    for fid in drafts:
        f = mgr.approve_finding(
            fid,
            APPROVE_PW,
            approved_by=EXAMINER,
            note="Lab auto-approve — Rocba test run (not 12-pass HITL)",
        )
        if f and f.approval_state == ApprovalState.APPROVED:
            approved.append(fid)
            print(f"  APPROVED {fid}", flush=True)
        else:
            print(f"  FAIL {fid}", flush=True)
    try:
        mgr.close()
    except Exception:
        pass
    if not approved:
        print("No DRAFTs approved", file=sys.stderr)
        return 1

    case_dir = Path.home() / ".nexus" / "cases" / CASE_ID
    ledger_path = case_dir / "extractions" / "_tool_lane_ledger.json"
    ledger = []
    if ledger_path.is_file():
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))

    result = await generate_report(
        {
            "case_id": CASE_ID,
            "approved_finding_ids": approved,
            "tool_run_ledger": ledger,
            "evidence_path": os.environ.get("NEXUS_SHARE_ROOT") or "",
            "rag_notes": [],
        },
        tools={},
    )
    print(json.dumps(result, indent=2, default=str), flush=True)
    return 0 if not result.get("error") else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
