#!/usr/bin/env python3
"""Run the product LangGraph pipeline against Rocba evidence (optional demo).

Modes (same as ``nexus pipeline --mode``):
  tools      — mandatory parser lane; no RAG, no LLM; TOOL-RUN.md
  coverage   — same lane + RAG interpret (alias: debug)
  design     — RAG, mandatory lane, ReAct extras, interpret → REPORT.md
  interpret  — reuse an existing tool-run case (``--from-case``)

Usage:
  python scripts/rocba_agentic_pipeline.py --mode tools
  python scripts/rocba_agentic_pipeline.py --from-case INC-20260812165727
  python scripts/rocba_agentic_pipeline.py --mode coverage
  python scripts/rocba_agentic_pipeline.py --mode design
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.chdir(ROOT)

def _pick_kape_root() -> Path:
    """Prefer the live Windows-root mount (Samba R: full NTFS, else KAPE H:\\C)."""
    candidates = (Path(r"R:\windows_mount"), Path("H:/C"))
    for cand in candidates:
        if (cand / "Windows").is_dir() or (cand / "Users").is_dir():
            return cand
    return ROOT / "Evidence-files" / "showcase" / "rocba-500"


DEFAULT_EVIDENCE = _pick_kape_root()

EXAMINER = "e2e_host"
APPROVE_PW = "E2E-Host-Test-2026!"

CASE_CONTEXT = {
    "name": "Rocba-500 — Insider misuse or external compromise",
    "description": (
        "FOR508 Rocba host triage pack. Dual examiner hypothesis: (1) insider "
        "misuse — authorized user abusing access / data staging; (2) external "
        "compromise — intrusion, malware, persistence, or C2. Evidence from "
        "tools chooses which lens fits. Do not invent an APT name."
    ),
    "hypothesis": "insider-threat or external compromise",
    "question": (
        "What host activity supports or refutes insider misuse / data staging, "
        "and what supports or refutes external compromise?"
    ),
    "timezone": "UTC",
    "window": "examiner-supplied; evidence timestamps win",
    "subjects": "rocba host user profiles",
    "playbooks": "usb_activity,data_staging,external_compromise",
    "notes": (
        "Interpret Windows host artifacts + SIFT memory under BOTH lenses. "
        "ITM (https://insiderthreatmatrix.org/) when facts support authorized-"
        "user abuse. MITRE ATT&CK when facts support intrusion. Benign "
        "authorized activity is a valid outcome. Do not invent APT campaigns. "
        "Use MFTECmd bodyfile + TSK mactime for the filesystem timeline (do not "
        "run full-tree plaso — SIFT disk cannot hold a 4G store). Cloud audit "
        "CSVs live on SIFT at /home/sansforensics/Evidence-files/rocba-500/*.csv."
    ),
    "host": "rocba",
    "sift_evidence_root": "/home/sansforensics/Evidence-files/rocba-500",
    "sift_triage_root": "/mnt/windows_mount1/C",
}


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", default=str(DEFAULT_EVIDENCE))
    ap.add_argument("--thread", default="pipeline-rocba")
    ap.add_argument(
        "--mode",
        default=os.environ.get("NEXUS_PIPELINE_MODE", "tools"),
        help="tools | coverage | design | interpret. Default: tools",
    )
    ap.add_argument(
        "--from-case",
        default="",
        help="Reuse an existing tool-run case_id (sets mode=interpret)",
    )
    ap.add_argument(
        "--insider-threat",
        action="store_true",
        default=True,
        help="Pass dual insider+external case_context (default: on)",
    )
    ap.add_argument(
        "--no-insider-threat",
        action="store_true",
        help="Omit examiner case_context (generic host-triage only)",
    )
    ap.add_argument(
        "--auto-approve",
        action="store_true",
        default=True,
        help="Operator HITL: approve DRAFTs after staging (coverage/design)",
    )
    ap.add_argument(
        "--no-auto-approve",
        action="store_true",
        help="Stop at HITL interrupt (manual nexus approve)",
    )
    ap.add_argument(
        "--with-e01",
        action="store_true",
        help="Opt-in: schedule SIFT fls against NEXUS_SIFT_E01 (not default)",
    )
    args = ap.parse_args()

    os.environ.setdefault("NEXUS_WINDOWS_MCP_URL", "http://127.0.0.1:4508/mcp")
    os.environ.setdefault("NEXUS_SIFT_MCP_URL", "http://192.168.77.135:4508/mcp")
    os.environ.setdefault(
        "NEXUS_SIFT_EVIDENCE_ROOT",
        "/home/sansforensics/Evidence-files/rocba-500",
    )
    os.environ.setdefault(
        "NEXUS_SIFT_MEMORY_FILE",
        "/home/sansforensics/Evidence-files/rocba-500/memory/Rocba-Memory.raw",
    )
    os.environ.setdefault("NEXUS_SIFT_TRIAGE_ROOT", "/mnt/windows_mount1/C")
    os.environ["NEXUS_SHARE_ROOT"] = str(Path(args.evidence))
    os.environ.setdefault("NEXUS_RAG_MODEL", "BAAI/bge-base-en-v1.5")
    os.environ.setdefault("NEXUS_MCP_SSE_READ_TIMEOUT", "7200")
    os.environ.setdefault("NEXUS_MCP_HTTP_TIMEOUT", "120")
    os.environ.pop("NEXUS_SIFT_SKIP_PLASO", None)
    if args.with_e01:
        os.environ.setdefault(
            "NEXUS_SIFT_E01",
            "/home/sansforensics/Evidence-files/rocba-500/C-Drive/rocba-cdrive.e01",
        )
    else:
        # Do not inherit a stale E01 from the parent shell for KAPE pack tests
        os.environ.pop("NEXUS_SIFT_E01", None)
    os.environ.setdefault("NEXUS_SIFT_SSH_HOST", "192.168.77.135")
    os.environ.setdefault(
        "NEXUS_SIFT_SSH_KEY",
        str(Path.home() / ".ssh" / "cadre-sift-key"),
    )
    os.environ.setdefault(
        "NEXUS_REPO_CASE_ROOT",
        str(ROOT / "Docs" / "cases"),
    )

    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.types import Command
    from nexus.langgraph.llm_pipeline import (
        _load_dotenv,
        _load_mcp_tools,
        build_graph,
        get_mcp_config,
        get_model,
        make_initial_state,
        resolve_pipeline_mode,
        validate_tools,
    )

    _load_dotenv()
    if args.from_case.strip():
        args.mode = "interpret"
    mode = resolve_pipeline_mode(args.mode)
    if mode == "tools":
        os.environ["NEXUS_TOOL_LANE_STRICT"] = "1"
    else:
        os.environ.pop("NEXUS_TOOL_LANE_STRICT", None)
    use_context = args.insider_threat and not args.no_insider_threat
    case_context = dict(CASE_CONTEXT) if use_context else {}
    auto_approve = (
        mode != "tools"
        and args.auto_approve
        and not args.no_auto_approve
    )

    print("Mode:", mode, flush=True)
    print("Case context (insider+external):", use_context, flush=True)
    print("Auto-approve (operator HITL):", auto_approve, flush=True)
    print("E01/fls:", bool(os.environ.get("NEXUS_SIFT_E01")), flush=True)
    print("MCP config:", get_mcp_config(), flush=True)
    print("Evidence:", args.evidence, flush=True)
    print("SIFT root:", os.environ.get("NEXUS_SIFT_EVIDENCE_ROOT"), flush=True)
    print("SIFT memory:", os.environ.get("NEXUS_SIFT_MEMORY_FILE"), flush=True)
    print("SIFT triage:", os.environ.get("NEXUS_SIFT_TRIAGE_ROOT"), flush=True)
    print("Windows share:", os.environ.get("NEXUS_SHARE_ROOT"), flush=True)
    print("Skip plaso:", os.environ.get("NEXUS_SIFT_SKIP_PLASO") or "0", flush=True)
    print("From case:", args.from_case or "(new)", flush=True)
    print("RAG model:", os.environ.get("NEXUS_RAG_MODEL"), flush=True)

    tools_by_name = await _load_mcp_tools(get_mcp_config())
    print(
        f"MCP tools: {len(tools_by_name)} "
        f"win={('run_windows_command' in tools_by_name)} "
        f"sift={('run_command' in tools_by_name)} "
        f"mirror={('_sift_case_init' in tools_by_name)}",
        flush=True,
    )
    validate_tools(tools_by_name)
    model = None if mode == "tools" else get_model()
    interrupt_before = [] if mode == "tools" else ["await_approval"]
    compiled = build_graph(tools_by_name, model, mode=mode).compile(
        checkpointer=MemorySaver(),
        interrupt_before=interrupt_before,
    )
    cfg = {"configurable": {"thread_id": f"{args.thread}-{mode}"}}
    result = await compiled.ainvoke(
        make_initial_state(
            evidence_path=args.evidence,
            case_context=case_context,
            pipeline_mode=mode,
            case_id=args.from_case.strip(),
        ),
        config=cfg,
    )
    if isinstance(result, dict):
        print("case_id:", result.get("case_id"), flush=True)
        print("drafts:", result.get("draft_finding_ids"), flush=True)
        ledger = result.get("tool_run_ledger") or []
        if ledger:
            ok = sum(1 for r in ledger if r.get("status") == "OK")
            fail = sum(1 for r in ledger if r.get("status") == "FAIL")
            skip = sum(1 for r in ledger if r.get("status") == "SKIP")
            print(f"tool_lane OK={ok} FAIL={fail} SKIP={skip}", flush=True)
            for row in ledger:
                print(
                    f"  [{row.get('status')}] {row.get('host')}/{row.get('tool')}: "
                    f"{(row.get('reason') or '')[:80]} "
                    f"audit={row.get('audit_id') or '-'} "
                    f"saved={row.get('output_saved_to') or '-'}",
                    flush=True,
                )
        print("steps:", result.get("step_log"), flush=True)
        print("error:", result.get("error"), flush=True)
        print("report_path:", result.get("report_path"), flush=True)
        print(
            "examiner_copy: Docs/cases/<case_id>/reports/  "
            "(not ~/.nexus/cases — that is runtime only)",
            flush=True,
        )

    if auto_approve and isinstance(result, dict) and result.get("case_id"):
        from nexus.case.compat import get_sqlite_manager
        from nexus.case.schemas import ApprovalState

        case_id = result["case_id"]
        mgr = get_sqlite_manager()
        mgr.set_case_approval_password(case_id, APPROVE_PW)
        drafts = result.get("draft_finding_ids") or [
            f.id for f in mgr.list_findings(case_id)
            if f.approval_state == ApprovalState.DRAFT
        ]
        approved = []
        for fid in drafts:
            f = mgr.approve_finding(
                fid, APPROVE_PW, approved_by=EXAMINER,
                note="Operator HITL approve — Rocba pack",
            )
            if f and f.approval_state == ApprovalState.APPROVED:
                approved.append(fid)
        print(f"Approved {len(approved)} / {len(drafts)} drafts", flush=True)
        try:
            mgr.close()
        except Exception:
            pass
        result2 = await compiled.ainvoke(
            Command(resume={"approved_ids": approved, "rejected_ids": []}),
            config=cfg,
        )
        if isinstance(result2, dict):
            print("report_path:", result2.get("report_path"), flush=True)
            print("final_steps:", result2.get("step_log"), flush=True)
        print("Report step done", flush=True)
    elif isinstance(result, dict) and result.get("case_id"):
        print(
            f"HITL pause: review drafts then: nexus approve --case {result['case_id']}",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
