"""LangGraph pipeline for DFIR-Nexus.

Drives a 6-node StateGraph investigation flow against the DFIR-Nexus
MCP server. Supports stdio (Lite) and HTTP (Full/gateway) modes.

Usage:
    export NEXUS_MODEL="claude-opus-4-7"
    python pipeline.py [--resume] [--case EVIDENCE_PATH]

    # Full mode (gateway):
    export NEXUS_GATEWAY_URL="http://sift-vm:4508/mcp"
    export NEXUS_BEARER_TOKEN="<bearer-token>"
    python pipeline.py [--resume]

    # Resume after human approval:
    python pipeline.py --resume
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, TypedDict, cast

from operator import add

logging.basicConfig(level=logging.INFO, format="%(levelname)-5s %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# State schema
# ---------------------------------------------------------------------------

class InvestigationState(TypedDict):
    case_id: str
    evidence_path: str
    evidence_audit_ids: Annotated[list[str], add]
    hosts: list[str]
    draft_finding_ids: Annotated[list[str], add]
    draft_timeline_ids: Annotated[list[str], add]
    approved_finding_ids: list[str]
    rejected_finding_ids: list[str]
    report_path: str | None
    step_log: Annotated[list[str], add]
    error: str | None


def make_initial_state(evidence_path: str = "") -> InvestigationState:
    return {
        "case_id": "",
        "evidence_path": evidence_path,
        "evidence_audit_ids": [],
        "hosts": [],
        "draft_finding_ids": [],
        "draft_timeline_ids": [],
        "approved_finding_ids": [],
        "rejected_finding_ids": [],
        "report_path": None,
        "step_log": [],
        "error": None,
    }


# ---------------------------------------------------------------------------
# Model selection
# ---------------------------------------------------------------------------

def get_model():
    provider = (os.environ.get("NEXUS_MODEL") or "").lower()

    if "openai" in provider:
        from langchain_openai import ChatOpenAI
        model_name = provider.replace("openai/", "")
        return ChatOpenAI(model=model_name or "gpt-4o")

    if "ollama" in provider:
        from langchain_ollama import ChatOllama
        model_name = provider.replace("ollama/", "")
        return ChatOllama(model=model_name or "qwen2.5:32b-instruct")

    # Default: Anthropic Claude
    from langchain_anthropic import ChatAnthropic
    model_name = provider or "claude-sonnet-4-20250514"
    return ChatAnthropic(model=model_name)


# ---------------------------------------------------------------------------
# MCP client wiring
# ---------------------------------------------------------------------------

def get_mcp_client():
    """Create MultiServerMCPClient connected to DFIR-Nexus.

    Mode priority:
    1. NEXUS_GATEWAY_URL env var → HTTP (Full/gateway mode)
    2. NEXUS_STDIO_CMD env var  → stdio with custom command
    3. Default: stdio via `nexus serve`
    """
    from langchain_mcp_adapters.client import MultiServerMCPClient

    gateway_url = os.environ.get("NEXUS_GATEWAY_URL")
    bearer_token = os.environ.get("NEXUS_BEARER_TOKEN", "")

    if gateway_url:
        headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
        config = {
            "dfir-nexus": {
                "transport": "streamable_http",
                "url": gateway_url,
                "headers": headers,
            }
        }
        logger.info("Connecting to DFIR-Nexus via HTTP: %s", gateway_url)
    else:
        stdio_cmd = os.environ.get("NEXUS_STDIO_CMD", "nexus")
        config = {
            "dfir-nexus": {
                "transport": "stdio",
                "command": stdio_cmd,
                "args": ["serve"],
            }
        }
        logger.info("Connecting to DFIR-Nexus via stdio: %s serve", stdio_cmd)

    return MultiServerMCPClient(config)


# ---------------------------------------------------------------------------
# Tool name validation (fail fast at boot)
# ---------------------------------------------------------------------------

_REQUIRED_TOOLS = {
    "case_init", "evidence_register",
    "idx_case_summary", "idx_search", "idx_aggregate",
    "forensic_rag_search",
    "run_command",
    "record_finding", "record_timeline_event",
    "generate_report", "list_profiles",
}


def validate_tools(tools_by_name: dict[str, Any]) -> list[str]:
    missing = [name for name in _REQUIRED_TOOLS if name not in tools_by_name]
    if missing:
        logger.warning("Missing tools (graph will still run): %s", missing)
    return missing


# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------

async def register_evidence(state: InvestigationState, tools: dict) -> dict:
    """Create case and register evidence. Deterministic node."""

    case_tool = tools.get("case_init")
    if not case_tool:
        return {"error": "case_init tool not available"}

    # Step 1: Create case
    result = await case_tool.ainvoke({
        "name": f"LangGraph Investigation - {Path(state['evidence_path']).name}",
        "description": "Automated investigation via LangGraph pipeline",
    })
    if isinstance(result, dict) and result.get("error"):
        return {"error": f"case_init failed: {result['error']}"}

    case_id = result.get("case_id", "unknown")
    logger.info("Case created: %s", case_id)

    # Step 2: Register evidence
    ev_tool = tools.get("evidence_register")
    if ev_tool and state["evidence_path"]:
        ev_result = await ev_tool.ainvoke({
            "path": state["evidence_path"],
            "description": "Evidence for automated investigation",
        })
        audit_ids = []
        if isinstance(ev_result, dict):
            aid = ev_result.get("audit_id") or ev_result.get("sha256", "")
            if aid:
                audit_ids.append(aid)

        return {
            "case_id": case_id,
            "evidence_audit_ids": audit_ids,
            "step_log": [f"Case {case_id} created, evidence registered"],
        }

    return {
        "case_id": case_id,
        "step_log": [f"Case {case_id} created (no evidence path provided)"],
    }


async def scope(state: InvestigationState, tools: dict, model) -> dict:
    """Scope the investigation — survey what evidence is available.

    Uses idx_case_summary if OpenSearch is available, otherwise
    lists available tools and suggests relevant ones.
    """
    case_id = state["case_id"]
    if not case_id:
        return {"error": "No active case ID"}

    summary_tool = tools.get("idx_case_summary")
    suggest_tool = tools.get("suggest_tools")
    rag_tool = tools.get("forensic_rag_search")
    run_tool = tools.get("run_command")
    hosts = []

    if summary_tool:
        result = await summary_tool.ainvoke({"case_id": case_id})
        if isinstance(result, dict) and result.get("hosts"):
            hosts = result["hosts"]
            logger.info("OpenSearch summary: %d hosts, %d docs",
                        len(hosts), result.get("total_documents", 0))

    if not hosts and suggest_tool:
        # No OpenSearch — suggest tools based on evidence type
        suggestions = await suggest_tool.ainvoke({"artifact_type": "evtx"})
        if isinstance(suggestions, list):
            for s in suggestions[:5]:
                logger.info("Suggested tool: %s", s.get("name", ""))

    if rag_tool and case_id:
        try:
            await rag_tool.ainvoke({"query": f"investigation guidance for case {case_id}"})
        except Exception:
            pass

    if run_tool:
        try:
            ls_result = await run_tool.ainvoke({
                "command": f"ls {state['evidence_path']}" if state.get("evidence_path") else "echo no evidence path",
                "purpose": "Survey available evidence files",
            })
            if isinstance(ls_result, dict):
                logger.info("Evidence survey: exit_code=%s", ls_result.get("exit_code"))
        except Exception:
            pass

    return {
        "hosts": hosts,
        "step_log": [f"Scoped investigation: {len(hosts)} hosts identified"],
    }


async def hunt(state: InvestigationState, tools: dict, model) -> dict:
    """Analyze evidence — search, aggregate, build timeline.

    Uses an LLM-driven agent to pick analysis tools.
    Falls back to simple tool calls if the agent isn't available.
    """
    from langgraph.prebuilt import create_react_agent

    hunt_tools_list = []
    for name in ("idx_search", "idx_aggregate", "idx_timeline",
                  "forensic_rag_search", "run_command", "suggest_tools"):
        t = tools.get(name)
        if t:
            hunt_tools_list.append(t)

    if not hunt_tools_list:
        logger.warning("No hunt tools available")
        return {"step_log": ["Hunt skipped — no analysis tools"]}

    agent = create_react_agent(
        model,
        hunt_tools_list,
        prompt=(
            "You are a DFIR investigator. Your case is {case_id}. "
            "Use the available tools to find evidence of suspicious activity. "
            "Focus on: lateral movement, credential theft, persistence, "
            "or data exfiltration. Run 2-3 analysis queries, then stop."
        ).format(case_id=state["case_id"]),
    )

    try:
        result = await agent.ainvoke({
            "messages": [{"role": "human",
                          "content": f"Analyze evidence for case {state['case_id']}. "
                                     f"Hosts: {state.get('hosts', [])}"}]
        })
        msg_count = len(result.get("messages", []))
        logger.info("Hunt agent completed: %d messages", msg_count)
    except Exception as e:
        logger.error("Hunt agent failed: %s", e)
        return {"step_log": [f"Hunt agent error: {e}"]}

    return {"step_log": ["Hunt analysis completed"]}


async def stage_findings(state: InvestigationState, tools: dict) -> dict:
    """Stage findings and timeline events as DRAFT.

    Parses the hunt agent's output for structured findings, then loops
    record_finding over them. Falls back to a placeholder if no
    structured findings are found.
    """
    finding_tool = tools.get("record_finding")
    timeline_tool = tools.get("record_timeline_event")
    if not finding_tool:
        return {"error": "record_finding tool not available"}

    draft_ids = []
    timeline_ids = []
    errors = []

    # Extract candidates from hunt agent's last message
    candidates = _parse_hunt_candidates(state.get("messages", []))

    if candidates:
        for candidate in candidates:
            try:
                result = await finding_tool.ainvoke(candidate)
                if isinstance(result, dict) and result.get("finding_id"):
                    draft_ids.append(result["finding_id"])
                    logger.info("Finding staged: %s", result["finding_id"])
                elif isinstance(result, dict) and result.get("error"):
                    errors.append(result["error"])
            except Exception as e:
                errors.append(str(e))

        # Also stage timeline events if timeline_tool is available
        if timeline_tool:
            for c in candidates:
                ts = c.get("event_timestamp", "")
                if not ts:
                    continue
                try:
                    result = await timeline_tool.ainvoke({
                        "timestamp": ts,
                        "description": c.get("observation", c.get("title", ""))[:500],
                        "event_type": c.get("type", "execution"),
                        "host": c.get("host", ""),
                    })
                    if isinstance(result, dict) and result.get("event_id"):
                        timeline_ids.append(result["event_id"])
                except Exception as e:
                    errors.append(str(e))
    else:
        # Fallback: stage a placeholder finding
        host = state["hosts"][0] if state.get("hosts") else ""
        result = await finding_tool.ainvoke({
            "title": f"Automated analysis for {state['case_id']}",
            "observation": "LangGraph pipeline completed initial analysis",
            "interpretation": "Reviewer should examine findings in Examiner Portal",
            "confidence": "MEDIUM",
            "host": host,
            "event_timestamp": datetime.utcnow().isoformat(),
        })
        if isinstance(result, dict) and result.get("finding_id"):
            draft_ids.append(result["finding_id"])
            logger.info("Placeholder finding staged: %s", result["finding_id"])

    log = [f"Staged {len(draft_ids)} findings, {len(timeline_ids)} timeline events"]
    if errors:
        log.append(f"Errors: {'; '.join(errors[:3])}")
    return {
        "draft_finding_ids": draft_ids,
        "draft_timeline_ids": timeline_ids,
        "step_log": log,
    }


from hunt_parser import parse_hunt_candidates as _parse_hunt_candidates  # noqa: E402
from hunt_parser import normalize_candidate as _normalize_candidate  # noqa: E402


def await_approval(state: InvestigationState) -> dict:
    """HUMAN IN THE LOOP — pause graph until examiner approves.

    The human reviews findings in the Examiner Portal or via
    nexus approve/reject. Graph resumes with Command(resume=...).
    """
    from langgraph.types import interrupt

    decision = interrupt({
        "message": (
            "DRAFT findings are staged. Review in the Examiner Portal "
            "(nexus serve --http, then open http://localhost:4508/portal/) "
            "or via: nexus approve"
        ),
        "draft_finding_ids": state["draft_finding_ids"],
        "draft_timeline_ids": state["draft_timeline_ids"],
    })

    approved = decision.get("approved_ids", []) if isinstance(decision, dict) else []
    rejected = decision.get("rejected_ids", []) if isinstance(decision, dict) else []

    logger.info("Human approved: %s", approved)
    logger.info("Human rejected: %s", rejected)

    return {
        "approved_finding_ids": approved,
        "rejected_finding_ids": rejected,
        "step_log": [f"Human approved {len(approved)}, rejected {len(rejected)}"],
    }


async def generate_report(state: InvestigationState, tools: dict) -> dict:
    """Generate an IR report from approved findings."""
    report_tool = tools.get("generate_report")
    save_tool = tools.get("save_report")
    if not report_tool:
        return {"error": "generate_report tool not available"}

    if not state["approved_finding_ids"]:
        logger.warning("No approved findings — generating status report")
        profile = "status"
    else:
        profile = "findings"

    result = await report_tool.ainvoke({
        "profile": profile,
        "case_id": state["case_id"],
        "finding_ids": state["approved_finding_ids"] or None,
    })
    if isinstance(result, dict) and result.get("error"):
        return {"error": result["error"]}

    if save_tool:
        content = json.dumps(result, indent=2, default=str)
        save_result = await save_tool.ainvoke({
            "filename": f"langgraph_report_{state['case_id']}.json",
            "content": content,
            "profile": profile,
        })
        report_path = save_result.get("path") if isinstance(save_result, dict) else None
        logger.info("Report saved: %s", report_path)
        return {
            "report_path": report_path,
            "step_log": [f"Report generated ({profile} profile)"],
        }

    return {"step_log": [f"Report generated ({profile} profile)"]}


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_graph():
    from langgraph.graph import END, StateGraph
    from langgraph.checkpoint.sqlite import AsyncSqliteSaver

    workflow = StateGraph(InvestigationState)

    workflow.add_node("register_evidence", register_evidence)
    workflow.add_node("scope", scope)
    workflow.add_node("hunt", hunt)
    workflow.add_node("stage_findings", stage_findings)
    workflow.add_node("await_approval", await_approval)
    workflow.add_node("generate_report", generate_report)

    workflow.set_entry_point("register_evidence")

    workflow.add_edge("register_evidence", "scope")
    workflow.add_edge("scope", "hunt")
    workflow.add_edge("hunt", "stage_findings")
    workflow.add_edge("stage_findings", "await_approval")
    workflow.add_edge("await_approval", "generate_report")
    workflow.add_edge("generate_report", END)

    return workflow


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run_pipeline(
    evidence_path: str = "",
    resume: bool = False,
    thread_id: str = "",
):
    """Run the DFIR-Nexus LangGraph investigation pipeline."""
    from langgraph.checkpoint.sqlite import AsyncSqliteSaver
    from langgraph.types import Command

    client = get_mcp_client()
    tools = await client.__aenter__()
    tools_by_name = {t.name: t for t in client.get_tools()}

    missing = validate_tools(tools_by_name)
    model = get_model()

    # Build graph with human-in-the-loop
    graph = build_graph()
    checkpointer = AsyncSqliteSaver.from_conn_string("pipeline.sqlite")
    compiled = graph.compile(checkpointer=checkpointer, interrupt_before=["await_approval"])

    config = {"configurable": {"thread_id": thread_id or "default"}}

    if resume:
        # Resume after human approval — read state and continue
        state = await compiled.aget_state(config)
        if not state or not state.values:
            logger.error("No checkpoint found to resume from")
            return

        # Verify approval against case directory
        current_state = state.values
        approved_ids = current_state.get("approved_finding_ids", [])

        if not approved_ids:
            logger.warning(
                "No approval data in resume payload. "
                "Make sure findings are approved via 'nexus approve' first."
            )
            # Try reading from case directory
            case_dir = Path.home() / ".nexus" / "cases" / current_state.get("case_id", "")
            approvals_file = case_dir / "approvals.jsonl"
            if approvals_file.exists():
                try:
                    with open(approvals_file) as f:
                        for line in f:
                            entry = json.loads(line.strip())
                            if entry.get("action") in ("APPROVED", "approved"):
                                approved_ids.append(entry.get("finding_id", ""))
                except (json.JSONDecodeError, OSError):
                    pass

        if approved_ids:
            logger.info("Resuming with approved findings: %s", approved_ids)
            await compiled.ainvoke(
                Command(resume={
                    "approved_ids": approved_ids,
                    "rejected_ids": current_state.get("rejected_finding_ids", []),
                }),
                config=config,
            )
        else:
            logger.warning("No approved findings to resume with")
        return

    # Fresh run
    initial = make_initial_state(evidence_path=evidence_path)
    result = await compiled.ainvoke(initial, config=config)

    result_state = result if isinstance(result, dict) else {}
    logger.info("Pipeline complete")
    logger.info("  Case ID:      %s", result_state.get("case_id", "N/A"))
    logger.info("  Approved:     %s", len(result_state.get("approved_finding_ids", [])))
    logger.info("  Draft:        %s", len(result_state.get("draft_finding_ids", [])))
    logger.info("  Report:       %s", result_state.get("report_path", "N/A"))
    logger.info("  Steps:        %d", len(result_state.get("step_log", [])))


def main():
    parser = argparse.ArgumentParser(description="DFIR-Nexus LangGraph pipeline")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from last checkpoint after human approval")
    parser.add_argument("--case", type=str, default="",
                        help="Path to evidence directory or file")
    parser.add_argument("--thread", type=str, default="",
                        help="Thread ID for checkpoint persistence")
    args = parser.parse_args()

    import asyncio
    asyncio.run(run_pipeline(
        evidence_path=args.case,
        resume=args.resume,
        thread_id=args.thread,
    ))


if __name__ == "__main__":
    main()
