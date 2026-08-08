"""LLM-driven LangGraph pipeline for DFIR-Nexus.

Connects to the DFIR-Nexus MCP server (via stdio or HTTP), drives a
6-node StateGraph investigation flow using an LLM (Anthropic/OpenAI/Ollama).

This is the "real" LLM-driven pipeline — the counterpart to the heuristic
agents in pipeline.py. It connects to the MCP server as a client and uses
a ReAct agent to pick analysis tools.

Usage:
    nexus pipeline --case /path/to/evidence
    nexus pipeline --resume
    nexus pipeline --model step-3.7-flash --case /path/to/evidence

LLM configuration (.env in the working directory, or environment):
    NEXUS_LLM_MODEL      Model name, e.g. "step-3.7-flash", "gpt-4o"
    NEXUS_LLM_BASE_URL   OpenAI-compatible endpoint URL (optional; required
                         for self-hosted / third-party-compatible providers)
    NEXUS_LLM_API_KEY    API key (optional for local endpoints like Ollama)
    NEXUS_LLM_PROVIDER   openai-compatible (default when BASE_URL is set) |
                         openai | anthropic | ollama
    NEXUS_LLM_REASONING  Optional reasoning effort passed through to the
                         model (provider-dependent, e.g. "high")

Legacy: NEXUS_MODEL="provider/model" prefix form still works
(e.g. "openai/gpt-4o", "ollama/qwen2.5:32b-instruct").

MCP connection:
    NEXUS_GATEWAY_URL — HTTP URL for MCP server (default: stdio)
    NEXUS_BEARER_TOKEN — bearer token for HTTP mode
    NEXUS_STDIO_CMD — command for stdio mode (default: "nexus")
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from datetime import UTC, datetime
from operator import add
from pathlib import Path
from typing import Annotated, Any, TypedDict

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# .env loading (no external dependency)
# ---------------------------------------------------------------------------

def _load_dotenv() -> None:
    """Load KEY=*** pairs from .env (CWD first, then repo root).

    Existing environment variables always win. Values may be quoted.
    """
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parents[3] / ".env",
    ]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            lines = candidate.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
        break


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
    messages: Annotated[list[Any], add]


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
        "messages": [],
    }


# ---------------------------------------------------------------------------
# Model selection
# ---------------------------------------------------------------------------

def get_model(model_name: str = ""):
    """Create the LLM instance from the NEXUS_LLM_* configuration.

    Contract (.env or environment):
      NEXUS_LLM_MODEL      model name (required unless legacy NEXUS_MODEL set)
      NEXUS_LLM_BASE_URL   OpenAI-compatible endpoint (optional)
      NEXUS_LLM_API_KEY    API key (optional for local endpoints)
      NEXUS_LLM_PROVIDER   openai-compatible (default when BASE_URL set) |
                           openai | anthropic | ollama
      NEXUS_LLM_REASONING  optional reasoning effort passthrough

    Legacy NEXUS_MODEL="provider/model" prefix routing still works.
    """
    _load_dotenv()

    model = model_name or os.environ.get("NEXUS_LLM_MODEL", "")
    base_url = os.environ.get("NEXUS_LLM_BASE_URL", "")
    api_key = os.environ.get("NEXUS_LLM_API_KEY", "")
    provider = os.environ.get("NEXUS_LLM_PROVIDER", "").lower()
    reasoning = os.environ.get("NEXUS_LLM_REASONING", "")

    if not model:
        # Legacy prefix form: "openai/gpt-4o", "ollama/qwen...", anthropic name
        legacy = os.environ.get("NEXUS_MODEL", "")
        if legacy.startswith("openai/"):
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model=legacy[len("openai/"):] or "gpt-4o")
        if legacy.startswith("ollama/"):
            try:
                from langchain_ollama import ChatOllama
            except ImportError:
                raise RuntimeError(
                    "langchain-ollama not installed — run: pip install langchain-ollama"
                ) from None
            return ChatOllama(model=legacy[len("ollama/"):])
        if legacy:
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model=legacy)
        raise RuntimeError(
            "No LLM configured. Create a .env with NEXUS_LLM_MODEL (plus "
            "NEXUS_LLM_BASE_URL / NEXUS_LLM_API_KEY for hosted providers), "
            "or set NEXUS_MODEL."
        )

    if provider == "anthropic" and not base_url:
        from langchain_anthropic import ChatAnthropic
        kwargs: dict[str, Any] = {}
        if api_key:
            kwargs["api_key"] = api_key
        return ChatAnthropic(model=model, **kwargs)

    if provider == "ollama" and not base_url:
        try:
            from langchain_ollama import ChatOllama
        except ImportError:
            raise RuntimeError(
                "langchain-ollama not installed — run: pip install langchain-ollama"
            ) from None
        return ChatOllama(model=model)

    # Default: any OpenAI-compatible endpoint (StepFun, OpenAI, LiteLLM,
    # vLLM, Ollama /v1, ...)
    from langchain_openai import ChatOpenAI
    kwargs = {"model": model, "api_key": api_key or "not-needed"}
    if base_url:
        kwargs["base_url"] = base_url
    if reasoning:
        kwargs["extra_body"] = {"reasoning_effort": reasoning}
    return ChatOpenAI(**kwargs)


# ---------------------------------------------------------------------------
# MCP client wiring
# ---------------------------------------------------------------------------

def get_mcp_config() -> dict[str, dict]:
    """Build MCP client config from environment variables.

    Priority:
    1. NEXUS_GATEWAY_URL → HTTP (streamable-http)
    2. NEXUS_STDIO_CMD → stdio (default: "nexus")
    """
    gateway_url = os.environ.get("NEXUS_GATEWAY_URL")
    bearer_token = os.environ.get("NEXUS_BEARER_TOKEN", "")

    if gateway_url:
        headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
        return {
            "dfir-nexus": {
                "transport": "streamable_http",
                "url": gateway_url,
                "headers": headers,
            }
        }

    stdio_cmd = os.environ.get("NEXUS_STDIO_CMD", "nexus")
    return {
        "dfir-nexus": {
            "transport": "stdio",
            "command": stdio_cmd,
            "args": ["serve"],
        }
    }


# ---------------------------------------------------------------------------
# Tool validation
# ---------------------------------------------------------------------------

_REQUIRED_TOOLS = {
    "case_init", "evidence_register",
    "record_finding", "record_timeline_event",
    "generate_report",
}


def _parse_tool_result(result: Any) -> dict:
    """Normalize an MCP-adapter tool result into a dict.

    langchain-mcp-adapters returns tool output as a list of content blocks
    (or a raw string), not the tool's dict. Extract the text payload and
    JSON-decode it when possible.
    """
    if isinstance(result, dict):
        return result
    text: str | None = None
    if isinstance(result, str):
        text = result
    elif isinstance(result, list):
        parts: list[str] = []
        for block in result:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
            elif isinstance(block, str):
                parts.append(block)
            elif hasattr(block, "text"):
                parts.append(str(getattr(block, "text", "")))
        text = "\n".join(parts)
    if text:
        with contextlib.suppress(json.JSONDecodeError, ValueError):
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
    return {}


def validate_tools(tools_by_name: dict[str, Any]) -> list[str]:
    missing = [name for name in _REQUIRED_TOOLS if name not in tools_by_name]
    if missing:
        log.warning("Missing tools (graph will still run): %s", missing)
    return missing


# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------

async def register_evidence(state: InvestigationState, tools: dict) -> dict:
    """Create case and register evidence. Deterministic node."""
    case_tool = tools.get("case_init")
    if not case_tool:
        return {"error": "case_init tool not available"}

    result = _parse_tool_result(await case_tool.ainvoke({
        "name": f"LangGraph Investigation - {Path(state['evidence_path']).name}",
        "description": "Automated investigation via LangGraph pipeline",
    }))
    if result.get("error"):
        return {"error": f"case_init failed: {result['error']}"}

    case_id = result.get("case_id", "unknown")
    log.info("Case created: %s", case_id)

    ev_tool = tools.get("evidence_register")
    if ev_tool and state["evidence_path"]:
        ev_result = _parse_tool_result(await ev_tool.ainvoke({
            "path": state["evidence_path"],
            "description": "Evidence for automated investigation",
        }))
        audit_ids = []
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
    """Scope the investigation — survey available evidence."""
    case_id = state["case_id"]
    if not case_id:
        return {"error": "No active case ID"}

    suggest_tool = tools.get("suggest_tools")
    rag_tool = tools.get("forensic_rag_search")
    hosts = []

    if suggest_tool:
        try:
            suggestions = await suggest_tool.ainvoke({"artifact_type": "evtx"})
            if isinstance(suggestions, list):
                for s in suggestions[:5]:
                    log.info("Suggested tool: %s", s.get("name", ""))
        except Exception:
            pass

    if rag_tool and case_id:
        with contextlib.suppress(Exception):
            await rag_tool.ainvoke({"query": f"investigation guidance for case {case_id}"})

    return {
        "hosts": hosts,
        "step_log": [f"Scoped investigation: {len(hosts)} hosts identified"],
    }


async def hunt(state: InvestigationState, tools: dict, model) -> dict:
    """Analyze evidence using a ReAct agent."""
    try:
        from langgraph.prebuilt import create_react_agent
    except ImportError:
        return {"error": "langgraph not installed — run: pip install dfir-nexus[pipeline]"}


    hunt_tools_list = []
    for name in ("run_command", "run_windows_command", "suggest_tools",
                  "forensic_rag_search", "ingest_auto", "analyze_gaps",
                  "deobfuscate_command", "predict_techniques", "check_kev"):
        t = tools.get(name)
        if t:
            hunt_tools_list.append(t)

    if not hunt_tools_list:
        log.warning("No hunt tools available")
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
        log.info("Hunt agent completed: %d messages", msg_count)
    except Exception as e:
        log.error("Hunt agent failed: %s", e)
        return {"step_log": [f"Hunt agent error: {e}"]}

    return {
        "step_log": ["Hunt analysis completed"],
        "messages": result.get("messages", []),
    }


async def stage_findings(state: InvestigationState, tools: dict) -> dict:
    """Stage findings as DRAFT from hunt agent output."""
    from nexus.langgraph.hunt_parser import parse_hunt_candidates

    finding_tool = tools.get("record_finding")
    timeline_tool = tools.get("record_timeline_event")
    if not finding_tool:
        return {"error": "record_finding tool not available"}

    draft_ids = []
    timeline_ids = []
    errors = []

    candidates = parse_hunt_candidates(state.get("messages", []))

    if candidates:
        for candidate in candidates:
            try:
                result = _parse_tool_result(await finding_tool.ainvoke(candidate))
                if result.get("finding_id"):
                    draft_ids.append(result["finding_id"])
                    log.info("Finding staged: %s", result["finding_id"])
                elif result.get("error"):
                    errors.append(result["error"])
            except Exception as e:
                errors.append(str(e))

        if timeline_tool:
            for c in candidates:
                ts = c.get("event_timestamp", "")
                if not ts:
                    continue
                try:
                    result = _parse_tool_result(await timeline_tool.ainvoke({
                        "timestamp": ts,
                        "description": c.get("observation", c.get("title", ""))[:500],
                        "event_type": c.get("type", "execution"),
                        "host": c.get("host", ""),
                    }))
                    if result.get("event_id"):
                        timeline_ids.append(result["event_id"])
                except Exception as e:
                    errors.append(str(e))
    else:
        host = state["hosts"][0] if state.get("hosts") else ""
        placeholder: dict[str, Any] = {
            "title": f"Automated analysis for {state['case_id']}",
            "observation": "LangGraph pipeline completed initial analysis",
            "interpretation": "Reviewer should examine findings in Examiner Portal",
            "confidence": "MEDIUM",
            "confidence_justification": "Pipeline placeholder for examiner review",
            "host": host,
            "event_timestamp": datetime.now(UTC).isoformat(),
        }
        # FD-001: reference the evidence registration audit trail so the
        # placeholder stages as DRAFT instead of being rejected.
        if state.get("evidence_audit_ids"):
            placeholder["artifacts"] = [
                {"audit_id": aid} for aid in state["evidence_audit_ids"]
            ]
        result = _parse_tool_result(await finding_tool.ainvoke(placeholder))
        if result.get("finding_id"):
            draft_ids.append(result["finding_id"])
            log.info("Placeholder finding staged: %s", result["finding_id"])
        elif result.get("error"):
            errors.append(result["error"])

    log_msg = [f"Staged {len(draft_ids)} findings, {len(timeline_ids)} timeline events"]
    if errors:
        log_msg.append(f"Errors: {'; '.join(errors[:3])}")
    return {
        "draft_finding_ids": draft_ids,
        "draft_timeline_ids": timeline_ids,
        "step_log": log_msg,
    }


def await_approval(state: InvestigationState) -> dict:
    """HUMAN IN THE LOOP — pause graph until examiner approves."""
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

    log.info("Human approved: %s", approved)
    log.info("Human rejected: %s", rejected)

    return {
        "approved_finding_ids": approved,
        "rejected_finding_ids": rejected,
        "step_log": [f"Human approved {len(approved)}, rejected {len(rejected)}"],
    }


async def generate_report(state: InvestigationState, tools: dict) -> dict:
    """Generate an IR report from approved findings."""
    report_tool = tools.get("generate_report")
    if not report_tool:
        return {"error": "generate_report tool not available"}

    profile = "findings" if state["approved_finding_ids"] else "status"

    result = _parse_tool_result(await report_tool.ainvoke({
        "profile": profile,
        "case_id": state["case_id"],
        "finding_ids": state["approved_finding_ids"] or None,
    }))
    if result.get("error"):
        return {"error": result["error"]}

    return {"step_log": [f"Report generated ({profile} profile)"]}


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_graph(tools: dict, model):
    """Build the investigation graph with tools and model captured in closures."""
    from langgraph.graph import END, StateGraph

    async def _register_evidence(state: InvestigationState) -> dict:
        return await register_evidence(state, tools)

    async def _scope(state: InvestigationState) -> dict:
        return await scope(state, tools, model)

    async def _hunt(state: InvestigationState) -> dict:
        return await hunt(state, tools, model)

    async def _stage_findings(state: InvestigationState) -> dict:
        return await stage_findings(state, tools)

    async def _generate_report(state: InvestigationState) -> dict:
        return await generate_report(state, tools)

    workflow = StateGraph(InvestigationState)

    workflow.add_node("register_evidence", _register_evidence)
    workflow.add_node("scope", _scope)
    workflow.add_node("hunt", _hunt)
    workflow.add_node("stage_findings", _stage_findings)
    workflow.add_node("await_approval", await_approval)
    workflow.add_node("generate_report", _generate_report)

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
    model_name: str = "",
):
    """Run the DFIR-Nexus LangGraph investigation pipeline."""
    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.types import Command

    config = get_mcp_config()
    client = MultiServerMCPClient(config)
    tools_list = await client.get_tools()
    tools_by_name = {t.name: t for t in tools_list}

    validate_tools(tools_by_name)
    model = get_model(model_name)

    graph = build_graph(tools_by_name, model)
    checkpointer = MemorySaver()
    compiled = graph.compile(checkpointer=checkpointer, interrupt_before=["await_approval"])

    cfg = {"configurable": {"thread_id": thread_id or "default"}}

    if resume:
        state = await compiled.aget_state(cfg)
        if not state or not state.values:
            log.error("No checkpoint found to resume from")
            return

        current_state = state.values
        approved_ids = current_state.get("approved_finding_ids", [])

        if not approved_ids:
            case_id = current_state.get("case_id", "")
            case_dir = Path.home() / ".nexus" / "cases" / case_id
            approvals_file = case_dir / "approvals.jsonl"
            if approvals_file.exists():
                try:
                    with open(approvals_file, encoding="utf-8") as f:
                        for line in f:
                            entry = json.loads(line.strip())
                            if entry.get("action") in ("APPROVED", "approved"):
                                approved_ids.append(entry.get("finding_id", ""))
                except (json.JSONDecodeError, OSError):
                    pass

        if approved_ids:
            log.info("Resuming with approved findings: %s", approved_ids)
            await compiled.ainvoke(
                Command(resume={
                    "approved_ids": approved_ids,
                    "rejected_ids": current_state.get("rejected_finding_ids", []),
                }),
                config=cfg,
            )
        else:
            log.warning("No approved findings to resume with")
        return

    initial = make_initial_state(evidence_path=evidence_path)
    result = await compiled.ainvoke(initial, config=cfg)

    result_state = result if isinstance(result, dict) else {}
    log.info("Pipeline complete")
    log.info("  Case ID:      %s", result_state.get("case_id", "N/A"))
    log.info("  Approved:     %s", len(result_state.get("approved_finding_ids", [])))
    log.info("  Draft:        %s", len(result_state.get("draft_finding_ids", [])))
    log.info("  Report:       %s", result_state.get("report_path", "N/A"))
    log.info("  Steps:        %d", len(result_state.get("step_log", [])))
