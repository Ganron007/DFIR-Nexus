"""LLM-driven LangGraph pipeline for DFIR-Nexus.

Connects to the DFIR-Nexus MCP server (via stdio or HTTP), drives a
StateGraph investigation flow. Three switchable modes (no hybrid graph):

  tools            — mandatory parser lane only; **no RAG, no LLM**; TOOL-RUN.md
  coverage (debug) — same mandatory lane; RAG+LLM interpret ledger+snippets
  design           — RAG load, mandatory lane, then ReAct may **add** extras
  interpret        — reuse an existing tool-run case (``--from-case``)

  REPORT.md (coverage/design/interpret) is a **deterministic template** from
  APPROVED findings — the LLM fills observation/interpretation, not the file
  structure. Huge tool CSVs are never fully injected into the LLM (bounded
  snippets only). See Docs/cases/TOOL-EVIDENCE-MAP.md.

Switch:
    nexus pipeline --mode design|coverage|tools --case /path/to/evidence
    NEXUS_PIPELINE_MODE=design|coverage|tools
    Aliases: react/hunt → design; debug/full/lane → coverage;
             tools_only/no_llm → tools

Usage:
    nexus pipeline --case /path/to/evidence
    nexus pipeline --mode tools --case /path/to/evidence
    nexus pipeline --mode coverage --case /path/to/evidence
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

# Pipeline modes: design = ReAct tool selection; coverage = force-run triage lane
PIPELINE_MODES = ("design", "coverage", "tools", "interpret")
_PIPELINE_MODE_ALIASES = {
    "react": "design",
    "hunt": "design",
    "agent": "design",
    "debug": "coverage",
    "full": "coverage",
    "lane": "coverage",
    "tool_lane": "coverage",
    "tools_only": "tools",
    "toolsonly": "tools",
    "no_llm": "tools",
    "nollm": "tools",
    "from_case": "interpret",
    "from-case": "interpret",
    "report": "interpret",
}


def resolve_pipeline_mode(mode: str | None = None) -> str:
    """Return ``design``, ``coverage``, or ``tools``.

    Resolution order: explicit ``mode`` arg → ``NEXUS_PIPELINE_MODE`` → ``design``.
    """
    raw = (mode if mode is not None else os.environ.get("NEXUS_PIPELINE_MODE", "")).strip().lower()
    if not raw:
        raw = "design"
    raw = _PIPELINE_MODE_ALIASES.get(raw, raw)
    if raw not in PIPELINE_MODES:
        raise ValueError(
            f"Unknown pipeline mode {mode!r}. Use design|coverage|tools|interpret "
            f"(aliases: react/hunt → design; debug/full/lane → coverage; "
            f"tools_only/no_llm → tools; from_case/report → interpret)."
        )
    return raw


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
    # Examiner-supplied narrative (optional). Keys commonly used:
    # name, description, hypothesis, notes, host, sift_evidence_root
    case_context: dict[str, str]
    tool_run_ledger: list[dict[str, Any]]
    rag_notes: Annotated[list[str], add]
    # design = ReAct tool selection; coverage = deterministic full triage
    pipeline_mode: str


def make_initial_state(
    evidence_path: str = "",
    case_context: dict[str, str] | None = None,
    pipeline_mode: str | None = None,
    case_id: str = "",
) -> InvestigationState:
    return {
        "case_id": case_id,
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
        "case_context": dict(case_context or {}),
        "tool_run_ledger": [],
        "rag_notes": [],
        "pipeline_mode": resolve_pipeline_mode(pipeline_mode),
    }


def _format_case_context(ctx: dict[str, str] | None) -> str:
    """Human-readable case intake for interpretation prompts."""
    ctx = ctx or {}
    keys = (
        "name", "description", "hypothesis", "notes", "host",
        "timezone", "window", "subjects", "known_good", "question", "playbooks",
    )
    if not any(str(ctx.get(k) or "").strip() for k in keys):
        return (
            "No examiner case narrative was provided. Interpret strictly from "
            "tool outputs and RAG methodology. Do NOT invent campaigns, threat "
            "actors, or unrelated lab environments. Benign/authorized activity "
            "is a valid outcome when the evidence supports it."
        )
    lines = [
        "Examiner case intake (hypothesis loses to evidence):",
    ]
    for key, label in (
        ("name", "Name"),
        ("description", "Description"),
        ("question", "Question to answer"),
        ("hypothesis", "Hypothesis"),
        ("timezone", "Timezone"),
        ("window", "Incident window"),
        ("subjects", "Subjects / SIDs / hosts"),
        ("known_good", "Known-good"),
        ("playbooks", "Playbooks"),
        ("notes", "Notes"),
        ("host", "Primary host"),
    ):
        val = str(ctx.get(key) or "").strip()
        if val:
            lines.append(f"- {label}: {val}")
    return "\n".join(lines)


_INTERPRETATION_RULES = (
    "Interpretation rules (product contract):\n"
    "1) Evidence before narrative — every claim cites audit_id and/or output_saved_to "
    "from tool results (design mode) or the tool-lane ledger (coverage/tools/interpret).\n"
    "2) RAG MUST be loaded (forensic_rag_status ready) before you interpret. "
    "Call forensic_rag_search for methodology AND insider-threat / data-staging / "
    "cloud-sync / SRUM / LNK / EVTX patterns. Use ALL tool-output snippets, not one tool.\n"
    "3) Map every finding to the Insider Threat Matrix "
    "(https://insiderthreatmatrix.org/) with itm_stage + itm_objects.\n"
    "4) If optional case context is present, use it only as a hypothesis — if tool "
    "outputs contradict it, say so explicitly.\n"
    "5) Separate observation (what the tool showed) from interpretation (what it means). "
    "Confidence MUST be one of HIGH, MEDIUM, LOW, SPECULATIVE (never N/A).\n"
    "6) MITRE IDs only when justified by the observation; omit rather than guess.\n"
    "7) Ordinary/authorized activity may appear in host artifacts — do not escalate "
    "to compromise without corroborating evidence, but still record the artifact "
    "and ITM object.\n"
    "8) Finish with a ```json fenced array of findings: title, observation, "
    "interpretation, confidence, confidence_justification, host, attack_ids, "
    "itm_stage, itm_objects, audit_ids, artifacts (paths/audit_ids). "
    "Emit multiple findings covering EVTX, execution (prefetch/amcache), "
    "user-access (LNK/jumplist/shellbags), SRUM/network, registry, memory, "
    "recycle-bin — skip a family only if that snippet is empty."
)

_COVERAGE_MODE_RULES = (
    "PIPELINE MODE: coverage (debug).\n"
    "Condition you MUST treat as true: every applicable host-triage tool was already "
    "force-executed against available evidence before this step. You do NOT select "
    "triage tools. The ledger is the inventory of what ran (OK/FAIL/SKIP).\n"
    "You MUST read the tool OUTPUT SNIPPETS (CSV/stdout heads) provided in the human "
    "message. Findings must cite CONCRETE facts from those snippets "
    "(usernames, process names, paths, timestamps, event IDs, URLs). "
    "FORBIDDEN titles: 'Successful … Extraction', 'Tool X completed'. "
    "FORBIDDEN: empty interpretation. "
    "FAIL/SKIP are coverage gaps only — do not invent compromise from a FAIL. "
    "Severity: low for routine artifacts; medium/high only when snippet facts "
    "support insider-misuse / staging / anomalous privilege under the hypothesis."
)

_DESIGN_MODE_RULES = (
    "PIPELINE MODE: design (mandatory lane already ran, then ReAct extras).\n"
    "The host-triage parsers for artifacts PRESENT on this evidence already ran. "
    "The ledger is the inventory (OK/FAIL/SKIP). You MUST NOT re-run hayabusa, "
    "pecmd, lecmd, jlecmd, sbecmd, srumecmd, recmd, evtxecmd, mftecmd, "
    "amcacheparser, appcompatcacheparser, rbcmd, sqlecmd, or wxtcmd against "
    "the same inputs.\n"
    "You MAY add corroboration tools from examiner playbooks (usb_activity, "
    "data_staging, …) and RAG methodology — only for artifacts the lane did "
    "not cover, or a second-pass parser with a different input.\n"
    "Call forensic_rag_search for methodology. Never emit findings with zero "
    "tool audit_ids — cite the lane ledger. Do not call generate_report. "
    "Stop after a focused extra hunt, then the interpret node writes findings."
)


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

def _mcp_http_timeouts() -> dict[str, float]:
    """Streamable-HTTP timeouts for long forensic tools.

    langchain-mcp-adapters defaults ``sse_read_timeout`` to 300s. SBECmd and
    log2timeline exceed that with no SSE event, which surfaces as
    ``unhandled errors in a TaskGroup``. Override via
    ``NEXUS_MCP_HTTP_TIMEOUT`` / ``NEXUS_MCP_SSE_READ_TIMEOUT``.
    """
    return {
        "timeout": float(os.environ.get("NEXUS_MCP_HTTP_TIMEOUT", "120")),
        "sse_read_timeout": float(os.environ.get("NEXUS_MCP_SSE_READ_TIMEOUT", "7200")),
    }


def get_mcp_config() -> dict[str, dict]:
    """Build MCP client config from environment variables.

    Priority for multi-host (Windows + SIFT — product default for investigations):
      NEXUS_WINDOWS_MCP_URL  e.g. http://127.0.0.1:4508/mcp
      NEXUS_SIFT_MCP_URL     e.g. http://192.168.77.135:4508/mcp
    Both may be set; MultiServerMCPClient merges tools (Windows has
    run_windows_command; SIFT has run_command).

    Single-gateway fallback:
      NEXUS_GATEWAY_URL → one HTTP server
      else NEXUS_STDIO_CMD → stdio (default: nexus serve)
    """
    bearer_token = os.environ.get("NEXUS_BEARER_TOKEN", "")
    headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
    http_timeouts = _mcp_http_timeouts()

    windows_url = os.environ.get("NEXUS_WINDOWS_MCP_URL", "").strip()
    sift_url = os.environ.get("NEXUS_SIFT_MCP_URL", "").strip()
    if windows_url or sift_url:
        cfg: dict[str, dict] = {}
        if windows_url:
            cfg["nexus-windows"] = {
                "transport": "streamable_http",
                "url": windows_url,
                "headers": dict(headers),
                **http_timeouts,
            }
        if sift_url:
            cfg["nexus-sift"] = {
                "transport": "streamable_http",
                "url": sift_url,
                "headers": dict(headers),
                **http_timeouts,
            }
        return cfg

    gateway_url = os.environ.get("NEXUS_GATEWAY_URL")
    if gateway_url:
        return {
            "dfir-nexus": {
                "transport": "streamable_http",
                "url": gateway_url,
                "headers": headers,
                **http_timeouts,
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
    """Create case and register evidence. Deterministic node.

    Dual-MCP contract: Windows is the case authority for findings/report.
    The same ``case_id`` is mirrored onto SIFT so ``run_command`` persists
    into ``~/.nexus/cases/<case_id>/extractions/`` on that host.
    """
    case_tool = tools.get("case_init")
    if not case_tool:
        return {"error": "case_init tool not available"}

    from datetime import UTC, datetime

    ctx = state.get("case_context") or {}
    case_id = f"INC-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
    case_name = (
        str(ctx.get("name") or "").strip()
        or f"LangGraph Investigation - {Path(state['evidence_path']).name}"
    )
    desc_parts = [
        str(ctx.get("description") or "").strip(),
        str(ctx.get("hypothesis") or "").strip(),
        "Automated investigation via LangGraph dual-MCP pipeline "
        "(Windows examiner authority + SIFT tool host; shared case_id).",
    ]
    case_desc = " | ".join(p for p in desc_parts if p)

    result = _parse_tool_result(await case_tool.ainvoke({
        "name": case_name,
        "description": case_desc,
        "case_id": case_id,
    }))
    if result.get("error"):
        return {"error": f"case_init failed: {result['error']}"}

    case_id = result.get("case_id", case_id)
    log.info("Case created (authority): %s", case_id)

    step_log = [f"Case {case_id} created on case-authority host"]
    try:
        from nexus.config import settings
        from nexus.langgraph.case_intake import persist_case_intake

        written = persist_case_intake(settings.cases_root / case_id, ctx)
        if written:
            step_log.append(f"Case intake written ({len(written)} fields)")
    except Exception as exc:  # noqa: BLE001
        step_log.append(f"Case intake persist skipped: {exc}")
    sift_init = tools.get("_sift_case_init")
    sift_activate = tools.get("_sift_case_activate")
    if sift_init:
        mirror = _parse_tool_result(await sift_init.ainvoke({
            "name": case_name,
            "description": case_desc,
            "case_id": case_id,
        }))
        if mirror.get("error"):
            step_log.append(f"SIFT case mirror warning: {mirror.get('error')}")
            log.warning("SIFT case_init mirror failed: %s", mirror.get("error"))
        else:
            step_log.append(f"Case {case_id} mirrored on SIFT")
            if sift_activate:
                act = _parse_tool_result(await sift_activate.ainvoke({"case_id": case_id}))
                if act.get("error"):
                    step_log.append(f"SIFT case_activate warning: {act.get('error')}")
                else:
                    step_log.append(f"Case {case_id} activated on SIFT")
    else:
        step_log.append(
            "SIFT case mirror skipped (single-host or no sift case_init handle)"
        )

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
        step_log.append("Evidence registered on case-authority host")
        return {
            "case_id": case_id,
            "evidence_audit_ids": audit_ids,
            "step_log": step_log,
        }

    return {
        "case_id": case_id,
        "step_log": step_log,
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
        ctx = state.get("case_context") or {}
        rag_q = (
            str(ctx.get("hypothesis") or ctx.get("description") or "").strip()
            or f"investigation guidance for case {case_id}"
        )
        with contextlib.suppress(Exception):
            await rag_tool.ainvoke({"query": rag_q[:400]})
        host_ctx = str(ctx.get("host") or "").strip()
        if host_ctx and host_ctx not in hosts:
            hosts.append(host_ctx)

    return {
        "hosts": hosts,
        "step_log": [f"Scoped investigation: {len(hosts)} hosts identified"],
    }


async def execute_tool_lane(state: InvestigationState, tools: dict) -> dict:
    """Deterministic MCP triage — all applicable tools run (coverage/tools)."""
    from nexus.langgraph.tool_lane import run_tool_lane

    case_id = state.get("case_id") or ""
    if not case_id:
        return {"error": "No case_id — cannot run tool lane"}

    mode = state.get("pipeline_mode") or "coverage"
    result = await run_tool_lane(
        tools=tools,
        evidence_path=state.get("evidence_path") or "",
        case_id=case_id,
        case_context=state.get("case_context") or {},
        parse_result=_parse_tool_result,
        skip_rag=True,
        pipeline_mode=mode,
    )
    steps = list(result.get("step_log") or [])
    label = "tools mode" if mode == "tools" else "coverage mode"
    steps.insert(0, f"{label}: deterministic tool lane")
    result["step_log"] = steps
    return result


async def ensure_rag_ready(state: InvestigationState, tools: dict) -> dict:
    """Block LLM modes until the Windows MCP RAG embedder is loaded."""
    status_tool = tools.get("forensic_rag_status")
    search_tool = tools.get("forensic_rag_search")
    notes: list[str] = []
    if not status_tool and not search_tool:
        return {"error": "RAG tools missing on Windows MCP — cannot run LLM modes"}
    status: dict = {}
    if status_tool:
        try:
            status = _parse_tool_result(await status_tool.ainvoke({}))
        except Exception as exc:  # noqa: BLE001
            return {"error": f"forensic_rag_status failed: {exc}"}
    ready = str(status.get("status") or "").lower() in ("ready", "ok", "loaded")
    if search_tool:
        try:
            for query in (
                "Windows host triage EVTX prefetch SRUM LNK Amcache methodology",
                "insider threat data staging cloud sync removable media SRUM",
            ):
                warm = _parse_tool_result(await search_tool.ainvoke({
                    "query": query,
                    "top_k": 5,
                }))
                notes.append(str(warm.get("results") or warm)[:2000])
            if status_tool:
                status = _parse_tool_result(await status_tool.ainvoke({}))
            ready = True
        except Exception as exc:  # noqa: BLE001
            return {"error": f"RAG warmup search failed: {exc}"}
    if str(status.get("status") or "").lower() in ("unavailable", "error", "not_initialized"):
        return {
            "error": (
                f"RAG not ready: {status}. Load BAAI/bge-base-en-v1.5 on Windows "
                "MCP (NEXUS_RAG_PRELOAD=1) before design/coverage/interpret."
            )
        }
    model = status.get("model") or status.get("model_load_path") or "loaded"
    count = status.get("document_count") or status.get("records") or "?"
    notes.insert(0, f"RAG ready model={model} records={count}")
    return {
        "rag_notes": notes,
        "step_log": [f"RAG embedder ready ({model}, {count} records)"],
    }


async def load_existing_case(state: InvestigationState, tools: dict) -> dict:
    """Reuse a completed tool-run case (ledger + snippets) for interpretation."""
    import json
    from nexus.config import settings
    from nexus.langgraph.snippets import write_snippets

    case_id = (state.get("case_id") or "").strip()
    if not case_id:
        return {"error": "load_existing_case requires case_id"}
    activate = tools.get("case_activate")
    step_log = []
    if activate:
        act = _parse_tool_result(await activate.ainvoke({"case_id": case_id}))
        if act.get("error"):
            step_log.append(f"case_activate warning: {act.get('error')}")
        else:
            step_log.append(f"Activated existing case {case_id}")
    case_dir = settings.cases_root / case_id
    ledger_path = case_dir / "extractions" / "_tool_lane_ledger.json"
    if not ledger_path.is_file():
        ledger_path = case_dir / "ledger" / "_tool_lane_ledger.json"
    ledger: list[dict] = []
    if ledger_path.is_file():
        try:
            ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return {"error": f"ledger unreadable: {exc}"}
    if not ledger:
        return {"error": f"No tool-lane ledger in {case_dir}"}
    write_snippets(case_dir, ledger)
    aids = [str(r.get("audit_id")) for r in ledger if r.get("audit_id")]
    step_log.append(f"Loaded {len(ledger)} ledger rows, {len(aids)} audit_ids")
    return {
        "case_id": case_id,
        "tool_run_ledger": ledger,
        "evidence_audit_ids": aids,
        "step_log": step_log,
    }


def _format_tool_run_markdown(state: InvestigationState) -> str:
    """Deterministic TOOL-RUN report — no LLM, no findings narrative."""
    ledger = list(state.get("tool_run_ledger") or [])
    case_id = state.get("case_id") or "unknown"
    ok = [r for r in ledger if r.get("status") == "OK"]
    fail = [r for r in ledger if r.get("status") == "FAIL"]
    skip = [r for r in ledger if r.get("status") == "SKIP"]
    lines = [
        f"# Tool-run ledger — `{case_id}`",
        "",
        f"**Mode:** `{state.get('pipeline_mode') or 'tools'}` (no LLM)",
        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Evidence:** `{state.get('evidence_path') or ''}`",
        "",
        f"Summary: **{len(ok)} OK** · **{len(fail)} FAIL** · **{len(skip)} SKIP** "
        f"(total {len(ledger)})",
        "",
        "> This is **not** an IR findings report. It proves MCP tools ran "
        "(or failed) against the mapped evidence. See "
        "`Docs/cases/TOOL-EVIDENCE-MAP.md`.",
        "",
        "| Host | Tool | Status | Purpose | audit_id | output |",
        "|---|---|---|---|---|---|",
    ]
    for row in ledger:
        lines.append(
            "| {host} | {tool} | {status} | {purpose} | `{aid}` | `{out}` |".format(
                host=row.get("host") or "",
                tool=row.get("tool") or "",
                status=row.get("status") or "",
                purpose=(row.get("purpose") or "").replace("|", "/"),
                aid=(row.get("audit_id") or row.get("reason") or "")[:48],
                out=(row.get("output_saved_to") or "")[:64],
            )
        )
    lines.extend(["", "## Failures / skips", ""])
    for row in fail + skip:
        lines.append(
            f"- **{row.get('status')}** `{row.get('host')}/{row.get('tool')}`: "
            f"{row.get('reason') or row.get('purpose') or ''}"
        )
    if not fail and not skip:
        lines.append("- (none)")
    lines.extend([
        "",
        "## Next",
        "",
        "When OK/FAIL are stable, run `--mode coverage` (LLM interpret) or "
        "`--mode design` (lane + ReAct extras). "
        "`REPORT.md` is templated from APPROVED findings — not from raw CSVs.",
        "",
    ])
    case_id = state.get("case_id") or ""
    if case_id:
        try:
            from nexus.config import settings
            comp = settings.cases_root / case_id / "extractions" / "_artifact_completeness.json"
            if comp.is_file():
                rows = json.loads(comp.read_text(encoding="utf-8"))
                lines.extend([
                    "## Artifact completeness (YAML map)",
                    "",
                    "SKIP/ABSENT = artifact not on this pack (OK). "
                    "PRESENT_NO_PARSER = present but no argv builder. "
                    "SCHEDULED = parser was queued.",
                    "",
                    "| Artifact | Status | Tools | Hits | Reason |",
                    "|---|---|---|---|---|",
                ])
                for row in rows:
                    lines.append(
                        "| {artifact} | {status} | {tools} | {hits} | {reason} |".format(
                            artifact=(row.get("artifact") or "").replace("|", "/"),
                            status=row.get("status") or "",
                            tools=(row.get("tools") or "-").replace("|", "/"),
                            hits=row.get("hits") or "0",
                            reason=(row.get("reason") or "").replace("|", "/")[:80],
                        )
                    )
                lines.append("")
        except (OSError, json.JSONDecodeError):
            pass
    return "\n".join(lines)


async def emit_tool_report(state: InvestigationState, tools: dict) -> dict:
    """Write TOOL-RUN.md + repo export. No findings, no HITL, no LLM."""
    del tools  # tools mode does not call generate_report MCP
    step_log: list[str] = []
    report_path: str | None = None
    export_root: str | None = None
    try:
        from nexus.config import settings
        from nexus.case.repo_export import export_case_to_repo

        case_dir = settings.cases_root / state["case_id"]
        md = _format_tool_run_markdown(state)
        out = case_dir / "reports" / "TOOL-RUN.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        step_log.append(f"Wrote {out}")

        # Persist ledger for export
        ledger_dir = case_dir / "ledger"
        ledger_dir.mkdir(parents=True, exist_ok=True)
        ledger_path = ledger_dir / "_tool_lane_ledger.json"
        ledger_path.write_text(
            json.dumps(state.get("tool_run_ledger") or [], indent=2),
            encoding="utf-8",
        )

        exported = export_case_to_repo(
            case_dir,
            report_markdown=md,
            extra_sift_dir=case_dir / "sift" / "extractions",
        )
        export_root = str(exported)
        (exported / "reports" / "TOOL-RUN.md").write_text(md, encoding="utf-8")
        report_path = str(exported / "reports" / "TOOL-RUN.md")
        step_log.append(f"Repo export: {exported}")
    except Exception as exc:  # noqa: BLE001
        step_log.append(f"Tool-run report/export failed: {exc}")
        return {"error": str(exc), "step_log": step_log}

    return {
        "report_path": report_path,
        "step_log": step_log,
        "rag_notes": [f"repo_export={export_root}"] if export_root else [],
    }


async def hunt(state: InvestigationState, tools: dict, model) -> dict:
    """Design mode: ReAct agent selects and runs MCP forensic tools."""
    try:
        from langgraph.prebuilt import create_react_agent
    except ImportError:
        return {"error": "langgraph not installed — run: pip install dfir-nexus[pipeline]"}

    hunt_tool_names = (
        "run_command",
        "run_windows_command",
        "suggest_tools",
        "suggest_windows_tools",
        "list_windows_tools",
        "get_windows_tool_help",
        "forensic_rag_search",
        "forensic_rag_status",
        "ingest_auto",
        "analyze_gaps",
        "deobfuscate_command",
        "predict_techniques",
        "check_kev",
        "check_file",
        "check_hash",
        "check_autorun",
    )
    hunt_tools_list = []
    for name in hunt_tool_names:
        t = tools.get(name)
        if t:
            hunt_tools_list.append(t)

    if not hunt_tools_list:
        log.warning("No hunt tools available")
        return {"step_log": ["Hunt skipped — no analysis tools"]}

    ctx_block = _format_case_context(state.get("case_context") or {})
    from nexus.langgraph.case_intake import extra_playbook_names
    pbs = extra_playbook_names(state.get("case_context") or {})
    pb_line = (
        f"Examiner playbooks for extras (do not skip present artifacts): {', '.join(pbs)}"
        if pbs else "No extra playbooks named."
    )
    available = ", ".join(t.name for t in hunt_tools_list)
    from nexus.langgraph.itm import itm_prompt_block

    agent = create_react_agent(
        model,
        hunt_tools_list,
        prompt=(
            "You are a DFIR investigator adding corroboration after the mandatory lane.\n"
            f"Case: {state['case_id']}.\n"
            f"{_DESIGN_MODE_RULES}\n"
            f"{ctx_block}\n"
            f"{pb_line}\n"
            f"{itm_prompt_block()}\n"
            f"Available tools: {available}."
        ),
    )

    try:
        result = await agent.ainvoke(
            {
                "messages": [{
                    "role": "human",
                    "content": (
                        f"Analyze extras for case {state['case_id']}.\n"
                        f"Evidence path: {state.get('evidence_path')}\n"
                        f"Hosts: {state.get('hosts', [])}\n"
                        "The mandatory tool lane already ran. Do not re-run those parsers.\n"
                        "1) forensic_rag_status — abort extras if RAG is not ready.\n"
                        "2) forensic_rag_search for playbook corroboration "
                        "(data staging, USB, cloud sync) using examiner intake.\n"
                        "3) You MAY run additional run_windows_command / run_command "
                        "only for artifacts the ledger SKIP'd as PRESENT_NO_PARSER "
                        "or playbook extras not already OK.\n"
                        "4) Do not emit the findings JSON here — interpret runs next. "
                        "Never call generate_report. Never finish with zero lane audit_ids."
                    ),
                }],
            },
            config={"recursion_limit": 50},
        )
        msg_count = len(result.get("messages", []))
        log.info("Hunt agent completed: %d messages", msg_count)
    except Exception as e:
        log.error("Hunt agent failed: %s", e)
        return {"step_log": [f"Hunt agent error: {e}"]}

    return {
        "step_log": ["design mode: ReAct hunt completed"],
        "messages": result.get("messages", []),
    }


async def interpret(state: InvestigationState, tools: dict, model) -> dict:
    """Coverage mode: LLM + RAG interpret tool outputs into finding candidates.

    Tools already ran. Reads ledger + analysis/snippets.md (tool stdout/CSV heads).
    """
    try:
        from langgraph.prebuilt import create_react_agent
    except ImportError:
        return {"error": "langgraph not installed — run: pip install dfir-nexus[pipeline]"}

    interpret_tools = []
    for name in (
        "forensic_rag_search",
        "forensic_rag_status",
        "ingest_auto",
        "analyze_gaps",
        "predict_techniques",
        "check_file",
        "check_hash",
        "check_autorun",
        "suggest_tools",
        "suggest_windows_tools",
    ):
        t = tools.get(name)
        if t:
            interpret_tools.append(t)

    ledger = state.get("tool_run_ledger") or []
    ledger_summary = []
    for row in ledger:
        ledger_summary.append({
            "host": row.get("host"),
            "tool": row.get("tool"),
            "status": row.get("status"),
            "reason": row.get("reason", "")[:200],
            "audit_id": row.get("audit_id"),
            "output_saved_to": row.get("output_saved_to"),
            "purpose": row.get("purpose", "")[:120],
        })
    ledger_json = json.dumps(ledger_summary, indent=2)[:24000]
    ctx_block = _format_case_context(state.get("case_context") or {})
    rag_prior = "\n".join(state.get("rag_notes") or [])[:1500]

    snippets = ""
    case_id = state.get("case_id") or ""
    if case_id:
        from nexus.config import settings
        snip_path = settings.cases_root / case_id / "analysis" / "snippets.md"
        if snip_path.is_file():
            snippets = snip_path.read_text(encoding="utf-8", errors="replace")[:60000]
        else:
            try:
                from nexus.langgraph.snippets import write_snippets
                write_snippets(settings.cases_root / case_id, ledger)
                if snip_path.is_file():
                    snippets = snip_path.read_text(encoding="utf-8", errors="replace")[:60000]
            except Exception as exc:  # noqa: BLE001
                snippets = f"(snippet build failed: {exc})"

    from nexus.langgraph.itm import itm_prompt_block

    agent = create_react_agent(
        model,
        interpret_tools,
        prompt=(
            "You are a DFIR analyst writing evidence-backed findings.\n"
            f"Case: {state['case_id']}.\n"
            f"{_COVERAGE_MODE_RULES}\n"
            f"{ctx_block}\n"
            f"{itm_prompt_block()}\n"
            f"{_INTERPRETATION_RULES}\n"
            "FIRST call forensic_rag_status (must be ready). "
            "THEN forensic_rag_search at least twice (host triage + insider threat / "
            "data staging / cloud exfil). THEN emit findings JSON covering every "
            "OK tool family in the snippets. Do NOT re-run host triage tools."
        ),
    )

    try:
        result = await agent.ainvoke(
            {
                "messages": [{
                    "role": "human",
                    "content": (
                        f"Interpret coverage results for case {state['case_id']}.\n"
                        f"Evidence path: {state.get('evidence_path')}\n"
                        f"Prior RAG notes:\n{rag_prior or '(none)'}\n\n"
                        f"Tool lane ledger:\n```json\n{ledger_json}\n```\n\n"
                        f"TOOL OUTPUT SNIPPETS (facts must come from here):\n{snippets or '(none)'}\n\n"
                        "Emit a ```json array of findings. Each finding MUST have:\n"
                        "- title naming the analytic claim (not 'Successful Tool')\n"
                        "- observation quoting concrete snippet facts\n"
                        "- interpretation (non-empty) under the examiner hypothesis\n"
                        "- itm_stage + itm_objects from https://insiderthreatmatrix.org/\n"
                        "- confidence + confidence_justification\n"
                        "- audit_ids from the OK ledger rows that support the claim\n"
                        "- attack_ids only when justified by those facts\n"
                        "Cover ALL OK extraction families present in the snippets.\n"
                    ),
                }],
            },
            config={"recursion_limit": 40},
        )
        msg_count = len(result.get("messages", []))
        log.info("Interpret agent completed: %d messages", msg_count)
    except Exception as e:
        log.error("Interpret agent failed: %s", e)
        return {"step_log": [f"Interpret agent error: {e}"]}

    return {
        "step_log": ["coverage mode: interpretation completed"],
        "messages": result.get("messages", []),
    }

# Audit IDs: "{mcp_name}-{examiner}-{YYYYMMDD}-{seq}" (mcp_name may contain _)
_AUDIT_ID_RE = __import__("re").compile(
    r"\b[A-Za-z0-9_]+-[A-Za-z0-9_.-]+-\d{8}-\d{3,}\b"
)


def _audit_ids_from_messages(messages: list[Any]) -> list[str]:
    """Collect MCP audit_id values embedded in hunt tool results / text."""
    found: list[str] = []
    for msg in messages or []:
        content = msg
        if hasattr(msg, "content"):
            content = getattr(msg, "content")
        elif isinstance(msg, dict):
            content = msg.get("content", msg)
        text = content if isinstance(content, str) else str(content)
        for m in _AUDIT_ID_RE.findall(text):
            if m not in found:
                found.append(m)
        if isinstance(content, list):
            for block in content:
                blob = block if isinstance(block, str) else str(block)
                for m in _AUDIT_ID_RE.findall(blob):
                    if m not in found:
                        found.append(m)
    return found


def _audit_ids_from_case_log(case_id: str) -> list[str]:
    """Fallback: read case audit/*.jsonl for tool audit_ids."""
    if not case_id:
        return []
    from nexus.config import settings

    audit_dir = settings.cases_root / case_id / "audit"
    if not audit_dir.is_dir():
        return []
    ids: list[str] = []
    for path in sorted(audit_dir.glob("*.jsonl")):
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                aid = row.get("audit_id")
                if aid and aid not in ids:
                    ids.append(str(aid))
        except OSError:
            continue
    return ids


def _is_tool_audit_id(aid: str) -> bool:
    """True for MCP tool audit IDs (exclude bare sha256 / short tokens)."""
    return bool(aid and _AUDIT_ID_RE.fullmatch(aid))


def _finding_tool_payload(candidate: dict, trail: list[str]) -> dict:
    """Map a hunt/interpret candidate to ``record_finding`` MCP kwargs.

    Avoids passing raw ``type`` / unknown keys that FastMCP may reject silently.
    Prefer candidate audit_ids; only pad from trail IDs that look like tool audits.
    """
    aids = [str(a) for a in (candidate.get("audit_ids") or []) if a]
    for aid in trail:
        if aid not in aids:
            aids.append(aid)
        if len(aids) >= 10:
            break
    aids = aids[:10]
    arts = [
        a for a in (candidate.get("artifacts") or [])
        if isinstance(a, dict) and a.get("audit_id")
    ]
    for aid in aids:
        if not any(a.get("audit_id") == aid for a in arts):
            arts.append({"audit_id": aid, "type": "audit"})
    ftype = str(candidate.get("type") or candidate.get("finding_type") or "finding")
    conf = str(candidate.get("confidence") or "MEDIUM").upper()
    if conf not in {"HIGH", "LOW", "MEDIUM", "SPECULATIVE"}:
        conf = "MEDIUM"
    payload = {
        "title": str(candidate.get("title") or "Untitled finding")[:200],
        "observation": str(
            candidate.get("observation") or candidate.get("description") or ""
        )[:8000],
        "interpretation": str(
            candidate.get("interpretation")
            or candidate.get("observation")
            or "See observation / tool outputs."
        )[:8000],
        "confidence": conf,
        "confidence_justification": str(
            candidate.get("confidence_justification")
            or "Grounded in MCP tool audit_ids from this investigation."
        )[:2000],
        "finding_type": ftype if ftype in {
            "finding", "execution", "persistence", "attribution", "exclusion",
            "conclusion", "network", "lateral", "auth", "file", "registry", "other",
        } else "finding",
        "host": str(candidate.get("host") or "")[:200],
        "attack_ids": list(candidate.get("attack_ids") or candidate.get("mitre_ids") or []),
        "audit_ids": aids,
        "artifacts": arts[:10],
    }
    itm_stage = str(candidate.get("itm_stage") or "").strip()
    if itm_stage:
        payload["itm_stage"] = itm_stage[:80]
    itm_objects = [str(x) for x in (candidate.get("itm_objects") or []) if x][:12]
    if itm_objects:
        payload["itm_objects"] = itm_objects
    return payload


def _fallback_candidates_from_state(
    state: InvestigationState,
    trail: list[str],
    host_default: str,
) -> list[dict]:
    """Build staging candidates from the tool-lane ledger when LLM JSON is missing."""
    ledger = state.get("tool_run_ledger") or []
    ok_rows = [r for r in ledger if r.get("status") == "OK" and r.get("audit_id")]
    ctx = state.get("case_context") or {}
    hyp = str(ctx.get("hypothesis") or "").strip()
    hyp_note = (
        f" Examiner hypothesis '{hyp}' is context only — evidence from this tool wins."
        if hyp else ""
    )
    out: list[dict] = []
    if ok_rows:
        for row in ok_rows[:12]:
            aid = str(row["audit_id"])
            tool = row.get("tool") or "tool"
            host = row.get("host") or host_default or ""
            saved = row.get("output_saved_to") or ""
            purpose = row.get("purpose") or tool
            out.append({
                "title": f"{host}/{tool}: {purpose}"[:200],
                "observation": (
                    f"Tool '{tool}' on {host or 'host'} completed OK "
                    f"(audit_id={aid})."
                    + (f" Output: {saved}." if saved else "")
                ),
                "interpretation": (
                    f"Coverage/collection evidence for '{purpose}'. "
                    f"Review the saved output for insider-threat or other signals."
                    f"{hyp_note} Not itself a compromise conclusion."
                ),
                "confidence": "MEDIUM",
                "confidence_justification": f"FD-001 via MCP audit_id {aid}.",
                "host": host,
                "type": "finding",
                "audit_ids": [aid],
                "artifacts": [{"audit_id": aid, "type": "audit"}],
            })
        return out

    if trail:
        mode = state.get("pipeline_mode") or "design"
        ok_n = sum(1 for r in ledger if r.get("status") == "OK")
        return [{
            "title": (
                f"Coverage tool lane complete — {state.get('case_id')} ({ok_n} OK)"
                if mode == "coverage"
                else f"ReAct hunt complete — {state.get('case_id')}"
            ),
            "observation": (
                f"Pipeline produced {len(trail)} MCP audit_ids without parseable "
                f"finding JSON from the LLM step."
            ),
            "interpretation": (
                "Examiner should review case/extractions and the audit trail. "
                f"Placeholder only.{hyp_note}"
            ),
            "confidence": "LOW",
            "confidence_justification": "FD-001 via MCP audit_ids; LLM JSON not parsed.",
            "host": host_default,
            "type": "finding",
            "audit_ids": trail[:10],
            "artifacts": [{"audit_id": a, "type": "audit"} for a in trail[:10]],
        }]
    return []


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

    trail = list(state.get("evidence_audit_ids") or [])
    for row in state.get("tool_run_ledger") or []:
        # Prefer OK tool audits for FD-001; FAIL rows may lack a verified bridge entry
        if row.get("status") != "OK":
            continue
        aid = row.get("audit_id")
        if aid and aid not in trail:
            trail.append(str(aid))
    for aid in _audit_ids_from_messages(state.get("messages", [])):
        if aid not in trail:
            trail.append(aid)
    for aid in _audit_ids_from_case_log(state.get("case_id", "")):
        if aid not in trail:
            trail.append(aid)
    # Prefer structured tool-run IDs over bare evidence hashes for FD-001
    tool_trail = [a for a in trail if _is_tool_audit_id(a)]
    trail = tool_trail or trail

    ctx = state.get("case_context") or {}
    host_default = str(ctx.get("host") or "").strip()
    candidates = parse_hunt_candidates(state.get("messages", []))
    # If LLM JSON missing/unparseable, synthesize candidates from ledger / trail
    if not candidates and trail:
        candidates = _fallback_candidates_from_state(state, trail, host_default)

    async def _stage_one(candidate: dict) -> None:
        nonlocal draft_ids
        payload = _finding_tool_payload(candidate, trail)
        try:
            result = _parse_tool_result(await finding_tool.ainvoke(payload))
        except Exception as e:
            errors.append(str(e))
            return
        fid = result.get("finding_id") or result.get("id")
        if fid:
            draft_ids.append(fid)
            log.info("Finding staged: %s", fid)
            return
        if result.get("status") == "REJECTED":
            errors.append(str(result.get("error") or result.get("missing_audit_ids") or result))
        elif result.get("status") == "VALIDATION_FAILED":
            errors.append(str(result.get("errors") or result))
        elif result.get("error"):
            errors.append(str(result["error"]))
        else:
            errors.append(f"unexpected record_finding result: {str(result)[:300]}")

    if candidates:
        for candidate in candidates:
            await _stage_one(candidate)

        # Last resort: LLM candidates all failed but we still have tool audit_ids
        if not draft_ids and trail:
            errors.append("LLM/parsed candidates failed staging — using ledger fallback")
            for candidate in _fallback_candidates_from_state(state, trail, host_default):
                await _stage_one(candidate)

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
        errors.append(
            "No hunt candidates and no MCP audit_ids available for FD-001 staging"
        )

    log_msg = [
        f"Staged {len(draft_ids)} findings, {len(timeline_ids)} timeline events",
        f"audit_trail_ids={len(trail)}",
    ]
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
    """Generate an IR report from approved findings.

    Calls MCP ``generate_report`` when available, then always writes a durable
    ``case/reports/dfir-report.md`` on the case-authority host from APPROVED
    findings + CASE.yaml + extractions (so the artifact is not MCP-profile gated).
    """
    report_tool = tools.get("generate_report")
    profile = "full" if state.get("approved_finding_ids") else "status"
    step_log: list[str] = []

    if report_tool:
        result = _parse_tool_result(await report_tool.ainvoke({
            "profile": profile,
            "case_id": state["case_id"],
            "finding_ids": state.get("approved_finding_ids") or None,
        }))
        if result.get("error"):
            step_log.append(f"MCP generate_report warning: {result['error']}")
        else:
            step_log.append(f"MCP report generated ({profile} profile)")
    else:
        step_log.append("generate_report MCP tool not available — writing local markdown")

    report_path: str | None = None
    export_root: str | None = None
    try:
        import json as _json
        import yaml
        from nexus.config import settings
        from nexus.cli.report import _extraction_notes, _load_flat_evidence
        from nexus.integration.dfir_report import build_dfir_markdown

        case_dir = settings.cases_root / state["case_id"]
        findings_path = case_dir / "findings.json"
        findings = []
        if findings_path.is_file():
            findings = _json.loads(findings_path.read_text(encoding="utf-8"))
        meta: dict = {}
        case_yaml = case_dir / "CASE.yaml"
        if case_yaml.is_file():
            meta = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
        timeline = []
        tl_path = case_dir / "timeline.json"
        if tl_path.is_file():
            timeline = _json.loads(tl_path.read_text(encoding="utf-8"))
        # Prefer sift/ notes when pulled; else windows extractions
        sift_notes = _extraction_notes(case_dir / "sift" / "extractions")
        if not sift_notes:
            sift_notes = _extraction_notes(case_dir / "extractions")
        evidence = _load_flat_evidence(case_dir)
        ledger = list(state.get("tool_run_ledger") or [])
        ev_path = state.get("evidence_path") or ""
        if ev_path and not any(
            (e.get("path") or "") == ev_path for e in evidence
        ):
            evidence.append({"name": "Registered evidence path", "path": ev_path})
        for row in ledger:
            saved = row.get("output_saved_to")
            if not saved:
                continue
            name = f"{row.get('host')}/{row.get('tool')}"
            if any((e.get("path") or "") == saved for e in evidence):
                continue
            evidence.append({
                "name": name,
                "path": saved,
                "description": row.get("purpose") or "",
            })
        md = build_dfir_markdown(
            case_id=state["case_id"],
            case_name=meta.get("name") or state["case_id"],
            findings=findings,
            evidence=evidence,
            timeline=timeline,
            sift_notes=sift_notes,
            rag_notes=list(state.get("rag_notes") or []),
            examiner=str(meta.get("examiner") or ""),
            status=str(meta.get("status") or "open"),
            case_summary=str(meta.get("description") or ""),
            tool_ledger=ledger,
        )
        # Append analysis snippets pointer for examiners
        snip = case_dir / "analysis" / "snippets.md"
        if snip.is_file():
            md += (
                "\n\n## Analysis Snippets\n\n"
                "Full tool-output heads used for LLM interpretation are in "
                "`analysis/snippets.md` (also exported under the repo case tree).\n"
            )
        out = case_dir / "reports" / "REPORT.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(md, encoding="utf-8")
        # Keep legacy name too
        (case_dir / "reports" / "dfir-report.md").write_text(md, encoding="utf-8")
        step_log.append(f"Wrote {out}")

        from nexus.case.repo_export import export_case_to_repo

        exported = export_case_to_repo(
            case_dir,
            report_markdown=md,
            extra_sift_dir=case_dir / "sift" / "extractions",
        )
        export_root = str(exported)
        report_path = str(exported / "reports" / "REPORT.md")
        step_log.append(f"Repo export: {exported}")
    except Exception as exc:  # noqa: BLE001
        step_log.append(f"Local report/export failed: {exc}")
        return {"error": str(exc), "step_log": step_log}

    return {
        "report_path": report_path,
        "step_log": step_log,
        "rag_notes": [f"repo_export={export_root}"] if export_root else [],
    }


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_graph(tools: dict, model, mode: str | None = None):
    """Build the investigation graph for ``design``, ``coverage``, or ``tools``."""
    from langgraph.graph import END, StateGraph

    mode = resolve_pipeline_mode(mode)

    async def _register_evidence(state: InvestigationState) -> dict:
        return await register_evidence(state, tools)

    async def _scope(state: InvestigationState) -> dict:
        return await scope(state, tools, model)

    async def _scope_tools_only(state: InvestigationState) -> dict:
        """No MCP RAG / suggest — hosts from case_context only."""
        ctx = state.get("case_context") or {}
        hosts = []
        host_ctx = str(ctx.get("host") or "").strip()
        if host_ctx:
            hosts.append(host_ctx)
        return {
            "hosts": hosts,
            "step_log": [f"tools mode scope: {len(hosts)} host(s) from case_context"],
        }

    async def _ensure_rag(state: InvestigationState) -> dict:
        return await ensure_rag_ready(state, tools)

    async def _load_existing(state: InvestigationState) -> dict:
        return await load_existing_case(state, tools)

    async def _hunt(state: InvestigationState) -> dict:
        return await hunt(state, tools, model)

    async def _execute_tool_lane(state: InvestigationState) -> dict:
        return await execute_tool_lane(state, tools)

    async def _interpret(state: InvestigationState) -> dict:
        return await interpret(state, tools, model)

    async def _stage_findings(state: InvestigationState) -> dict:
        return await stage_findings(state, tools)

    async def _generate_report(state: InvestigationState) -> dict:
        return await generate_report(state, tools)

    async def _emit_tool_report(state: InvestigationState) -> dict:
        return await emit_tool_report(state, tools)

    workflow = StateGraph(InvestigationState)

    if mode == "tools":
        workflow.add_node("register_evidence", _register_evidence)
        workflow.add_node("scope", _scope_tools_only)
        workflow.add_node("execute_tool_lane", _execute_tool_lane)
        workflow.add_node("emit_tool_report", _emit_tool_report)
        workflow.set_entry_point("register_evidence")
        workflow.add_edge("register_evidence", "scope")
        workflow.add_edge("scope", "execute_tool_lane")
        workflow.add_edge("execute_tool_lane", "emit_tool_report")
        workflow.add_edge("emit_tool_report", END)
        return workflow

    workflow.add_node("ensure_rag", _ensure_rag)
    workflow.set_entry_point("ensure_rag")

    if mode == "interpret":
        workflow.add_node("load_existing", _load_existing)
        workflow.add_node("interpret", _interpret)
        workflow.add_node("stage_findings", _stage_findings)
        workflow.add_node("await_approval", await_approval)
        workflow.add_node("generate_report", _generate_report)
        workflow.add_edge("ensure_rag", "load_existing")
        workflow.add_edge("load_existing", "interpret")
        workflow.add_edge("interpret", "stage_findings")
        workflow.add_edge("stage_findings", "await_approval")
        workflow.add_edge("await_approval", "generate_report")
        workflow.add_edge("generate_report", END)
        return workflow

    workflow.add_node("register_evidence", _register_evidence)
    workflow.add_node("scope", _scope)
    workflow.add_node("stage_findings", _stage_findings)
    workflow.add_node("await_approval", await_approval)
    workflow.add_node("generate_report", _generate_report)
    workflow.add_edge("ensure_rag", "register_evidence")
    workflow.add_edge("register_evidence", "scope")

    if mode == "coverage":
        workflow.add_node("execute_tool_lane", _execute_tool_lane)
        workflow.add_node("interpret", _interpret)
        workflow.add_edge("scope", "execute_tool_lane")
        workflow.add_edge("execute_tool_lane", "interpret")
        workflow.add_edge("interpret", "stage_findings")
    else:
        workflow.add_node("execute_tool_lane", _execute_tool_lane)
        workflow.add_node("hunt", _hunt)
        workflow.add_node("interpret", _interpret)
        workflow.add_edge("scope", "execute_tool_lane")
        workflow.add_edge("execute_tool_lane", "hunt")
        workflow.add_edge("hunt", "interpret")
        workflow.add_edge("interpret", "stage_findings")

    workflow.add_edge("stage_findings", "await_approval")
    workflow.add_edge("await_approval", "generate_report")
    workflow.add_edge("generate_report", END)

    return workflow


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def _load_mcp_tools(config: dict[str, dict]) -> dict[str, Any]:
    """Load MCP tools with Windows as case authority when dual-host.

    Shared names (case_init, record_finding, …) prefer ``nexus-windows``.
    SIFT ``case_init`` / ``case_activate`` are retained as ``_sift_case_*``
    so the pipeline can mirror the same case_id onto the tool host.
    """
    from langchain_mcp_adapters.client import MultiServerMCPClient

    tools_by_name: dict[str, Any] = {}
    if not config:
        return tools_by_name

    # Load one server at a time so we know provenance (merged get_tools loses it).
    for server_name, server_cfg in config.items():
        client = MultiServerMCPClient({server_name: server_cfg})
        try:
            tools_list = await client.get_tools()
        except Exception as exc:  # noqa: BLE001
            log.error("Failed loading MCP tools from %s: %s", server_name, exc)
            continue
        is_sift = server_name == "nexus-sift" or "sift" in server_name.lower()
        is_windows = (
            server_name == "nexus-windows"
            or "windows" in server_name.lower()
            or (not is_sift and len(config) == 1)
        )
        for t in tools_list:
            name = t.name
            if is_sift and name in ("case_init", "case_activate"):
                tools_by_name[f"_sift_{name}"] = t
            # Windows examiner host wins collisions (case/findings/report authority).
            if name not in tools_by_name or is_windows:
                tools_by_name[name] = t

    return tools_by_name


async def run_pipeline(
    evidence_path: str = "",
    resume: bool = False,
    thread_id: str = "",
    model_name: str = "",
    case_context: dict[str, str] | None = None,
    mode: str | None = None,
):
    """Run the DFIR-Nexus LangGraph investigation pipeline."""
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.types import Command

    pipeline_mode = resolve_pipeline_mode(mode)
    log.info("Pipeline mode: %s", pipeline_mode)

    config = get_mcp_config()
    tools_by_name = await _load_mcp_tools(config)
    log.info(
        "MCP tools loaded: %d (has run_command=%s run_windows_command=%s sift_mirror=%s)",
        len(tools_by_name),
        "run_command" in tools_by_name,
        "run_windows_command" in tools_by_name,
        "_sift_case_init" in tools_by_name,
    )

    validate_tools(tools_by_name)
    if pipeline_mode == "tools":
        model = None
        interrupt_nodes: list[str] = []
    else:
        model = get_model(model_name)
        interrupt_nodes = ["await_approval"]

    graph = build_graph(tools_by_name, model, mode=pipeline_mode)
    checkpointer = MemorySaver()
    compiled = graph.compile(checkpointer=checkpointer, interrupt_before=interrupt_nodes)

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

    initial = make_initial_state(
        evidence_path=evidence_path,
        case_context=case_context,
        pipeline_mode=pipeline_mode,
    )
    result = await compiled.ainvoke(initial, config=cfg)

    result_state = result if isinstance(result, dict) else {}
    log.info("Pipeline complete")
    log.info("  Mode:         %s", pipeline_mode)
    log.info("  Case ID:      %s", result_state.get("case_id", "N/A"))
    log.info("  Approved:     %s", len(result_state.get("approved_finding_ids", [])))
    log.info("  Draft:        %s", len(result_state.get("draft_finding_ids", [])))
    log.info("  Report:       %s", result_state.get("report_path", "N/A"))
    log.info("  Steps:        %d", len(result_state.get("step_log", [])))
