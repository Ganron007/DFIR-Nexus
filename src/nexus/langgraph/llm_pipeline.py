"""LLM-driven LangGraph pipeline for DFIR-Nexus.

Connects to the DFIR-Nexus MCP server (via stdio or HTTP), drives a
StateGraph investigation flow. Three switchable modes (no hybrid graph):

  tools            — mandatory parser lane only; **no RAG, no LLM**; TOOL-RUN.md
  coverage (debug) — same mandatory lane; RAG+LLM interpret ledger + case digest
  design           — RAG load, mandatory lane, then ReAct may **add** extras
  interpret        — reuse an existing tool-run case (``--from-case``)

  REPORT.md (coverage/design/interpret) is a **deterministic template** from
  APPROVED findings — the LLM fills observation/interpretation, not the file
  structure. N5 reads the case digest (its top leads cite the calls that hold their rows)
  and queries the index itself; ``analysis/query_pack.md`` is the examiner's needle file.
  See Docs/cases/TOOL-EVIDENCE-MAP.md.

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

import asyncio
import contextlib
import json
import logging
import os
import re
from datetime import UTC, datetime
from operator import add
from pathlib import Path
from typing import Annotated, Any, TypedDict

from nexus.langgraph.tool_call import call_timeout, call_tool

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
    evidence_paths: list[str]
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
    run_id: str
    run_dir: str
    parent_run_id: str
    # WO-1C item 3: `independent` (default) or `informed`. Decided before the
    # run and recorded on the run record, so a report can always say which
    # policy produced it.
    context_policy: str
    # D193: the interpret loop's answers for digest items it makes no claim about. Declared, so
    # LangGraph carries them from the interpret node to staging and the verdict.
    dispositions: list[dict[str, Any]]
    # Live stage feed (JSONL the dashboard reads while the run is in flight)
    progress_path: str


def make_initial_state(
    evidence_path: str = "",
    case_context: dict[str, str] | None = None,
    pipeline_mode: str | None = None,
    case_id: str = "",
    evidence_paths: list[str] | None = None,
    progress_path: str = "",
) -> InvestigationState:
    paths = [p for p in (evidence_paths or []) if str(p).strip()]
    if evidence_path and evidence_path not in paths:
        paths = [evidence_path] + paths
    return {
        "case_id": case_id,
        "evidence_path": evidence_path or (paths[0] if paths else ""),
        "evidence_paths": paths,
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
        "run_id": "",
        "run_dir": "",
        "parent_run_id": "",
        "context_policy": "independent",
        "dispositions": [],
        "progress_path": str(progress_path or ""),
    }


def emit_stage(state: InvestigationState | dict, stage: str, status: str,
               detail: str = "", **extra: Any) -> None:
    """Append one stage event to the live progress JSONL (best-effort).

    ``extra`` carries the granular fields the live feed renders (``tool``,
    ``host``, ``command``, ``duration_s``, ``output``, ``reason``,
    ``audit_id``) — scalar values only, capped, never nested.
    """
    # Every stage also goes to the `nexus.progress` logger, which the CLI prints. A CLI run has
    # no progress file, so a 40-minute Mode 1 run used to print nothing until it ended and
    # read as stuck (2026-10-14).
    logging.getLogger("nexus.progress").info(
        "%s %s%s", stage, status, f": {str(detail)[:200]}" if detail else "")
    path_raw = ""
    if isinstance(state, dict):
        path_raw = str(state.get("progress_path") or "")
    if not path_raw:
        return
    try:
        from datetime import UTC, datetime

        path = Path(path_raw)
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "stage": stage,
            "status": status,
            "detail": str(detail)[:300],
        }
        for key, value in (extra or {}).items():
            if key not in _PROGRESS_EXTRA_KEYS or value in (None, "", [], {}):
                continue
            if isinstance(value, (int, float, bool)):
                entry[key] = value
            else:
                entry[key] = str(value)[:400]
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


# Allowlisted journal extras (scalar, feed-rendered).
_PROGRESS_EXTRA_KEYS = frozenset({
    "tool", "host", "command", "duration_s", "output", "reason", "audit_id",
    "round", "rounds", "docs", "rows",
})


def _is_placeholder_intake(text: str) -> bool:
    """True when the string is empty or examiner boilerplate, not a real N1 value."""
    collapsed = re.sub(r"\s+", " ", (text or "").strip()).strip(" .;:-")
    if not collapsed:
        return True
    low = collapsed.lower()
    if "evidence timestamps win" in low:
        return True
    if low.startswith("examiner-supplied") or low.startswith("examiner supplied"):
        return True
    return low in {
        "tbd",
        "n/a",
        "na",
        "none",
        "unknown",
        "placeholder",
        "examiner-supplied",
        "examiner supplied",
    }


def has_examiner_intake(ctx: dict[str, str] | None) -> bool:
    """N1 gate: a real examiner question or incident window.

    Placeholder window text (``examiner-supplied; evidence timestamps win``)
    does not count as intake — coverage/design must degrade to TOOL-RUN.
    """
    ctx = ctx or {}
    question = str(ctx.get("question") or "")
    window = str(ctx.get("window") or "")
    return (not _is_placeholder_intake(question)) or (
        not _is_placeholder_intake(window)
    )


def _format_case_context(ctx: dict[str, str] | None) -> str:
    """Human-readable case intake for interpretation prompts."""
    ctx = ctx or {}
    keys = (
        "name", "description", "hypothesis", "notes", "host",
        "timezone", "window", "subjects", "known_good", "question", "playbooks", "extras",
        "query_extra", "set_by",
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


def _registry_context_block(state: InvestigationState | dict, cap: int = 900) -> str:
    """AI/malware registry matches (ATLAS/MBC) for the case question (F7)."""
    try:
        from nexus.knowledge.registry_context import (
            atlas_context_for,
            mbc_context_for,
        )

        question = str((state.get("case_context") or {}).get("question") or "")
        parts = [
            text
            for text in (atlas_context_for(question), mbc_context_for(question))
            if text
        ]
        if not parts:
            return ""
        return ("Framework registry matches (ATLAS/MBC):\n" + "\n".join(parts))[:cap]
    except Exception:  # noqa: BLE001 — optional registries
        return ""


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

# What get_model actually built, so a run record can name the model that was
# called instead of re-deriving it from the environment (D48). The second
# parser disagreed with the first: 36c's three modes ran on two models and the
# records did not show it.
_BUILT_MODEL: dict[str, str] = {"provider": "none", "model": "none"}


def built_model_record() -> dict[str, str]:
    """Provider and model of the last model `get_model` built.

    This is the only source for a run record's ``model`` field. A value of
    ``none`` means no model was built in this process, which is different from
    "a model ran" — a deterministic (no-LLM) run records it, and a run that
    never built one is not read as having used a model.
    """
    return dict(_BUILT_MODEL)


def _record_built_model(provider: str, model: str) -> None:
    _BUILT_MODEL["provider"] = provider or "none"
    _BUILT_MODEL["model"] = model or "none"


def _llm_extra_body() -> dict[str, Any]:
    """NEXUS_LLM_EXTRA_BODY: a JSON object of request fields for an OpenAI-compatible host.

    A value that is not a JSON object is refused loudly: a silently dropped setting would let a
    run go out without the switch the operator set.
    """
    raw = os.environ.get("NEXUS_LLM_EXTRA_BODY", "").strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise RuntimeError(f"NEXUS_LLM_EXTRA_BODY is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("NEXUS_LLM_EXTRA_BODY must be a JSON object")
    return value


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

    The provider and model of the object it returns are recorded (D48), so
    ``built_model_record()`` always names what was actually constructed.
    """
    _load_dotenv()
    from nexus.llm.providers import llm_timeout

    model = model_name or os.environ.get("NEXUS_LLM_MODEL", "")
    base_url = os.environ.get("NEXUS_LLM_BASE_URL", "")
    api_key = os.environ.get("NEXUS_LLM_API_KEY", "")
    provider = os.environ.get("NEXUS_LLM_PROVIDER", "").lower()
    reasoning = os.environ.get("NEXUS_LLM_REASONING", "")
    # Every client gets the call timeout: a slow model makes a run slow, a stalled one must never hold it.
    # Only the OpenAI-compatible client had one, so a local Ollama model or Anthropic could hang a run (D228).
    timeout = llm_timeout()

    if not model:
        # Legacy prefix form: "openai/gpt-4o", "ollama/qwen...", anthropic name
        legacy = os.environ.get("NEXUS_MODEL", "")
        if legacy.startswith("openai/"):
            from langchain_openai import ChatOpenAI
            built = legacy[len("openai/"):] or "gpt-4o"
            _record_built_model("openai", built)
            return ChatOpenAI(model=built, timeout=timeout)
        if legacy.startswith("ollama/"):
            try:
                from langchain_ollama import ChatOllama
            except ImportError:
                raise RuntimeError(
                    "langchain-ollama not installed — run: pip install langchain-ollama"
                ) from None
            built = legacy[len("ollama/"):]
            _record_built_model("ollama", built)
            return ChatOllama(model=built, client_kwargs={"timeout": timeout})
        if legacy:
            from langchain_anthropic import ChatAnthropic
            _record_built_model("anthropic", legacy)
            return ChatAnthropic(model=legacy, timeout=timeout)
        # No model configured. The run record must not claim one ran (D48).
        _record_built_model("none", "none")
        raise RuntimeError(
            "No LLM configured. Create a .env with NEXUS_LLM_MODEL (plus "
            "NEXUS_LLM_BASE_URL / NEXUS_LLM_API_KEY for hosted providers), "
            "or set NEXUS_MODEL."
        )

    if provider == "anthropic" and not base_url:
        from langchain_anthropic import ChatAnthropic
        kwargs: dict[str, Any] = {"timeout": timeout}
        if api_key:
            kwargs["api_key"] = api_key
        _record_built_model("anthropic", model)
        return ChatAnthropic(model=model, **kwargs)

    if provider == "ollama" and not base_url:
        try:
            from langchain_ollama import ChatOllama
        except ImportError:
            raise RuntimeError(
                "langchain-ollama not installed — run: pip install langchain-ollama"
            ) from None
        _record_built_model("ollama", model)
        return ChatOllama(model=model, client_kwargs={"timeout": timeout})

    # Default: any OpenAI-compatible endpoint (StepFun, OpenAI, LiteLLM,
    # vLLM, Ollama /v1, ...)
    from langchain_openai import ChatOpenAI
    kwargs = {"model": model, "api_key": api_key or "not-needed"}
    if base_url:
        kwargs["base_url"] = base_url
    # Explicit client timeout — a stalled provider must never hang a turn
    # (the 4j.33 latency budget depends on this).
    kwargs["timeout"] = timeout
    # reasoning_effort is an OpenAI-only param. Compatible hosts (e.g.
    # StepFun) reject it as "no active step plan subscription".
    if reasoning:
        host = ""
        try:
            from urllib.parse import urlparse
            host = (urlparse(base_url).hostname or "").lower()
        except Exception:
            host = ""
        openai_like = (
            provider == "openai"
            or host.endswith("openai.com")
            or host.endswith("openai.azure.com")
            or (not base_url and not provider)
        )
        if openai_like:
            kwargs["extra_body"] = {"reasoning_effort": reasoning}
        else:
            # Said, not dropped without a word: agnes-3.0-flash has no reasoning levels, and
            # NEXUS_LLM_REASONING=high sat in the operator's .env for every run (2026-10-15).
            log.warning(
                "NEXUS_LLM_REASONING=%s is not sent to %s: reasoning_effort is an OpenAI parameter. "
                "Set the host's own switch in NEXUS_LLM_EXTRA_BODY instead.", reasoning, host or base_url)
    # A host's own request fields, declared in NEXUS_LLM_EXTRA_BODY as JSON, e.g. agnes-3.0-flash's
    # thinking switch {"chat_template_kwargs": {"enable_thinking": true}}: an OpenAI-compatible host
    # names its parameters its own way, and NEXUS_LLM_REASONING only reaches OpenAI hosts.
    extra = _llm_extra_body()
    if extra:
        kwargs["extra_body"] = {**kwargs.get("extra_body", {}), **extra}
    built = ChatOpenAI(**kwargs)
    _record_built_model(provider or "openai-compatible", model)
    from nexus.llm.egress import attach_egress, egress_required

    if egress_required(base_url):
        return attach_egress(built)
    return built


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
            "env": _stdio_mcp_env(),
        }
    }


def _stdio_mcp_env() -> dict[str, str]:
    """Pass a full env to the stdio MCP child.

    LangChain stdio spawn does not reliably inherit the parent environment.
    Without this copy, ``NEXUS_RAG_PRELOAD=0`` is ignored and the child
    reloads the CUDA embedder on every tool call.

    ``NEXUS_MCP_CHILD`` marks this process as a per-call pipeline child: a
    child must never reap run records (it would mark its own caller's live
    run ``interrupted`` - the 2026-09-29 flow-test hang).
    """
    env = {str(k): str(v) for k, v in os.environ.items()}
    env["NEXUS_MCP_CHILD"] = "1"
    raw = env.get("NEXUS_PIPELINE_MODE", "").strip()
    if raw:
        try:
            if resolve_pipeline_mode(raw) == "tools":
                env["NEXUS_RAG_PRELOAD"] = "0"
        except ValueError:
            pass
    return env


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
    existing = (state.get("case_id") or "").strip()
    case_name = (
        str(ctx.get("name") or "").strip()
        or f"LangGraph Investigation - {Path(state.get('evidence_path') or 'evidence').name}"
    )
    desc_parts = [
        str(ctx.get("description") or "").strip(),
        str(ctx.get("hypothesis") or "").strip(),
        "Automated investigation via LangGraph dual-MCP pipeline "
        "(Windows examiner authority + SIFT tool host; shared case_id).",
    ]
    case_desc = " | ".join(p for p in desc_parts if p)

    if existing:
        case_id = existing
        log.info("Reusing case (authority): %s", case_id)
        # The run is bound to this case by its id: run_windows_command takes case_id and run_id (D41).
        # The examiner host's case_activate is not called. Its plain name is the Windows server's tool
        # (llm_pipeline._load_mcp_tools), and it writes this machine's global active-case pointer
        # (tools/case.py), which a pipeline run must not change (2026-10-11).
        from nexus.config import settings as _bind_settings

        if not (_bind_settings.cases_root / case_id / "CASE.yaml").is_file():
            return {"error": f"Case not found: {case_id}"}
        step_log = [f"Reusing case {case_id} (no new INC id; the global active case is not changed)"]
    else:
        case_id = f"INC-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
        result = _parse_tool_result(await call_tool(
            case_tool,
            {
                "name": case_name,
                "description": case_desc,
                "case_id": case_id,
            },
            label="case_init",
        ))
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
    if existing and sift_activate:
        act = _parse_tool_result(
            await call_tool(sift_activate, {"case_id": case_id}, label="case_activate(sift)")
        )
        if act.get("error") and sift_init:
            mirror = _parse_tool_result(await call_tool(
                sift_init,
                {
                    "name": case_name,
                "description": case_desc,
                "case_id": case_id,
            }))
            if mirror.get("error"):
                step_log.append(f"SIFT case mirror warning: {mirror.get('error')}")
            else:
                step_log.append(f"Case {case_id} mirrored on SIFT")
                act = _parse_tool_result(
                    await call_tool(
                        sift_activate, {"case_id": case_id}, label="case_activate(sift)"
                    )
                )
        if act.get("error"):
            step_log.append(f"SIFT case_activate warning: {act.get('error')}")
        else:
            step_log.append(f"Case {case_id} activated on SIFT")
    elif sift_init:
        mirror = _parse_tool_result(await call_tool(
            sift_init,
            {
                "name": case_name,
                "description": case_desc,
                "case_id": case_id,
            },
            label="case_init(sift)",
        ))
        if mirror.get("error"):
            step_log.append(f"SIFT case mirror warning: {mirror.get('error')}")
            log.warning("SIFT case_init mirror failed: %s", mirror.get("error"))
        else:
            step_log.append(f"Case {case_id} mirrored on SIFT")
            if sift_activate:
                act = _parse_tool_result(
                    await call_tool(
                        sift_activate, {"case_id": case_id}, label="case_activate(sift)"
                    )
                )
                if act.get("error"):
                    step_log.append(f"SIFT case_activate warning: {act.get('error')}")
                else:
                    step_log.append(f"Case {case_id} activated on SIFT")
    else:
        step_log.append(
            "SIFT case mirror skipped (single-host or no sift case_init handle)"
        )

    ev_tool = tools.get("evidence_register")
    audit_ids = []
    paths = list(state.get("evidence_paths") or [])
    primary = state.get("evidence_path") or ""
    if primary and primary not in paths:
        paths = [primary] + paths
    if ev_tool:
        for p in paths:
            if not p:
                continue
            ev_result = _parse_tool_result(await call_tool(
                ev_tool,
                {
                    "path": p,
                    "description": "Evidence for automated investigation",
                    # The run's own case: the registry takes it there, never the global active case.
                    "case_id": case_id,
                },
                label="evidence_register",
                # A content hash of a multi-GB image or triage tree is the
                # tool's work. The 300s control-call budget killed it on
                # rd01 (evidence_register, tool budget none) before the lane
                # planned a single parser.
                timeout=_evidence_register_budget(p),
            ))
            aid = ev_result.get("audit_id") or ev_result.get("sha256", "")
            if aid:
                audit_ids.append(aid)
            if ev_result.get("error"):
                step_log.append(f"Evidence register warning ({p}): {ev_result.get('error')}")
            elif ev_result.get("status") == "already_registered":
                step_log.append(f"Evidence already registered (unchanged): {p}")
            else:
                step_log.append(f"Evidence registered: {p}")

    try:
        from nexus.config import settings
        from nexus.langgraph.pipeline_runs import create_run

        pipeline_run = create_run(
            settings.cases_root / case_id,
            state.get("pipeline_mode") or "tools",
            paths,
        )
        step_log.append(f"Started immutable run {pipeline_run.run_id}")
    except (OSError, ValueError) as exc:
        return {"error": f"Could not create immutable pipeline run: {exc}", "step_log": step_log}

    return {
        "case_id": case_id,
        "evidence_audit_ids": audit_ids,
        "run_id": pipeline_run.run_id,
        "run_dir": str(pipeline_run.path),
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
            suggestions = await call_tool(
                suggest_tool, {"artifact_type": "evtx"}, label="suggest_tools"
            )
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
            await call_tool(rag_tool, {"query": rag_q[:400]}, label="forensic_rag_search")
        host_ctx = str(ctx.get("host") or "").strip()
        if host_ctx and host_ctx not in hosts:
            hosts.append(host_ctx)

    return {
        "hosts": hosts,
        "step_log": [f"Scoped investigation: {len(hosts)} hosts identified"],
    }


def _import_file_cap() -> int:
    """Optional operator cap on files routed to importers. 0 = unlimited.

    D50's lesson: a silent cap drops evidence while the gate still reports the
    lane complete. If the operator sets one, every file it drops is counted and
    reported - never skipped quietly.
    """
    raw = os.environ.get("NEXUS_IMPORT_FILE_CAP", "").strip()
    if not raw:
        return 0
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _i1_route(path: str | Path, *, windows_root: Path | None = None) -> str:
    """Assign an evidence file to the host lane or the confirmed importer lane."""
    from nexus.ingest.detect import has_importer
    from nexus.langgraph.tool_lane import is_host_evidence

    candidate = Path(path)
    if is_host_evidence(candidate):
        return "host"
    if windows_root is None:
        # A registered single file may be nested inside a drive tree rather
        # than reached by walking the tree. Bound discovery to this case's
        # evidence directory; an unbounded ancestor search can mistake the
        # analyst workstation's own C:\Windows for the evidence image.
        from nexus.langgraph.tool_lane import find_windows_root

        evidence_dir = next(
            (parent for parent in candidate.parents if parent.name.lower() == "evidence"),
            None,
        )
        if evidence_dir is not None:
            windows_root = find_windows_root(evidence_dir)
    if windows_root is not None:
        try:
            candidate.relative_to(windows_root)
        except ValueError:
            pass
        else:
            return "importer" if has_importer(candidate) else "host-unconfirmed"
    return "importer"


async def execute_tool_lane(state: InvestigationState, tools: dict) -> dict:
    """Deterministic MCP triage - all applicable tools run (coverage/tools)."""
    from nexus.langgraph.tool_lane import run_tool_lane

    case_id = state.get("case_id") or ""
    if not case_id:
        return {"error": "No case_id — cannot run tool lane"}

    mode = state.get("pipeline_mode") or "coverage"

    def _lane_event(status: str, detail: str, extra: dict[str, Any]) -> None:
        """Per-job tool events -> the same live feed the stages use."""
        emit_stage(state, "tool", status, detail, **extra)

    # D276: an archive in the evidence is expanded first, and the tree it holds is planned like registered evidence;
    # the archive file itself is then not an importer's input.
    from nexus.config import settings as _arch_settings
    from nexus.langgraph.evidence_archives import (
        archive_gate_rows,
        expand_archives,
        is_expansion_marker,
    )

    registered = [p for p in (state.get("evidence_paths") or [state.get("evidence_path")]) if p]
    # D285: a Magnet AXIOM case is read from its Case.mfdb; its own index, logs, log archive and attachment store
    # are gate rows that say what they are, and are neither expanded nor imported as evidence.
    from nexus.ingest.df.axiom import case_parts, find_axiom_cases, part_gate_rows

    axiom_rows: list[dict[str, str]] = []
    axiom_parts: set[Path] = set()
    for db in find_axiom_cases([str(p) for p in registered]):
        parts = case_parts(db)
        axiom_parts.update(parts)
        axiom_rows.extend(part_gate_rows(db, parts))
    expansions = expand_archives([str(p) for p in registered], _arch_settings.cases_root / case_id,
                                 exclude=axiom_parts)
    expanded_roots = [e["root"] for e in expansions if e["status"] == "OK"]
    consumed_archives = {str(Path(e["archive"])) for e in expansions}
    lane_paths = [*registered, *expanded_roots]

    result = await run_tool_lane(
        tools=tools,
        evidence_path=state.get("evidence_path") or "",
        case_id=case_id,
        run_id=state.get("run_id") or "",
        case_context=state.get("case_context") or {},
        parse_result=_parse_tool_result,
        skip_rag=True,
        pipeline_mode=mode,
        evidence_paths=(lane_paths if expansions else state.get("evidence_paths")) or None,
        on_event=_lane_event,
    )
    if expansions or axiom_rows:
        from nexus.langgraph.lane_gate import record_import_results

        record_import_results(_arch_settings.cases_root / case_id, [*archive_gate_rows(expansions), *axiom_rows])
        result.setdefault("step_log", [])
        result["step_log"] = [*result["step_log"], *(
            f"I0 archive {Path(e['archive']).name}: {e['status']} - {e['reason']}" for e in expansions)]
    # Phase 4h: every registered path is planned by the lane; paths the Windows
    # tool lane cannot parse (PCAP/Zeek/Suricata/cloud/syslog) go to importers.
    from nexus.ingest.detect import is_raw_container

    all_paths = lane_paths
    # Directories are routed PER FILE: a mixed tree (one EVTX + pcaps/zeek
    # logs) used to send the WHOLE tree to the host lane, silently skipping
    # every non-host file.
    #
    # WO-TA item 4 / D50: there is no arbitrary file cap. The old bound of 200
    # silently truncated a real volume - SC1's Windows\System32\Tasks holds 225
    # files, so 25 tasks never reached the importer and the gate still reported
    # the lane complete. A cap that drops evidence without recording it is the
    # same defect as D50's copy cap, one level up. The walk is now bounded only
    # by what is on the evidence, and every file it drops is recorded.
    _MAX_IMPORTED_FILES = _import_file_cap()
    _import_truncated = 0
    ingest_paths: list[str] = []
    raw_skipped: list[str] = []
    windows_unconfirmed: list[str] = []
    for p in all_paths:
        p_path = Path(p)
        if p_path.is_dir():
            try:
                import os as _os

                from nexus.langgraph.tool_lane import find_windows_root

                windows_root = find_windows_root(p_path)

                for root_dir, _dirs, files in _os.walk(p_path, followlinks=False):
                    for fname in files:
                        fp = str(Path(root_dir) / fname)
                        if is_expansion_marker(Path(fp)):
                            continue  # D295: lane-generated expansion metadata is not evidence
                        if _MAX_IMPORTED_FILES and len(ingest_paths) >= _MAX_IMPORTED_FILES:
                            _import_truncated += 1
                            continue
                        if fp in consumed_archives:
                            continue  # expanded above (D276): its contents are planned, not the file
                        if Path(fp) in axiom_parts:
                            continue  # AXIOM's own file (D285): a gate row above, read with Case.mfdb or not at all
                        if is_raw_container(Path(fp)):
                            raw_skipped.append(fname)
                            continue
                        route = _i1_route(fp, windows_root=windows_root)
                        if route == "importer":
                            ingest_paths.append(fp)
                        elif route == "host-unconfirmed":
                            windows_unconfirmed.append(fp)
            except OSError:
                continue
        elif (
            str(p_path) in consumed_archives
            or p_path in axiom_parts
            or is_expansion_marker(p_path)
        ):
            continue
        elif is_raw_container(p_path):
            raw_skipped.append(p_path.name)
        else:
            route = _i1_route(p)
            if route == "importer":
                ingest_paths.append(p)
            elif route == "host-unconfirmed":
                windows_unconfirmed.append(p)
    if raw_skipped:
        # Recorded now, appended to the step log once `steps` exists below.
        result["_raw_skipped_note"] = (
            "I1 skipped raw container(s) (SIFT/imager lane, not importers): "
            + ", ".join(sorted(set(raw_skipped))[:6])
        )
    if windows_unconfirmed:
        examples = ", ".join(Path(item).name for item in windows_unconfirmed[:5])
        result["_windows_unconfirmed_note"] = (
            f"I1 left {len(windows_unconfirmed)} file(s) inside a recognised Windows root on the host lane "
            f"because no importer confirmed them; check the Windows-lane completeness rows. Examples: {examples}"
        )
    if _import_truncated:
        # A cap the operator set is reported, not hidden: the gate and the
        # briefing must both show that evidence was left unrouted.
        result["_import_truncated_note"] = (
            f"I1 routed {len(ingest_paths)} file(s) to importers; "
            f"{_import_truncated} more were left unrouted by "
            f"NEXUS_IMPORT_FILE_CAP={_MAX_IMPORTED_FILES}."
        )
    if ingest_paths:
        import asyncio as _asyncio
        import threading as _threading

        from nexus.config import settings as _settings
        from nexus.langgraph.network_lane import enrich_local_network
        from nexus.langgraph.timeline_merge import (
            anchor_assumed_years,
            ingest_into_case,
            rebuild_case_timeline,
        )
        from nexus.langgraph.tool_lane import _lane_concurrency, find_windows_root

        case_dir = _settings.cases_root / case_id
        steps = list(result.get("step_log") or [])
        # EH-15: store writes are serialized (artifacts.jsonl/audit append);
        # parsing/enrichment may overlap up to NEXUS_TOOL_LANE_CONCURRENCY.
        write_lock = _threading.Lock()

        from nexus.langgraph.lane_gate import import_row, record_import_results
        from nexus.langgraph.pipeline_runs import resolve_tools_extractions

        # Every file of the pass is a gate row: read, empty, or not read (2026-10-18).
        import_rows: list[dict[str, str]] = []
        # A capture's local app logs go to this run's extractions, which the index reads (D272).
        run_extractions = resolve_tools_extractions(case_dir, str(state.get("run_id") or ""))

        def _process(p: str) -> list[str]:
            lines: list[str] = []
            path = Path(p)
            net: dict | None = None
            # EH-14b session guarantee: Zeek/Suricata when available locally +
            # tshark flow projection always. Runs before import so the flows
            # CSV is part of the same evidence pass.
            if path.suffix.lower() in (".pcap", ".pcapng", ".cap"):
                try:
                    net = enrich_local_network(path, case_dir, run_extractions)
                    lines.extend(str(s) for s in (net.get("steps") or []))
                    for err in net.get("errors") or []:
                        lines.append(f"I1 network warning: {err}")
                except Exception as exc:  # noqa: BLE001
                    lines.append(f"I1 network enrichment failed: {exc}")
            if find_windows_root(path) is not None:
                lines.append(
                    f"Extra Windows root registered (not re-parsed this pass): {p}"
                )
                return lines
            try:
                with write_lock:
                    info = ingest_into_case(path, case_dir)
            except Exception as exc:  # noqa: BLE001 — one bad path must not sink the lane
                lines.append(f"I1 ingest extra path {p} failed: {exc}")
                import_rows.append(import_row(path, {"error": str(exc)}, net))
                return lines
            import_rows.append(import_row(path, info, net))
            capped = " (capped)" if info.get("artifacts_capped") else ""
            err_note = ""
            problems = list(info.get("errors") or [])
            if info.get("error"):
                problems.insert(0, str(info["error"]))
            if problems:
                err_note = " errors=" + " | ".join(str(e)[:120] for e in problems[:2])
            lines.append(
                f"I1 ingest extra path {p}: {info.get('source')} "
                f"artifacts={info.get('artifacts')}/{info.get('artifacts_total')}{capped} "
                f"ok={info.get('success')}{err_note}"
            )
            if str(info.get("source") or "") in ("generic_csv", "generic_jsonl") and path.suffix.lower() in (
                ".json", ".jsonl"
            ):
                lines.append(
                    f"I1 warning: {path.name} resolved as {info.get('source')} — "
                    "structured JSON may be misrouted; check importer detection"
                )
            return lines

        try:
            conc = _lane_concurrency()
            per_path: list[list[str]] = []
            if conc <= 1 or len(ingest_paths) <= 1:
                for p in ingest_paths:
                    per_path.append(await _asyncio.to_thread(_process, p))
            else:
                sem = _asyncio.Semaphore(conc)

                async def _one(p: str) -> list[str]:
                    async with sem:
                        return await _asyncio.to_thread(_process, p)

                per_path = list(await _asyncio.gather(*(_one(p) for p in ingest_paths)))
            # Input order preserved in the step log regardless of concurrency
            # — the ledger reads identically at 1 and 4 workers.
            for lines in per_path:
                steps.extend(lines)
        except Exception as exc:  # noqa: BLE001
            steps.append(f"I1 ingest lane failed: {exc}")
        try:
            gate = record_import_results(case_dir, import_rows)
            if gate:
                failed = [r for r in import_rows if r.get("status") == "FAIL"]
                steps.append(
                    f"N2 gate with the importer pass: {gate.get('status')} ({len(import_rows)} file(s) read, "
                    f"{len(failed)} not read)"
                )
        except Exception as exc:  # noqa: BLE001 - the gate keeps its tool-lane state
            steps.append(f"N2 gate update from the importer pass failed: {exc}")
        try:
            # D262: a yearless time takes the year of the case's dated evidence, before the timeline is built.
            years = anchor_assumed_years(case_dir)
            if years.get("anchored") or years.get("unresolved"):
                steps.append(
                    f"I1 yearless times: {years.get('anchored', 0)} given the year of {years.get('basis') or '-'}; "
                    f"{years.get('unresolved', 0)} left with the current year (flagged)"
                )
        except Exception as exc:  # noqa: BLE001
            steps.append(f"I1 yearless-time anchoring failed: {exc}")
        try:
            rebuild_case_timeline(case_dir)
        except Exception as exc:  # noqa: BLE001
            steps.append(f"I3 merge after extra ingest skipped: {exc}")
        result["step_log"] = steps
    steps = list(result.get("step_log") or [])
    label = "tools mode" if mode == "tools" else "coverage mode"
    steps.insert(0, f"{label}: deterministic tool lane")
    raw_note = str(result.pop("_raw_skipped_note", "") or "")
    if raw_note:
        steps.append(raw_note)
    windows_note = str(result.pop("_windows_unconfirmed_note", "") or "")
    if windows_note:
        steps.append(windows_note)
    result["step_log"] = steps
    try:
        from nexus.config import settings as _set
        from nexus.langgraph.query_pack import load_case_intake

        ctx = dict(state.get("case_context") or {})
        for key, val in load_case_intake(_set.cases_root / case_id).items():
            if val and not str(ctx.get(key) or "").strip():
                ctx[key] = val
        if ctx:
            result["case_context"] = ctx
    except Exception:
        pass
    # Mode 2/3 promise ES-backed evidence: coverage/design go straight to
    # interpret, so the index MUST exist before that node. Tools mode indexes
    # in emit_tool_report; here (fresh case → no index yet) we index now.
    if mode in ("coverage", "design"):
        steps = list(result.get("step_log") or [])
        try:
            from nexus.config import settings as _idx_settings

            steps.extend(_autoindex_case(_idx_settings.cases_root / case_id))
        except Exception as exc:  # noqa: BLE001 — interpret's EH-13 gate reports
            steps.append(f"N3 auto-index failed: {exc}")
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
            status = _parse_tool_result(
                await call_tool(status_tool, {}, label="forensic_rag_status")
            )
        except Exception as exc:  # noqa: BLE001
            return {"error": f"forensic_rag_status failed: {exc}"}
    if search_tool:
        try:
            for query in (
                "Windows host triage EVTX prefetch SRUM LNK Amcache methodology",
                "insider threat data staging cloud sync removable media SRUM",
            ):
                warm = _parse_tool_result(await call_tool(
                    search_tool,
                    {
                        "query": query,
                        "top_k": 5,
                    },
                    label="forensic_rag_search",
                ))
                notes.append(str(warm.get("results") or warm)[:2000])
            if status_tool:
                status = _parse_tool_result(
                    await call_tool(status_tool, {}, label="forensic_rag_status")
                )
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
    """Reuse a completed tool-run case (its ledger) for interpretation."""
    import json

    from nexus.config import settings
    from nexus.langgraph.query_pack import load_case_intake
    from nexus.langgraph.snippets import write_snippets

    case_id = (state.get("case_id") or "").strip()
    if not case_id:
        return {"error": "load_existing_case requires case_id"}
    # Bound by its case id. The examiner host's case_activate is not called: it writes this machine's
    # global active-case pointer (tools/case.py), which a pipeline run must not change (2026-10-11).
    step_log = [f"Bound run to case {case_id} (the global active case is not changed)"]
    case_dir = settings.cases_root / case_id
    from nexus.langgraph.pipeline_runs import create_run, load_manifest, resolve_run

    try:
        tools_run = resolve_run(case_dir, "tools")
    except ValueError as exc:
        # load_error: the graph stops here. Without it the edge went on to interpret, and
        # the model was called over a case with no tools run (2026-10-10, the picker journey).
        return {"error": str(exc), "load_error": str(exc)}
    ledger_path = tools_run.extractions / "_tool_lane_ledger.json"
    if not ledger_path.is_file():
        ledger_path = tools_run.path / "ledger" / "_tool_lane_ledger.json"
    ledger: list[dict] = []
    if ledger_path.is_file():
        try:
            ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return {"error": f"ledger unreadable: {exc}", "load_error": f"ledger unreadable: {exc}"}
    if not ledger:
        msg = f"No tool-lane ledger in {tools_run.path}"
        return {"error": msg, "load_error": msg}
    interpret_run = create_run(
        case_dir,
        "interpret",
        load_manifest(tools_run.path).get("evidence_paths") or [],
        parent_run_id=tools_run.run_id,
    )
    write_snippets(tools_run.path, ledger)
    intake = load_case_intake(case_dir)
    ctx = dict(state.get("case_context") or {})
    for key, val in intake.items():
        ctx.setdefault(key, val)
    aids = [str(r.get("audit_id")) for r in ledger if r.get("audit_id")]
    step_log.append(f"Loaded {len(ledger)} ledger rows, {len(aids)} audit_ids")
    return {
        "case_id": case_id,
        "tool_run_ledger": ledger,
        "evidence_audit_ids": aids,
        "case_context": ctx,
        "run_id": interpret_run.run_id,
        "run_dir": str(interpret_run.path),
        "parent_run_id": tools_run.run_id,
        "step_log": step_log,
    }


def _format_tool_run_markdown(state: InvestigationState) -> str:
    """Deterministic TOOL-RUN report — no LLM, no findings narrative."""
    ledger = list(state.get("tool_run_ledger") or [])
    case_id = state.get("case_id") or "unknown"
    ok = [r for r in ledger if r.get("status") == "OK"]
    warn = [r for r in ledger if r.get("status") == "WARN"]
    fail = [r for r in ledger if r.get("status") == "FAIL"]
    skip = [r for r in ledger if r.get("status") == "SKIP"]
    lines = [
        f"# Tool-run ledger — `{case_id}`",
        "",
        f"**Mode:** `{state.get('pipeline_mode') or 'tools'}` (no LLM)",
        f"**Run:** `{state.get('run_id') or 'unknown'}`",
        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Evidence:** `{state.get('evidence_path') or ''}`",
        "",
        # WARN belongs in the summary: it is a row that ran and needs reading,
        # and leaving it out made the arithmetic look like rows had vanished
        # (7 OK / 0 FAIL / 0 SKIP out of 15).
        f"Summary: **{len(ok)} OK** · **{len(warn)} WARN** · **{len(fail)} FAIL** "
        f"· **{len(skip)} SKIP** (total {len(ledger)})",
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
    try:
        from nexus.langgraph.tool_context import build_tool_context_markdown
        lines.append(build_tool_context_markdown(
            state.get("case_context") or {},
            ledger,
        ))
    except Exception:  # noqa: BLE001
        pass
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
                    "STAGED = present and copied (plain text, no parser). "
                    "PRESENT_NO_PARSER = present but no argv builder or parser missing. "
                    "PARSED = a related parser ran OK. "
                    "FAIL = parser ran and lost. "
                    "SCHEDULED = still queued (should be empty after the lane finishes).",
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
        from nexus.case.repo_export import (
            export_case_to_repo,
            live_case_is_in_repo,
            repo_export_enabled,
        )
        from nexus.config import settings
        from nexus.langgraph.pipeline_runs import finalize_run, resolve_run

        case_dir = settings.cases_root / state["case_id"]
        pipeline_run = resolve_run(case_dir, run_id=state.get("run_id") or "")
        md = _format_tool_run_markdown(state)
        out = pipeline_run.reports / "TOOL-RUN.md"
        out.write_text(md, encoding="utf-8")
        step_log.append(f"Wrote {out}")

        ledger_dir = pipeline_run.path / "ledger"
        ledger_path = ledger_dir / "_tool_lane_ledger.json"
        ledger_path.write_text(
            json.dumps(state.get("tool_run_ledger") or [], indent=2),
            encoding="utf-8",
        )

        if not repo_export_enabled():
            step_log.append(
                "Repo sample-export disabled (set NEXUS_REPO_EXPORT=1 for the examiner copy)"
            )
        # Build the index BEFORE publishing the terminal status. A poller fires the
        # moment the status is terminal, and every downstream consumer reads the
        # index: the Mode 1 needle scan, Modes 2 and 3, the coverage audit. Publishing
        # `completed` first meant a run could be read as finished while the index was
        # still being written - seen live, status complete with no index_state.json on
        # disk and ES still climbing past 352,000 docs.
            step_log.extend(_autoindex_case(case_dir, run_id=pipeline_run.run_id))
            finalize_run(pipeline_run, "completed")
            return {
                "report_path": str(out),
                "step_log": step_log,
                "rag_notes": [f"live_case={case_dir}"],
            }

        if live_case_is_in_repo(case_dir):
            step_log.append("Repo sample-export skipped (live case already in-repo)")
            step_log.extend(_autoindex_case(case_dir, run_id=pipeline_run.run_id))
            finalize_run(pipeline_run, "completed")
            return {
                "report_path": str(out),
                "step_log": step_log,
                "rag_notes": [f"live_case={case_dir}"],
            }

        exported = export_case_to_repo(
            case_dir,
            extra_sift_dir=pipeline_run.path / "sift" / "extractions",
        )
        export_root = str(exported)
        (exported / "reports" / "TOOL-RUN.md").write_text(md, encoding="utf-8")
        report_path = str(exported / "reports" / "TOOL-RUN.md")
        step_log.append(f"Repo export: {exported}")
        step_log.extend(_autoindex_case(case_dir, run_id=pipeline_run.run_id))
        finalize_run(pipeline_run, "completed")
    except Exception as exc:  # noqa: BLE001
        if "pipeline_run" in locals():
            finalize_run(pipeline_run, "failed", str(exc))
        step_log.append(f"Tool-run report/export failed: {exc}")
        return {"error": str(exc), "step_log": step_log}

    return {
        "report_path": report_path,
        "step_log": step_log,
        "rag_notes": [f"repo_export={export_root}"] if export_root else [],
    }


def _autoindex_case(case_dir: Path, run_id: str = "") -> list[str]:
    """Best-effort N3 auto-index after the tools lane (WP 1.2).

    Enabled by default when NEXUS_ES_URL is set; disable with
    NEXUS_ES_AUTOINDEX=0. Never fails the run — indexing problems are
    logged as step notes.
    """
    import os

    if (os.environ.get("NEXUS_ES_AUTOINDEX") or "").strip().lower() in {"0", "false", "no"}:
        return ["N3 auto-index disabled (NEXUS_ES_AUTOINDEX=0)"]
    if not (os.environ.get("NEXUS_ES_URL") or "").strip():
        return ["N3 auto-index skipped (NEXUS_ES_URL empty — CSV pack remains the backend)"]

    # The LLM-driven modes promise ES-backed evidence — a mid-run index failure
    # silently degrades them to the CSV pack, so the note must say so loudly.
    case_mode = ""
    try:
        import yaml

        meta_yaml = case_dir / "CASE.yaml"
        if meta_yaml.is_file():
            _m = yaml.safe_load(meta_yaml.read_text(encoding="utf-8")) or {}
            if isinstance(_m, dict):
                from nexus.langgraph.mode_mapping import resolve_stored_mode

                canonical = resolve_stored_mode(
                    _m.get("investigation_mode"), _m.get("mode_scheme"))
                case_mode = str(canonical) if canonical else ""
    except Exception:
        case_mode = ""

    try:
        from nexus.langgraph.case_index import index_case

        # Pass the case's own query vocabulary so large files (hayabusa/MFT)
        # keep the rows the case actually asks about — not just the hardcoded
        # needle list.
        extra_needles: list[str] = []
        try:
            from nexus.langgraph.query_pack import collect_query_terms, load_case_intake

            extra_needles = collect_query_terms(load_case_intake(case_dir))
        except Exception:  # noqa: BLE001 — vocabulary is best-effort
            extra_needles = []
        # B6: incremental by default — only files whose mtime advanced since
        # the last build are re-indexed (full rebuild on fresh/absent state).
        meta = index_case(case_dir, extra_needles=extra_needles, incremental=True, run_id=run_id)
        # D271: rows Elasticsearch refused are not indexed, whatever was sent. The line used to count them as
        # indexed; they are now named, and the gate holds each file as unprocessed until it indexes whole.
        rejected = meta.get("rejected") or {}
        from nexus.langgraph.lane_gate import record_index_rejections

        record_index_rejections(case_dir, rejected)
        refused = sum(int(r.get("rows") or 0) for r in rejected.values())
        line = f"N3 auto-index: {int(meta.get('docs') or 0) - refused} docs -> {meta.get('index')}"
        if refused:
            first_file, first = next(iter(rejected.items()))
            line += (f"; {refused} row(s) of {len(rejected)} file(s) REJECTED by Elasticsearch, not indexed "
                     f"(e.g. {first_file}: {first.get('reason')})")
        return [line]
    except Exception as exc:  # noqa: BLE001
        if case_mode in ("2", "3"):
            return [
                f"N3 auto-index FAILED — Mode {case_mode} degraded to the CSV pack "
                f"(the LLM cannot see an index that never built): {exc}"
            ]
        return [f"N3 auto-index failed (CSV pack remains usable): {exc}"]


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
    from nexus.langgraph.tool_lane import CasePipelineTool

    hunt_roots: list[Path] = []
    for raw_root in (state.get("evidence_paths") or [state.get("evidence_path")]):
        if raw_root:
            hunt_roots.append(Path(raw_root))
    run_id = str(state.get("run_id") or "")
    if run_id and state.get("case_id"):
        try:
            from nexus.config import settings
            from nexus.langgraph.pipeline_runs import resolve_run

            hunt_roots.append(
                resolve_run(settings.cases_root / state["case_id"], run_id=run_id).extractions
            )
        except Exception:  # noqa: BLE001 — the evidence roots still bind the call
            log.debug("hunt extractions root unavailable", exc_info=True)
    hunt_tools_list = []
    for name in hunt_tool_names:
        t = tools.get(name)
        if not t:
            continue
        if name == "run_windows_command":
            t = CasePipelineTool(t, hunt_roots)
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
            f"{itm_prompt_block(question=str((state.get('case_context') or {}).get('question') or ''))}\n"
            f"{_registry_context_block(state)}\n"
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


# Mode 2 interpret toolset — RAG + evidence (own ES queries) + TI.
# All read-only; the evidence/knowledge tools are the same case-gated MCP
# tools the examiner sees (n4_* require the active case's case_id).
INTERPRET_TOOL_NAMES = (
    # RAG methodology (required)
    "forensic_rag_search",
    "forensic_rag_status",
    # evidence index — Mode 2/3 use the ES-native surface ONLY (4k.5.5).
    # The typed DSL tools remain registered for Mode 1 / deterministic paths
    # but are not part of the Mode 2/3 agent allowlist.
    "es_fields",
    "es_search",
    "es_aggregate",
    "es_sample",
    "index_mappings",
    "family_fields",
    # WP 10.53: the tool-lane ledger is part of the interpret surface so the
    # loop can distinguish never-parsed from not-found.
    "run_record",
    # threat intel (keyed providers auto-included)
    "ti_lookup",
    "ti_fanout",
    "ti_list_providers",
    # triage validation + tooling hints
    "ingest_auto",
    "analyze_gaps",
    "predict_techniques",
    "check_file",
    "check_hash",
    "check_autorun",
    "suggest_tools",
    "suggest_windows_tools",
)


def make_interpret_executor(case_dir: Path | None, tools: dict):
    """The evidence executor the Mode 1 interpret loop calls (WO-R2F item 1, D41).

    The run's ES calls read the run's own case through the bound backbone. The MCP
    tool gate follows the examiner's active case, so routing through it refused
    every call whenever another case was active (36e real-path test: "no active
    case"). Other tools keep the MCP path.
    """
    async def _execute_tool(name: str, payload: dict) -> dict:
        if name in ("es_search", "es_aggregate", "es_sample") and case_dir is not None:
            from nexus.audit import AuditWriter
            from nexus.langgraph.backbone import backbone_call

            bound_audit = AuditWriter("nexus", audit_dir=Path(case_dir) / "audit")
            kwargs = {k: v for k, v in payload.items() if k != "case_id"}
            return backbone_call(name, audit=bound_audit, case_dir=Path(case_dir), **kwargs)
        tool = tools.get(name)
        if tool is None:
            return {"error": f"tool {name} not available"}
        return _parse_tool_result(await call_tool(tool, payload, label=name))

    return _execute_tool


async def interpret(state: InvestigationState, tools: dict, model) -> dict:
    """Coverage/interpret: the bounded interpret loop over the case digest and N4 hits.

    The loop is the only interpreter. A second, unbounded ReAct agent used to run when the
    loop raised or returned no findings, recorded only in a log line (D131): it overrode a
    legitimate "nothing found" and hid loop failures. A loop that finds nothing now ends
    the node with that result, and a loop that fails, fails the node with its reason.
    """
    ledger = state.get("tool_run_ledger") or []
    ledger_summary = []
    for row in ledger:
        ledger_summary.append({
            "tool": row.get("tool"),
            "status": row.get("status"),
            "audit_id": row.get("audit_id"),
            "purpose": str(row.get("purpose") or "")[:80],
        })
    ledger_json = json.dumps(ledger_summary, indent=2)[:4000]
    rag_prior = "\n".join(state.get("rag_notes") or [])[:1500]

    case_id = state.get("case_id") or ""
    ti_block = ""
    inv_md = ""
    playbook_block = ""
    digest_md = ""
    digest: dict[str, Any] = {}
    digest_error = ""
    if case_id:
        from nexus.config import settings
        # No N4 query pack (D168, operator 2026-10-14): ~50 keyword-needle rows that could not be
        # cited filled 58% of orient's prompt (run 4: all `info` level, from lsass / encodedcommand
        # / termsrv). The digest's top leads carry the detections with their citations, and the
        # loop queries the index itself. query_pack.md stays the examiner's needle file.
        # Case Digest — deterministic "everything" (signal map incl. 0-hit
        # needles, alerts, entities + spans, ledger, timeline, scope rules,
        # TI). The LLM reconciles EVERY item; raw detail via n4_sample.
        try:
            from nexus.langgraph.case_digest import (
                build_case_digest,
                render_digest_markdown,
                write_case_digest,
            )

            emit_stage(state, "interpret", "setup", "case digest (signal map, alerts, leads)")
            digest = build_case_digest(settings.cases_root / case_id)
            write_case_digest(settings.cases_root / case_id, digest)
            digest_md = render_digest_markdown(digest)
        except Exception as exc:  # noqa: BLE001 - reported below if the loop cannot run
            digest_error = f"{type(exc).__name__}: {exc}"
            log.warning("case digest build failed: %s", exc)
        # B5: ONE wide case scan, shared by the TI sweep and the entity
        # census (each used to run its own match-all fetch back-to-back).
        wide_hits: list[dict[str, Any]] = []
        try:
            from nexus.tools.evidence_index import do_n4_query as _wide_query

            _wide = _wide_query(case_id=case_id, dsl="", limit=400, match_all=True)
            wide_hits = [h for h in (_wide.get("hits") or []) if isinstance(h, dict)]
        except Exception as exc:  # noqa: BLE001 — builders fall back to their own fetch
            log.debug("wide case scan unavailable: %s", exc)
        share_hits = wide_hits or None

        # Mode 2 deterministic lane: IOC sweep + TI enrichment. Context only —
        # findings still cite evidence audit_ids (FD-001).
        try:
            from nexus.langgraph.ti_context import build_case_ti_context, write_ti_context

            emit_stage(state, "interpret", "setup", "threat-intel context")
            ti_ctx = build_case_ti_context(case_id, max_iocs=6, hits=share_hits)
            write_ti_context(settings.cases_root / case_id, ti_ctx)
            ti_block = str(ti_ctx.get("markdown") or "")
        except Exception as exc:  # noqa: BLE001 — TI is best-effort context
            log.warning("TI context build failed: %s", exc)
        # Deterministic entity census — the interpret agent must address every
        # item (broad, extensive coverage; gaps are listed after staging).
        inv: dict[str, Any] = {}
        try:
            from nexus.langgraph.entity_inventory import (
                build_entity_inventory,
                render_inventory_markdown,
                write_entity_inventory,
            )

            emit_stage(state, "interpret", "setup", "entity inventory")
            inv = build_entity_inventory(case_id, cap=40, hits=share_hits)
            write_entity_inventory(settings.cases_root / case_id, inv)
            inv_md = render_inventory_markdown(inv)
        except Exception as exc:  # noqa: BLE001 — inventory is best-effort
            log.warning("entity inventory build failed: %s", exc)
        # Playbook caveats/identification steps for the case's families.
        try:
            from nexus.langgraph.briefing import _family_inventory

            # Reuse the digest's inventory (already computed above) instead of
            # walking the extraction tree again for family names.
            families = sorted((digest.get("inventory") or {}).keys())
            if not families:
                families = sorted(_family_inventory(settings.cases_root / case_id))
            try:
                from nexus.modes.llm_guided import _playbook_context_for_families

                playbook_block = _playbook_context_for_families(set(families), budget=3000)
            except Exception as exc:  # noqa: BLE001
                log.debug("playbook context unavailable: %s", exc)
        except Exception as exc:  # noqa: BLE001 — playbooks best-effort
            log.warning("playbook context build failed: %s", exc)

    ledger_block = f"OK/FAIL ledger (audit_ids only — not facts):\n```json\n{ledger_json}\n```"
    sections = [
        (0, "case_digest", digest_md),
        (2, "entity_inventory", inv_md),
        (3, "threat_intel_context", ti_block),
        (4, "playbook_guidance", playbook_block),
        (5, "run_ledger", ledger_block),
        (6, "prior_rag_notes", rag_prior),
    ]

    case_dir_for_ctx: Path | None = None
    if case_id:
        from nexus.config import settings

        case_dir_for_ctx = settings.cases_root / case_id

    # ── The bounded interpret round loop (the only interpreter) ─────────
    # Orient → Verify ×N → Reconcile, with artifacts under
    # analysis/interpret_rounds/.
    # EH-13: Mode 2/3 promise ES-backed evidence. If the backend fell back
    # to the CSV pack (ES lost mid-run, index gone), STOP here — a silent CSV
    # interpretation is a different analysis with different coverage.
    if (
        case_dir_for_ctx is not None
        and str(state.get("pipeline_mode") or "") in {"coverage", "design"}
        and digest
        and str(digest.get("backend") or "") != "elasticsearch"
    ):
        fallback = str((digest.get("scan_stats") or {}).get("fallback_reason") or
                       "Elasticsearch unavailable")
        emit_stage(state, "interpret", "error", f"ES required: {fallback}")
        log.error("Interpret refused: %s", fallback)
        # A refused interpret must not leave the run reading as 'running'
        # forever — mark it failed with the real reason.
        try:
            from nexus.langgraph.pipeline_runs import finalize_run, resolve_run

            _run = resolve_run(
                case_dir_for_ctx, run_id=str(state.get("run_id") or "")
            )
            finalize_run(_run, "failed", f"interpret refused: {fallback}")
        except Exception:  # noqa: BLE001 — status bookkeeping must not mask the refusal
            pass
        return {
            "error": (
                f"Mode 2/3 requires Elasticsearch — N4 backend fell back to the "
                f"CSV pack ({fallback}). No analysis was staged; restore ES and "
                "re-run (nexus index rebuild if the index is missing)."
            ),
            "step_log": [f"interpret refused (no ES): {fallback}"],
        }

    def _fail(reason: str) -> dict:
        emit_stage(state, "interpret", "error", reason)
        log.error("Interpret failed: %s", reason)
        if case_dir_for_ctx is not None:
            try:
                from nexus.langgraph.pipeline_runs import finalize_run, resolve_run

                finalize_run(
                    resolve_run(case_dir_for_ctx, run_id=str(state.get("run_id") or "")),
                    "failed", f"interpret: {reason}",
                )
            except Exception:  # noqa: BLE001 - status bookkeeping must not mask the failure
                pass
        return {"error": f"interpret: {reason}", "step_log": [f"interpret failed: {reason}"]}

    if case_dir_for_ctx is None:
        return _fail("no case_id on the run")
    if not digest:
        return _fail("the case digest could not be built"
                     + (f" ({digest_error})" if digest_error else ""))

    from nexus.langgraph.interpret_loop import run_interpret_loop

    # P2: scan coverage is part of the run record - files scanned vs eligible and
    # needles queried vs requested (never silently dropped).
    _stats = (digest.get("scan_stats") or {}) if isinstance(digest, dict) else {}
    if _stats.get("files_total"):
        _cov = (
            f"scan coverage: files {_stats.get('files_scanned', 0)}/{_stats.get('files_total', 0)}"
            f", needles {_stats.get('terms_queried', 0)}/{_stats.get('terms_requested', 0)}"
        )
        if _stats.get("fallback_reason"):
            _cov += f" - fallback: {_stats['fallback_reason']}"
        emit_stage(state, "interpret", "coverage", _cov)

    try:
        loop_result = await run_interpret_loop(
            case_dir=case_dir_for_ctx,
            case_id=case_id,
            model=model,
            state=state,
            digest=digest,
            digest_md=digest_md,
            sections=sections,
            execute=make_interpret_executor(case_dir_for_ctx, tools),
            # WO-1C item 2: the interpret loop is an analysis run with its own id, like
            # Modes 2 and 3, so its queries, round artifacts and family ledger are
            # attributed to it.
            run_id=str(state.get("run_id") or ""),
            # WO-1C item 3: the run's context policy, decided before the run and
            # recorded on it (independent by default).
            context_policy=str(state.get("context_policy") or "independent"),
        )
    except Exception as exc:  # noqa: BLE001 - the failure is the node's result
        return _fail(f"the interpret loop failed: {type(exc).__name__}: {exc}")

    log.info(
        "Interpret loop: %d/%d rounds (%s), %d findings, %d unaddressed",
        loop_result.get("rounds_run"), loop_result.get("rounds_requested"),
        loop_result.get("stop_reason"), loop_result.get("findings_emitted"),
        len(loop_result.get("unaddressed") or []),
    )
    return {
        "step_log": [
            f"interpret loop: {loop_result.get('rounds_run')} round(s), stop "
            f"{loop_result.get('stop_reason')}, "
            f"{loop_result.get('findings_emitted')} finding candidate(s)"
        ],
        "messages": loop_result.get("messages") or [],
        "dispositions": list(loop_result.get("dispositions") or []),
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
            content = msg.content
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


def _is_tool_audit_id(aid: str) -> bool:
    """True for MCP tool audit IDs (exclude bare sha256 / short tokens)."""
    return bool(aid and _AUDIT_ID_RE.fullmatch(aid))


def _finding_tool_payload(candidate: dict) -> dict:
    """Map a hunt/interpret candidate to ``record_finding`` MCP kwargs.

    Avoids passing raw ``type`` / unknown keys that FastMCP may reject silently.
    The finding cites the calls the model cited, and only those. Staging used to pad the list to
    ten with "linked" calls: the first calls in the case log touching the same artifact families,
    the same eight or nine on every DRAFT (2026-10-14: a 0-row CobaltStrike query and an MFT
    ``wacsvc`` query on a credential-theft finding). The padding made the FD-006/007 audit-count cap
    unreachable, and since a finding's evidence and entity come from its cited calls, two different
    claims became one DRAFT.
    """
    aids = [str(a) for a in (candidate.get("audit_ids") or []) if a][:10]
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
    # WO-R2F item 7 (D47): Mode 1 staged 7/7 DRAFTs with an empty severity
    # because this payload never carried one, even though the candidate did.
    # `CaseManager.record_finding` stores `severity` (case_manager.py:549) and
    # Modes 2/3 stage with the same vocabulary (multi_role.py:855), so the
    # gap was in this mapping alone. Same vocabulary, same default shape.
    severity = str(candidate.get("severity") or "").strip().upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"}:
        severity = ""
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
        "severity": severity,
        "finding_type": ftype if ftype in {
            "finding", "execution", "persistence", "attribution", "exclusion",
            "conclusion", "network", "lateral", "auth", "file", "registry", "other",
        } else "finding",
        "host": str(candidate.get("host") or "")[:200],
        "attack_ids": list(candidate.get("attack_ids") or candidate.get("mitre_ids") or []),
        "audit_ids": aids,
        "artifacts": arts[:10],
    }
    ev_rows = candidate.get("evidence")
    if isinstance(ev_rows, list) and ev_rows:
        payload["evidence"] = ev_rows[:12]
    # WO-1C item 4 (option b): the entity is not taken from the model. stage_findings derives it from the
    # rows the cited audit calls stored, so a model's wording never decides a finding's identity.
    itm_stage = str(candidate.get("itm_stage") or "").strip()
    if itm_stage:
        payload["itm_stage"] = itm_stage[:80]
    itm_objects = [str(x) for x in (candidate.get("itm_objects") or []) if x][:12]
    if itm_objects:
        payload["itm_objects"] = itm_objects
    return payload


def _is_collection_stub(candidate: dict) -> bool:
    """True for parser-OK / coverage-placeholder rows — never IR claims."""
    title = str(candidate.get("title") or "")
    blob = (
        f"{title} {candidate.get('observation', '')} "
        f"{candidate.get('interpretation', '')}"
    ).lower()
    if "completed ok" in blob:
        return True
    if "coverage/collection evidence" in blob:
        return True
    if "placeholder only" in blob:
        return True
    if title.lower().startswith("coverage gap") or "coverage gap:" in blob:
        return True
    if "/" in title and ": " in title:
        left = title.split(": ", 1)[0].strip()
        if "/" in left and " " not in left:
            return True
    return False


async def stage_findings(state: InvestigationState, tools: dict, model=None) -> dict:
    """Stage findings as DRAFT from hunt agent output."""
    from nexus.langgraph.hunt_parser import parse_hunt_candidates

    # EH-13: an upstream hard error (e.g. interpret refused without ES) must
    # not be silently salvaged into CSV-derived findings.
    if state.get("error"):
        return {"step_log": [f"stage_findings skipped: {state['error']}"]}

    finding_tool = tools.get("record_finding")
    timeline_tool = tools.get("record_timeline_event")
    if not finding_tool:
        return {"error": "record_finding tool not available"}

    draft_ids = []
    linked_drafts: list[dict[str, str]] = []
    decided_claims: list[dict[str, str]] = []
    timeline_ids = []
    errors = []

    # Only the interpret run's own candidates are staged (D130). Needle hits are digest items the
    # loop must disposition; they used to be staged as findings when the model produced none, when
    # every model candidate was rejected ("N4 hit salvage"), and beside the model's findings, chosen
    # by a keyword list from earlier cases.
    parsed = parse_hunt_candidates(state.get("messages", []))
    candidates = [c for c in parsed if not _is_collection_stub(c)]
    # A coverage or disposition item is not staged as a finding, and it is recorded as such: the
    # filter used to drop it with no trace (2026-10-14: "Malicious IOC contact ... not
    # established" vanished because its text said "coverage gap:").
    rejected: list[dict[str, str]] = [
        {"title": str(c.get("title") or "")[:200],
         "reason": "a coverage or disposition item (absence, gap or collection note), not a finding"}
        for c in parsed if _is_collection_stub(c)
    ]
    # The loop's dispositions (D193) answer for digest items without being claims: recorded with
    # the run and given to the verdict, never staged.
    dispositions = [d for d in state.get("dispositions") or [] if isinstance(d, dict)]

    stage_case_id = str(state.get("case_id") or "")
    stage_case_dir: Path | None = None
    if stage_case_id:
        from nexus.config import settings as _stage_settings

        stage_case_dir = _stage_settings.cases_root / stage_case_id

    async def _stage_one(candidate: dict) -> str:
        """Stage one candidate; return its finding id, or "" with the reason recorded."""
        title = str(candidate.get("title") or "")[:200]

        def _reject(reason: str) -> str:
            errors.append(reason)
            rejected.append({"title": title, "reason": reason[:500]})
            emit_stage(state, "stage_findings", "not staged", f"{title[:80]}: {reason[:160]}")
            return ""

        payload = _finding_tool_payload(candidate)
        if stage_case_dir is not None:
            from nexus.langgraph.evidence_rows import evidence_rows_for_audit_ids

            stored = evidence_rows_for_audit_ids(stage_case_dir, [str(a) for a in payload.get("audit_ids") or []])
            if stored:
                payload["evidence"] = stored[:12]
            # record_finding derives the subject and category from these same audit rows (operator
            # decision 2026-10-12), so the payload carries no identity of its own.
        if stage_case_id:
            # The run's own case: the tool stages there, never into the global active case.
            payload["case_id"] = stage_case_id
        if state.get("run_id"):
            # The DRAFT names the run that produced it, as Mode 2 and 3 DRAFTs do (WO-1C item 5).
            payload["run_id"] = str(state.get("run_id"))
        try:
            result = _parse_tool_result(
                await call_tool(finding_tool, payload, label="record_finding")
            )
        except Exception as e:
            return _reject(str(e))
        fid = result.get("finding_id") or result.get("id")
        if fid and result.get("status") == "DECIDED":
            # The examiner already approved or rejected this claim (D223): it is not staged again.
            decision = str(result.get("decision") or "").lower()
            decided_claims.append({"title": title, "finding_id": str(fid), "decision": decision})
            emit_stage(state, "stage_findings", "decided", f"{fid} ({decision} by the examiner): {title[:100]}")
            return ""
        if fid and result.get("duplicate"):
            # The same claim on the same rows as an existing DRAFT: record_finding linked this run to
            # it. It is not a new finding, and the log said "staged" for it.
            linked_drafts.append({"title": title, "finding_id": str(fid)})
            emit_stage(state, "stage_findings", "linked", f"{fid} (existing DRAFT, same rows): {title[:100]}")
            return str(fid)
        if fid:
            draft_ids.append(fid)
            emit_stage(state, "stage_findings", "staged", f"{fid}: {title[:120]}")
            return str(fid)
        if result.get("status") == "REJECTED":
            return _reject(str(result.get("error") or result.get("missing_audit_ids") or result))
        if result.get("status") == "VALIDATION_FAILED":
            return _reject(str(result.get("errors") or result))
        if result.get("error"):
            return _reject(str(result["error"]))
        return _reject(f"unexpected record_finding result: {str(result)[:300]}")

    staged_candidates: list[dict] = []
    if candidates:
        for candidate in candidates:
            if await _stage_one(candidate):
                staged_candidates.append(candidate)

        # A timeline event belongs to a staged finding only; a rejected candidate's event is not
        # evidence of anything.
        if timeline_tool:
            for c in staged_candidates:
                ts = c.get("event_timestamp", "")
                if not ts:
                    continue
                try:
                    result = _parse_tool_result(await call_tool(
                        timeline_tool,
                        {
                            "timestamp": ts,
                            "description": c.get("observation", c.get("title", ""))[:500],
                            "event_type": c.get("type", "execution"),
                            "host": c.get("host", ""),
                            "case_id": stage_case_id,
                        },
                        label="record_timeline_event",
                    ))
                    if result.get("event_id"):
                        timeline_ids.append(result["event_id"])
                except Exception as e:
                    errors.append(str(e))

    log_msg = [
        f"Staged {len(draft_ids)} of {len(candidates)} finding candidate(s), "
        f"{len(timeline_ids)} timeline events",
    ]
    if not candidates:
        log_msg.append("The interpret run produced no finding candidates; nothing was staged")
    for item in linked_drafts:
        log_msg.append(f"Linked to existing DRAFT {item['finding_id']}: {item['title']}")
    for item in decided_claims:
        log_msg.append(f"Already {item['decision']} by the examiner as {item['finding_id']}: {item['title']}")
    for item in rejected:
        log_msg.append(f"Not staged: {item['title'] or '(untitled)'}: {item['reason'][:300]}")
    if errors and len(errors) > len(rejected):
        log_msg.append(f"Errors: {'; '.join(errors[len(rejected):][:3])}")
    # This run's own findings: the verdict covers them, not every DRAFT in the case. It used to
    # read findings.json whole, so an independent run's verdict listed 23 findings from four
    # runs (2026-10-14, D169).
    run_finding_ids = {str(f) for f in draft_ids} | {item["finding_id"] for item in linked_drafts}
    # The run record says what was staged and what was refused, and why.
    if stage_case_dir is not None:
        try:
            from nexus.langgraph.pipeline_runs import _atomic_json, resolve_run

            _run = resolve_run(stage_case_dir, run_id=str(state.get("run_id") or ""))
            _atomic_json(_run.analysis / "staging.json", {
                "run_id": _run.run_id,
                "candidates": len(candidates),
                "staged": list(draft_ids),
                "linked": linked_drafts,
                "decided": decided_claims,
                "rejected": rejected,
                "dispositions": dispositions,
            })
        except Exception as exc:  # noqa: BLE001 - the step log still carries the outcome
            log_msg.append(f"staging record not written: {exc}")
    # No model-written draft report here (D169, operator 2026-10-14). The designed flow ends a run
    # at DRAFTs + interpretation.md; the report is written from APPROVED findings, and the
    # examiner's preview of DRAFTs is `nexus report generate`. The draft report was half of every
    # Mode 1 run (21 of 42 minutes on 2026-10-14).

    # Mode 1 verdict: coverage gaps vs the entity inventory + digest
    # reconciliation + interpretation.md (deterministic skeleton + optional
    # LLM executive verdict).
    try:
        from nexus.config import settings as _settings
        from nexus.langgraph.entity_inventory import compute_coverage_gaps
        from nexus.langgraph.interpretation import write_interpretation_summary

        case_dir = _settings.cases_root / str(state.get("case_id") or "")
        gaps: list[dict[str, str]] = []
        staged: list[dict[str, Any]] = []
        findings_path = case_dir / "findings.json"
        if findings_path.is_file():
            loaded = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                staged = [f for f in loaded
                          if isinstance(f, dict) and str(f.get("id")) in run_finding_ids]
        inv_path = case_dir / "analysis" / "entity_inventory.json"
        if inv_path.is_file():
            inv = json.loads(inv_path.read_text(encoding="utf-8"))
            gaps = compute_coverage_gaps(inv, staged)
        reconciliation: dict[str, Any] = {}
        digest_path = case_dir / "analysis" / "case_digest.json"
        if digest_path.is_file():
            from nexus.langgraph.case_digest import reconciliation_checklist

            reconciliation = reconciliation_checklist(
                json.loads(digest_path.read_text(encoding="utf-8")), staged, dispositions
            )
        emit_stage(state, "interpretation", "running", "the executive verdict")
        out = await write_interpretation_summary(
            case_dir, findings=staged, gaps=gaps, reconciliation=reconciliation, model=model,
            run_id=str(state.get("run_id") or ""), dispositions=dispositions,
        )
        emit_stage(state, "interpretation", "done", str(out or ""))
        if out:
            log_msg.append(
                f"Wrote {out.name} (gaps={len(gaps)}, "
                f"reconciliation_unaddressed={len(reconciliation.get('unaddressed') or [])})"
            )
    except Exception as exc:  # noqa: BLE001 — verdict is best-effort
        log_msg.append(f"interpretation summary skipped: {exc}")

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
    del tools
    step_log: list[str] = ["Writing run-scoped report from APPROVED findings"]

    report_path: str | None = None
    export_root: str | None = None
    try:
        import json as _json

        import yaml

        from nexus.cli.report import _load_flat_evidence
        from nexus.config import settings
        from nexus.detection.draft_from_findings import draft_from_approved
        from nexus.integration.dfir_report import (
            _split_questions,
            build_dfir_markdown,
            load_case_ledger,
            sift_notes_from_ledger,
        )
        from nexus.langgraph.pipeline_runs import finalize_run, resolve_run
        from nexus.langgraph.timeline_merge import rebuild_case_timeline

        case_dir = settings.cases_root / state["case_id"]
        pipeline_run = resolve_run(case_dir, run_id=state.get("run_id") or "")
        findings_path = case_dir / "findings.json"
        findings = []
        if findings_path.is_file():
            findings = _json.loads(findings_path.read_text(encoding="utf-8"))
        meta: dict = {}
        case_yaml = case_dir / "CASE.yaml"
        if case_yaml.is_file():
            meta = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
        try:
            timeline = rebuild_case_timeline(case_dir)
            step_log.append(f"N7 chronology: {len(timeline)} events")
        except Exception as exc:  # noqa: BLE001
            step_log.append(f"N7 chronology skipped: {exc}")
            timeline = []
            tl_path = case_dir / "timeline.json"
            if tl_path.is_file():
                timeline = _json.loads(tl_path.read_text(encoding="utf-8"))
        try:
            this_run = list(state.get("approved_finding_ids") or [])
            d1 = draft_from_approved(case_dir, findings, finding_ids=this_run or None)
            step_log.append(f"D1 drafts: {d1.get('dir')} needles={d1.get('needles')}")
        except Exception as exc:  # noqa: BLE001
            step_log.append(f"D1 draft skipped: {exc}")
        intake = meta.get("intake") if isinstance(meta.get("intake"), dict) else {}
        questions = _split_questions(str((intake or {}).get("question") or meta.get("question") or ""))
        evidence = _load_flat_evidence(case_dir)
        ledger = list(state.get("tool_run_ledger") or []) or load_case_ledger(case_dir)
        sift_notes = sift_notes_from_ledger(ledger)
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
            case_summary=str((intake or {}).get("question") or meta.get("description") or ""),
            tool_ledger=ledger,
            finding_ids=list(state.get("approved_finding_ids") or []) or None,
            questions=questions,
            severity=str(meta.get("severity") or "unrated"),
            case_dir=case_dir,
        )
        # Append analysis pointers for examiners
        extra = []
        if (case_dir / "analysis" / "chronology.md").is_file():
            extra.append("N7 chronology is `analysis/chronology.md`.")
        if (case_dir / "analysis" / "detections" / "README.md").is_file():
            extra.append("D1 SIEM drafts are `analysis/detections/` (not N5 facts).")
        if extra:
            md += "\n\n## Analysis artifacts\n\n" + " ".join(extra) + "\n"
        out = pipeline_run.reports / "REPORT.md"
        out.write_text(md, encoding="utf-8")
        (pipeline_run.reports / "dfir-report.md").write_text(md, encoding="utf-8")
        step_log.append(f"Wrote {out}")

        from nexus.case.repo_export import (
            export_case_to_repo,
            live_case_is_in_repo,
            repo_export_enabled,
        )

        if not repo_export_enabled():
            finalize_run(pipeline_run, "completed")
            step_log.append(
                "Repo sample-export disabled (set NEXUS_REPO_EXPORT=1 for the examiner copy)"
            )
            return {
                "report_path": str(out),
                "step_log": step_log,
                "rag_notes": [f"live_case={case_dir}"],
            }

        if live_case_is_in_repo(case_dir):
            finalize_run(pipeline_run, "completed")
            step_log.append("Repo sample-export skipped (live case already in-repo)")
            return {
                "report_path": str(out),
                "step_log": step_log,
                "rag_notes": [f"live_case={case_dir}"],
            }

        exported = export_case_to_repo(
            case_dir,
            report_markdown=md,
            extra_sift_dir=case_dir / "sift" / "extractions",
        )
        export_root = str(exported)
        report_path = str(exported / "reports" / "REPORT.md")
        step_log.append(f"Repo export: {exported}")
        finalize_run(pipeline_run, "completed")
    except Exception as exc:  # noqa: BLE001
        if "pipeline_run" in locals():
            finalize_run(pipeline_run, "failed", str(exc))
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

def _route_after_load_existing(state: dict) -> str:
    """Stop when the case has no tools run to interpret; otherwise interpret it."""
    return "end" if state.get("load_error") else "interpret"


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
        return await stage_findings(state, tools, model)

    async def _generate_report(state: InvestigationState) -> dict:
        return await generate_report(state, tools)

    async def _emit_tool_report(state: InvestigationState) -> dict:
        return await emit_tool_report(state, tools)

    workflow = StateGraph(InvestigationState)

    # Live stage feed: every node announces running/done/error (with the last
    # step_log line as detail) to the progress JSONL the dashboard polls.
    def _trace(name: str, fn):
        async def _inner(state: InvestigationState) -> dict:
            emit_stage(state, name, "running")
            try:
                out = await fn(state)
            except Exception as exc:  # noqa: BLE001 — feed the error, then re-raise
                emit_stage(state, name, "error", str(exc)[:200])
                raise
            detail = ""
            if isinstance(out, dict):
                tail = out.get("step_log") or []
                if isinstance(tail, list) and tail:
                    detail = str(tail[-1])[:200]
                elif out.get("error"):
                    detail = str(out.get("error"))[:200]
            emit_stage(state, name, "done", detail)
            return out

        return _inner

    _add_node = workflow.add_node

    def _add_traced(name: str, fn) -> None:
        _add_node(name, _trace(name, fn))


    if mode == "tools":
        _add_traced("register_evidence", _register_evidence)
        _add_traced("scope", _scope_tools_only)
        _add_traced("execute_tool_lane", _execute_tool_lane)
        _add_traced("emit_tool_report", _emit_tool_report)
        workflow.set_entry_point("register_evidence")
        workflow.add_edge("register_evidence", "scope")
        workflow.add_edge("scope", "execute_tool_lane")
        workflow.add_edge("execute_tool_lane", "emit_tool_report")
        workflow.add_edge("emit_tool_report", END)
        return workflow

    _add_traced("ensure_rag", _ensure_rag)
    workflow.set_entry_point("ensure_rag")

    if mode == "interpret":
        _add_traced("load_existing", _load_existing)
        _add_traced("interpret", _interpret)
        _add_traced("stage_findings", _stage_findings)
        _add_traced("await_approval", await_approval)
        _add_traced("generate_report", _generate_report)
        workflow.add_edge("ensure_rag", "load_existing")
        workflow.add_conditional_edges(
            "load_existing",
            _route_after_load_existing,
            {"interpret": "interpret", "end": END},
        )
        workflow.add_edge("interpret", "stage_findings")
        workflow.add_edge("stage_findings", "await_approval")
        workflow.add_edge("await_approval", "generate_report")
        workflow.add_edge("generate_report", END)
        return workflow

    _add_traced("register_evidence", _register_evidence)
    _add_traced("scope", _scope)
    _add_traced("stage_findings", _stage_findings)
    _add_traced("await_approval", await_approval)
    _add_traced("generate_report", _generate_report)
    _add_traced("emit_tool_report", _emit_tool_report)
    workflow.add_edge("ensure_rag", "register_evidence")
    workflow.add_edge("register_evidence", "scope")

    def _has_intake(st: InvestigationState) -> bool:
        """N1 gate: did the examiner supply a real question or incident window?"""
        return has_examiner_intake(st.get("case_context") or {})

    def _route_after_tool_lane(st: InvestigationState) -> str:
        # Empty or placeholder intake on coverage/design degrades to TOOL-RUN.
        return "interpret_path" if _has_intake(st) else "tools_only"

    if mode == "coverage":
        _add_traced("execute_tool_lane", _execute_tool_lane)
        _add_traced("interpret", _interpret)
        workflow.add_edge("scope", "execute_tool_lane")
        workflow.add_conditional_edges(
            "execute_tool_lane",
            _route_after_tool_lane,
            {"interpret_path": "interpret", "tools_only": "emit_tool_report"},
        )
        workflow.add_edge("interpret", "stage_findings")
    else:
        _add_traced("execute_tool_lane", _execute_tool_lane)
        _add_traced("hunt", _hunt)
        _add_traced("interpret", _interpret)
        workflow.add_edge("scope", "execute_tool_lane")
        workflow.add_conditional_edges(
            "execute_tool_lane",
            _route_after_tool_lane,
            {"interpret_path": "hunt", "tools_only": "emit_tool_report"},
        )
        workflow.add_edge("hunt", "interpret")
        workflow.add_edge("interpret", "stage_findings")

    workflow.add_edge("stage_findings", "await_approval")
    workflow.add_edge("await_approval", "generate_report")
    workflow.add_edge("generate_report", END)
    workflow.add_edge("emit_tool_report", END)

    return workflow


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def _load_mcp_tools(
    config: dict[str, dict],
    sessions: contextlib.AsyncExitStack | None = None,
) -> dict[str, Any]:
    """Load MCP tools with Windows as case authority when dual-host.

    Shared names (case_init, record_finding, …) prefer ``nexus-windows``.
    SIFT ``case_init`` / ``case_activate`` are retained as ``_sift_case_*``
    so the pipeline can mirror the same case_id onto the tool host.

    With ``sessions``, each server's tools are bound to one session that stays open until the
    caller closes the stack, so a run makes every call over one connection. Without it, each tool
    call opens its own session; over stdio that started a new DFIR-Nexus server for every call,
    each reloading the RAG embedder (about 60 s), and a 36h Mode 1 run made 69 calls in 30
    minutes (D71).
    """
    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langchain_mcp_adapters.tools import load_mcp_tools

    tools_by_name: dict[str, Any] = {}
    if not config:
        return tools_by_name

    # Load one server at a time so we know provenance (merged get_tools loses it).
    for server_name, server_cfg in config.items():
        client = MultiServerMCPClient({server_name: server_cfg})
        try:
            # Handshake (initialize + tools/list) is bounded: an unresponsive
            # server must fail the load, not hang the pipeline before any
            # evidence is read. The run then reports a real reason.
            if sessions is not None:
                session = await asyncio.wait_for(
                    sessions.enter_async_context(client.session(server_name)),
                    timeout=call_timeout(None),
                )
                tools_list = await asyncio.wait_for(
                    load_mcp_tools(session, server_name=server_name),
                    timeout=call_timeout(None),
                )
            else:
                tools_list = await asyncio.wait_for(
                    client.get_tools(),
                    timeout=call_timeout(None),
                )
        except TimeoutError:
            log.error(
                "MCP tool load from %s timed out after %.0fs — server not answering",
                server_name,
                call_timeout(None),
            )
            continue
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


def _case_evidence_paths(case_id: str) -> list[str]:
    """Local evidence paths registered on an existing case.

    A tools/interpret run that is given a case but no evidence paths must
    inherit the case's evidence. Without this the Windows planner is handed no
    paths, so EVTX is never scheduled (EvtxECmd / Hayabusa / Chainsaw all sit
    unused), the discovery job SKIPs, and the pass reports clean over evidence
    it never read.

    Only paths that exist on THIS machine are returned. SIFT-hosted evidence is
    registered as ``/evidence/<name>`` - a path on the SIFT host - and is left
    to the SIFT lane rather than handed to the local planner.
    """
    from nexus.config import settings

    path = Path(str(settings.cases_root)) / str(case_id or "").strip() / "evidence.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    items = data if isinstance(data, list) else (data.get("evidence") or [])
    if not isinstance(items, list):
        return []
    case_root = Path(str(settings.cases_root)) / str(case_id or "").strip()
    out: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        # A tool's own output is not evidence (D57). Its registry entry is kind tool_extraction, and a
        # plain file entry under the case's runs or extractions folders is the same output registered
        # again. Handing either to the planner, or to the evidence register step, makes a tool output
        # examiner evidence (found on CASE-C5B04D31: hayabusa_stdout.txt was registered on the re-run).
        if str(item.get("kind") or "") == "tool_extraction":
            continue
        raw = str(item.get("path") or "").strip()
        if not raw:
            continue
        if _is_under_case_outputs(Path(raw), case_root):
            continue
        try:
            local = Path(raw)
            if local.exists() and str(local) not in out:
                out.append(str(local))
        except OSError:
            continue
    return out


def _is_under_case_outputs(path: Path, case_root: Path) -> bool:
    """True when a path sits in a case's tool-output folders (tool output, never examiner evidence)."""
    from nexus.langgraph.pipeline_runs import is_tool_output

    return is_tool_output(path, case_root)


def _evidence_register_budget(path: str) -> float:
    """Seconds to content-hash this path, at a slow-disk floor of 20 MB/s.

    ``call_tool`` applies the 300s control budget when a call declares none.
    Hashing ``rd01-memory.img`` (5.3 GB) or the triage tree does not finish
    in that window, so the pipeline raised ToolCallTimeout and never reached
    the parsers.
    """
    p = Path(path)
    nbytes = 0
    try:
        if p.is_file():
            nbytes = p.stat().st_size
        elif p.is_dir():
            for child in p.rglob("*"):
                if child.is_file():
                    nbytes += child.stat().st_size
    except OSError:
        nbytes = 0
    seconds = nbytes / (20 * 1024 * 1024) + 180.0
    return max(300.0, min(seconds, 6 * 3600.0))


def inherit_evidence_paths(
    case_id: str,
    evidence_path: str,
    evidence_paths: list[str] | None,
) -> list[str] | None:
    """The evidence paths a case-based run should use.

    Returns what the caller supplied when it supplied anything, otherwise the
    case's own registered local paths. **No mode parameter, deliberately**: every
    mode that runs the lane (tools, coverage, design, interpret) needs these, and
    scoping an earlier version of this to `tools`/`interpret` left `coverage`
    - which is what Mode 1 runs - planning an empty lane.
    """
    case = str(case_id or "").strip()
    if case and evidence_paths:
        # A tool's output is not evidence, whoever supplies the list. A run inherits its predecessor's list,
        # and that list held 184 stdout files of an earlier run (CASE-C5B04D31, 2026-10-11).
        from nexus.config import settings
        from nexus.langgraph.pipeline_runs import drop_tool_outputs

        kept = drop_tool_outputs(list(evidence_paths), Path(str(settings.cases_root)) / case)
        if kept:
            return kept
        return _case_evidence_paths(case) or kept
    if evidence_path or evidence_paths:
        return evidence_paths
    if not case:
        return evidence_paths
    return _case_evidence_paths(case) or evidence_paths


def _unfinished_reason(result: Any) -> str:
    """Why a finished graph produced no completed run, or "" when it did.

    A node can return ``{"error": ...}`` without raising. The graph then ends
    normally while the run record is never finalized, so the manifest reads
    ``running`` for a run that is over. The node's own error is the reason.
    """
    state = result if isinstance(result, dict) else {}
    if state.get("report_path"):
        return ""
    error = str(state.get("error") or "").strip()
    if error:
        return error[:400]
    drafts = state.get("draft_finding_ids") or []
    return (
        "run ended without a report"
        + (f" ({len(drafts)} draft finding(s) staged)" if drafts else
           " and staged no findings")
    )


def _final_state(initial: InvestigationState | dict, result: Any) -> dict:
    """The state a finalize must read: where the nodes left the run id.

    ``initial`` is built by ``make_initial_state`` with ``run_id=""`` — the id is
    minted later, in ``register_evidence`` (tools) or ``load_existing_case``
    (interpret). Finalizing from ``initial`` therefore resolved the WRONG run:
    with an empty id, ``_run_to_finalize`` falls back to the newest run, which
    is a *previous* run while the current one is still being written. The
    approval pause was logged while the paused run stayed `running` and some
    older run was stamped instead (SC1, 2026-10-07).

    Prefer the returned state's values, then the initial state's, so a node's
    own ``run_id``/``run_dir`` wins.
    """
    merged = dict(initial) if isinstance(initial, dict) else {}
    if isinstance(result, dict):
        for key in ("run_id", "run_dir", "case_id"):
            if result.get(key):
                merged[key] = result[key]
    return merged


def _run_to_finalize(state: InvestigationState | dict) -> Any:
    """The run record a finalize call must touch.

    The graph's initial state carries ``run_id = ""``; the id is minted in
    ``load_existing_case`` (interpret) or ``register_evidence``. Resolving with
    ``run_id=""`` therefore falls back to the ACTIVE RUN FOR A MODE, and passing
    no mode defaults to ``tools`` — which finalized the *tool lane* while the
    interpret run it was meant to record stayed `running` (SC1, 2026-10-07, the
    first version of this fix).

    So: prefer the run this pipeline actually created (``run_dir``), then the
    state's ``run_id``, then the newest run by mtime rather than a defaulted
    mode. Never guess a mode.
    """
    from nexus.config import settings
    from nexus.langgraph.pipeline_runs import _load_run, resolve_run

    st = state if isinstance(state, dict) else {}
    case_dir = settings.cases_root / str(st.get("case_id") or "")
    rid = str(st.get("run_id") or "").strip()
    if rid:
        return resolve_run(case_dir, run_id=rid)
    run_dir = str(st.get("run_dir") or "").strip()
    if run_dir:
        return _load_run(case_dir, Path(run_dir).name)
    runs = case_dir / "runs"
    if runs.is_dir():
        dirs = [d for d in runs.iterdir() if d.is_dir()]
        if dirs:
            newest = max(dirs, key=lambda d: d.stat().st_mtime)
            return _load_run(case_dir, newest.name)
    raise ValueError(f"no run found to finalize in {case_dir.name}")


async def _finalize_died(
    initial: InvestigationState | dict,
    exc: BaseException,
    *,
    compiled: Any = None,
    cfg: dict | None = None,
) -> None:
    """Record a run that raised, so it never reads `running` afterwards."""
    try:
        from nexus.langgraph.pipeline_runs import finalize_run

        state = initial
        if compiled is not None and cfg is not None:
            snapshot = await _snapshot(compiled, cfg)
            if snapshot is not None:
                state = _final_state(initial, getattr(snapshot, "values", None))
        try:
            run = _run_to_finalize(state)
        except ValueError:
            # The pipeline died before creating a run (e.g. a load error): nothing to finalise.
            log.info("no run record to finalize: the pipeline stopped before creating one")
            return
        finalize_run(run, "failed", f"{type(exc).__name__}: {exc}"[:400])
    except Exception:  # noqa: BLE001 — status bookkeeping must not mask the error
        log.exception("could not finalize a run that died")


async def _snapshot(compiled: Any, cfg: dict) -> Any:
    """The graph's current snapshot, or None."""
    try:
        return await compiled.aget_state(cfg)
    except Exception:  # noqa: BLE001 — a state read must not mask the run
        return None


async def _finalize_if_unfinished(
    initial: InvestigationState | dict,
    result: Any,
    *,
    compiled: Any = None,
    cfg: dict | None = None,
) -> None:
    """Record a run that ended without a report, naming the node's error.

    Two shapes end here, and they are not the same:

    * **Paused at the approval interrupt** — `ainvoke` RETURNS at
      `interrupt_before=["await_approval"]`, so the run has staged its findings
      and is waiting for the examiner. That is the designed boundary, not a
      failure: recorded `interrupted` (the vocabulary's "ended without
      completing") with the node it waits on, never `failed`.
    * **A node returned `{"error": ...}`** instead of raising, leaving a run
      that is over with nothing to show. Recorded `failed` with that error.
    """
    reason = _unfinished_reason(result)
    if not reason:
        return
    pending: list[str] = []
    if compiled is not None and cfg is not None:
        snapshot = await _snapshot(compiled, cfg)
        pending = list(getattr(snapshot, "next", ()) or ()) if snapshot else []
    state = _final_state(initial, result)
    try:
        from nexus.langgraph.pipeline_runs import finalize_run

        try:
            run = _run_to_finalize(state)
        except ValueError:
            # The pipeline stopped before creating a run (e.g. a load error): its own error is
            # the answer, so there is no run record to finalise.
            log.info("no run record to finalize: the pipeline stopped before creating one")
            return
        if pending:
            drafts = len(state.get("draft_finding_ids") or (result or {}).get(
                "draft_finding_ids") or [])
            finalize_run(
                run, "interrupted",
                f"awaiting approval at {pending[0]}"
                + (f" ({drafts} DRAFT finding(s) staged)" if drafts else ""),
            )
            log.info("Run paused at %s awaiting approval — not failed", pending[0])
            return
        finalize_run(run, "failed", reason)
        log.error("Run ended without a report: %s", reason)
    except Exception:  # noqa: BLE001
        log.exception("could not finalize an unfinished run")


async def run_pipeline(
    evidence_path: str = "",
    resume: bool = False,
    thread_id: str = "",
    model_name: str = "",
    case_context: dict[str, str] | None = None,
    mode: str | None = None,
    evidence_paths: list[str] | None = None,
    case_id: str = "",
    progress_path: str = "",
    context_policy: str = "independent",
):
    """Run the DFIR-Nexus LangGraph investigation pipeline."""
    from nexus.analysis.context_policy import normalize_policy

    pipeline_mode = resolve_pipeline_mode(mode)
    policy = normalize_policy(context_policy)
    from_case = (case_id or "").strip()
    log.info("Pipeline mode: %s", pipeline_mode)

    _progress = {"progress_path": str(progress_path or "")}
    emit_stage(_progress, "pipeline", "running", f"mode={pipeline_mode}")

    config = get_mcp_config()
    async with contextlib.AsyncExitStack() as sessions:
        tools_by_name = await _load_mcp_tools(config, sessions=sessions)
        return await _run_pipeline_with_tools(
            tools_by_name,
            pipeline_mode=pipeline_mode,
            policy=policy,
            from_case=from_case,
            evidence_path=evidence_path,
            resume=resume,
            thread_id=thread_id,
            model_name=model_name,
            case_context=case_context,
            evidence_paths=evidence_paths,
            progress_path=progress_path,
        )


async def _run_pipeline_with_tools(
    tools_by_name: dict[str, Any],
    *,
    pipeline_mode: str,
    policy: str,
    from_case: str,
    evidence_path: str,
    resume: bool,
    thread_id: str,
    model_name: str,
    case_context: dict[str, str] | None,
    evidence_paths: list[str] | None,
    progress_path: str,
):
    """The run itself, while ``run_pipeline`` holds the MCP sessions open (D71)."""
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.types import Command

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
            from nexus.config import settings
            case_dir = settings.cases_root / case_id
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

    # A run on an EXISTING case must inherit that case's registered evidence.
    # Without this the Windows planner is handed no paths, EVTX is never
    # scheduled, and the lane reports a clean pass over evidence it never read.
    if from_case and not (evidence_path or evidence_paths):
        inherited = inherit_evidence_paths(from_case, evidence_path, evidence_paths)
        if inherited:
            evidence_paths = inherited
            log.info(
                "%s run inherits %d evidence path(s) from case %s",
                pipeline_mode, len(inherited), from_case,
            )
        else:
            log.warning(
                "%s run has no evidence paths for case %s: none supplied and "
                "none of the registered paths exist on this machine",
                pipeline_mode, from_case,
            )

    initial = make_initial_state(
        evidence_path=evidence_path,
        case_context=case_context,
        pipeline_mode=pipeline_mode,
        evidence_paths=evidence_paths,
        case_id=from_case,
        progress_path=progress_path,
    )
    # WO-1C item 3: the policy decided before the run travels with the state,
    # so the interpret loop and the run record cannot disagree about it.
    initial["context_policy"] = policy
    try:
        result = await compiled.ainvoke(initial, config=cfg)
    except BaseException as exc:
        # A run that dies must not be left reading `running`. Without this the
        # manifest stayed `running` with no reason, no report and no findings,
        # and the next reader could not tell a crash from an in-flight run
        # (SC1, 2026-10-07). `BaseException` so a cancellation is recorded too;
        # `finalize_run` is idempotent and never raises out of here.
        emit_stage(initial, "pipeline", "error", str(exc)[:200])
        await _finalize_died(initial, exc, compiled=compiled, cfg=cfg)
        raise
    emit_stage(
        initial, "pipeline", "done",
        f"drafts={len(result.get('draft_finding_ids') or [])}" if isinstance(result, dict) else "",
    )
    # The graph reached the end but may still have failed after the tool lane:
    # a node that returned `{"error": ...}` instead of raising, with no report
    # written, leaves the same `running` record. Record it as failed with the
    # node's own reason rather than reporting a completed run that has nothing.
    await _finalize_if_unfinished(
        _final_state(initial, result), result, compiled=compiled, cfg=cfg
    )

    result_state = result if isinstance(result, dict) else {}
    log.info("Pipeline complete")
    log.info("  Mode:         %s", pipeline_mode)
    log.info("  Case ID:      %s", result_state.get("case_id", "N/A"))
    log.info("  Approved:     %s", len(result_state.get("approved_finding_ids", [])))
    log.info("  Draft:        %s", len(result_state.get("draft_finding_ids", [])))
    log.info("  Report:       %s", result_state.get("report_path", "N/A"))
    log.info("  Steps:        %d", len(result_state.get("step_log", [])))
    return result_state
