"""Mode 3 agent runtime — M1/M2/M5 foundation.

This module is the real agentic execution layer, not the old
``run_orchestrator`` simulation:

- **Roles** are data (``AgentRole``): scoped read-only tool allowlists, system
  prompt, budget, and fallback behaviour.
- **Work orders** are the examiner-visible unit of agent work (``WorkOrder``):
  task, family, priority tools, expected artifact/event IDs, acceptance,
  negative-evidence rule and a bounded budget.
- **Workers** execute through the shared ``run_context_loop`` (WP 10.53/10.54):
  every tool call is audited through ``backbone_call``, budget expiry returns
  partial results, and no role can stage or approve a finding.
- **Events** use one envelope (``run_id``/``turn_id``/``agent_id``/``call_id``/
  ``input_call_ids``) persisted to ``analysis/mode3_runs/<run_id>.jsonl`` and
  streamed through an optional callback (SSE/CLI consume the same events).
- **Supervisor** is a LangGraph ``StateGraph``: director -> worker(s) ->
  verifier -> synthesis -> finalize, with persistent run state and bounded
  loops. Deterministic fallbacks exist for every role.

No hidden chain-of-thought is recorded: plans, tool calls, hypotheses, notes,
decisions and outputs only.
"""
from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from nexus.audit import AuditWriter
from nexus.langgraph.context_loop import LoopBudget, run_context_loop

log = logging.getLogger(__name__)

_MODE3_DIR = "analysis/mode3_runs"


def _env_int(name: str, default: int, *, low: int, high: int) -> int:
    try:
        value = int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        value = default
    return max(low, min(value, high))


def _env_float(name: str, default: float, *, low: float, high: float) -> float:
    try:
        value = float(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        value = default
    return max(low, min(value, high))


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _short(text: Any, limit: int = 500) -> str:
    return " ".join(str(text or "").split())[:limit]


# ---------------------------------------------------------------------------
# Event envelope (M5.1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentEvent:
    """One observable Mode 3 event (never hidden reasoning)."""

    event_id: str
    ts: str
    run_id: str
    event_type: str
    actor: str
    turn_id: str = ""
    agent_id: str = ""
    call_id: str = ""
    parent_call_id: str = ""
    tool: str = ""
    why: str = ""
    audit_id: str = ""
    status: str = ""
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def new_event(
    run_id: str,
    event_type: str,
    *,
    actor: str = "system",
    turn_id: str = "",
    agent_id: str = "",
    call_id: str = "",
    parent_call_id: str = "",
    tool: str = "",
    why: str = "",
    audit_id: str = "",
    status: str = "",
    detail: str = "",
    data: dict[str, Any] | None = None,
) -> AgentEvent:
    return AgentEvent(
        event_id=f"evt-{uuid4().hex[:16]}",
        ts=_now(),
        run_id=run_id,
        event_type=str(event_type)[:80],
        actor=str(actor)[:40],
        turn_id=str(turn_id)[:40],
        agent_id=str(agent_id)[:60],
        call_id=str(call_id)[:40],
        parent_call_id=str(parent_call_id)[:40],
        tool=str(tool)[:80],
        why=_short(why, 200),
        audit_id=str(audit_id)[:80],
        status=str(status)[:40],
        detail=_short(detail, 400),
        data=data or {},
    )


class EventSink:
    """Persist + optionally stream Mode 3 events (M5.1/M5.3)."""

    def __init__(self, case_dir: Path, run_id: str,
                 callback: Callable[[dict[str, Any]], None] | None = None):
        self.case_dir = Path(case_dir)
        self.run_id = run_id
        self.callback = callback
        self.path = self.case_dir / _MODE3_DIR / f"{run_id}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: AgentEvent) -> None:
        payload = event.to_dict()
        try:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, default=str) + "\n")
        except OSError as exc:  # noqa: BLE001 — observability must not kill a run
            log.warning("mode3 event write failed: %s", exc)
        if self.callback is not None:
            try:
                self.callback(payload)
            except Exception:  # noqa: BLE001 — streaming must not kill a run
                log.debug("mode3 event callback failed", exc_info=True)


# ---------------------------------------------------------------------------
# Roles (M2.1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentRole:
    name: str
    description: str
    tools: tuple[str, ...]
    system_prompt: str
    max_rounds: int = 4
    max_calls: int = 8
    max_seconds: float = 240.0

    def budget(self) -> LoopBudget:
        return LoopBudget(
            rounds=self.max_rounds,
            seconds=self.max_seconds,
            calls=self.max_calls,
        )


ROLES: dict[str, AgentRole] = {
    "evidence": AgentRole(
        name="evidence",
        description="Family-scoped evidence retrieval and hypothesis testing.",
        tools=("es_mappings", "es_search", "es_aggregate", "sample_rows", "run_record"),
        system_prompt=(
            "You are an evidence agent. Answer the work order using ONLY the "
            "read-only tools for this case. Start from the assigned family, "
            "but check other families when corroboration is needed. Always use "
            "run_record before claiming something is absent. Return JSON: "
            '{"notes":[{"statement":"...","evidence":["family/file:line ..."],'
            '"audit_ids":["..."]}],"entities":["..."],'
            '"candidate_findings":[{"title":"...","observation":"...",'
            '"interpretation":"...","confidence":"LOW|MEDIUM|HIGH",'
            '"audit_ids":["..."]}],"coverage":{"checked":["..."],'
            '"not_checked":["..."]},"next_questions":["..."]}. '
            "Do not invent evidence; a zero-hit search is not negative evidence "
            "until run_record shows the parser ran."
        ),
        max_rounds=4,
        max_calls=8,
        max_seconds=240.0,
    ),
    "correlation": AgentRole(
        name="correlation",
        description="Cross-family entity/temporal corroboration.",
        tools=("es_search", "es_aggregate", "sample_rows", "run_record"),
        system_prompt=(
            "You are the correlation agent. Given the evidence notes, identify "
            "entities that appear across families and temporal chains worth "
            "investigating. Verify each link with a tool call before asserting "
            "it. Return JSON with keys: corroborated_entities, chains, "
            "unexplained, next_questions, coverage."
        ),
        max_rounds=3,
        max_calls=6,
        max_seconds=180.0,
    ),
    "pattern": AgentRole(
        name="pattern",
        description="ITM/ATT&CK/ATLAS/MBC pattern matching.",
        tools=("es_search", "es_aggregate", "run_record", "kb_query", "rag_search"),
        system_prompt=(
            "You are the pattern agent. Match the evidence against the case's "
            "framework registries (ITM/ATT&CK/ATLAS/MBC) through rag_search and "
            "kb_query, and verify the required evidence rows exist with "
            "es_search/es_aggregate. Return JSON with keys: patterns, evidence, "
            "caveats, next_questions, coverage. Do not force a pattern when the "
            "required evidence is missing."
        ),
        max_rounds=3,
        max_calls=6,
        max_seconds=180.0,
    ),
    "verifier": AgentRole(
        name="verifier",
        description="Adversarial refutation of candidate findings.",
        tools=("es_search", "es_aggregate", "sample_rows", "run_record",
               "kb_query", "rag_search"),
        system_prompt=(
            "You are the verifier. For EACH candidate finding, re-check its "
            "cited claims with tools and classify it confirmed, inferred or "
            "refuted. A refuted finding must state the counter-evidence. Return "
            "JSON: {\"verdicts\":[{\"title\":\"...\",\"class\":"
            "\"confirmed|inferred|refuted\",\"basis\":\"...\","
            "\"audit_ids\":[\"...\"]}],\"coverage\":{...}}"
        ),
        max_rounds=4,
        max_calls=10,
        max_seconds=300.0,
    ),
    "synthesis": AgentRole(
        name="synthesis",
        description="Case narrative + DRAFT candidate findings.",
        tools=("es_aggregate", "sample_rows", "run_record", "kb_query", "rag_search"),
        system_prompt=(
            "You are the synthesis agent. Build the investigation narrative "
            "from the verified notes only, and propose DRAFT candidate findings "
            "with audit_ids. Return JSON: {\"narrative\":\"...\","
            "\"findings\":[{\"title\":\"...\",\"observation\":\"...\","
            "\"interpretation\":\"...\",\"confidence\":\"LOW|MEDIUM|HIGH\","
            "\"confidence_justification\":\"...\",\"audit_ids\":[\"...\"],"
            "\"attack_ids\":[\"...\"],\"itm_stage\":\"...\","
            "\"itm_objects\":\"...\"}],\"gaps\":[\"...\"],"
            "\"coverage\":{...}}. Never approve anything."
        ),
        max_rounds=3,
        max_calls=6,
        max_seconds=240.0,
    ),
    "reporter": AgentRole(
        name="reporter",
        description="Report-ready narrative from verified findings.",
        tools=("run_record", "kb_query", "rag_search"),
        system_prompt=(
            "You are the report agent. Write a compact examiner-ready summary "
            "of the verified findings, their evidence, confidence and the "
            "remaining gaps. Return JSON: {\"summary\":\"...\","
            "\"sections\":[{\"title\":\"...\",\"body\":\"...\"}],"
            "\"gaps\":[\"...\"]}."
        ),
        max_rounds=2,
        max_calls=4,
        max_seconds=120.0,
    ),
}


def role_for(name: str) -> AgentRole:
    if name not in ROLES:
        raise KeyError(f"unknown Mode 3 role: {name!r}")
    return ROLES[name]


def _steering_path(case_dir: Path, run_id: str) -> Path:
    return Path(case_dir) / _MODE3_DIR / f"{run_id}.steering.jsonl"


def append_steering(case_dir: Path, run_id: str, text: str) -> dict[str, Any]:
    """Append an examiner directive for the next work-order turn."""
    entry = {"ts": _now(), "text": _short(text, 600)}
    path = _steering_path(case_dir, run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, default=str) + "\n")
    return entry


def read_steering(case_dir: Path, run_id: str, limit: int = 50) -> list[dict[str, Any]]:
    path = _steering_path(case_dir, run_id)
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict):
                out.append(entry)
    except OSError:
        return []
    return out[-limit:]


def mark_paused(case_dir: Path, run_id: str, paused: bool = True) -> bool:
    """Set/clear the cooperative pause flag in the persisted run record."""
    state = read_run_record(case_dir, run_id)
    if state is None:
        return False
    state["pause_requested"] = bool(paused)
    _persist_state(Path(case_dir), run_id, state)
    return True


# ---------------------------------------------------------------------------
# Work orders (M3.1)
# ---------------------------------------------------------------------------


@dataclass
class WorkOrder:
    order_id: str
    role: str
    task: str
    family: str = ""
    why: str = ""
    priority_tools: tuple[str, ...] = ()
    expected_artifact_ids: tuple[str, ...] = ()
    expected_event_ids: tuple[str, ...] = ()
    acceptance: str = ""
    negative_evidence_rule: str = (
        "A zero-hit query is not negative evidence until run_record shows the "
        "relevant parser ran."
    )
    max_rounds: int = 4
    max_calls: int = 8
    max_seconds: float = 240.0
    status: str = "pending"
    result: dict[str, Any] | None = None
    error: str = ""

    @staticmethod
    def new_id() -> str:
        return f"wo-{uuid4().hex[:12]}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_work_order(order: WorkOrder) -> list[str]:
    """Return a list of validation problems (empty = valid)."""
    problems: list[str] = []
    if order.role not in ROLES:
        problems.append(f"unknown role {order.role!r}")
    if not str(order.task).strip():
        problems.append("task is required")
    role = ROLES.get(order.role)
    if role is not None:
        unknown = [t for t in order.priority_tools if t not in role.tools]
        if unknown:
            problems.append(
                f"priority tools outside {order.role} allowlist: {unknown}")
    if order.max_rounds < 1 or order.max_calls < 1 or order.max_seconds < 5:
        problems.append("budget must be positive")
    return problems


# ---------------------------------------------------------------------------
# Worker execution (M2.2)
# ---------------------------------------------------------------------------


@dataclass
class AgentResult:
    order_id: str
    role: str
    status: str
    reply: str = ""
    parsed: dict[str, Any] = field(default_factory=dict)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    hits: list[dict[str, Any]] = field(default_factory=list)
    aggregations: list[dict[str, Any]] = field(default_factory=list)
    audit_id: str = ""
    partial: bool = False
    partial_reason: str = ""
    elapsed_ms: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_json_object(text: str) -> dict[str, Any]:
    raw = (text or "").strip()
    if not raw:
        return {}
    start, end = raw.find("{"), raw.rfind("}")
    candidates = [raw]
    if start != -1 and end > start:
        candidates.insert(0, raw[start:end + 1])
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def _fallback_result(order: WorkOrder, reason: str) -> AgentResult:
    """Deterministic honest fallback: no evidence invented, reason recorded."""
    return AgentResult(
        order_id=order.order_id,
        role=order.role,
        status="fallback",
        reply=(
            f"Work order {order.order_id} ({order.role}) could not run the "
            f"agent loop: {reason}. No evidence was retrieved by this order. "
            f"Task: {_short(order.task, 300)}"
        ),
        parsed={
            "notes": [],
            "coverage": {
                "checked": [],
                "not_checked": [order.task],
                "fallback_reason": reason,
            },
            "next_questions": [],
        },
        partial=True,
        partial_reason=reason,
    )


def run_work_order(
    order: WorkOrder,
    *,
    case_dir: Path,
    model: Any,
    run_id: str,
    sink: EventSink,
    agent_id: str = "",
    context: dict[str, Any] | None = None,
) -> AgentResult:
    """Execute one work order through the shared bounded tool loop.

    The role's tool allowlist is enforced by the shared loop; the work order
    cannot widen it. No finding is staged here — candidates are returned for
    the verifier/synthesis stages and the examiner's approval gate.
    """
    problems = validate_work_order(order)
    if problems:
        return AgentResult(
            order_id=order.order_id, role=order.role, status="invalid",
            error="; ".join(problems),
        )
    role = role_for(order.role)
    case_dir = Path(case_dir)
    agent_id = agent_id or f"{order.role}-{order.order_id}"
    turn_id = f"turn-{uuid4().hex[:10]}"
    started = time.monotonic()

    work_context = json.dumps(context or {}, default=str)[:6000]
    question = (
        f"WORK ORDER {order.order_id}\n"
        f"Role: {role.name}\n"
        f"Task: {order.task}\n"
        f"Assigned family: {order.family or '(cross-family)'}\n"
        f"Why: {order.why or '(not stated)'}\n"
        f"Priority tools: {', '.join(order.priority_tools) or '(role default)'}\n"
        f"Expected artifact IDs: {', '.join(order.expected_artifact_ids) or '(none)'}\n"
        f"Expected event IDs: {', '.join(order.expected_event_ids) or '(none)'}\n"
        f"Acceptance: {order.acceptance or 'return evidence-linked notes'}\n"
        f"Negative-evidence rule: {order.negative_evidence_rule}\n"
        f"Run context: {work_context}\n\n"
        "Return the role JSON object as the final answer. Use the read-only "
        "tools; never claim evidence you did not retrieve."
    )
    sink.emit(new_event(
        run_id, "work_order.started", actor="director", turn_id=turn_id,
        agent_id=agent_id, detail=order.task, data={
            "order_id": order.order_id, "role": order.role,
            "family": order.family, "why": order.why,
        },
    ))

    def _on_loop_event(event: dict[str, Any]) -> None:
        kind = str(event.get("event") or "event")
        if kind == "tool_call":
            sink.emit(new_event(
                run_id, "tool.call", actor="agent", turn_id=turn_id,
                agent_id=agent_id, tool=str(event.get("tool") or ""),
                why=str(event.get("why") or ""),
                data={"args": event.get("args") or {}},
            ))
        elif kind == "tool_result":
            sink.emit(new_event(
                run_id, "tool.result", actor="agent", turn_id=turn_id,
                agent_id=agent_id, tool=str(event.get("tool") or ""),
                audit_id=str(event.get("audit_id") or ""),
                status="error" if event.get("error") else "ok",
                detail=str(event.get("error") or ""),
                data={"summary": event.get("summary") or {}},
            ))
        elif kind == "round":
            sink.emit(new_event(
                run_id, "agent.round", actor="agent", turn_id=turn_id,
                agent_id=agent_id,
                detail=f"round {event.get('round')}/{event.get('max_rounds')}",
            ))
        elif kind in ("partial", "loop_done"):
            sink.emit(new_event(
                run_id, "agent.partial" if kind == "partial" else "agent.done",
                actor="agent", turn_id=turn_id, agent_id=agent_id,
                detail=str(event.get("reason") or event.get("partial") or ""),
            ))

    try:
        loop = run_context_loop(
            case_dir=case_dir,
            case_id=case_dir.name,
            question=question,
            model=model,
            system_prompt=role.system_prompt,
            task=f"mode3-{role.name}",
            on_event=_on_loop_event,
            budget=LoopBudget(
                rounds=order.max_rounds or role.max_rounds,
                seconds=order.max_seconds or role.max_seconds,
                calls=order.max_calls or role.max_calls,
            ),
            audit=AuditWriter("nexus", audit_dir=case_dir / "audit"),
            terminal_keys=(
                "notes", "candidate_findings", "narrative", "verdicts",
                "patterns", "corroborated_entities", "summary",
            ),
            allowed_tools=role.tools,
        )
    except Exception as exc:  # noqa: BLE001 — every role has an honest fallback
        log.warning("mode3 work order failed (%s): %s", order.order_id, exc)
        result = _fallback_result(order, f"{type(exc).__name__}: {exc}")
        result.elapsed_ms = round((time.monotonic() - started) * 1000, 1)
        order.status = "fallback"
        order.error = result.error or result.partial_reason
        sink.emit(new_event(
            run_id, "work_order.failed", actor="agent", turn_id=turn_id,
            agent_id=agent_id, status="fallback", detail=result.partial_reason,
            data={"order_id": order.order_id},
        ))
        return result

    parsed = _parse_json_object(str(loop.get("reply") or ""))
    result = AgentResult(
        order_id=order.order_id,
        role=order.role,
        status="ok" if parsed else "unparsed",
        reply=str(loop.get("reply") or ""),
        parsed=parsed,
        tool_calls=list(loop.get("tool_calls") or []),
        hits=list(loop.get("hits") or []),
        aggregations=list(loop.get("aggregations") or []),
        audit_id=str(loop.get("audit_id") or ""),
        partial=bool(loop.get("partial")),
        partial_reason=str(loop.get("partial_reason") or ""),
        elapsed_ms=round((time.monotonic() - started) * 1000, 1),
    )
    order.status = result.status
    order.result = {
        "notes": len((parsed.get("notes") or []) if isinstance(parsed, dict) else []),
        "candidates": len((parsed.get("candidate_findings") or []) if isinstance(parsed, dict) else []),
        "audit_id": result.audit_id,
        "partial": result.partial,
    }
    sink.emit(new_event(
        run_id, "work_order.completed", actor="agent", turn_id=turn_id,
        agent_id=agent_id, status=result.status, audit_id=result.audit_id,
        detail=f"{len(result.tool_calls)} tool call(s), "
               f"{len(result.hits)} row(s)",
        data={"order_id": order.order_id, "partial": result.partial},
    ))
    return result


# ---------------------------------------------------------------------------
# Director (M1.2/M3.1)
# ---------------------------------------------------------------------------


def plan_work_orders(
    case_dir: Path,
    question: str,
    *,
    run_id: str,
    sink: EventSink,
    max_orders: int = 6,
) -> list[WorkOrder]:
    """Deterministic director: one evidence order per family + correlation/pattern."""
    case_dir = Path(case_dir)
    audit = AuditWriter("nexus", audit_dir=case_dir / "audit")
    try:
        from nexus.langgraph.backbone import backbone_call

        index = backbone_call("index_mappings", audit=audit, case_id=case_dir.name)
        families = {
            str(k): int(v or 0)
            for k, v in (index.get("family_rows") or {}).items()
        }
    except Exception as exc:  # noqa: BLE001 — director must still plan
        log.warning("mode3 director index_mappings failed: %s", exc)
        families = {}

    ranked = sorted(families.items(), key=lambda kv: (-kv[1], kv[0]))
    orders: list[WorkOrder] = []
    for family, rows in ranked:
        if len(orders) >= max(1, max_orders - 2):
            break
        orders.append(WorkOrder(
            order_id=WorkOrder.new_id(),
            role="evidence",
            task=(f"Investigate family '{family}' ({rows} indexed rows) for "
                  f"the case question: {question or '(no examiner question)'}"),
            family=family,
            why=f"Highest-value family with {rows} indexed rows",
            priority_tools=("es_mappings", "es_search", "es_aggregate", "run_record"),
            acceptance="evidence-linked notes with audit_ids and explicit coverage",
        ))
    orders.append(WorkOrder(
        order_id=WorkOrder.new_id(),
        role="correlation",
        task=(f"Correlate entities and times across all evidence families for: "
              f"{question or '(no examiner question)'}"),
        why="Cross-family corroboration before pattern matching",
        priority_tools=("es_search", "es_aggregate", "run_record"),
        acceptance="corroborated entities/chains with audit_ids or explicit none",
    ))
    orders.append(WorkOrder(
        order_id=WorkOrder.new_id(),
        role="pattern",
        task=(f"Match the evidence against ITM/ATT&CK/ATLAS/MBC patterns for: "
              f"{question or '(no examiner question)'}"),
        why="Framework-grounded pattern check after correlation",
        priority_tools=("rag_search", "kb_query", "es_search", "es_aggregate"),
        acceptance="patterns with required evidence rows, or explicit no-match",
    ))
    for order in orders:
        sink.emit(new_event(
            run_id, "plan.work_order", actor="director",
            data={"order_id": order.order_id, "role": order.role,
                  "family": order.family, "task": order.task},
        ))
    return orders[:max_orders]


# ---------------------------------------------------------------------------
# Supervisor (M1.2) — LangGraph StateGraph
# ---------------------------------------------------------------------------


class Mode3State(dict):
    """Typed-ish state; LangGraph accepts a plain dict subclass here."""


def _persist_state(case_dir: Path, run_id: str, state: dict[str, Any]) -> None:
    path = Path(case_dir) / _MODE3_DIR / f"{run_id}.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
        tmp.replace(path)
    except OSError as exc:
        log.warning("mode3 state persist failed: %s", exc)


def run_mode3(
    case_dir: Path,
    question: str,
    *,
    model: Any = None,
    run_id: str = "",
    on_event: Callable[[dict[str, Any]], None] | None = None,
    max_orders: int = 6,
    resume: bool = True,
) -> dict[str, Any]:
    """Run the Mode 3 supervisor graph and return the final run record.

    Steps: director -> worker(s) -> verifier -> synthesis -> finalize.
    Every state change is persisted so a reload can resume; every tool call is
    audited; DRAFT candidates are returned but never staged here.
    """
    case_dir = Path(case_dir)
    run_id = run_id or f"M3-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}-{uuid4().hex[:6]}"
    sink = EventSink(case_dir, run_id, callback=on_event)
    state: dict[str, Any] = {
        "run_id": run_id,
        "case_id": case_dir.name,
        "question": question,
        "created_at": _now(),
        "status": "running",
        "orders": [],
        "order_index": 0,
        "results": [],
        "verdicts": [],
        "narrative": "",
        "candidates": [],
        "gaps": [],
        "coverage": {},
        "steering": [],
        "stop_reason": "",
        "max_orders": max_orders,
    }
    state_path = case_dir / _MODE3_DIR / f"{run_id}.json"
    if resume and state_path.is_file():
        try:
            loaded = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and loaded.get("run_id") == run_id:
                state.update(loaded)
                state["status"] = "running"
        except (OSError, ValueError):
            pass

    sink.emit(new_event(run_id, "run.started", actor="system",
                        detail=question, data={"case_id": case_dir.name}))

    def _order_dicts() -> list[dict[str, Any]]:
        return [o if isinstance(o, dict) else o.to_dict() for o in state["orders"]]

    # ── Director node ──────────────────────────────────────────────────
    def director_node(_state: dict[str, Any]) -> dict[str, Any]:
        if not state["orders"]:
            orders = plan_work_orders(
                case_dir, question, run_id=run_id, sink=sink,
                max_orders=max_orders,
            )
            state["orders"] = [o.to_dict() for o in orders]
        state["status"] = "planned"
        _persist_state(case_dir, run_id, state)
        sink.emit(new_event(run_id, "plan.ready", actor="director",
                            detail=f"{len(state['orders'])} work order(s)"))
        return state

    # ── Worker node ────────────────────────────────────────────────────
    def worker_node(_state: dict[str, Any]) -> dict[str, Any]:
        record = read_run_record(case_dir, run_id) or {}
        if record.get("pause_requested"):
            state["status"] = "paused"
            state["stop_reason"] = "paused"
            _persist_state(case_dir, run_id, state)
            sink.emit(new_event(run_id, "run.paused", actor="examiner",
                                detail="pause requested"))
            return state
        orders = _order_dicts()
        index = int(state.get("order_index") or 0)
        if index >= len(orders):
            return state
        raw = orders[index]
        order = WorkOrder(
            order_id=str(raw.get("order_id") or WorkOrder.new_id()),
            role=str(raw.get("role") or "evidence"),
            task=str(raw.get("task") or ""),
            family=str(raw.get("family") or ""),
            why=str(raw.get("why") or ""),
            priority_tools=tuple(raw.get("priority_tools") or ()),
            expected_artifact_ids=tuple(raw.get("expected_artifact_ids") or ()),
            expected_event_ids=tuple(raw.get("expected_event_ids") or ()),
            acceptance=str(raw.get("acceptance") or ""),
            max_rounds=int(raw.get("max_rounds") or 4),
            max_calls=int(raw.get("max_calls") or 8),
            max_seconds=float(raw.get("max_seconds") or 240.0),
        )
        context = {
            "previous_results": [
                {
                    "role": r.get("role"),
                    "order_id": r.get("order_id"),
                    "notes": (r.get("parsed") or {}).get("notes") or [],
                    "candidates": (r.get("parsed") or {}).get("candidate_findings") or [],
                    "coverage": (r.get("parsed") or {}).get("coverage") or {},
                }
                for r in state.get("results", [])
            ],
            "steering": read_steering(case_dir, run_id),
        }
        result = run_work_order(
            order, case_dir=case_dir, model=model, run_id=run_id,
            sink=sink, context=context,
        )
        state.setdefault("results", []).append(result.to_dict())
        state["order_index"] = index + 1
        _persist_state(case_dir, run_id, state)
        return state

    # ── Verifier node ──────────────────────────────────────────────────
    def verify_node(_state: dict[str, Any]) -> dict[str, Any]:
        candidates: list[dict[str, Any]] = []
        for result in state.get("results", []):
            parsed = result.get("parsed") or {}
            candidates.extend(parsed.get("candidate_findings") or [])
            candidates.extend(parsed.get("findings") or [])
        if not candidates:
            state["verdicts"] = []
            state["status"] = "verified"
            _persist_state(case_dir, run_id, state)
            return state
        order = WorkOrder(
            order_id=WorkOrder.new_id(),
            role="verifier",
            task=("Verify or refute these candidate findings with tool calls:\n"
                  + json.dumps(candidates, default=str)[:8000]),
            why="Adversarial refutation before synthesis",
            acceptance="per-candidate class confirmed/inferred/refuted with basis",
        )
        result = run_work_order(
            order, case_dir=case_dir, model=model, run_id=run_id, sink=sink,
            context={"candidates": candidates},
        )
        state.setdefault("results", []).append(result.to_dict())
        parsed = result.parsed or {}
        state["verdicts"] = parsed.get("verdicts") or []
        state["status"] = "verified"
        _persist_state(case_dir, run_id, state)
        return state

    # ── Synthesis node ─────────────────────────────────────────────────
    def synthesis_node(_state: dict[str, Any]) -> dict[str, Any]:
        rejected = {
            str(v.get("title") or "").strip().lower()
            for v in (state.get("verdicts") or [])
            if str(v.get("class") or "").lower() == "refuted"
        }
        candidates: list[dict[str, Any]] = []
        for result in state.get("results", []):
            parsed = result.get("parsed") or {}
            for candidate in (parsed.get("candidate_findings") or []):
                title = str(candidate.get("title") or "").strip().lower()
                if title and title in rejected:
                    continue
                candidates.append(candidate)
        if candidates:
            order = WorkOrder(
                order_id=WorkOrder.new_id(),
                role="synthesis",
                task=("Build the narrative and final DRAFT candidates from the "
                      "verified evidence:\n"
                      + json.dumps({
                          "question": question,
                          "verdicts": state.get("verdicts") or [],
                          "candidates": candidates,
                      }, default=str)[:9000]),
                why="Final narrative + DRAFT candidate findings",
                acceptance="narrative + findings with audit_ids; no approvals",
            )
            result = run_work_order(
                order, case_dir=case_dir, model=model, run_id=run_id,
                sink=sink, context={"verdicts": state.get("verdicts") or []},
            )
            state.setdefault("results", []).append(result.to_dict())
            parsed = result.parsed or {}
            state["narrative"] = str(parsed.get("narrative") or "")
            state["candidates"] = parsed.get("findings") or candidates
            state["gaps"] = parsed.get("gaps") or []
            state["coverage"] = parsed.get("coverage") or {}
        else:
            state["candidates"] = []
            state["narrative"] = ""
        state["status"] = "completed"
        state["stop_reason"] = "converged" if not state["candidates"] else "completed"
        _persist_state(case_dir, run_id, state)
        sink.emit(new_event(
            run_id, "run.completed", actor="director",
            detail=f"{len(state['candidates'])} candidate finding(s)",
            data={"stop_reason": state["stop_reason"]},
        ))
        return state

    # ── Graph ──────────────────────────────────────────────────────────
    try:
        from langgraph.graph import END, START, StateGraph

        graph = StateGraph(dict)
        def pause_node(_state: dict[str, Any]) -> dict[str, Any]:
            # Cooperative pause: the worker stopped before the next order.
            sink.emit(new_event(run_id, "run.paused", actor="system",
                                detail="awaiting resume"))
            return state

        graph.add_node("director", director_node)
        graph.add_node("worker", worker_node)
        graph.add_node("pause", pause_node)
        graph.add_node("verify", verify_node)
        graph.add_node("synthesize", synthesis_node)

        graph.add_edge(START, "director")
        graph.add_edge("director", "worker")

        def _more_orders(_state: dict[str, Any]) -> str:
            if str(state.get("status") or "") == "paused":
                return "pause"
            if int(state.get("order_index") or 0) < len(_order_dicts()):
                return "worker"
            return "verify"

        graph.add_conditional_edges("worker", _more_orders,
                                    {"worker": "worker", "verify": "verify",
                                     "pause": "pause"})
        graph.add_edge("pause", END)
        graph.add_edge("verify", "synthesize")
        graph.add_edge("synthesize", END)
        compiled = graph.compile()
        compiled.invoke(state)
    except Exception as exc:  # noqa: BLE001 — a supervisor failure is recorded
        log.exception("mode3 supervisor failed")
        state["status"] = "failed"
        state["stop_reason"] = f"supervisor_error: {type(exc).__name__}: {exc}"
        _persist_state(case_dir, run_id, state)
        sink.emit(new_event(
            run_id, "run.failed", actor="system", status="error",
            detail=str(exc)[:300],
        ))

    if str(state.get("status") or "") == "paused":
        state["stop_reason"] = "paused"
    elif state.get("status") != "failed":
        state["status"] = "completed"
        if not state.get("stop_reason"):
            state["stop_reason"] = "completed"
    state["completed_at"] = _now()
    _persist_state(case_dir, run_id, state)
    return state


def run_record_path(case_dir: Path, run_id: str) -> Path:
    return Path(case_dir) / _MODE3_DIR / f"{run_id}.json"


def read_run_record(case_dir: Path, run_id: str) -> dict[str, Any] | None:
    path = run_record_path(case_dir, run_id)
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return loaded if isinstance(loaded, dict) else None


def read_run_events(
    case_dir: Path, run_id: str, *, limit: int = 2000,
) -> list[dict[str, Any]]:
    path = Path(case_dir) / _MODE3_DIR / f"{run_id}.jsonl"
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict):
                out.append(entry)
    except OSError:
        return []
    return out[-limit:]


def latest_run_id(case_dir: Path) -> str:
    directory = Path(case_dir) / _MODE3_DIR
    if not directory.is_dir():
        return ""
    files = sorted(directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0].stem if files else ""
