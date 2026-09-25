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
import re
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from nexus.audit import AuditWriter
from nexus.langgraph.context_loop import LoopBudget, _call_model, run_context_loop
from nexus.langgraph.prompt_budget import budget_chars, case_window

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


def mode3_loop_budget(case_dir: Path | None = None) -> LoopBudget:
    """Per-agent tool budget for a Mode 3 investigation.

    Rounds, calls and seconds are env-tunable and large enough for a
    cross-family corroboration pass. The character ceiling is the case
    context window (``NEXUS_LLM_CONTEXT_WINDOW`` × fill ratio), not a
    fixed few-thousand-character slice. Convergence and examiner stop
    end the run; this budget must not.
    """
    window = case_window(case_dir) if case_dir is not None else None
    return LoopBudget(
        rounds=_env_int("NEXUS_MODE3_ROUNDS", 24, low=1, high=80),
        seconds=_env_float("NEXUS_MODE3_SECONDS", 1800.0, low=30.0, high=7200.0),
        calls=_env_int("NEXUS_MODE3_CALLS", 48, low=1, high=200),
        call_chars=budget_chars(window),
    )


def _pack(text: str, case_dir: Path | None = None) -> str:
    """Keep investigation text up to the context-window budget."""
    window = case_window(case_dir) if case_dir is not None else None
    limit = budget_chars(window)
    body = text or ""
    if len(body) <= limit:
        return body
    return body[:limit] + "\n…[truncated at context-window budget]"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _short(text: Any, limit: int = 500) -> str:
    return " ".join(str(text or "").split())[:limit]


_STOPWORDS = {
    "what", "when", "where", "which", "who", "whom", "whose", "why", "how",
    "does", "did", "was", "were", "has", "have", "had", "the", "and", "for",
    "with", "from", "into", "onto", "over", "under", "that", "this", "these",
    "those", "case", "evidence", "investigate", "trace", "check", "find",
    "look", "show", "tell", "about", "there", "their", "then", "than",
}


def _question_keywords(question: str, limit: int = 12) -> list[str]:
    """Cheap keyword extraction for skill retrieval (no model call)."""
    words = re.findall(r"[a-zA-Z0-9_\-]{4,}", str(question or "").lower())
    out: list[str] = []
    for word in words:
        if word in _STOPWORDS or word in out:
            continue
        out.append(word)
        if len(out) >= limit:
            break
    return out


def _skill_lookup() -> dict[str, dict[str, Any]]:
    """All registered skills by id; {} when the KB is unavailable."""
    try:
        from nexus.knowledge.loader import get_skills

        return {
            str(skill.get("skill")): skill
            for skill in get_skills()
            if str(skill.get("skill") or "").strip()
        }
    except Exception:  # noqa: BLE001 — skills are an enhancement, not a gate
        log.debug("mode3 skill lookup failed", exc_info=True)
        return {}


# M3.2 — every shipped skill belongs to one supervisor role. Artifact
# procedures are evidence work; cross-source sequencing is correlation;
# attack-class procedures are pattern work. A skill missing from this map
# is an orphan and the mapping test fails.
SKILL_ROLES: dict[str, str] = {
    "windows_event_log_analysis": "evidence",
    "registry_artifact_analysis": "evidence",
    "usb_device_intrusion": "evidence",
    "lnk_jumplist_analysis": "evidence",
    "execution_artifact_analysis": "evidence",
    "deleted_file_recovery": "evidence",
    "browser_artifact_analysis": "evidence",
    "mft_file_activity": "evidence",
    "memory_process_analysis": "evidence",
    "email_phishing": "evidence",
    "windows_data_hiding": "evidence",
    "malware_analysis_triage": "evidence",
    "macos_forensics": "evidence",
    "mobile_forensics": "evidence",
    "ics_ot_forensics": "evidence",
    "container_forensics": "evidence",
    "cloud_identity_forensics": "evidence",
    "evidence_acquisition_handling": "evidence",
    "timeline_construction": "correlation",
    "ir_scoping_and_leads": "correlation",
    "network_session_analysis": "correlation",
    "lateral_movement": "correlation",
    "powershell_abuse": "pattern",
    "exfiltration": "pattern",
    "execution_anomaly": "pattern",
    "lsass_credential_access": "pattern",
    "sam_ntds_credential_theft": "pattern",
    "linux_compromise": "pattern",
    "ad_credential_attacks": "pattern",
    "webshell_investigation": "pattern",
    "persistence": "pattern",
    "log_clearing": "pattern",
    "impact_ransomware": "pattern",
    "initial_access": "pattern",
    "discovery_recon": "pattern",
    "defense_evasion": "pattern",
    "c2_beaconing": "pattern",
}


def skill_role(skill_id: str) -> str:
    """Role that owns a skill. Unknown ids raise — no silent orphan."""
    role = SKILL_ROLES.get(str(skill_id or "").strip())
    if role not in ROLES:
        raise KeyError(f"skill {skill_id!r} has no Mode 3 role")
    return role


def _retrieve_skill_refs(
    families: list[str], keywords: list[str], limit: int = 3,
) -> list[dict[str, Any]]:
    """Ranked skill provenance for a work order (M3.2).

    Returns ``[{skill, title, version, score, why, citations, mitre}]`` —
    the exact procedure version an agent may follow. A failure to load the KB
    degrades to no skills, never to invented steps.
    """
    try:
        from nexus.knowledge.skills import retrieve_skills

        refs = retrieve_skills(
            families=families, keywords=keywords, limit=limit)
        for ref in refs:
            try:
                ref["role"] = skill_role(str(ref.get("skill") or ""))
            except KeyError:
                ref["role"] = ""
        return refs
    except Exception:  # noqa: BLE001
        log.debug("mode3 skill retrieval failed", exc_info=True)
        return []


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
    max_rounds: int = 24
    max_calls: int = 48
    max_seconds: float = 1800.0

    def budget(self) -> LoopBudget:
        """Shared investigation budget. The context window is the character cap."""
        return mode3_loop_budget()


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


def _control_path(case_dir: Path, run_id: str) -> Path:
    return Path(case_dir) / _MODE3_DIR / f"{run_id}.control.json"


def read_controls(case_dir: Path, run_id: str) -> dict[str, bool]:
    """Examiner control flags (pause/stop) — a sidecar the graph never writes."""
    path = _control_path(case_dir, run_id)
    out = {"pause_requested": False, "stop_requested": False}
    if not path.is_file():
        return out
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    if isinstance(data, dict):
        for key in out:
            out[key] = bool(data.get(key))
    return out


def _update_controls(case_dir: Path, run_id: str, **changes: bool) -> bool:
    case_dir = Path(case_dir)
    if read_run_record(case_dir, run_id) is None:
        return False
    controls = read_controls(case_dir, run_id)
    controls.update({key: bool(value) for key, value in changes.items()})
    path = _control_path(case_dir, run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(controls, indent=2), encoding="utf-8")
    tmp.replace(path)
    return True


def mark_paused(case_dir: Path, run_id: str, paused: bool = True) -> bool:
    """Set/clear the cooperative pause flag (sidecar; graph-safe)."""
    return _update_controls(case_dir, run_id, pause_requested=paused)


def request_stop(case_dir: Path, run_id: str) -> bool:
    """Set the cooperative stop flag — the run halts before the next order."""
    return _update_controls(case_dir, run_id, stop_requested=True)


def read_case_findings(case_dir: Path) -> list[dict[str, Any]]:
    """Examiner-visible findings for the next round (4j.16)."""
    path = Path(case_dir) / "findings.json"
    if not path.is_file():
        return []
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [row for row in rows if isinstance(row, dict)]


def examiner_feedback(case_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """Approved/DRAFT/rejected findings as run feedback.

    Approved findings seed a deepen order; rejected findings become explicit
    exclusion constraints (no re-proposal without new independent evidence);
    pending DRAFTs are de-duplication context. Titles only — no agent reads or
    writes finding state, and nothing here approves.
    """
    out: dict[str, list[dict[str, Any]]] = {
        "approved": [], "draft": [], "rejected": [],
    }
    for row in read_case_findings(case_dir):
        status = str(row.get("status") or "").upper()
        item = {
            "id": str(row.get("id") or ""),
            "title": str(row.get("title") or ""),
            "confidence": str(row.get("confidence") or ""),
        }
        if status == "APPROVED":
            out["approved"].append(item)
        elif status == "REJECTED":
            out["rejected"].append(item)
        elif status == "DRAFT":
            out["draft"].append(item)
    return out


def _candidate_audit_ids(candidate: dict[str, Any]) -> list[str]:
    ids = candidate.get("audit_ids")
    if not ids and candidate.get("audit_id"):
        ids = [candidate.get("audit_id")]
    out: list[str] = []
    for item in ids or []:
        text = str(item or "").strip()
        if text and text not in out:
            out.append(text)
    return out


def _normalise_evidence(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in (candidate.get("evidence") or candidate.get("notes") or []):
        if isinstance(item, dict):
            row = dict(item)
            if not row.get("source"):
                row["source"] = str(
                    row.get("family") or row.get("file") or "mode3")
            rows.append(row)
        elif isinstance(item, str) and item.strip():
            rows.append({"source": "mode3", "detail": _short(item, 300)})
    return rows[:12]


def stage_run_candidates(
    case_dir: Path,
    run_id: str,
    *,
    candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Stage a run's verified candidates as DRAFT findings (examiner action).

    This is the examiner's staging button, not an agent action: agents never
    call it. Only candidates that carry at least one real ``audit_id`` are
    staged (FD-001); refuted verdicts and evidence-free candidates are skipped
    with reasons. Every staged finding keeps ``run_id`` / ``input_call_ids``
    lineage so the run event stream is the provenance. Approval remains
    password-gated and examiner-only — nothing here approves or promotes.
    """
    from nexus.langgraph.mode1 import save_draft_finding

    case_dir = Path(case_dir)
    record = read_run_record(case_dir, run_id)
    if record is None:
        return {"error": "run not found", "run_id": run_id,
                "staged": [], "skipped": []}
    verdicts = {
        str(v.get("title") or "").strip().lower(): v
        for v in (record.get("verdicts") or [])
    }
    rows = candidates if candidates is not None else (record.get("candidates") or [])
    sink = EventSink(case_dir, run_id)
    staged: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    for candidate in rows:
        title = str(candidate.get("title") or "").strip() or "Mode 3 candidate"
        audit_ids = _candidate_audit_ids(candidate)
        if not audit_ids:
            skipped.append({"title": title,
                            "reason": "FD-001: candidate has no audit_id"})
            continue
        verdict = verdicts.get(title.lower(), {})
        vclass = str(verdict.get("class") or "").lower()
        if vclass == "refuted":
            skipped.append({"title": title, "reason": "verifier refuted"})
            continue
        observation = str(
            candidate.get("observation") or candidate.get("note") or "").strip()
        interpretation = str(candidate.get("interpretation") or "").strip()
        if not observation or not interpretation:
            skipped.append({
                "title": title,
                "reason": "missing observation/interpretation (FD-005 shape)",
            })
            continue
        confidence = str(candidate.get("confidence") or "LOW").upper()
        if confidence not in ("LOW", "MEDIUM", "HIGH", "SPECULATIVE"):
            confidence = "LOW"
        justification = str(
            candidate.get("confidence_justification") or "").strip() or (
            f"Mode 3 run {run_id} synthesis candidate"
            + (f"; verifier class={vclass}" if vclass else "")
            + "; confidence auto-capped per FD-006/007 until corroborated."
        )
        mitre = [
            str(t) for t in (
                candidate.get("attack_ids")
                or candidate.get("mitre_ids")
                or candidate.get("mitre_techniques")
                or []
            ) if t
        ]
        draft = {
            "title": title,
            "observation": observation,
            "interpretation": interpretation,
            "confidence": confidence,
            "confidence_justification": justification,
            "type": "finding",
            "audit_ids": audit_ids,
            "evidence": _normalise_evidence(candidate),
            "status": "DRAFT",
            "source": "mode3",
            "run_id": run_id,
            "input_call_ids": audit_ids,
            "mitre_ids": mitre,
            "itm_stage": str(candidate.get("itm_stage") or ""),
            "itm_objects": str(candidate.get("itm_objects") or ""),
            "examiner_selected": False,
        }
        saved = save_draft_finding(case_dir, draft)
        if str(saved.get("status") or "") == "STAGED":
            entry = {
                "title": title,
                "finding_id": saved.get("finding_id"),
                "input_call_ids": audit_ids,
                "verifier_class": vclass,
            }
            staged.append(entry)
            sink.emit(new_event(
                run_id, "finding.staged", actor="examiner", status="DRAFT",
                detail=title, data=entry,
            ))
        else:
            reasons = [str(e) for e in (saved.get("errors") or [])]
            if not reasons:
                reasons = [str(saved.get("status") or "failed")]
            skipped.append({"title": title, "reason": "; ".join(reasons)})

    return {
        "run_id": run_id,
        "staged": staged,
        "skipped": skipped,
        "staged_count": len(staged),
        "skipped_count": len(skipped),
    }


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
    skill_refs: list[dict[str, Any]] = field(default_factory=list)
    max_rounds: int = 0
    max_calls: int = 0
    max_seconds: float = 0.0
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
    if order.max_rounds < 0 or order.max_calls < 0 or order.max_seconds < 0:
        problems.append("budget cannot be negative")
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


# Role answer schemas for the format-only turn (restructure, never invent).
_ROLE_SCHEMAS: dict[str, str] = {
    "evidence": (
        '{"notes":[{"statement":"...","evidence":["family/file:line ..."],'
        '"audit_ids":["..."]}],"entities":["..."],'
        '"candidate_findings":[{"title":"...","observation":"...",'
        '"interpretation":"...","confidence":"LOW|MEDIUM|HIGH",'
        '"audit_ids":["..."]}],"coverage":{"checked":["..."],'
        '"not_checked":["..."]},"next_questions":["..."]}'
    ),
    "correlation": (
        '{"corroborated_entities":["..."],"chains":[{"entities":["..."],'
        '"times":["..."],"evidence":["family/file:line ..."],'
        '"audit_ids":["..."]}],"unexplained":["..."],'
        '"candidate_findings":[{"title":"...","observation":"...",'
        '"interpretation":"...","confidence":"LOW|MEDIUM|HIGH",'
        '"audit_ids":["..."]}],"next_questions":["..."],'
        '"coverage":{"checked":["..."],"not_checked":["..."]}}'
    ),
    "pattern": (
        '{"patterns":[{"name":"...","technique_ids":["..."],'
        '"evidence":["family/file:line ..."],"audit_ids":["..."]}],'
        '"candidate_findings":[{"title":"...","observation":"...",'
        '"interpretation":"...","confidence":"LOW|MEDIUM|HIGH",'
        '"audit_ids":["..."]}],"caveats":["..."],"next_questions":["..."],'
        '"coverage":{"checked":["..."],"not_checked":["..."]}}'
    ),
    "verifier": (
        '{"verdicts":[{"title":"...","class":"confirmed|inferred|refuted",'
        '"basis":"...","audit_ids":["..."]}],"coverage":{"checked":["..."],'
        '"not_checked":["..."]}}'
    ),
    "synthesis": (
        '{"narrative":"...","findings":[{"title":"...","observation":"...",'
        '"interpretation":"...","confidence":"LOW|MEDIUM|HIGH",'
        '"confidence_justification":"...","audit_ids":["..."],'
        '"attack_ids":["..."],"itm_stage":"...","itm_objects":"..."}],'
        '"gaps":["..."],"coverage":{"checked":["..."],"not_checked":["..."]}}'
    ),
    "reporter": (
        '{"summary":"...","sections":[{"title":"...","body":"..."}],'
        '"gaps":["..."]}'
    ),
}


def _format_final_answer(model: Any, role_name: str, reply: str) -> dict[str, Any]:
    """One bounded, tool-free turn: restructure a prose answer into role JSON.

    The agent already did the work; this only re-formats its own text. The
    prompt forbids adding, dropping or reinterpreting any evidence, number,
    file name or audit_id. Returns ``{}`` when the model is unavailable or the
    conversion fails — the role result is then honestly marked unparsed.
    """
    if model is None or not str(reply or "").strip():
        return {}
    schema = _ROLE_SCHEMAS.get(role_name, _ROLE_SCHEMAS["evidence"])
    messages = [
        {
            "role": "system",
            "content": (
                "You convert a finished forensic agent answer into a JSON "
                "object. Do NOT add, drop, merge, rank or reinterpret evidence, "
                "claims, numbers, file names, hosts or audit_id values; only "
                "restructure the text that is already there. Keep audit ids "
                "verbatim and in place. Reply with ONE JSON object only."
            ),
        },
        {
            "role": "user",
            "content": (
                "Target JSON shape:\n" + schema
                + "\n\nAgent answer to restructure:\n" + _pack(str(reply))
            ),
        },
    ]
    try:
        raw = _call_model(model, messages)
    except Exception:  # noqa: BLE001 — unparsed is honest; formatting is best-effort
        log.debug("mode3 answer formatting failed", exc_info=True)
        return {}
    parsed = _parse_json_object(raw)
    return parsed if isinstance(parsed, dict) else {}


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


def _skill_procedure_block(order: WorkOrder) -> str:
    """Render the KB-cited procedures attached to a work order (M3.2).

    Steps are copied from the KB skill, never invented; each block carries the
    skill id, content version and KB chunk citations so an agent (and later a
    staged finding) can be traced to the exact procedure version.
    """
    if not order.skill_refs:
        return ""
    by_id = _skill_lookup()
    lines: list[str] = []
    for ref in order.skill_refs:
        skill_id = str(ref.get("skill") or "")
        skill = by_id.get(skill_id)
        if not skill:
            continue
        cites = ", ".join(str(c) for c in (ref.get("citations") or [])) or "none"
        lines.append(
            f"- {skill_id} v{ref.get('version') or '?'} "
            f"role={ref.get('role') or ''} (KB {cites}): "
            f"{ref.get('title') or skill.get('title') or ''}"
        )
        for step in (skill.get("steps") or []):
            if not isinstance(step, dict):
                continue
            name = str(step.get("name") or "")
            query = str(step.get("query") or "")
            look = str(step.get("look_for") or "")
            lines.append(
                f"    * {name}: {query}"
                + (f" | look_for: {look}" if look else "")
            )
        caveats = [str(c) for c in (skill.get("caveats") or [])]
        negative = str(skill.get("negative") or "")
        if caveats:
            lines.append("    ! caveats: " + "; ".join(caveats))
        if negative:
            lines.append(f"    ! negative: {negative}")
    if not lines:
        return ""
    return (
        "KB-CITED PROCEDURES (follow the step queries; keep the skill id + "
        "version + citations for anything you use):\n" + "\n".join(lines) + "\n"
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

    work_context = _pack(json.dumps(context or {}, default=str), case_dir)
    skill_block = _pack(_skill_procedure_block(order), case_dir)
    shared = mode3_loop_budget(case_dir)
    budget = LoopBudget(
        rounds=order.max_rounds or shared.rounds,
        seconds=order.max_seconds or shared.seconds,
        calls=order.max_calls or shared.calls,
        call_chars=shared.call_chars,
    )
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
        + skill_block
        + f"Run context: {work_context}\n\n"
        "Return the role JSON object as the final answer. Use the read-only "
        "tools; never claim evidence you did not retrieve."
    )
    sink.emit(new_event(
        run_id, "work_order.started", actor="director", turn_id=turn_id,
        agent_id=agent_id, detail=order.task, data={
            "order_id": order.order_id, "role": order.role,
            "family": order.family, "why": order.why,
            "budget": {"rounds": budget.rounds, "calls": budget.calls,
                       "seconds": budget.seconds},
            "skills": [
                {"skill": r.get("skill"), "version": r.get("version")}
                for r in order.skill_refs
            ],
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
            budget=budget,
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

    raw_reply = str(loop.get("reply") or "")
    parsed = _parse_json_object(raw_reply)
    if not parsed and raw_reply.strip():
        parsed = _format_final_answer(model, role.name, raw_reply)
        if parsed:
            sink.emit(new_event(
                run_id, "agent.formatted", actor="agent", turn_id=turn_id,
                agent_id=agent_id,
                detail="prose answer restructured into the role JSON envelope",
            ))
    result = AgentResult(
        order_id=order.order_id,
        role=order.role,
        status="ok" if parsed else "unparsed",
        reply=raw_reply,
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
    known_findings: dict[str, list[dict[str, Any]]] | None = None,
) -> list[WorkOrder]:
    """Deterministic director: families + correlation/pattern + examiner feedback."""
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
    keywords = _question_keywords(question)
    all_families = [family for family, _rows in ranked]
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
            skill_refs=_retrieve_skill_refs([family], keywords, limit=8),
        ))
    orders.append(WorkOrder(
        order_id=WorkOrder.new_id(),
        role="correlation",
        task=(f"Correlate entities and times across all evidence families for: "
              f"{question or '(no examiner question)'}"),
        why="Cross-family corroboration before pattern matching",
        priority_tools=("es_search", "es_aggregate", "run_record"),
        acceptance="corroborated entities/chains with audit_ids or explicit none",
        skill_refs=_retrieve_skill_refs(all_families, keywords, limit=8),
    ))
    orders.append(WorkOrder(
        order_id=WorkOrder.new_id(),
        role="pattern",
        task=(f"Match the evidence against ITM/ATT&CK/ATLAS/MBC patterns for: "
              f"{question or '(no examiner question)'}"),
        why="Framework-grounded pattern check after correlation",
        priority_tools=("rag_search", "kb_query", "es_search", "es_aggregate"),
        acceptance="patterns with required evidence rows, or explicit no-match",
        skill_refs=_retrieve_skill_refs(all_families, keywords, limit=8),
    ))

    # 4j.16 — examiner accept/reject feeds the next round: approved findings
    # seed a deepen order, rejected findings become exclusion constraints.
    feedback = known_findings or {}
    approved = list(feedback.get("approved") or [])
    draft = list(feedback.get("draft") or [])
    rejected = list(feedback.get("rejected") or [])
    feedback_order: WorkOrder | None = None
    if approved or draft or rejected:
        parts = [f"Examiner findings feedback for: {question or '(none)'}."]
        if approved:
            parts.append(
                "EXAMINER-APPROVED (deepen/extend with new independent "
                "evidence; do not merely restate): "
                + "; ".join(f"{f.get('id')} {f.get('title')}" for f in approved[:8])
                + ".")
        if draft:
            parts.append(
                "PENDING DRAFTS (already staged — only re-propose with new "
                "corroboration or a material correction): "
                + "; ".join(f"{f.get('id')} {f.get('title')}" for f in draft[:8])
                + ".")
        if rejected:
            parts.append(
                "EXAMINER-REJECTED (negative constraint — do not re-propose "
                "without new, independent, cited evidence; if the existing "
                "evidence supports the rejection, say so): "
                + "; ".join(f"{f.get('id')} {f.get('title')}" for f in rejected[:8])
                + ".")
        parts.append(
            "Use new queries and cite audit_ids; a restatement of already "
            "staged evidence is not new evidence.")
        feedback_order = WorkOrder(
            order_id=WorkOrder.new_id(),
            role="correlation",
            task=" ".join(parts),
            why=(
                f"examiner feedback: {len(approved)} approved / "
                f"{len(draft)} draft / {len(rejected)} rejected"),
            priority_tools=("es_search", "es_aggregate", "run_record"),
            acceptance=(
                "per-finding disposition: deepened with new evidence, kept "
                "as-is, or explicitly dropped"),
            skill_refs=_retrieve_skill_refs(all_families, keywords, limit=8),
        )
        orders = orders[: max(1, max_orders - 1)] + [feedback_order]

    for order in orders:
        sink.emit(new_event(
            run_id, "plan.work_order", actor="director",
            data={"order_id": order.order_id, "role": order.role,
                  "family": order.family, "task": order.task,
                  "skills": [
                      {"skill": r.get("skill"), "version": r.get("version"),
                       "why": r.get("why")}
                      for r in order.skill_refs
                  ]},
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
        "followup_rounds": 0,
        "followups_limit": _env_int(
            "NEXUS_MODE3_FOLLOWUPS", 8, low=0, high=24),
        "evidence_signature": None,
        "converged_no_new_evidence": False,
        "examiner_feedback": {},
    }
    state_path = case_dir / _MODE3_DIR / f"{run_id}.json"
    if resume and state_path.is_file():
        try:
            loaded = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and loaded.get("run_id") == run_id:
                state.update(loaded)
                # Stopped, completed, and failed runs are terminal. Resuming
                # them used to re-enter verify/synthesis and append a second
                # pass onto a finished investigation.
                if str(state.get("status") or "") in (
                    "stopped", "completed", "failed",
                ):
                    return state
                state["status"] = "running"
                state.pop("completed_at", None)
                state.setdefault("followup_rounds", 0)
                state.setdefault("followups_limit", _env_int(
                    "NEXUS_MODE3_FOLLOWUPS", 8, low=0, high=24))
                state.setdefault("evidence_signature", None)
                state.setdefault("converged_no_new_evidence", False)
                state.setdefault("examiner_feedback", {})
        except (OSError, ValueError):
            pass

    sink.emit(new_event(run_id, "run.started", actor="system",
                        detail=question, data={"case_id": case_dir.name}))

    def _order_dicts() -> list[dict[str, Any]]:
        return [o if isinstance(o, dict) else o.to_dict() for o in state["orders"]]

    # ── Director node ──────────────────────────────────────────────────
    def director_node(_state: dict[str, Any]) -> dict[str, Any]:
        # 4j.16 — read examiner decisions fresh so a resumed run also picks up
        # findings approved/rejected since the last turn.
        state["examiner_feedback"] = examiner_feedback(case_dir)
        if not state["orders"]:
            orders = plan_work_orders(
                case_dir, question, run_id=run_id, sink=sink,
                max_orders=max_orders,
                known_findings=state["examiner_feedback"],
            )
            state["orders"] = [o.to_dict() for o in orders]
        state["status"] = "planned"
        _persist_state(case_dir, run_id, state)
        sink.emit(new_event(
            run_id, "plan.ready", actor="director",
            detail=f"{len(state['orders'])} work order(s)",
            data={
                "feedback": {
                    key: len(state["examiner_feedback"].get(key) or [])
                    for key in ("approved", "draft", "rejected")
                },
            },
        ))
        return state

    def _halt_if_requested() -> bool:
        """Apply the control sidecar at a work-order boundary.

        Checked before every worker, and again before verify/synthesis, so a
        stop or pause requested during the last evidence order still halts
        before the verifier starts. The pause node is the only emitter.
        """
        controls = read_controls(case_dir, run_id)
        if controls.get("stop_requested"):
            state["status"] = "stopped"
            state["stop_reason"] = "examiner_stop"
            _persist_state(case_dir, run_id, state)
            return True
        if controls.get("pause_requested"):
            state["status"] = "paused"
            state["stop_reason"] = "paused"
            _persist_state(case_dir, run_id, state)
            return True
        return False

    # ── Worker node ────────────────────────────────────────────────────
    def worker_node(_state: dict[str, Any]) -> dict[str, Any]:
        if _halt_if_requested():
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
            skill_refs=list(raw.get("skill_refs") or []),
            max_rounds=int(raw.get("max_rounds") or 0),
            max_calls=int(raw.get("max_calls") or 0),
            max_seconds=float(raw.get("max_seconds") or 0.0),
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
            "examiner_feedback": state.get("examiner_feedback") or {},
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
    def _candidate_pool() -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for result in state.get("results", []):
            if str(result.get("role") or "") in ("verifier", "synthesis"):
                continue
            parsed = result.get("parsed") or {}
            rows.extend(parsed.get("candidate_findings") or [])
            rows.extend(parsed.get("findings") or [])
        return rows

    def verify_node(_state: dict[str, Any]) -> dict[str, Any]:
        candidates = _candidate_pool()
        if not candidates:
            state["status"] = "verified"
            _persist_state(case_dir, run_id, state)
            return state
        order = WorkOrder(
            order_id=WorkOrder.new_id(),
            role="verifier",
            task=("Verify or refute these candidate findings with tool calls:\n"
                  + _pack(json.dumps(candidates, default=str), case_dir)),
            why="Adversarial refutation before synthesis",
            acceptance="per-candidate class confirmed/inferred/refuted with basis",
        )
        result = run_work_order(
            order, case_dir=case_dir, model=model, run_id=run_id, sink=sink,
            context={"candidates": candidates},
        )
        state.setdefault("results", []).append(result.to_dict())
        parsed = result.parsed or {}
        merged = {
            str(v.get("title") or "").strip().lower(): v
            for v in (state.get("verdicts") or [])
            if str(v.get("title") or "").strip()
        }
        for verdict in parsed.get("verdicts") or []:
            title = str(verdict.get("title") or "").strip().lower()
            if title:
                merged[title] = verdict
        state["verdicts"] = list(merged.values())
        state["status"] = "verified"
        _persist_state(case_dir, run_id, state)
        sink.emit(new_event(
            run_id, "verify.completed", actor="verifier",
            detail=f"{len(state['verdicts'])} verdict(s)",
            data={"classes": sorted({
                str(v.get("class") or "").lower()
                for v in state["verdicts"] if v.get("class")
            })},
        ))
        return state

    # ── Corroboration assessor (M4) ────────────────────────────────────
    def assess_node(_state: dict[str, Any]) -> dict[str, Any]:
        verdicts = state.get("verdicts") or []
        classes = {str(v.get("class") or "").lower() for v in verdicts}
        notes = candidates = calls = 0
        for result in state.get("results", []):
            parsed = result.get("parsed") or {}
            notes += len(parsed.get("notes") or [])
            candidates += len(parsed.get("candidate_findings") or [])
            candidates += len(parsed.get("findings") or [])
            calls += len(result.get("tool_calls") or [])
        signature = [notes, candidates, calls, len(verdicts)]
        previous = state.get("evidence_signature")
        if previous is not None and signature == previous:
            state["converged_no_new_evidence"] = True
            state["status"] = "assessed"
            _persist_state(case_dir, run_id, state)
            sink.emit(new_event(
                run_id, "run.converged", actor="director",
                detail="no new evidence in the last follow-up round"))
            return state
        state["evidence_signature"] = signature

        used = int(state.get("followup_rounds") or 0)
        limit = int(state.get("followups_limit") or 0)
        needs = classes & {"refuted", "inferred"}
        if not needs or used >= limit:
            state["status"] = "assessed"
            _persist_state(case_dir, run_id, state)
            return state

        refuted = [str(v.get("title") or "(untitled)")
                   for v in verdicts
                   if str(v.get("class") or "").lower() == "refuted"]
        inferred = [str(v.get("title") or "(untitled)")
                    for v in verdicts
                    if str(v.get("class") or "").lower() == "inferred"]
        role = "correlation" if (inferred or not refuted) else "evidence"
        priority = (
            ("es_search", "es_aggregate", "sample_rows", "run_record")
            if role == "evidence"
            else ("es_search", "es_aggregate", "run_record")
        )
        task_parts = [
            f"Follow-up corroboration round {used + 1}/{limit}.",
            f"Examiner question: {question or '(none)'}.",
        ]
        if refuted:
            task_parts.append(
                "REFUTED candidates — find independent counter-evidence or "
                "confirm the refutation with a second artifact family: "
                + "; ".join(refuted[:6]) + ".")
        if inferred:
            task_parts.append(
                "INFERRED candidates — corroborate with an independent "
                "family/audit run to escalate, or show the inference is not "
                "supported: " + "; ".join(inferred[:6]) + ".")
        task_parts.append(
            "Use new queries, not a re-run of the same query. If nothing new "
            "exists, say so explicitly and cite run_record.")
        families = [str(o.get("family") or "") for o in _order_dicts()
                    if o.get("family")]
        order = WorkOrder(
            order_id=WorkOrder.new_id(),
            role=role,
            task=" ".join(task_parts),
            why=f"{len(refuted)} refuted / {len(inferred)} inferred candidate(s)",
            priority_tools=priority,
            acceptance=(
                "per-candidate corroboration or honest exhaustion; no invented "
                "evidence"),
            skill_refs=_retrieve_skill_refs(
                families, _question_keywords(question), limit=3),
        )
        state["orders"].append(order.to_dict())
        state["followup_rounds"] = used + 1
        state["status"] = "assessed"
        _persist_state(case_dir, run_id, state)
        sink.emit(new_event(
            run_id, "plan.work_order", actor="director",
            detail=order.task,
            data={"order_id": order.order_id, "role": order.role,
                  "followup": state["followup_rounds"],
                  "refuted": refuted, "inferred": inferred},
        ))
        sink.emit(new_event(
            run_id, "run.followup", actor="director",
            detail=f"round {state['followup_rounds']}/{limit} ({role})",
            data={"refuted": refuted, "inferred": inferred},
        ))
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
                      + _pack(json.dumps({
                          "question": question,
                          "verdicts": state.get("verdicts") or [],
                          "candidates": candidates,
                          "examiner_feedback": state.get("examiner_feedback") or {},
                      }, default=str), case_dir)),
                why="Final narrative + DRAFT candidate findings",
                acceptance="narrative + findings with audit_ids; no approvals",
            )
            result = run_work_order(
                order, case_dir=case_dir, model=model, run_id=run_id,
                sink=sink, context={
                    "verdicts": state.get("verdicts") or [],
                    "examiner_feedback": state.get("examiner_feedback") or {},
                },
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
        state["stop_reason"] = (
            "converged_no_new_evidence"
            if state.get("converged_no_new_evidence")
            else ("converged" if not state["candidates"] else "completed")
        )
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
            # Cooperative halt: the worker stopped before the next order.
            status = str(state.get("status") or "")
            if status == "stopped":
                sink.emit(new_event(run_id, "run.stopped", actor="system",
                                    detail="halted by examiner"))
            else:
                sink.emit(new_event(run_id, "run.paused", actor="system",
                                    detail="awaiting resume"))
            return state

        graph.add_node("director", director_node)
        graph.add_node("worker", worker_node)
        graph.add_node("pause", pause_node)
        graph.add_node("verify", verify_node)
        graph.add_node("assess", assess_node)
        graph.add_node("synthesize", synthesis_node)

        graph.add_edge(START, "director")
        graph.add_edge("director", "worker")

        def _halted() -> bool:
            return str(state.get("status") or "") in ("paused", "stopped")

        def _more_orders(_state: dict[str, Any]) -> str:
            if _halted() or _halt_if_requested():
                return "pause"
            if int(state.get("order_index") or 0) < len(_order_dicts()):
                return "worker"
            return "verify"

        graph.add_conditional_edges("worker", _more_orders,
                                    {"worker": "worker", "verify": "verify",
                                     "pause": "pause"})
        graph.add_edge("pause", END)

        def _after_assess(_state: dict[str, Any]) -> str:
            if _halted() or _halt_if_requested():
                return "pause"
            if int(state.get("order_index") or 0) < len(_order_dicts()):
                return "worker"
            return "synthesize"

        graph.add_edge("verify", "assess")
        graph.add_conditional_edges("assess", _after_assess,
                                    {"worker": "worker",
                                     "synthesize": "synthesize",
                                     "pause": "pause"})
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

    final_status = str(state.get("status") or "")
    if final_status == "paused":
        state["stop_reason"] = "paused"
    elif final_status == "stopped":
        state["stop_reason"] = "examiner_stop"
    elif final_status != "failed":
        state["status"] = "completed"
        if not state.get("stop_reason"):
            state["stop_reason"] = "completed"
    if str(state.get("status") or "") != "paused":
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
