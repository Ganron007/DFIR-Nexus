"""Mode 4 concurrent multi-agent runtime (plan ids MA4.1–MA4.9).

A model supervisor spawns evidence, correlation, and pattern seats in one
superstep. Each seat has its own context and publishes a board entry. The
join compares claims and can send a seat back. Synthesis writes DRAFT
candidates only after the join settles. Agents never stage or approve.

Product label after the rename: this runtime is **Mode 3 — Multi-agent**.
The on-disk run id prefix stays ``M4-`` so it cannot collide with a Mode 3
multi-role run. Case picker storage for a new multi-agent case is ``4``.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, TypedDict
from uuid import uuid4

from nexus.langgraph.mode3_runtime import (
    EventSink,
    append_steering,
    new_event,
    read_steering,
    stage_run_candidates,
)
from nexus.langgraph.prompt_budget import budget_chars, case_window

log = logging.getLogger(__name__)

_DIR = "analysis/mode4_runs"
_CLAIM_KINDS = {"presence", "absence", "attribution", "time_order"}
_SEATS = ("evidence", "correlation", "pattern")
_SINK_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _env_int(name: str, default: int, *, low: int, high: int) -> int:
    try:
        value = int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        value = default
    return max(low, min(value, high))


def _run_dir(case_dir: Path) -> Path:
    path = Path(case_dir) / _DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def _record_path(case_dir: Path, run_id: str) -> Path:
    return _run_dir(case_dir) / f"{run_id}.json"


def _control_path(case_dir: Path, run_id: str) -> Path:
    return _run_dir(case_dir) / f"{run_id}.control.json"


def read_controls(case_dir: Path, run_id: str) -> dict[str, bool]:
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


def _write_controls(case_dir: Path, run_id: str, **changes: bool) -> bool:
    if read_run_record(case_dir, run_id) is None:
        return False
    controls = read_controls(case_dir, run_id)
    controls.update({k: bool(v) for k, v in changes.items()})
    path = _control_path(case_dir, run_id)
    path.write_text(json.dumps(controls, indent=2), encoding="utf-8")
    return True


def mark_paused(case_dir: Path, run_id: str, paused: bool = True) -> bool:
    return _write_controls(case_dir, run_id, pause_requested=paused)


def request_stop_run(case_dir: Path, run_id: str) -> bool:
    return _write_controls(case_dir, run_id, stop_requested=True)


def read_run_record(case_dir: Path, run_id: str) -> dict[str, Any] | None:
    path = _record_path(case_dir, run_id)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _persist(case_dir: Path, run_id: str, record: dict[str, Any]) -> None:
    path = _record_path(case_dir, run_id)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def latest_run_id(case_dir: Path) -> str:
    directory = Path(case_dir) / _DIR
    if not directory.is_dir():
        return ""
    files = sorted(directory.glob("M4-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0].stem if files else ""


def read_run_events(case_dir: Path, run_id: str, limit: int = 5000) -> list[dict[str, Any]]:
    path = _run_dir(case_dir) / f"{run_id}.jsonl"
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                out.append(item)
    except OSError:
        return []
    return out[-limit:]


def emit_event(case_dir: Path, run_id: str, event: Any) -> None:
    """Append an event to the Mode 4 stream the SSE tail reads."""
    sink = EventSink(Path(case_dir), run_id)
    sink.path = _run_dir(Path(case_dir)) / f"{run_id}.jsonl"
    sink.emit(event)


def elasticsearch_ready() -> bool:
    try:
        from nexus.langgraph.case_index import es_available

        return bool(es_available())
    except Exception:  # noqa: BLE001
        return False


def add_board(left: list[dict[str, Any]] | None, right: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Channel reducer: parallel seats append, nothing is dropped."""
    return list(left or []) + list(right or [])


def _claim_key(claim: dict[str, Any]) -> tuple[str, str, str] | None:
    kind = str(claim.get("claim_kind") or "")
    if kind not in _CLAIM_KINDS:
        return None
    entity_type = str(claim.get("entity_type") or "").strip().lower()
    entity_value = str(claim.get("entity_value") or "").strip().lower()
    if not entity_type or not entity_value:
        return None
    return (entity_type, entity_value, kind)


def _audit_ids(claim: dict[str, Any]) -> list[str]:
    raw = claim.get("audit_ids") or claim.get("audit_id") or []
    if isinstance(raw, str):
        raw = [raw]
    return [str(item).strip() for item in raw if str(item).strip()]


def accept_claim(claim: dict[str, Any]) -> str:
    """FD-001..007 on one board claim. Empty string means keep."""
    if not _audit_ids(claim):
        return "FD-001: claim has no audit_id"
    if str(claim.get("claim_kind") or "") == "attribution":
        return "FD-003: agents do not attribute"
    if not str(claim.get("confidence_justification") or "").strip():
        return "FD-005: confidence has no justification"
    return ""


def find_disputes(board: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for entry in board:
        for claim in entry.get("claims") or []:
            if not isinstance(claim, dict) or accept_claim(claim):
                continue
            key = _claim_key(claim)
            if key is None:
                continue
            grouped.setdefault(key, []).append({
                "polarity": str(claim.get("polarity") or "affirm"),
                "value": str(claim.get("value") or ""),
                "agent_id": str(entry.get("agent_id") or ""),
                "role": str(entry.get("role") or ""),
                "family": str(entry.get("family") or ""),
                "audit_ids": _audit_ids(claim),
            })
    disputes: list[dict[str, Any]] = []
    for key, rows in grouped.items():
        polarities = {row["polarity"] for row in rows}
        values = {row["value"] for row in rows if row["value"]}
        if len(polarities) > 1 or len(values) > 1:
            disputes.append({
                "entity_type": key[0],
                "entity_value": key[1],
                "claim_kind": key[2],
                "seats": sorted({row["role"] for row in rows if row["role"]}),
                "families": sorted({row["family"] for row in rows if row["family"]}),
                "audit_ids": sorted({aid for row in rows for aid in row["audit_ids"]}),
            })
    return disputes


def _fingerprint(board: list[dict[str, Any]]) -> list[str]:
    rows: list[str] = []
    for entry in board:
        for claim in entry.get("claims") or []:
            if not isinstance(claim, dict) or accept_claim(claim):
                continue
            key = _claim_key(claim)
            if key:
                rows.append("|".join(key) + "|" + str(claim.get("polarity") or "") + "|" + str(claim.get("value") or ""))
    return sorted(rows)


def plan_spawns(
    families: list[tuple[str, int]],
    *,
    max_agents: int,
    question: str,
) -> list[dict[str, Any]]:
    """Deterministic team when no model is configured. Largest families first."""
    cap = max(2, max_agents)
    ranked = sorted(families, key=lambda item: (-int(item[1]), item[0]))
    evidence_slots = max(0, cap - 2)
    spawns: list[dict[str, Any]] = []
    for family, rows in ranked[:evidence_slots]:
        spawns.append({
            "role": "evidence",
            "family": family,
            "why": f"{rows} indexed rows",
            "question": question,
        })
    spawns.append({"role": "correlation", "family": "", "why": "cross-family", "question": question})
    spawns.append({"role": "pattern", "family": "", "why": "framework patterns", "question": question})
    return spawns[:cap]


def _validated_spawns(
    raw_spawns: Any,
    families: list[tuple[str, int]],
    *,
    max_agents: int,
    question: str,
    why_default: str,
) -> list[dict[str, Any]]:
    """Shape and bound a model's spawn list. Empty means "use the fallback"."""
    names = {str(name).strip().lower() for name, _rows in families}
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in raw_spawns or []:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip().lower()
        family = str(item.get("family") or "").strip()
        if role not in _SEATS:
            continue
        if role == "evidence":
            if family.lower() not in names:
                continue
        else:
            family = ""
        key = (role, family.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "role": role,
            "family": family,
            "why": str(item.get("why") or why_default)[:160],
            "question": question,
        })
        if len(out) >= max_agents:
            break
    return out


def _supervisor_with_model(
    model: Any,
    *,
    case_dir: Path,
    question: str,
    families: list[tuple[str, int]],
    board_digest: str,
    steering: str,
    max_agents: int,
) -> list[dict[str, Any]]:
    """MA4.2 — the model chooses the team; [] on any doubt (caller falls back)."""
    from nexus.langgraph.context_loop import _call_model

    family_lines = "\n".join(
        f"- {name} ({rows} rows)" for name, rows in families[:40]
    ) or "(no indexed families visible)"
    limit = budget_chars(case_window(case_dir))
    messages = [
        {
            "role": "system",
            "content": (
                "You supervise a concurrent forensic investigation. Choose the "
                "seats to spawn for the next superstep. Roles: evidence (one per "
                "indexed family), correlation (cross-family), pattern "
                "(ITM/ATT&CK/ATLAS/MBC). Reply with ONE JSON object only: "
                '{"spawns":[{"role":"evidence|correlation|pattern",'
                '"family":"<family or empty>","why":"one clause"}]}. '
                f"At most {max_agents} seats. Evidence families must come from "
                "the indexed list. No prose outside the JSON."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Objective: {question}\n\nIndexed families:\n{family_lines}\n\n"
                + (f"Examiner steering:\n{steering}\n\n" if steering else "")
                + "Board so far:\n"
                + ((board_digest or "(empty)")[:limit])
            ),
        },
    ]
    try:
        raw = _call_model(model, messages)
    except Exception:  # noqa: BLE001 — fallback is the contract
        log.debug("mode4 model supervisor failed", exc_info=True)
        return []
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end <= start:
        return []
    try:
        parsed = json.loads(raw[start:end + 1])
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, dict):
        return []
    return _validated_spawns(
        parsed.get("spawns"),
        families,
        max_agents=max_agents,
        question=question,
        why_default="model supervisor",
    )


def _fallback_entry(spawn: dict[str, Any], superstep: int) -> dict[str, Any]:
    role = str(spawn.get("role") or "evidence")
    family = str(spawn.get("family") or "")
    return {
        "entry_id": f"be-{uuid4().hex[:10]}",
        "agent_id": f"{role}:{family or 'board'}:{superstep}",
        "role": role,
        "family": family,
        "superstep": superstep,
        "claims": [],
        "open_questions": [
            "No model configured. Seat listed the family and did not invent claims."
        ],
        "note": str(spawn.get("why") or ""),
    }


def _parse_claims(text: str) -> list[dict[str, Any]]:
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return []
    try:
        parsed = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return []
    claims = parsed.get("claims") if isinstance(parsed, dict) else None
    if not isinstance(claims, list):
        return []
    return [item for item in claims if isinstance(item, dict)]


def _seat_with_model(
    spawn: dict[str, Any],
    *,
    case_dir: Path,
    model: Any,
    run_id: str,
    sink: EventSink,
    board_digest: str,
    superstep: int,
    audit: Any = None,
) -> dict[str, Any]:
    from nexus.langgraph.context_loop import LoopBudget, run_context_loop
    from nexus.langgraph.mode3_runtime import role_for

    role_name = str(spawn.get("role") or "evidence")
    try:
        role = role_for(role_name if role_name in _SEATS else "evidence")
    except KeyError:
        role = role_for("evidence")
    family = str(spawn.get("family") or "")
    question = (
        f"You are the {role_name} seat. Examiner objective: {spawn.get('question') or ''}\n"
        f"Family: {family or '(cross-family)'}. Why you were spawned: {spawn.get('why') or ''}\n"
        f"Board so far:\n{board_digest}\n\n"
        'Return JSON {"claims":[{"entity_type":"...","entity_value":"...",'
        '"claim_kind":"presence|absence|attribution|time_order","polarity":"affirm|deny",'
        '"value":"...","audit_ids":["..."],"confidence":"LOW|MEDIUM|HIGH",'
        '"confidence_justification":"..."}],"open_questions":["..."]}. '
        "Every claim needs an audit_id from a tool call. Do not attribute an actor."
    )
    rounds = _env_int("NEXUS_MODE4_ROUNDS", 24, low=1, high=80)
    calls = _env_int("NEXUS_MODE4_CALLS", 48, low=1, high=200)
    seconds = float(_env_int("NEXUS_MODE4_SECONDS", 1800, low=30, high=7200))
    loop = run_context_loop(
        case_dir=case_dir,
        case_id=case_dir.name,
        question=question,
        model=model,
        system_prompt=role.system_prompt,
        task=f"mode4-{role_name}",
        budget=LoopBudget(rounds=rounds, seconds=seconds, calls=calls, call_chars=budget_chars(case_window(case_dir))),
        audit=audit,
        allowed_tools=role.tools,
        terminal_keys=("claims",),
    )
    entry = _fallback_entry(spawn, superstep)
    entry["claims"] = _parse_claims(str(loop.get("reply") or ""))
    entry["open_questions"] = []
    sink.emit(new_event(
        run_id, "board.entry", actor="agent", agent_id=entry["agent_id"],
        detail=f"{role_name} {family}".strip(),
        data={"claims": len(entry["claims"])},
    ))
    return entry


class Mode4State(TypedDict, total=False):
    board: Annotated[list[dict[str, Any]], add_board]
    spawns: list[dict[str, Any]]
    status: str
    quiet: int
    redispatch_used: int
    superstep: int
    last_fp: list[str]
    disputes: list[dict[str, Any]]
    steering_seen: int


class _LockedSink:
    def __init__(self, inner: EventSink):
        self.inner = inner

    def emit(self, event: Any) -> None:
        with _SINK_LOCK:
            self.inner.emit(event)


def run_mode4(
    case_dir: Path,
    question: str,
    *,
    model: Any = None,
    run_id: str = "",
    families: list[tuple[str, int]] | None = None,
    seat_fn: Callable[[dict[str, Any], list[dict[str, Any]], int], dict[str, Any]] | None = None,
    es_ok: bool | None = None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    resume_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one concurrent investigation. Returns the run record. Never stages."""
    case_dir = Path(case_dir)
    run_id = run_id or f"M4-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}-{uuid4().hex[:6]}"
    from nexus.audit import AuditWriter

    # One writer per run (locked decision): seats share it, no seat builds one.
    run_audit = AuditWriter("nexus", audit_dir=case_dir / "audit")
    ready = elasticsearch_ready() if es_ok is None else bool(es_ok)
    record: dict[str, Any] = {
        "run_id": run_id,
        "case_id": case_dir.name,
        "question": question,
        "created_at": _now(),
        "status": "running",
        "stop_reason": "",
        "board": [],
        "disputes": [],
        "candidates": [],
        "gaps": [],
        "narrative": "",
        "superstep": 0,
        "product_mode": "multi-agent",
    }
    if resume_state is not None:
        existing = read_run_record(case_dir, run_id)
        if existing is not None and str(existing.get("status") or "") in {
            "completed", "failed", "stopped",
        }:
            return existing
        if existing is not None:
            record.update(existing)
            record["status"] = "running"
            record["stop_reason"] = ""
            record.pop("resume_state", None)
            record.pop("completed_at", None)
    if not ready:
        record["status"] = "failed"
        record["stop_reason"] = "elasticsearch_required"
        _persist(case_dir, run_id, record)
        return record
    # Persist before the graph runs so mid-run controls (pause/stop), status
    # polling and the SSE tail all see the record from superstep 0.
    _persist(case_dir, run_id, record)

    max_agents = _env_int("NEXUS_MODE4_MAX_AGENTS", 4, low=2, high=8)
    max_steps = _env_int("NEXUS_MODE4_MAX_SUPERSTEPS", 6, low=1, high=12)
    max_calls = _env_int("NEXUS_MODE4_MAX_CALLS", 120, low=1, high=400)
    settle_k = _env_int("NEXUS_MODE4_SETTLE_SUPERSTEPS", 2, low=1, high=6)
    max_redispatch = _env_int("NEXUS_MODE4_MAX_REDISPATCH", 2, low=0, high=6)
    sink = _LockedSink(EventSink(case_dir, run_id, callback=on_event))
    # EventSink writes under mode3_runs. Mirror the jsonl next to the mode4 record.
    sink.inner.path = _run_dir(case_dir) / f"{run_id}.jsonl"
    sink.inner.path.parent.mkdir(parents=True, exist_ok=True)

    indexed = list(families or [])
    if not indexed:
        try:
            from nexus.langgraph.backbone import backbone_call

            index = backbone_call(
                "index_mappings",
                audit=run_audit,
                case_id=case_dir.name,
            )
            indexed = [
                (str(name), int(rows or 0))
                for name, rows in (index.get("family_rows") or {}).items()
            ]
        except Exception:  # noqa: BLE001
            log.debug("mode4 index_mappings failed", exc_info=True)
            indexed = []

    calls_used = {"n": 0}

    def _halted() -> str:
        flags = read_controls(case_dir, run_id)
        if flags["stop_requested"]:
            return "stopped"
        if flags["pause_requested"]:
            return "paused"
        return ""

    def supervisor(state: Mode4State) -> dict[str, Any]:
        halt = _halted()
        step = int(state.get("superstep") or 0) + 1
        if halt:
            return {"status": halt, "superstep": step, "spawns": []}
        if step > max_steps or calls_used["n"] >= max_calls:
            return {"status": "capped", "superstep": step, "spawns": []}
        steering = read_steering(case_dir, run_id)
        seen = int(state.get("steering_seen") or 0)
        if len(steering) > seen:
            fresh = steering[seen:]
            spawns = [
                {
                    "role": "correlation",
                    "family": "",
                    "why": f"examiner steer: {str(line.get('text') or '')[:80]}",
                    "question": str(line.get("text") or question),
                }
                for line in fresh
            ][:max_agents]
            sink.emit(new_event(
                run_id, "supervisor.steer", actor="supervisor",
                detail=f"{len(fresh)} steer line(s)",
                data={"agents": len(spawns)},
            ))
            return {
                "spawns": spawns, "superstep": step, "status": "running",
                "steering_seen": len(steering),
            }
        disputes = state.get("disputes") or []
        used = int(state.get("redispatch_used") or 0)
        if disputes and used < max_redispatch and int(state.get("quiet") or 0) < settle_k:
            spawns = []
            for dispute in disputes:
                seats = dispute.get("seats") or ["evidence"]
                family = (dispute.get("families") or [""])[0]
                for role in seats:
                    if role in _SEATS:
                        spawns.append({
                            "role": role,
                            "family": family,
                            "why": f"dispute {dispute.get('entity_value')}",
                            "question": question,
                        })
            spawns = spawns[:max_agents]
            sink.emit(new_event(
                run_id, "supervisor.spawn", actor="supervisor",
                detail=f"redispatch {used + 1}",
                data={"agents": len(spawns)},
            ))
            return {"spawns": spawns, "superstep": step, "status": "running", "redispatch_used": used + 1}
        if step == 1 or not state.get("board"):
            spawns: list[dict[str, Any]] = []
            if model is not None:
                spawns = _supervisor_with_model(
                    model,
                    case_dir=case_dir,
                    question=question,
                    families=indexed,
                    board_digest=json.dumps(state.get("board") or [], default=str),
                    steering="\n".join(
                        f"- {str(line.get('text') or '')}" for line in steering[-3:]
                    ),
                    max_agents=max_agents,
                )
            supervisor_mode = "model" if spawns else "deterministic"
            if not spawns:
                spawns = plan_spawns(indexed, max_agents=max_agents, question=question)
            sink.emit(new_event(
                run_id, "supervisor.spawn", actor="supervisor",
                detail=f"{len(spawns)} seats ({supervisor_mode})",
                data={"agents": [s["role"] for s in spawns],
                      "chosen_by": supervisor_mode},
            ))
            return {"spawns": spawns, "superstep": step, "status": "running"}
        return {"status": "settled", "superstep": step, "spawns": []}

    def fan(state: Mode4State) -> Any:
        from langgraph.types import Send

        status = str(state.get("status") or "")
        if status in {"stopped", "paused", "capped", "settled"}:
            return "join"
        board = state.get("board") or []
        digest = json.dumps(board, default=str)
        steering = read_steering(case_dir, run_id)
        if steering:
            steer_text = "\n".join(
                f"- {str(line.get('text') or '')}" for line in steering[-3:]
            )
            digest += f"\nEXAMINER STEERING:\n{steer_text}"
        limit = budget_chars(case_window(case_dir))
        if len(digest) > limit:
            digest = digest[:limit]
        sends = []
        for spawn in state.get("spawns") or []:
            sends.append(Send("seat", {
                "spawn": spawn,
                "board_digest": digest,
                "superstep": int(state.get("superstep") or 1),
            }))
        return sends or "join"

    def seat(payload: dict[str, Any]) -> dict[str, Any]:
        spawn = payload.get("spawn") or {}
        step = int(payload.get("superstep") or 1)
        if calls_used["n"] >= max_calls:
            return {"board": []}
        calls_used["n"] += 1
        if seat_fn is not None:
            entry = seat_fn(spawn, [], step)
        elif model is not None:
            entry = _seat_with_model(
                spawn, case_dir=case_dir, model=model, run_id=run_id,
                sink=sink, board_digest=str(payload.get("board_digest") or ""),
                superstep=step, audit=run_audit,
            )
        else:
            entry = _fallback_entry(spawn, step)
            sink.emit(new_event(
                run_id, "board.entry", actor="agent", agent_id=entry["agent_id"],
                detail="deterministic seat",
            ))
        kept = []
        for claim in entry.get("claims") or []:
            if isinstance(claim, dict) and not accept_claim(claim):
                kept.append(claim)
        entry["claims"] = kept
        return {"board": [entry]}

    def join(state: Mode4State) -> dict[str, Any]:
        halt = _halted()
        if halt:
            return {"status": halt}
        board = list(state.get("board") or [])
        disputes = find_disputes(board)
        fp = _fingerprint(board)
        quiet = int(state.get("quiet") or 0)
        quiet = quiet + 1 if fp == list(state.get("last_fp") or []) else 0
        status = str(state.get("status") or "running")
        if status != "capped" and (
            (disputes and quiet >= settle_k)
            or (not disputes and int(state.get("superstep") or 0) >= 1)
        ):
            status = "settled"
        sink.emit(new_event(
            run_id, "join.decision", actor="join",
            detail=status,
            data={"disputes": len(disputes), "quiet": quiet},
        ))
        for dispute in disputes:
            sink.emit(new_event(
                run_id, "dispute.opened", actor="join",
                detail=f"{dispute['entity_value']} {dispute['claim_kind']}",
            ))
        return {"disputes": disputes, "quiet": quiet, "last_fp": fp, "status": status}

    def after_join(state: Mode4State) -> str:
        status = str(state.get("status") or "")
        if status in {"settled", "stopped", "paused", "capped"}:
            return "synthesize"
        return "supervisor"

    def synthesize(state: Mode4State) -> dict[str, Any]:
        disputes = find_disputes(list(state.get("board") or []))
        open_keys = {
            (d["entity_type"], d["entity_value"], d["claim_kind"]) for d in disputes
        }
        candidates: list[dict[str, Any]] = []
        gaps = [f"unresolved {d['entity_value']} {d['claim_kind']}" for d in disputes]
        for entry in state.get("board") or []:
            for claim in entry.get("claims") or []:
                if not isinstance(claim, dict):
                    continue
                reason = accept_claim(claim)
                if reason:
                    gaps.append(reason)
                    continue
                key = _claim_key(claim)
                if key in open_keys:
                    continue
                candidates.append({
                    "title": f"{claim.get('entity_value')}: {claim.get('claim_kind')}",
                    "observation": str(claim.get("value") or ""),
                    "confidence": str(claim.get("confidence") or "LOW"),
                    "confidence_justification": str(claim.get("confidence_justification") or ""),
                    "audit_ids": _audit_ids(claim),
                    "agent_id": entry.get("agent_id"),
                })
        sink.emit(new_event(
            run_id, "synthesis.candidates", actor="synthesis",
            detail=f"{len(candidates)} candidate(s)",
        ))
        return {}

    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(Mode4State)
    graph.add_node("supervisor", supervisor)
    graph.add_node("seat", seat)
    graph.add_node("join", join)
    graph.add_node("synthesize", synthesize)
    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges("supervisor", fan, ["seat", "join"])
    graph.add_edge("seat", "join")
    graph.add_conditional_edges("join", after_join, ["supervisor", "synthesize"])
    graph.add_edge("synthesize", END)
    seed: dict[str, Any] = {
        "board": [], "quiet": 0, "redispatch_used": 0, "superstep": 0,
        "status": "running", "steering_seen": 0,
    }
    if resume_state:
        seed.update({
            "board": list(resume_state.get("board") or []),
            "superstep": int(resume_state.get("superstep") or 0),
            "quiet": int(resume_state.get("quiet") or 0),
            "redispatch_used": int(resume_state.get("redispatch_used") or 0),
            "steering_seen": int(resume_state.get("steering_seen") or 0),
        })
    final = graph.compile().invoke(seed)

    status = str(final.get("status") or "completed")
    if status == "settled":
        status = "completed"
        stop_reason = "settled"
    elif status == "capped":
        status = "completed"
        stop_reason = "run_cap"
    elif status == "stopped":
        stop_reason = "examiner_stop"
    elif status == "paused":
        stop_reason = "paused"
    else:
        stop_reason = status
    record.update({
        "status": status,
        "stop_reason": stop_reason,
        "board": list(final.get("board") or []),
        "disputes": list(final.get("disputes") or []),
        "superstep": int(final.get("superstep") or 0),
        "completed_at": _now() if status != "paused" else "",
    })
    if status == "paused":
        # File-based superstep checkpoint: resume rebuilds the graph state.
        record["resume_state"] = {
            "board": list(record.get("board") or []),
            "superstep": int(record.get("superstep") or 0),
            "quiet": int(final.get("quiet") or 0),
            "redispatch_used": int(final.get("redispatch_used") or 0),
            "steering_seen": int(final.get("steering_seen") or 0),
        }
    # Synthesis return was empty so candidates are derived here from the board.
    disputes = record["disputes"]
    open_keys = {(d["entity_type"], d["entity_value"], d["claim_kind"]) for d in disputes}
    candidates = []
    gaps = [f"unresolved {d['entity_value']} {d['claim_kind']}" for d in disputes]
    for entry in record["board"]:
        for claim in entry.get("claims") or []:
            if not isinstance(claim, dict):
                continue
            reason = accept_claim(claim)
            if reason:
                gaps.append(reason)
                continue
            key = _claim_key(claim)
            if key in open_keys:
                continue
            candidates.append({
                "title": f"{claim.get('entity_value')}: {claim.get('claim_kind')}",
                "observation": str(claim.get("value") or ""),
                "confidence": str(claim.get("confidence") or "LOW"),
                "confidence_justification": str(claim.get("confidence_justification") or ""),
                "audit_ids": _audit_ids(claim),
                "agent_id": entry.get("agent_id"),
            })
    record["candidates"] = candidates
    record["gaps"] = gaps
    record["narrative"] = (
        f"{len(candidates)} settled claim(s); {len(disputes)} unresolved dispute(s)."
    )
    steering = read_steering(case_dir, run_id)
    if steering:
        record["steering"] = steering
    _persist(case_dir, run_id, record)
    return record


def resume_mode4(
    case_dir: Path,
    run_id: str,
    *,
    model: Any = None,
    seat_fn: Callable[[dict[str, Any], list[dict[str, Any]], int], dict[str, Any]] | None = None,
    es_ok: bool | None = None,
) -> dict[str, Any]:
    """Continue a paused run from its persisted board/superstep snapshot."""
    record = read_run_record(case_dir, run_id)
    if record is None:
        return {"error": "run not found", "run_id": run_id}
    status = str(record.get("status") or "")
    if status in {"stopped", "completed", "failed"}:
        return {**record, "error": f"run is {status}; start a new run"}
    if status != "paused":
        return {**record, "error": f"run is {status}; nothing to resume"}
    mark_paused(case_dir, run_id, False)
    return run_mode4(
        case_dir,
        str(record.get("question") or ""),
        model=model,
        run_id=run_id,
        seat_fn=seat_fn,
        es_ok=es_ok,
        resume_state=record.get("resume_state") or {},
    )


def stage_mode4(case_dir: Path, run_id: str) -> dict[str, Any]:
    """Examiner action. Copies candidates onto a record shape stage_run_candidates reads."""
    record = read_run_record(case_dir, run_id)
    if record is None:
        return {"error": "run not found", "run_id": run_id, "staged": [], "skipped": []}
    from nexus.langgraph.mode3_runtime import _MODE3_DIR

    bridge = Path(case_dir) / _MODE3_DIR
    bridge.mkdir(parents=True, exist_ok=True)
    path = bridge / f"{run_id}.json"
    payload = {
        "run_id": run_id,
        "candidates": record.get("candidates") or [],
        "verdicts": [],
        "results": [],
    }
    path.write_text(json.dumps(payload, default=str), encoding="utf-8")
    result = stage_run_candidates(case_dir, run_id, candidates=record.get("candidates") or [])
    return result


# Re-export stop helper name used by the CLI. The Mode 3 sidecar is not used.
request_stop = request_stop_run
append_mode4_steering = append_steering
