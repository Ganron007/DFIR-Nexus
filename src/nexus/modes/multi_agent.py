"""Mode 3 concurrent multi-agent runtime (plan ids MA4.1–MA4.9).

A model supervisor spawns evidence, correlation, and pattern seats in one
superstep. Each seat has its own context and publishes a board entry. The
join compares claims and can send a seat back. Synthesis writes DRAFT
candidates only after the join settles. Agents never stage or approve.

Product label after the rename: this runtime is **Mode 3 — Multi-agent**.
Run files live under ``analysis/mode3_runs`` with ids ``M3-``.
Multi-role runs use ``analysis/mode2_runs`` and ``M2-``.
A new multi-agent case stores ``investigation_mode: 3``.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, TypedDict
from uuid import uuid4

from nexus.langgraph.case_index import elasticsearch_ready
from nexus.langgraph.prompt_budget import budget_chars, case_window
from nexus.modes.multi_role import (
    EventSink,
    WorkOrder,
    _question_keywords,
    _retrieve_skill_refs,
    _skill_procedure_block,
    new_event,
    stage_run_candidates,
)

log = logging.getLogger(__name__)

_DIR = "analysis/mode3_runs"
_CLAIM_KINDS = {"presence", "absence", "attribution", "time_order"}
_SEATS = ("evidence", "correlation", "pattern")
_SINK_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _recorded_model() -> dict[str, str]:
    """The configured LLM, for the run record (36c: R2 must know which ran).

    Reads the same env the model is built from (`NEXUS_LLM_MODEL` /
    `NEXUS_LLM_PROVIDER` / legacy `NEXUS_MODEL`). A run with no model
    configured records `"none"` — the deterministic path is a real path and
    must be distinguishable from "a model ran".
    """
    from nexus.langgraph.pipeline_runs import configured_model

    return configured_model()


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
    files = sorted(directory.glob("M3-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0].stem if files else ""


def _steering_path(case_dir: Path, run_id: str) -> Path:
    return _run_dir(case_dir) / f"{run_id}.steering.jsonl"


def append_mode3_steering(case_dir: Path, run_id: str, text: str) -> dict[str, Any]:
    """Queue an examiner directive for the Mode 3 run (its own steering file)."""
    entry = {"ts": _now(), "text": str(text or "")[:600]}
    path = _steering_path(case_dir, run_id)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
    return entry


def read_mode3_steering(case_dir: Path, run_id: str, limit: int = 50) -> list[dict[str, Any]]:
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
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                out.append(item)
    except OSError:
        return []
    return out[-limit:]


def active_seats(
    case_dir: Path,
    run_id: str,
    *,
    events: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Seats that have started work and have not yet reported.

    The board holds only seats that have *finished*, so on its own it cannot
    answer "how many agents are running right now" - the question an examiner
    watching a live run actually has. Liveness is derived from the event stream
    instead: a ``seat.started`` with no matching ``board.entry`` is in flight.

    Derived rather than stored on purpose: the stream is already the append-only
    record of what the agents did, so a second mutable liveness counter could
    disagree with it and there would be no way to tell which was telling the
    truth.
    """
    stream = events if events is not None else read_run_events(case_dir, run_id)
    started: dict[str, dict[str, Any]] = {}
    reported: set[str] = set()
    for ev in stream:
        if not isinstance(ev, dict):
            continue
        kind = str(ev.get("event_type") or "")
        agent = str(ev.get("agent_id") or "").strip()
        if not agent:
            continue
        if kind == "seat.started":
            started[agent] = {
                "agent_id": agent,
                "role": (ev.get("data") or {}).get("role") or agent.split(":")[0],
                "family": (ev.get("data") or {}).get("family") or "",
                "superstep": (ev.get("data") or {}).get("superstep"),
                "why": (ev.get("data") or {}).get("why") or "",
                "started_at": ev.get("ts") or "",
            }
        elif kind == "board.entry":
            reported.add(agent)
    # Later starts win, so a re-dispatched seat shows its current superstep.
    return [s for a, s in started.items() if a not in reported]


def interaction_timeline(
    stream: list[dict[str, Any]], limit: int = 200,
) -> list[dict[str, Any]]:
    """The agent-to-agent interaction log, in the shape the board renders.

    One row per event an examiner would want to read as a narrative: who acted,
    which seat, what they touched, and why. Tool calls and results are included
    because "seat claimed X" is only meaningful next to the call that produced it.
    """
    rows: list[dict[str, Any]] = []
    for ev in stream:
        if not isinstance(ev, dict):
            continue
        kind = str(ev.get("event_type") or "")
        if not kind:
            continue
        data = ev.get("data") if isinstance(ev.get("data"), dict) else {}
        rows.append({
            "ts": ev.get("ts") or "",
            "event": kind,
            "actor": ev.get("actor") or "",
            "agent_id": ev.get("agent_id") or "",
            "detail": ev.get("detail") or "",
            "tool": ev.get("tool") or "",
            "audit_id": ev.get("audit_id") or "",
            "data": data,
        })
    return rows[-limit:]


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
    """Append an event to the Mode 3 stream the SSE tail reads."""
    sink = EventSink(Path(case_dir), run_id)
    sink.path = _run_dir(Path(case_dir)) / f"{run_id}.jsonl"
    sink.emit(event)


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


def settled_candidates(
    board: list[dict[str, Any]],
    disputes: list[dict[str, Any]],
    *,
    case_dir: Path | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """DRAFT-shaped candidates from settled claims.

    Staging requires observation and interpretation. A claim that passes
    ``accept_claim`` already has a justification; that text is the
    interpretation so the examiner stage step does not skip the row.

    WO-A7: a claim the board **disputed** is the Mode 3 refutation - it is
    excluded from staging and, when ``case_dir`` is given, recorded as a
    negative-space event (an audited non-finding). Without ``case_dir`` this
    stays a pure function.

    WO-R1F-M3 item 2: a claim the **verifier refuted** is likewise excluded,
    and recorded as negative space when ``case_dir`` is given.
    """
    open_keys = {
        (d["entity_type"], d["entity_value"], d["claim_kind"]) for d in disputes
    }
    # WO-R1F-M3 item 2: the verifier's refuted subjects, so a refuted claim
    # never becomes a candidate. The verifier's subject is
    # "<entity_type>=<entity_value>", so the claim's entity_value is what
    # matters; refuted subjects are normalised the same way.
    refuted: set[str] = set()
    confirmed: dict[str, str] = {}
    for entry in board:
        for verdict in entry.get("verdicts") or []:
            raw = str(verdict.get("subject") or "")
            if not raw:
                continue
            evalue = _norm_key(raw.split("=", 1)[1]) if "=" in raw else _norm_key(raw)
            cls = str(verdict.get("class") or "").lower()
            if evalue:
                if cls == "refuted":
                    refuted.add(evalue)
                elif cls == "confirmed":
                    confirmed.setdefault(evalue, str(verdict.get("basis") or ""))
    candidates: list[dict[str, Any]] = []
    gaps = [f"unresolved {d['entity_value']} {d['claim_kind']}" for d in disputes]
    for entry in board:
        for claim in entry.get("claims") or []:
            if not isinstance(claim, dict):
                continue
            reason = accept_claim(claim)
            if reason:
                gaps.append(reason)
                continue
            key = _claim_key(claim)
            # WO-R1F-M3 item 2: a verifier-refuted claim is excluded and
            # recorded as negative space (the refutation is the result, not
            # an open finding).
            if key and key[1] in refuted:
                if case_dir is not None:
                    with contextlib.suppress(Exception):
                        from nexus.analysis.negative_space import record
                        record(
                            case_dir, "refuted",
                            f"{claim.get('entity_value') or '?'} "
                            f"{claim.get('claim_kind') or '?'}",
                            "the verifier refuted this claim; "
                            "it was excluded from staging",
                            refs=list(_audit_ids(claim)),
                        )
                continue
            if key in open_keys:
                # WO-A7: the board contradicted this claim, so it never
                # becomes a finding - record the refutation (audit ids as refs).
                if case_dir is not None:
                    with contextlib.suppress(Exception):
                        from nexus.analysis.negative_space import record

                        record(
                            case_dir, "refuted",
                            f"{claim.get('entity_value') or '?'} "
                            f"{claim.get('claim_kind') or '?'}",
                            "the Mode 3 board disputed this claim; "
                            "it was excluded from staging",
                            refs=list(_audit_ids(claim)),
                        )
                continue
            justification = str(claim.get("confidence_justification") or "").strip()
            value = str(claim.get("value") or "").strip()
            kind = str(claim.get("claim_kind") or "")
            entity = str(claim.get("entity_value") or "")
            # WO-R1F-M3 item 2: carry the verifier's confirmed basis onto the
            # candidate so the examiner can see the corroboration.
            verifier_basis = confirmed.get(key[1]) if key else None
            if verifier_basis:
                justification = f"{justification}\nVerifier: {verifier_basis}"
            from nexus.analysis.titles import claim_title

            candidates.append({
                # "evtxecmd: presence" is a dispute key rendered as English. The
                # claim carries a value and a justification, and either is a
                # sentence an examiner can read, so one of them leads the title.
                "title": claim_title(entity, kind, value=value,
                                     justification=justification),
                "observation": value or f"{kind} recorded for {entity}",
                "interpretation": justification,
                "confidence": str(claim.get("confidence") or "LOW"),
                "confidence_justification": justification,
                "audit_ids": _audit_ids(claim),
                "agent_id": entry.get("agent_id"),
            })
    return candidates, gaps


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

    # WO-K5: the supervisor gets the same leads the director used, and the
    # families are ordered by artifact value rather than by row count - a
    # volume-ordered list makes the model pick the biggest family, which is the
    # defect this replaces.
    try:
        from nexus.analysis.work_orders import rank_families

        ranked_names = rank_families([name for name, _rows in families])
        by_name = {name: rows for name, rows in families}
        ordered = [(name, by_name.get(name, 0)) for name in ranked_names]
    except Exception:  # noqa: BLE001
        ordered = list(families)

    family_lines = "\n".join(
        f"- {name} ({rows} rows)" for name, rows in ordered[:40]
    ) or "(no indexed families visible)"

    lead_lines = "(no leads)"
    try:
        from nexus.analysis.leads import build_leads

        leads = build_leads(case_dir, write=False)
        if leads:
            lead_lines = "\n".join(
                f"- [{lead.kind}] {lead.subject}: {lead.detail[:160]}"
                for lead in leads[:20]
            )
    except Exception as exc:  # noqa: BLE001 - the supervisor must still run
        log.debug("supervisor could not read leads: %s", exc)

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
                "the indexed list. No prose outside the JSON.\n"
                "Prefer families a lead points at: they are ordered by artifact "
                "value (execution, persistence, logon/credential, lateral, "
                "network, bulk filesystem), not by size.\n"
                "COVERAGE REQUIREMENT: every family must end the run accounted "
                "for - examined, or not examined and why. A family that silently "
                "never ran is a failure, not a clean result."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Objective: {question}\n\nIndexed families (artifact value "
                f"order):\n{family_lines}\n\nLeads raised so far:\n{lead_lines}\n\n"
                + (f"Examiner steering:\n{steering}\n\n" if steering else "")
                + "Board so far:\n"
                + ((board_digest or "(empty)")[:limit])
            ),
        },
    ]
    try:
        raw = _call_model(model, messages)
    except Exception:  # noqa: BLE001 — fallback is the contract
        log.debug("mode3 model supervisor failed", exc_info=True)
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
    return _claims_from_object(parsed)


def _parse_seat_fields(text: str) -> dict[str, Any]:
    """Parse open_questions, lead_disposition and verdicts from a seat reply.

    Root cause (WO-R1F-M3 items 1/2/3): _parse_claims only read the claims
    key, so a reply's open_questions / lead_disposition / verdicts were
    dropped and entry["open_questions"] was reset to [] at multi_agent.py:770.
    """
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return {}
    try:
        parsed = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    out: dict[str, Any] = {}
    raw_q = parsed.get("open_questions")
    if isinstance(raw_q, list):
        out["open_questions"] = [str(item).strip() for item in raw_q if str(item).strip()]
    raw_disp = parsed.get("lead_disposition")
    if isinstance(raw_disp, dict):
        out["lead_disposition"] = {
            "lead": str(raw_disp.get("lead") or ""),
            "status": str(raw_disp.get("status") or "insufficient"),
            "basis": str(raw_disp.get("basis") or "")[:400],
        }
    raw_verdicts = parsed.get("verdicts")
    if isinstance(raw_verdicts, list):
        out["verdicts"] = [
            {
                "subject": str(v.get("subject") or ""),
                "class": str(v.get("class") or "inferred"),
                "basis": str(v.get("basis") or "")[:400],
                "audit_ids": [str(a) for a in (v.get("audit_ids") or []) if str(a)],
            }
            for v in raw_verdicts if isinstance(v, dict)
        ]
    return out


#: Keys a seat has been observed to use instead of `claims` (WO-R1F item 7).
#: Measured on SC1: a seat answered `{"notes": [...]}` — a real answer, lost
#: because the key differed by one word.
_CLAIM_ALTERNATES = ("notes", "findings", "observations", "claims")


def _claims_from_object(parsed: Any) -> list[dict[str, Any]]:
    """Claims from a parsed reply, accepting the known alternate keys."""
    if not isinstance(parsed, dict):
        return []
    for key in _CLAIM_ALTERNATES:
        claims = parsed.get(key)
        if isinstance(claims, list):
            return [item for item in claims if isinstance(item, dict)]
    return []


def _has_claims_key(text: str) -> bool:
    """True when the reply carries any of the accepted claim keys."""
    return any(f'"{key}"' in str(text or "") for key in _CLAIM_ALTERNATES)


def _claim_is_coverage_only(claim: dict[str, Any]) -> bool:
    """A claim that only says "tool X parsed N records" is COVERAGE (item 7).

    It is not a finding: it describes the parser, not the evidence. It goes to
    the coverage report instead — otherwise every seat's first inventory
    statement becomes a candidate and the board fills with noise.
    """
    import re

    entity = str(claim.get("entity_value") or "").strip().lower()
    value = str(claim.get("value") or "").strip().lower()
    blob = f"{entity} {value}"
    if not blob.strip():
        return False
    parsed = re.search(r"\bparsed\b", blob)
    if not parsed:
        return False
    # "parsed N records/rows/files/entries" with no behavioural content.
    return bool(re.search(r"\bparsed\s+\d[\d,]*\s+"
                          r"(record|row|file|entr|event|hit|item|line)", blob))


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
    from nexus.langgraph.context_loop import LoopBudget, _call_model, run_context_loop
    from nexus.modes.multi_role import _investigative_extras, role_for

    role_name = str(spawn.get("role") or "evidence")
    try:
        role = role_for(role_name if role_name in _SEATS else "evidence")
    except KeyError:
        role = role_for("evidence")
    family = str(spawn.get("family") or "")
    objective = str(spawn.get("question") or "")
    # Announce the seat before it works. The board only holds seats that have
    # *reported*, so without this an examiner watching a run cannot tell one
    # agent grinding from three - and the interaction timeline has no start.
    seat_agent_id = (
        f"{role_name if role_name in _SEATS else 'evidence'}:{family or 'unknown'}:{superstep}"
    )
    sink.emit(new_event(
        run_id, "seat.started", actor="agent", agent_id=seat_agent_id,
        detail=f"{role_name} {family}".strip(),
        data={"role": role_name, "family": family, "superstep": superstep,
              "why": spawn.get("why") or "", "question": objective},
    ))
    # WO-R1F-M3 item 6: a lead hypothesis seat runs the procedures for the
    # lead's own ATT&CK technique (item 8's attribution), not just the
    # family's. `spawn` carries the lead dict (via `_spawns_for_agenda`),
    # whose `extra.attack_ids` names the techniques; otherwise the domain's
    # skills are used as today.
    lead_extra = spawn.get("lead_extra") or {}
    techniques = [str(t) for t in (lead_extra.get("attack_ids") or []) if t]
    skill_refs = _retrieve_skill_refs(
        [family] if family else [],
        _question_keywords(objective),
        techniques=techniques,
        limit=8,
    )
    skill_block = _skill_procedure_block(WorkOrder(
        order_id="seat",
        role=role_name if role_name in _SEATS else "evidence",
        task=objective or "investigate",
        family=family,
        skill_refs=skill_refs,
    ))
    # WO-R1F-M3 item 2: the verifier seat returns `verdicts`, not `claims`.
    # Use the right terminal key, or the loop never recognises the reply and
    # the verdicts are lost (the original defect in this seat path).
    is_verifier = role_name == "verifier"
    terminal_keys = ("verdicts",) if is_verifier else ("claims",)
    if is_verifier:
        question = (
            f"You are the {role_name} seat. Examiner objective: {objective}\n"
            f"{skill_block}\n"
            f"Board so far:\n{board_digest}\n\n"
            + _investigative_extras(case_dir)
            + 'Return JSON {"verdicts":[{"subject":"<entity_type>=<entity_value>",'
            '"class":"confirmed|inferred|refuted","basis":"one clause",'
            '"audit_ids":["..."]}]}. '
            "A refuted verdict must name the counter-evidence (audit_ids required). "
            "Do not attribute an actor."
        )
    else:
        question = (
            f"You are the {role_name} seat. Examiner objective: {objective}\n"
            f"Family: {family or '(cross-family)'}. Why you were spawned: {spawn.get('why') or ''}\n"
            f"{skill_block}\n"
            f"Board so far:\n{board_digest}\n\n"
            + _investigative_extras(case_dir)
            + 'Return JSON {"claims":[{"entity_type":"...","entity_value":"...",'
            '"claim_kind":"presence|absence|attribution|time_order","polarity":"affirm|deny",'
            '"value":"...","audit_ids":["..."],"confidence":"LOW|MEDIUM|HIGH",'
            '"confidence_justification":"..."}],"open_questions":["..."]}. '
            + (
                'When investigating a lead, also return '
                '"lead_disposition":{"lead":"<subject>","status":"'
                'supported|refuted|benign|insufficient","basis":"one clause"}. '
            ) if spawn.get("lead") else ""
            + "Every claim needs an audit_id from a tool call. Do not attribute an actor."
        )
    rounds = _env_int("NEXUS_MODE3_ROUNDS", 24, low=1, high=80)
    calls = _env_int("NEXUS_MODE3_CALLS", 48, low=1, high=200)
    seconds = float(_env_int("NEXUS_MODE3_SECONDS", 1800, low=30, high=7200))
    loop = run_context_loop(
        case_dir=case_dir,
        case_id=case_dir.name,
        question=question,
        model=model,
        system_prompt=role.system_prompt,
        task=f"mode3-{role_name}",
        budget=LoopBudget(rounds=rounds, seconds=seconds, calls=calls, call_chars=budget_chars(case_window(case_dir))),
        audit=audit,
        allowed_tools=role.tools,
        terminal_keys=terminal_keys,
    )
    entry = _fallback_entry(spawn, superstep)
    reply_text = str(loop.get("reply") or "")
    entry["claims"] = _parse_claims(reply_text)
    # WO-R1F-M3 items 1, 2, 3: parse the full reply object once, so open_questions,
    # lead_disposition and verdicts are all available to the entry (and to the
    # corrective retry below, which used to re-prompt on a lead reply that had
    # already returned a disposition).
    fields_parsed = _parse_seat_fields(reply_text)
    # WO-R1F item 7: when the reply carries NO claim key at all, ONE corrective
    # re-prompt asks for the schema. Measured on SC1: a seat answered
    # `{"notes": [...]}` — and the alternates are accepted in `_parse_claims`, so
    # this fires only for a reply with none of them (prose, or a wrong key).
    # A verifier seat never returns claims, so the corrective retry only applies
    # to non-verifier seats that returned nothing usable.
    if (
        not is_verifier
        and not entry["claims"]
        and not fields_parsed.get("lead_disposition")
        and reply_text.strip()
        and not _has_claims_key(reply_text)
        and str(loop.get("finish_reason") or "") not in ("model_error", "empty_model")
    ):
        try:
            corrected = _call_model(
                model,
                [
                    {"role": "system", "content": role.system_prompt},
                    {
                        "role": "user",
                        "content": (
                            question
                            + "\n\nYour previous reply had no claims. Return ONLY "
                            'JSON: {"claims":[{"entity_type":"...",'
                            '"entity_value":"...",'
                            '"claim_kind":"presence|absence|attribution|time_order",'
                            '"polarity":"affirm|deny","value":"...",'
                            '"audit_ids":["..."],"confidence":"LOW|MEDIUM|HIGH",'
                            '"confidence_justification":"..."}],'
                            '"open_questions":["..."]}. If nothing is supportable, '
                            'return {"claims": [], "open_questions": ["..."]}.'
                        ),
                    },
                ],
            )
            if corrected.strip():
                entry["claims"] = _parse_claims(corrected)
                corrected_fields = _parse_seat_fields(corrected)
                if corrected_fields.get("lead_disposition"):
                    entry["lead_disposition"] = corrected_fields["lead_disposition"]
                entry["corrective_retry_used"] = True
                entry["reply_excerpt"] = " ".join(str(corrected).split())[:600]
        except Exception as exc:  # noqa: BLE001 — the retry is best-effort
            log.warning("seat corrective re-prompt failed: %s", exc)
    # Item 7: a claim that only says "tool X parsed N records" is COVERAGE, not
    # a finding. Split it out so the board holds evidence, not parser inventory.
    kept: list[dict[str, Any]] = []
    entry["coverage_only"] = []
    for claim in entry["claims"]:
        if _claim_is_coverage_only(claim):
            entry["coverage_only"].append(claim)
        else:
            kept.append(claim)
    entry["claims"] = kept
    # WO-R1F-M3 items 1, 2, 3: the reply's open_questions, lead_disposition and
    # verdicts were all being dropped here (open_questions hard-reset to [] and
    # the other two never read). Root cause: only `_parse_claims` ran, which
    # returns the claims list alone. `_parse_seat_fields` reads the full object.
    fields = _parse_seat_fields(reply_text)
    if is_verifier:
        # The verifier's terminal key is `verdicts`; its claims list is empty by
        # design. Parse the verdicts from the same reply object.
        entry["verdicts"] = fields.get("verdicts", [])
        entry["open_questions"] = fields.get("open_questions", [])
        entry["lead_disposition"] = fields.get("lead_disposition")
    else:
        entry["open_questions"] = fields.get("open_questions", [])
        entry["lead_disposition"] = fields.get("lead_disposition")
        entry["verdicts"] = fields.get("verdicts", [])
    # What the seat actually returned, capped. Without it the board records only
    # the *spawn reason* when a seat produces no claims, so "the model answered
    # in prose / returned an empty object" and "the seat never ran" are
    # indistinguishable after the fact - which is what made SC1 Mode 3's empty
    # board undiagnosable from the run record (2026-10-07).
    entry["reply_excerpt"] = " ".join(reply_text.split())[:600]
    # How the seat finished. `model_error` is the structured signal that the
    # model never answered - the difference between a seat that legitimately
    # found nothing and a seat that never ran, which look identical from an empty
    # claim list and must not be reported the same way.
    entry["finish_reason"] = str(loop.get("finish_reason") or "")
    # The seat's REAL tool-call count, from its own loop (item 7b's "add a real
    # tool-call budget"). Summed at the run level; without it the run cannot say
    # how much work it did or what the budget stopped.
    try:
        entry["tool_calls_used"] = len(loop.get("tool_calls") or [])
    except (TypeError, ValueError):
        entry["tool_calls_used"] = 0
    # Return the procedures this seat was given. Without them the run record
    # cannot say which documented method produced its claims, so "did the agent
    # follow a procedure or improvise" is unanswerable from the case afterwards
    # - which is the question a Phase 6 review asks first.
    entry["skill_refs"] = [
        {"skill": str(r.get("skill") or ""), "version": r.get("version"),
         "role": r.get("role"), "citations": list(r.get("citations") or [])[:6]}
        for r in (skill_refs or []) if isinstance(r, dict) and r.get("skill")
    ]
    sink.emit(new_event(
        run_id, "board.entry", actor="agent", agent_id=entry["agent_id"],
        detail=f"{role_name} {family}".strip(),
        data={"claims": len(entry["claims"])},
    ))
    return entry


class Mode3State(TypedDict, total=False):
    board: Annotated[list[dict[str, Any]], add_board]
    spawns: list[dict[str, Any]]
    status: str
    quiet: int
    redispatch_used: int
    superstep: int
    last_fp: list[str]
    disputes: list[dict[str, Any]]
    steering_seen: int
    # WO-R1F-M3 item 4: pivots and open questions already investigated, so a
    # consumed pivot or an answered question is not re-queued next superstep.
    consumed_pivots: list[dict[str, Any]]
    answered_questions: list[str]


class _LockedSink:
    def __init__(self, inner: EventSink):
        self.inner = inner

    def emit(self, event: Any) -> None:
        with _SINK_LOCK:
            self.inner.emit(event)


def _layer_status_for_record() -> dict[str, Any]:
    """The ablation toggle state, for the run record (WO-K8). Best-effort."""
    try:
        from nexus.analysis.layers import layer_status

        return layer_status()
    except Exception:  # noqa: BLE001 - never fail a run over a reporting nicety
        return {}


def _absence_for_record(case_dir: Path) -> dict[str, Any]:
    """The absence statement, for the run record (WO-K7). Best-effort."""
    try:
        from nexus.analysis.absence import record

        return record(case_dir)
    except Exception:  # noqa: BLE001
        return {}


def _open_agenda(
    case_dir: Path,
    board: list[dict[str, Any]],
    state: Mapping[str, Any],
) -> dict[str, Any]:
    """What still needs investigating, from the board (WO-R1F item 7b).

    The four sources the WO names:

    * (a) seats' ``open_questions`` — "I need X checked" must reach someone;
    * (b) unexplained crit/high leads and digest items;
    * (c) **pivots on new entities** — a beacon process implies its persistence,
      parent, network and credential activity;
    * (d) disputes (handled by the caller's redispatch branch).

    Pure over its inputs plus the case's lead file, so a scripted model can drive
    it. Empty agenda == everything dispositioned.

    WO-R1F-M3: consumed items are tracked in ``state`` so a pivot or question
    that has already been investigated is not re-queued (item 4, "pivots
    consumed"), which is what lets the stop rule actually terminate.
    """
    consumed_pivots = {
        (_norm_key(p.get("entity_type")), _norm_key(p.get("entity_value")))
        for p in (state.get("consumed_pivots") or [])
        if isinstance(p, dict)
    }
    answered_questions = {
        _norm_key(q) for q in (state.get("answered_questions") or [])
    }
    questions: list[str] = []
    for entry in board:
        for q in entry.get("open_questions") or []:
            text = " ".join(str(q).split())
            if not text or text in questions:
                continue
            if _norm_key(text) in answered_questions:
                continue
            questions.append(text)

    dispositioned = _dispositioned_keys(board)
    crit_leads: list[dict[str, Any]] = []
    try:
        from nexus.analysis.leads import read_leads

        for lead in read_leads(case_dir):
            extra = lead.get("extra") or {}
            if not extra.get("crit_high"):
                continue
            key = _norm_key(lead.get("subject"))
            if key and key not in dispositioned:
                crit_leads.append(lead)
    except Exception:  # noqa: BLE001 — an agenda must never break the run
        crit_leads = []

    pivots = _pivot_entities(board, state)
    # Pivots already consumed in a previous superstep are dropped (item 4):
    # a pivot seat that already ran on this entity does not re-queue it.
    if consumed_pivots:
        pivots = [
            p for p in pivots
            if (_norm_key(p.get("entity_type")), _norm_key(p.get("entity_value")))
            not in consumed_pivots
        ]
    return {
        "questions": questions,
        "crit_leads": crit_leads,
        "pivots": pivots,
    }


#: Entity types worth a follow-up seat when first seen (item 7b (c)).
_PIVOT_ENTITIES = {
    "process": "its parent, persistence and network activity",
    "domain": "name resolution and the processes that contacted it",
    "ipv4": "the processes that connected and what they transferred",
    "registry": "what wrote it and what it launches",
    "service": "what installed it and under which account",
    "user": "how the account was used and from where",
}


def _pivot_entities(
    board: list[dict[str, Any]],
    state: Mapping[str, Any],
) -> list[dict[str, str]]:
    """Entities raised on the board that no later seat picked up."""
    claimed: set[tuple[str, str]] = set()
    for entry in board:
        for claim in entry.get("claims") or []:
            key = _claim_key(claim)
            if key:
                claimed.add((key[0], key[1]))
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for entry in board:
        for claim in entry.get("claims") or []:
            key = _claim_key(claim)
            if not key:
                continue
            etype, evalue, _kind = key
            look = (etype, evalue)
            if look in seen or etype not in _PIVOT_ENTITIES:
                continue
            seen.add(look)
            out.append({
                "entity_type": etype,
                "entity_value": evalue,
                "why": _PIVOT_ENTITIES[etype],
            })
    del claimed
    return out


def _norm_key(value: Any) -> str:
    return " ".join(str(value or "").split()).lower()


def _dispositioned_keys(board: list[dict[str, Any]]) -> set[str]:
    """Lead/entity keys the board has already disposed of.

    A lead is dispositioned when a claim names it, a verifier refuted it, an
    explicit gap entry names it, or a lead disposition entry records it —
    the four ways the WO allows.

    WO-R1F-M3 item 3: a ``lead_disposition`` entry (from a hypothesis seat)
    disposes its named lead. This is what makes "never re-spawn the same
    lead" work: once a lead seat has run and returned a disposition (even
    "insufficient"), the lead's subject key is dispositioned and the agenda
    does not queue it again.

    NOTE: `entry["lead"]` (the spawn's lead subject) is NOT a disposition on
    its own — the seat ran but may have found nothing. Only an explicit
    `lead_disposition` or a claim naming the subject counts.
    """
    keys: set[str] = set()
    for entry in board:
        for claim in entry.get("claims") or []:
            key = _claim_key(claim)
            if key:
                keys.add(key[1])
                keys.add(key[0])
        for verdict in entry.get("verdicts") or []:
            raw = str(verdict.get("subject") or verdict.get("title") or "")
            if raw:
                keys.add(_norm_key(raw.split("=", 1)[1]) if "=" in raw else _norm_key(raw))
        for gap in entry.get("coverage_gaps") or []:
            keys.add(_norm_key(gap))
        # WO-R1F-M3 item 3: the lead a hypothesis seat disposed. Only an
        # explicit `lead_disposition` dict counts — the mere fact that a seat
        # ran on a lead (`entry["lead"]`) is not a disposition.
        disp = entry.get("lead_disposition")
        if isinstance(disp, dict):
            dlead = str(disp.get("lead") or "").strip()
            if dlead:
                keys.add(_norm_key(dlead))
    return {k for k in keys if k}


def _spawns_for_agenda(
    agenda: dict[str, Any],
    board: list[dict[str, Any]],
    *,
    max_agents: int,
    question: str,
    superstep: int,
    indexed: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Seats for the open agenda, strongest first (item 7b).

    Order: unexplained crit/high leads (a hypothesis seat each) -> open questions
    -> pivots. Correlation and pattern seats run only from superstep 2, on a
    non-empty board, and are appended last so they never crowd out the work.

    WO-R1F-M3 items 3/4/5: a lead seat carries its lead dict and its
    `extra` (for the technique-based skills, item 6); a pivot seat marks the
    pivot entity so it is recorded as consumed; superstep 1 keeps room for
    the present domain families alongside the lead seats.
    """
    spawns: list[dict[str, Any]] = []
    taken: set[str] = set()

    for lead in (agenda.get("crit_leads") or [])[:max_agents]:
        subject = str(lead.get("subject") or "")
        key = _norm_key(subject)
        if not key or key in taken:
            continue
        taken.add(key)
        lead_extra = dict(lead.get("extra") or {})
        spawns.append({
            "role": "evidence",
            "family": str(lead.get("family") or ""),
            "why": f"unexplained {str(lead_extra.get('level') or '')} lead",
            "question": f"{question}\nInvestigate the lead: {subject}",
            "lead": subject,
            "lead_extra": lead_extra,
        })

    for text in agenda.get("questions") or []:
        if len(spawns) >= max_agents:
            break
        key = _norm_key(text)[:80]
        if not key or key in taken:
            continue
        taken.add(key)
        spawns.append({
            "role": "evidence",
            "family": "",
            "why": "open question from a seat",
            "question": f"{question}\nA seat asked: {text}",
        })

    for pivot in agenda.get("pivots") or []:
        if len(spawns) >= max_agents:
            break
        evalue = str(pivot.get("entity_value") or "")
        key = _norm_key(evalue)
        if not key or key in taken:
            continue
        taken.add(key)
        spawns.append({
            "role": "correlation" if superstep >= 2 else "evidence",
            "family": "",
            "why": f"pivot on {pivot.get('entity_type')} {evalue}",
            "question": (
                f"{question}\nPivot on {pivot.get('entity_type')} {evalue}: "
                f"check {pivot.get('why')}"
            ),
            # item 4: the pivot entity this seat is expected to consume.
            "pivot_entity": {
                "entity_type": str(pivot.get("entity_type") or ""),
                "entity_value": evalue,
            },
        })

    # Correlation/pattern only from superstep 2, on a non-empty board: they exist
    # to cross-examine what the evidence seats reported.
    if superstep >= 2 and board and len(spawns) < max_agents:
        have = {str(s.get("role") or "") for s in spawns}
        if "correlation" not in have:
            spawns.append({
                "role": "correlation", "family": "",
                "why": "cross-family corroboration on the board",
                "question": question,
            })
        if len(spawns) < max_agents and "pattern" not in have:
            spawns.append({
                "role": "pattern", "family": "",
                "why": "framework pattern matching on the board",
                "question": question,
            })

    # WO-R1F-M3 item 5: on the FIRST superstep, keep room for the present
    # domain families (memory when `vol` exists, event logs, file system, ...)
    # alongside the lead seats. The domains take at most half the seats; the
    # lead seats above always come first, so a strong crit lead is never
    # crowded out. Families already covered by a lead seat's own family are
    # not re-spawned as domains — that would duplicate work.
    if superstep == 1 and indexed:
        lead_families = {
            str(s.get("family") or "").lower().strip()
            for s in spawns if str(s.get("family") or "").strip()
        }
        domains = []
        for name, _rows in indexed:
            low = str(name or "").lower().strip()
            if not low:
                continue
            if low in lead_families:
                continue
            if low in {"correlation", "pattern"}:
                continue
            domains.append(low)
        # At most half the seats go to domains; the remaining seats stay with
        # the lead/question/pivot seats that came first.
        cap = max(1, max_agents // 2)
        # Free up room: pop the weakest tail seats (never the first lead seats)
        # until there are `cap` free slots, then fill them with domains.
        free = max(0, cap)
        while len(spawns) > (max_agents - free):
            spawns.pop()
            free = min(free, cap)  # one seat freed, one domain will fill it
        for added, domain in enumerate(domains):
            if added >= cap or len(spawns) >= max_agents:
                break
            spawns.append({
                "role": "evidence",
                "family": domain,
                "why": f"domain seat for the indexed {domain} family",
                "question": question,
            })
    return spawns[:max_agents]


def _unverified_claims(board: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Accepted claims on the board with no verifier verdict yet (item 7b).

    A verifier verdict names its subject as ``"<entity_type>=<entity_value>"``
    (the format the verifier prompt asks for); a claim whose entity value is
    already judged has been cross-examined and is not re-queued.
    """
    judged: set[str] = set()
    for entry in board:
        for verdict in entry.get("verdicts") or []:
            raw = str(verdict.get("subject") or verdict.get("title") or "")
            if "=" in raw:
                # "<etype>=<value>": the claim key's value half is what matters.
                judged.add(_norm_key(raw.split("=", 1)[1]))
            elif raw:
                judged.add(_norm_key(raw))
    out: list[dict[str, Any]] = []
    for entry in board:
        for claim in entry.get("claims") or []:
            key = _claim_key(claim)
            if not key:
                continue
            if key[1] in judged:
                continue
            out.append(claim)
    return out


def _verifier_spawn(
    claims: list[dict[str, Any]],
    *,
    question: str,
    superstep: int,
) -> dict[str, Any] | None:
    """The verifier seat for claims not yet cross-examined (item 7b).

    Reuses Mode 2's adversarial verifier role (`ROLES["verifier"]`).
    """
    if not claims:
        return None
    subjects = []
    for claim in claims[:12]:
        key = _claim_key(claim)
        if key:
            subjects.append(f"{key[0]}={key[1]}")
    return {
        "role": "verifier",
        "family": "",
        "why": f"verify {len(claims)} new claim(s) from superstep {superstep}",
        "question": (
            f"{question}\nRe-check these claims and classify each confirmed / "
            f"inferred / refuted: {', '.join(subjects) or '(see the board)'}"
        ),
    }


def run_mode3(
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
    run_id = run_id or f"M3-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}-{uuid4().hex[:6]}"
    from nexus.audit import AuditWriter

    # One writer per run (locked decision): seats share it, no seat builds one.
    run_audit = AuditWriter("nexus", audit_dir=case_dir / "audit")
    ready = elasticsearch_ready() if es_ok is None else bool(es_ok)
    from nexus.langgraph.lane_gate import coverage_snapshot

    # WO-R1F item 7b budgets: up to 6 seats per superstep (ceiling 10) and up to
    # 10 supersteps. `NEXUS_MODE3_MAX_AGENTS` counts SEATS, which is what it is
    # named for; the tool-call budget is a separate, real counter.
    max_agents = _env_int("NEXUS_MODE3_MAX_AGENTS", 6, low=2, high=10)
    max_steps = _env_int("NEXUS_MODE3_MAX_SUPERSTEPS", 10, low=1, high=20)
    max_calls = _env_int("NEXUS_MODE3_MAX_CALLS", 120, low=1, high=400)
    # The WO's wall-clock budget (default 4 h) is enforced by the caller's own
    # time budget; this records it so the run states what stopped it.
    wall_seconds = float(_env_int("NEXUS_MODE3_SECONDS", 14400, low=30, high=28800))

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
        # WO-R1F item 7b: the budgets the run actually used, named honestly —
        # seats (not "calls"), tool calls, supersteps and the wall-clock ceiling.
        "budgets": {
            "max_seats_per_superstep": max_agents,
            "max_supersteps": max_steps,
            "max_seats": max_calls,
            "wall_seconds": wall_seconds,
            "seats_used": 0,
            "tool_calls_used": 0,
        },
        "evidence_coverage": coverage_snapshot(case_dir),
        # WO-K8/WO-K7: the Mode 3 record carries the layer state and the absence
        # statement too (D30), so an ablation number can be read against what was
        # active and a zero-finding run can say what it observed.
        "layers": _layer_status_for_record(),
        "absence": _absence_for_record(case_dir),
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

    # WO-R1F item 7b budgets: up to 6 seats per superstep (ceiling 10) and up to
    # 10 supersteps. `NEXUS_MODE3_MAX_AGENTS` counts SEATS, which is what it is
    # named for; the tool-call budget is a separate, real counter.
    settle_k = _env_int("NEXUS_MODE3_SETTLE_SUPERSTEPS", 2, low=1, high=6)
    # settled whenever `superstep >= 1 and not disputes`, so a first superstep
    # whose seats happened not to collide ended the investigation at one round:
    # four evidence seats looked at four families, never cross-examined, and the
    # correlation and pattern seats never got a turn. The criterion rewarded
    # not colliding, which is backwards - an un-cross-examined board is the
    # strongest argument for another round, not for stopping.
    min_supersteps = _env_int("NEXUS_MODE3_MIN_SUPERSTEPS", 2, low=1, high=6)
    max_redispatch = _env_int("NEXUS_MODE3_MAX_REDISPATCH", 2, low=0, high=6)
    sink = _LockedSink(EventSink(case_dir, run_id, callback=on_event))
    # EventSink defaults to the multi-role directory. Keep this jsonl beside the Mode 3 record.
    sink.inner.path = _run_dir(case_dir) / f"{run_id}.jsonl"
    sink.inner.path.parent.mkdir(parents=True, exist_ok=True)

    # WO-4 (D40): build the signal map before the graph runs, so the coverage
    # audit can answer for the needles this run's claims were drawn from
    # instead of "unknown". Best-effort by design: a briefing failure must
    # not take the run down.
    try:
        from nexus.langgraph.briefing import case_briefing

        brief = case_briefing(case_dir)
        sink.emit(new_event(
            run_id, "briefing.ready", actor="system",
            detail=f"{brief.get('scanned_needles', 0)} needle(s) scanned",
            data={"signal_map": bool((brief.get("artifacts") or {}).get("signal_map_csv"))},
        ))
    except Exception as exc:  # noqa: BLE001
        sink.emit(new_event(
            run_id, "briefing.failed", actor="system", detail=str(exc)[:200],
        ))

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
            log.debug("mode3 index_mappings failed", exc_info=True)
            indexed = []

    # The counter is SEATS, and it is named so (WO-R1F item 7b): the old name
    # claimed to count tool calls while counting seats, so "120 calls" was a
    # budget nobody could reason about. `max_calls` is the seat budget; each
    # seat's own LoopBudget bounds its tool calls, and the seat reports the count
    # it actually used.
    seats_used = {"n": 0}
    tool_calls_used = {"n": 0}

    def _halted() -> str:
        flags = read_controls(case_dir, run_id)
        if flags["stop_requested"]:
            return "stopped"
        if flags["pause_requested"]:
            return "paused"
        return ""

    def supervisor(state: Mode3State) -> dict[str, Any]:
        halt = _halted()
        step = int(state.get("superstep") or 0) + 1
        if halt:
            return {"status": halt, "superstep": step, "spawns": []}
        if step > max_steps or seats_used["n"] >= max_calls:
            return {"status": "capped", "superstep": step, "spawns": []}
        steering = read_mode3_steering(case_dir, run_id)
        seen = int(state.get("steering_seen") or 0)
        fresh_steer = ""
        if len(steering) > seen:
            fresh_steer = str(steering[-1].get("text") or "")
            sink.emit(new_event(
                run_id, "supervisor.steer", actor="supervisor",
                detail=fresh_steer[:160],
                data={"lines": len(steering) - seen},
            ))
        disputes = state.get("disputes") or []
        used = int(state.get("redispatch_used") or 0)
        # WO-R1F item 7b: the supervisor RE-PLANS every superstep from the board —
        # seats' open questions, unexplained crit/high leads and digest items,
        # pivots on new entities, and disputes. The old shape spawned only on
        # `step == 1` (or fresh steering) and otherwise returned `settled`, so a
        # "2 superstep" run was one wave of <= 4 seats and a stop.
        board = state.get("board") or []
        agenda = _open_agenda(case_dir, board, state)
        # A returned agenda dict is never empty of keys, so `if agenda` was
        # always true and domain seats (item 5) preempted steering and the
        # model supervisor on a case with no open leads. Enter this path only
        # when something is actually open.
        has_agenda = bool(
            (agenda.get("questions") or [])
            or (agenda.get("crit_leads") or [])
            or (agenda.get("pivots") or [])
        )
        if has_agenda and step <= max_steps:
            # The verifier has to run on claims already on the board. Lead and
            # domain seats fill `max_agents` exactly, so appending afterwards
            # never happened and refuted claims stayed candidates (probe:
            # verifier seats=0). Hold one seat back when there is something
            # to cross-examine.
            unverified = _unverified_claims(board)
            seat_budget = max_agents - (1 if unverified else 0)
            spawns = _spawns_for_agenda(
                agenda, board, max_agents=max(1, seat_budget), question=question,
                superstep=step, indexed=indexed,
            )
            if spawns:
                # WO-R1F item 7b: a verifier seat runs each superstep on that
                # superstep's new claims, reusing Mode 2's adversarial verifier
                # role. Refuted claims are excluded (settled_candidates).
                verifier = _verifier_spawn(
                    unverified, question=question, superstep=step,
                )
                if verifier and len(spawns) < max_agents:
                    spawns.append(verifier)
                sink.emit(new_event(
                    run_id, "supervisor.replan", actor="supervisor",
                    detail=f"{len(spawns)} seat(s) from the open agenda",
                    data={
                        "open_questions": len(agenda.get("questions") or []),
                        "open_crit_leads": len(agenda.get("crit_leads") or []),
                        "pivots": len(agenda.get("pivots") or []),
                        "disputes": len(disputes),
                        "superstep": step,
                    },
                ))
                return {
                    "spawns": spawns, "superstep": step, "status": "running",
                    "steering_seen": len(steering),
                }
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
        if step == 1 or not state.get("board") or fresh_steer:
            focus = f"{question}\nExaminer steer: {fresh_steer}" if fresh_steer else question
            spawns: list[dict[str, Any]] = []
            if model is not None:
                spawns = _supervisor_with_model(
                    model,
                    case_dir=case_dir,
                    question=focus,
                    families=indexed,
                    board_digest=json.dumps(state.get("board") or [], default=str),
                    steering="\n".join(
                        f"- {str(line.get('text') or '')}" for line in steering[-3:]
                    ),
                    max_agents=max_agents,
                )
            supervisor_mode = "model" if spawns else "deterministic"
            if not spawns:
                spawns = plan_spawns(indexed, max_agents=max_agents, question=focus)
            sink.emit(new_event(
                run_id, "supervisor.spawn", actor="supervisor",
                detail=f"{len(spawns)} seats ({supervisor_mode})",
                data={"agents": [s["role"] for s in spawns],
                      "chosen_by": supervisor_mode},
            ))
            return {
                "spawns": spawns, "superstep": step, "status": "running",
                "steering_seen": len(steering),
            }
        return {"status": "settled", "superstep": step, "spawns": []}

    def fan(state: Mode3State) -> Any:
        from langgraph.types import Send

        status = str(state.get("status") or "")
        if status in {"stopped", "paused", "capped", "settled"}:
            return "join"
        board = state.get("board") or []
        digest = json.dumps(board, default=str)
        steering = read_mode3_steering(case_dir, run_id)
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
        if seats_used["n"] >= max_calls:
            return {"board": []}
        seats_used["n"] += 1
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
        # WO-R1F-M3 item 3: record which lead this seat was spawned for, so a
        # seat that returns no claims still disposes its lead (the disposition
        # is the fact that it was investigated, even when it found nothing).
        if spawn.get("lead"):
            entry["lead"] = str(spawn.get("lead") or "")
        with contextlib.suppress(TypeError, ValueError):
            tool_calls_used["n"] += int(entry.get("tool_calls_used") or 0)
        return {"board": [entry]}

    def join(state: Mode3State) -> dict[str, Any]:
        halt = _halted()
        if halt:
            return {"status": halt}
        board = list(state.get("board") or [])
        disputes = find_disputes(board)
        fp = _fingerprint(board)
        quiet = int(state.get("quiet") or 0)
        quiet = quiet + 1 if fp == list(state.get("last_fp") or []) else 0
        status = str(state.get("status") or "running")
        step_no = int(state.get("superstep") or 0)
        # WO-R1F item 7b's stop rule: stop when every crit/high lead and every
        # digest item has a disposition (a claim, refuted, or an explicit gap)
        # AND no open question remains — or when the budget ends. NEVER on "the
        # board was quiet", which is what made a 2-superstep run look complete.
        agenda = _open_agenda(case_dir, board, state)
        open_items = (
            len(agenda.get("questions") or [])
            + len(agenda.get("crit_leads") or [])
            + len(agenda.get("pivots") or [])
        )
        stop_rule = ""
        if status not in {"capped", "stopped", "paused"}:
            if step_no >= max_steps:
                status, stop_rule = "capped", "budget: max supersteps"
            elif not disputes and open_items == 0 and step_no >= min_supersteps:
                status, stop_rule = "settled", "every lead and question dispositioned"
            elif disputes and quiet >= settle_k:
                status, stop_rule = "settled", "disputes settled"
        if stop_rule:
            sink.emit(new_event(
                run_id, "join.stop_rule", actor="join", detail=stop_rule,
                data={"superstep": step_no, "open_items": open_items,
                      "disputes": len(disputes)},
            ))
        # Settling is a claim that the investigation is done, so record which
        # roles actually contributed. A run where only evidence seats ever ran has
        # not cross-examined anything, and saying so is the point.
        roles_used = sorted({
            str((e or {}).get("role") or "") for e in board if (e or {}).get("role")
        })
        if status == "settled" and len(set(roles_used) & set(_SEATS)) < len(_SEATS):
            missing = sorted(set(_SEATS) - set(roles_used))
            gaps = list(state.get("gaps") or [])
            note = (
                f"settled after {step_no} superstep(s) with no {', '.join(missing)} "
                f"seat - those roles never contributed"
            )
            if note not in gaps:
                gaps.append(note)
            sink.emit(new_event(
                run_id, "join.role_gap", actor="join", detail=note,
                data={"roles_used": roles_used, "missing": missing,
                      "superstep": step_no},
            ))
            return {"disputes": disputes, "quiet": quiet, "last_fp": fp,
                    "status": status, "gaps": gaps, "roles_used": roles_used}
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
        # WO-R1F-M3 item 4: record which pivots and open questions this
        # superstep's seats consumed, so the next superstep does not re-queue
        # them. The spawn dicts that ran are on `state["spawns"]`.
        consumed = [
            p for p in (state.get("consumed_pivots") or []) if isinstance(p, dict)
        ]
        seen_pivots = {
            (_norm_key(p.get("entity_type")), _norm_key(p.get("entity_value")))
            for p in consumed
        }
        for spawn in state.get("spawns") or []:
            pentity = spawn.get("pivot_entity")
            if isinstance(pentity, dict):
                key = (_norm_key(pentity.get("entity_type")),
                       _norm_key(pentity.get("entity_value")))
                if key not in seen_pivots:
                    consumed.append(dict(pentity))
                    seen_pivots.add(key)
        answered = list(state.get("answered_questions") or [])
        answered_seen = {_norm_key(q) for q in answered}
        for spawn in state.get("spawns") or []:
            question_text = str(spawn.get("question") or "")
            marker = "A seat asked: "
            if marker in question_text:
                qtext = question_text.split(marker, 1)[1].splitlines()[0].strip()
                key = _norm_key(qtext)[:80]
                if key and key not in answered_seen:
                    answered.append(qtext)
                    answered_seen.add(key)
        return {
            "disputes": disputes, "quiet": quiet, "last_fp": fp, "status": status,
            "consumed_pivots": consumed, "answered_questions": answered,
        }

    def after_join(state: Mode3State) -> str:
        status = str(state.get("status") or "")
        if status in {"settled", "stopped", "paused", "capped"}:
            return "synthesize"
        return "supervisor"

    def synthesize(state: Mode3State) -> dict[str, Any]:
        disputes = find_disputes(list(state.get("board") or []))
        candidates, _gaps = settled_candidates(
            list(state.get("board") or []), list(disputes), case_dir=case_dir,
        )
        sink.emit(new_event(
            run_id, "synthesis.candidates", actor="synthesis",
            detail=f"{len(candidates)} candidate(s)",
        ))
        return {}

    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(Mode3State)
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
    # A run where every seat came back empty because the model was unreachable has
    # not settled - it never ran. Mode 2 recorded that state as
    # "completed / converged", and Mode 3 settles on an empty board for the same
    # reason, so a dead model reads as a clean investigation in both.
    _board = list(final.get("board") or [])
    _seats = [e for e in _board if isinstance(e, dict)]
    # Keyed on the model's own finish reason, not on an empty claim list: a seat
    # that ran and found nothing is a real result, and failing it would be wrong.
    # A seat that never got an answer is not.
    _model_dead = bool(_seats) and all(
        str(e.get("finish_reason") or "") == "model_error" for e in _seats
    )
    _dead_model = _model_dead
    if _dead_model and status in ("settled", "completed"):
        status = "failed"
        stop_reason = (
            f"model unavailable: {len(_seats)} seat(s) returned no claims"
        )
        # Set `error` as well as `stop_reason`: a consumer reading only `error`
        # would otherwise see a failed run with no reason on it. Mode 2 sets both
        # and the two runtimes should not disagree about what a failure looks like.
        record["error"] = stop_reason
    elif status == "settled":
        status = "completed"
        stop_reason = "settled"
    elif status == "capped":
        status = "completed"
        stop_reason = (
            "budget: max supersteps"
            if int(final.get("superstep") or 0) >= max_steps
            else "budget: tool-call budget"
        )
    elif status == "stopped":
        stop_reason = "examiner_stop"
    elif status == "paused":
        stop_reason = "paused"
    else:
        stop_reason = status
    # Which documented procedures this run actually used, aggregated from what
    # each seat was given. Without this the run record cannot answer "did the
    # agent follow a method or improvise", and skill usage cannot be measured.
    used: list[dict[str, Any]] = []
    seen_skills: set[tuple[str, str]] = set()
    for entry in (final.get("board") or []):
        for ref in (entry.get("skill_refs") or []):
            if not isinstance(ref, dict):
                continue
            key = (str(ref.get("skill") or ""), str(ref.get("version") or ""))
            if not key[0] or key in seen_skills:
                continue
            seen_skills.add(key)
            used.append({
                "skill": key[0], "version": ref.get("version"),
                "role": ref.get("role"), "agent_id": entry.get("agent_id"),
                "citations": list(ref.get("citations") or [])[:6],
            })
    record["skills_used"] = used

    # WO-R1F-M3 item 3: aggregate the per-seat lead dispositions into the run
    # record. Every crit/high lead that got a hypothesis seat is here, with
    # the status the seat returned — so "the run record dispositions every
    # crit/high lead" is checkable from the record itself. The key is the
    # original lead subject (as it appears in leads.jsonl), matching the
    # probe's `l.get("subject") not in disp` check.
    lead_dispositions: dict[str, dict[str, Any]] = {}
    for entry in (final.get("board") or []):
        if not isinstance(entry, dict):
            continue
        disp = entry.get("lead_disposition")
        spawn_lead = str(entry.get("lead") or "").strip()
        if isinstance(disp, dict) and (disp.get("lead") or spawn_lead):
            subject = str(disp.get("lead") or spawn_lead).strip()
            if subject and subject not in lead_dispositions:
                lead_dispositions[subject] = {
                    "status": str(disp.get("status") or "insufficient"),
                    "basis": str(disp.get("basis") or "")[:400],
                    "agent_id": entry.get("agent_id"),
                    "lead": subject,
                }
        elif spawn_lead:
            # A lead seat ran and returned no explicit disposition: the honest
            # status is "insufficient" (investigated, nothing to report), which
            # is what the WO means by "insufficient becomes an explicit gap".
            if spawn_lead not in lead_dispositions:
                lead_dispositions[spawn_lead] = {
                    "status": "insufficient",
                    "basis": "lead seat returned no disposition",
                    "agent_id": entry.get("agent_id"),
                    "lead": spawn_lead,
                }
    record["lead_dispositions"] = lead_dispositions

    # 36c: the run record carries the configured model, so R2 knows which one
    # ran. Read from the same env the model was built from; a deterministic
    # (no-model) run records "none".
    record["model"] = _recorded_model()

    record.update({
        "status": status,
        "stop_reason": stop_reason,
        # Named here as well so the record always carries the key: a consumer
        # reading `error` on a failed Mode 3 run must find the reason, not None.
        "error": str(record.get("error") or (stop_reason if status == "failed" else "")),
        "board": list(final.get("board") or []),
        "disputes": list(final.get("disputes") or []),
        "superstep": int(final.get("superstep") or 0),
        # The counters the run actually reached (item 7b).
        "budgets": {
            **dict(record.get("budgets") or {}),
            "seats_used": int(seats_used["n"]),
            "tool_calls_used": int(tool_calls_used["n"]),
        },
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
    candidates, gaps = settled_candidates(
        list(record.get("board") or []), list(record.get("disputes") or []),
    )
    record["candidates"] = candidates
    record["gaps"] = gaps
    record["narrative"] = (
        f"{len(candidates)} settled claim(s); "
        f"{len(record.get('disputes') or [])} unresolved dispute(s)."
    )
    steering = read_mode3_steering(case_dir, run_id)
    if steering:
        record["steering"] = steering
    _persist(case_dir, run_id, record)
    return record


def resume_mode3(
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
    return run_mode3(
        case_dir,
        str(record.get("question") or ""),
        model=model,
        run_id=run_id,
        seat_fn=seat_fn,
        es_ok=es_ok,
        resume_state=record.get("resume_state") or {},
    )


def stage_mode3(case_dir: Path, run_id: str) -> dict[str, Any]:
    """Examiner action. Copies candidates onto a record shape stage_run_candidates reads."""
    record = read_run_record(case_dir, run_id)
    if record is None:
        return {"error": "run not found", "run_id": run_id, "staged": [], "skipped": []}
    from nexus.modes.multi_role import _MODE2_DIR

    bridge = Path(case_dir) / _MODE2_DIR
    bridge.mkdir(parents=True, exist_ok=True)
    path = bridge / f"{run_id}.json"
    rows = list(record.get("candidates") or [])
    provenance = [
        {"skill": u["skill"], "version": u.get("version"), "role": u.get("role")}
        for u in (record.get("skills_used") or [])
    ]
    if provenance:
        for cand in rows:
            if isinstance(cand, dict) and not cand.get("skill_provenance"):
                cand["skill_provenance"] = provenance
    payload = {
        "run_id": run_id,
        "product_mode": "multi-agent",
        "candidates": rows,
        "skills_used": record.get("skills_used") or [],
        "verdicts": [],
        "results": [],
    }
    path.write_text(json.dumps(payload, default=str), encoding="utf-8")
    result = stage_run_candidates(case_dir, run_id, candidates=record.get("candidates") or [])
    return result


# Re-export stop helper name used by the CLI. The Mode 3 sidecar is not used.
request_stop = request_stop_run
