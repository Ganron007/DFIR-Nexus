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
import re
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, TypedDict
from uuid import uuid4

from nexus.langgraph.case_index import elasticsearch_ready
from nexus.langgraph.model_json import loads_model_json
from nexus.langgraph.prompt_budget import budget_chars, case_window
from nexus.langgraph.subject import attach_subjects
from nexus.llm.egress import egress_bound
from nexus.modes.multi_role import QUESTION_ID_RE as _QUESTION_ID
from nexus.modes.multi_role import (
    QUESTION_STATUSES,
    EventSink,
    WorkOrder,
    _question_keywords,
    _retrieve_skill_refs,
    _skill_procedure_block,
    attack_method_block,
    new_event,
    question_id,
    stage_run_candidates,
)
from nexus.modes.multi_role import norm_key as _norm_key

log = logging.getLogger(__name__)

_DIR = "analysis/mode3_runs"
_CLAIM_KINDS = {"presence", "absence", "attribution", "time_order"}
_SEATS = ("evidence", "correlation", "pattern")
_SINK_LOCK = threading.Lock()


def _run_family_ledger(case_dir: Path, run_id: str) -> dict[str, Any]:
    """This run's family coverage ledger, or ``{}`` when it cannot be built.

    WO-1C item 7 (KR4): a run must account for every indexed family from its
    own execution records. Best-effort by design.
    """
    if not run_id:
        return {}
    try:
        from nexus.analysis.family_ledger import build_family_ledger

        return build_family_ledger(case_dir, run_id=run_id)
    except Exception:  # noqa: BLE001
        return {}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _recorded_model(model: Any = None) -> dict[str, str]:
    """The LLM this run actually called, for the run record.

    D48: this used to read the environment, so the record could name one model
    while the seats called another — 36c ran its three modes on two models and
    the records did not show it. The record is now derived from the object that
    ran: when a caller passes a model in, that object's own name is used;
    otherwise it is read from what `get_model` built.

    A run with no model records ``none`` — the deterministic path is a real
    path and must be distinguishable from "a model ran".
    """
    name = str(getattr(model, "model_name", "") or getattr(model, "model", "") or "").strip()
    if name:
        provider = (
            str(getattr(model, "provider", "") or "").strip().lower()
            or "openai-compatible"
        )
        return {"provider": provider, "model": name}
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
    if not isinstance(data, dict):
        return None
    from nexus.langgraph.pipeline_runs import effective_mode_run_record

    return effective_mode_run_record(case_dir, run_id, data)


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
    """The join key: the subject the claim's cited rows give, and the claim's kind.

    Operator decision 2026-10-12: the subject is the one attach_subjects derived from the rows the claim
    cites, not the seat's entity labels, which are wording. The kind is the model's closed claim vocabulary
    (presence, absence, attribution, time_order), which is a claim type, not an identity. A claim with no
    derived subject has no key, so the board does not compare it. A time_order claim joins on its pair of
    entities instead (D87): one subject is not an ordering.
    """
    kind = str(claim.get("claim_kind") or "")
    if kind not in _CLAIM_KINDS:
        return None
    if kind == "time_order":
        canonical = _time_order_canonical(claim)
        return ("pair", canonical[0], kind) if canonical else None
    subject = claim.get("subject") if isinstance(claim.get("subject"), dict) else {}
    etype = str(subject.get("type") or "").strip().lower()
    evalue = str(subject.get("value") or "").strip().lower()
    if not etype or not evalue:
        return None
    return (etype, evalue, kind)


def _verification_ref(claim: dict[str, Any]) -> str:
    """What a verifier verdict names this claim by: the subject its rows give, else its label.

    The join key is the row-derived subject (operator decision 2026-10-12), and a claim whose
    rows name no subject has none, so the verifier never saw it while it still became a
    candidate (D154; for example a claim on Amcache, WER or MemProcFS rows, D93). The model's
    entity label stands in for verification only, as it already does for a candidate's title
    when the rows name no subject. Disputes stay keyed on row subjects alone.
    """
    key = _claim_key(claim)
    if key:
        return key[1]
    return _norm_key(claim.get("entity_value"))


def _audit_ids(claim: dict[str, Any]) -> list[str]:
    raw = claim.get("audit_ids") or claim.get("audit_id") or []
    if isinstance(raw, str):
        raw = [raw]
    return [str(item).strip() for item in raw if str(item).strip()]


#: The directions a time_order claim may state: its subject happened before or after its other entity.
_TIME_ORDER_DIRECTIONS = frozenset({"before", "after"})


def _time_order_pair(claim: dict[str, Any]) -> tuple[tuple[str, str], tuple[str, str]] | None:
    """The two entities of a time_order claim, the subject first; None unless both are grounded and distinct.

    The subject is the one attach_subjects derived from the cited rows. The other entity is kept only when a
    cited row carries it (subject.ground_other_entity, D87).
    """
    subject = claim.get("subject") if isinstance(claim.get("subject"), dict) else {}
    other = claim.get("other_subject") if isinstance(claim.get("other_subject"), dict) else {}
    first = (str(subject.get("type") or "").strip().lower(), str(subject.get("value") or "").strip().lower())
    second = (str(other.get("type") or "").strip().lower(), str(other.get("value") or "").strip().lower())
    if not all(first) or not all(second) or first == second:
        return None
    return first, second


def _time_order_canonical(claim: dict[str, Any]) -> tuple[str, str] | None:
    """The pair key and the polarity of a time_order claim in the pair's sorted order (D87).

    The claim says its subject happened before its other entity ("before") or after it ("after"), and a deny
    reverses the statement. Two events have one order, so "B before A" is "A after B". The pair is sorted, and
    the polarity is that of "the sorted first entity happened before the sorted second". So two orderings of
    one pair conflict as a polarity conflict, as an affirmation and a denial of one ordering do.
    """
    pair = _time_order_pair(claim)
    direction = str(claim.get("value") or "").strip().lower()
    if pair is None or direction not in _TIME_ORDER_DIRECTIONS:
        return None
    subject, _other = pair
    before = direction == "before"
    if str(claim.get("polarity") or "affirm") == "deny":
        before = not before
    first, second = sorted(pair)
    first_before_second = before if subject == first else not before
    return f"{first[0]}:{first[1]}|{second[0]}:{second[1]}", "affirm" if first_before_second else "deny"


def _polarity_for_key(claim: dict[str, Any], default: str) -> str:
    """The polarity a claim is compared by: a time_order claim's canonical polarity, else its own."""
    if str(claim.get("claim_kind") or "") == "time_order":
        canonical = _time_order_canonical(claim)
        if canonical:
            return canonical[1]
    return str(claim.get("polarity") or default)


def accept_claim(claim: dict[str, Any]) -> str:
    """FD-001..007 on one board claim, and TO-1/TO-2 on a time_order claim. Empty string means keep."""
    if not _audit_ids(claim):
        return "FD-001: claim has no audit_id"
    if claim.get("unrecorded_events"):
        # D238: the claim says its rows are events the calls it cites did not return (attach_subjects).
        return ("EV-1: the claim names " + ", ".join(map(str, claim["unrecorded_events"]))
                + " but no call it cites returned that event")
    if claim.get("ungrounded_verdicts"):
        # D258: the claim credits a baseline check it does not cite, or with an answer the call did not give.
        return "TV-1: the claim credits " + "; ".join(map(str, claim["ungrounded_verdicts"]))
    if str(claim.get("claim_kind") or "") == "attribution":
        return "FD-003: agents do not attribute"
    if not str(claim.get("confidence_justification") or "").strip():
        return "FD-005: confidence has no justification"
    if str(claim.get("claim_kind") or "") == "time_order":
        if str(claim.get("value") or "").strip().lower() not in _TIME_ORDER_DIRECTIONS:
            return "TO-1: time_order names no direction (before or after)"
        if _time_order_pair(claim) is None:
            return "TO-2: time_order needs a second entity the cited rows contain, distinct from the subject"
    return ""


#: What the synthesis seat composes besides findings (IC-10): the case an examiner reads.
CASE_PARTS = ("timeline", "attack_chain", "entities", "open_questions")


def compose_case(
    case_dir: Path,
    run_id: str,
    question: str,
    settled: list[dict[str, Any]],
    disputes: list[dict[str, Any]],
    *,
    model: Any,
    sink: Any,
    not_answered: list[str] | None = None,
) -> dict[str, Any]:
    """The case Mode 3's settled board makes, composed by the synthesis seat Mode 2 uses (IC-10, D237).

    ``not_answered`` is what the seats said this evidence cannot answer (``_board_gaps``): the synthesis
    seat composes with it and writes no gaps of its own (D463); the record takes the seats' account.

    Mode 3 used to stage every settled claim and end on a count ("103 settled claim(s)"): run 4 staged 63
    DRAFTs, of which the examiner could approve none (18 absences, 10 inventories, 15 context, 5 duplicates).
    The settled claims are now the synthesis seat's material: it writes the narrative, the timeline, the
    attack chain, the entities and the open questions, and composes the findings, naming in `merges` the
    claims each is built from so their calls and tests follow (D225). An absence is never a finding: it
    stays on the record as what was looked for. No synthesis (no model, a failed or unparsed reply) means
    no finding; the settled claims stay on the record and the reason is a gap, never a fallback that
    stages them.
    """
    from nexus.modes.multi_role import (
        _backfill_audit_ids,
        _candidate_audit_ids,
        _carry_claim_tests,
        _pack,
        _zero_hit_citation,
        run_work_order,
    )

    absences = [c for c in settled if str(c.get("claim_kind") or "") == "absence"]
    claims = [{**c, "candidate_id": f"C{n}"}
              for n, c in enumerate((c for c in settled if str(c.get("claim_kind") or "") != "absence"), 1)]
    out: dict[str, Any] = {
        "findings": [], "narrative": "", "case": {}, "gaps": [],
        "absences": [{"title": str(c.get("title") or ""), "audit_ids": _candidate_audit_ids(c)}
                     for c in absences],
    }
    if not claims:
        out["gaps"].append("no settled claim to compose the case from")
        return out
    if model is None:
        out["gaps"].append("the case was not composed: no model for the synthesis seat; the settled claims are "
                           "on the record and none is staged")
        return out
    order = WorkOrder(
        order_id=WorkOrder.new_id(),
        role="synthesis",
        task=("Compose the case from the settled claims of the board: the narrative, the timeline, the attack "
              "chain, the entities, the open questions, and the findings each built from the claims it names "
              "in `merges`:\n" + _pack(json.dumps({
                  "question": question,
                  "claims": claims,
                  "absences": [a["title"] for a in out["absences"]],
                  "disputes": disputes,
                  "not_answered": list(not_answered or []),
              }, default=str), case_dir)),
        why="The case from the settled board (IC-10)",
        acceptance="narrative, timeline, attack chain, entities, open questions; findings with audit_ids",
    )
    result = run_work_order(order, case_dir=case_dir, model=model, run_id=run_id, sink=sink, context={})
    parsed = result.parsed or {}
    if result.status in {"failed", "error", "invalid", "unparsed", "fallback"} or not parsed:
        out["gaps"].append(f"the case was not composed: the synthesis seat {result.status or 'failed'}"
                           + (f" ({result.error[:160]})" if result.error else "")
                           + "; the settled claims are on the record and none is staged")
        return out
    if "narrative" not in parsed and "findings" not in parsed:
        # A reply off the synthesis contract (a seat's claims object, an answer envelope) composed nothing; read
        # as a synthesis it would be a case with no narrative and no finding that nobody had concluded.
        out["gaps"].append("the case was not composed: the synthesis seat answered off its contract (keys "
                           + ", ".join(sorted(str(k) for k in parsed)[:8])
                           + "); the settled claims are on the record and none is staged")
        return out
    finals = [f for f in parsed.get("findings") or [] if isinstance(f, dict)]
    _carry_claim_tests(finals, claims)
    _backfill_audit_ids(finals, claims)
    from nexus.langgraph.evidence_rows import subject_rows_for_audit_ids
    from nexus.langgraph.subject import derive_subject

    for final in finals:
        ids = _candidate_audit_ids(final)
        if ids and _zero_hit_citation(case_dir, ids):
            out["gaps"].append(f"composed finding not staged: {str(final.get('title') or '')[:160]} "
                               "(every call it cites returned 0 rows)")
            continue
        # The subject is the one its cited rows give, by the rule every mode uses (operator, 2026-10-12).
        subject = derive_subject(subject_rows_for_audit_ids(case_dir, ids)) if ids else {}  # D256
        if subject and not final.get("entity"):
            final["entity"], final["category"] = subject.get("entity"), subject.get("category")
        out["findings"].append(final)
    out["narrative"] = str(parsed.get("narrative") or "")
    out["case"] = {part: parsed.get(part) or [] for part in CASE_PARTS}
    sink.emit(new_event(run_id, "synthesis.composed", actor="synthesis",
                        detail=f"{len(out['findings'])} finding(s) from {len(claims)} settled claim(s); "
                               f"{len(absences)} absence(s) kept on the record"))
    return out


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
            ref = _verification_ref(claim)
            # WO-R1F-M3 item 2: a verifier-refuted claim is excluded and
            # recorded as negative space (the refutation is the result, not
            # an open finding).
            if ref and ref in refuted:
                if case_dir is not None:
                    with contextlib.suppress(Exception):
                        from nexus.analysis.negative_space import record
                        record(
                            case_dir, "refuted",
                            f"{ref} "
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
                            f"{key[1]} "
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
            verifier_basis = confirmed.get(ref) if ref else None
            if verifier_basis:
                justification = f"{justification}\nVerifier: {verifier_basis}"
            from nexus.analysis.titles import claim_title
            from nexus.langgraph.evidence_rows import subject_rows_for_audit_ids
            from nexus.langgraph.subject import derive_subject

            # Operator decision 2026-10-12: the subject is derived from the rows this claim cites,
            # by the rule every mode uses, all of them (D256). The model's entity labels are not the identity.
            audit_rows = (subject_rows_for_audit_ids(case_dir, _audit_ids(claim))
                          if case_dir is not None else [])
            subject = derive_subject(audit_rows)
            # The text names the subject the candidate carries, so its title and its identity cannot
            # disagree. The model's label is the fallback only when the rows name no subject.
            named = (subject["entity"].get("value") if subject["entity"] else "") or entity
            # D87: a time_order candidate carries its pair and its canonical polarity; cross-mode compares the pair.
            time_order: dict[str, Any] = {}
            if kind == "time_order" and key:
                canonical = _time_order_canonical(claim)
                if canonical:
                    time_order = {"claim_kind": kind, "subject_pair": canonical[0], "polarity": canonical[1]}
            candidates.append({
                "entity": subject["entity"],
                "category": subject["category"],
                # "evtxecmd: presence" is a dispute key rendered as English. The
                # claim carries a value and a justification, and either is a
                # sentence an examiner can read, so one of them leads the title.
                "title": claim_title(named, kind, value=value,
                                     justification=justification),
                "observation": value or f"{kind} recorded for {named}",
                "interpretation": justification,
                "confidence": str(claim.get("confidence") or "LOW"),
                "confidence_justification": justification,
                # D227: the seat's rating; staging keeps one of LOW..CRITICAL and leaves the rest empty.
                "severity": str(claim.get("severity") or "").strip().upper(),
                "audit_ids": _audit_ids(claim),
                "agent_id": entry.get("agent_id"),
                "claim_kind": kind,
                **time_order,
            })
    return candidates, gaps


def find_disputes(board: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The subject and kind that one claim affirms and another denies.

    Differing wording is not a dispute. A time_order claim is compared on its pair of entities and its canonical
    polarity (D87), so two orderings of one pair conflict, as do an affirmation and a denial of one ordering.
    """
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for entry in board:
        for claim in entry.get("claims") or []:
            if not isinstance(claim, dict) or accept_claim(claim):
                continue
            key = _claim_key(claim)
            if key is None:
                continue
            grouped.setdefault(key, []).append({
                "polarity": _polarity_for_key(claim, "affirm"),
                "value": str(claim.get("value") or ""),
                "agent_id": str(entry.get("agent_id") or ""),
                "role": str(entry.get("role") or ""),
                "family": str(entry.get("family") or ""),
                "audit_ids": _audit_ids(claim),
            })
    disputes: list[dict[str, Any]] = []
    for key, rows in grouped.items():
        polarities = {row["polarity"] for row in rows}
        # Operator decision 2026-10-12: a dispute is a polarity conflict. Differing wording is not one.
        if len(polarities) > 1:
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
                # Operator decision 2026-10-12: convergence ignores wording, so the fingerprint is key and polarity.
                rows.append("|".join(key) + "|" + _polarity_for_key(claim, ""))
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
    prior_context: str = "",
) -> list[dict[str, Any]]:
    """MA4.2 — the model chooses the team; [] on any doubt (caller falls back).

    ``prior_context`` is what an ``informed`` run adds (WO-1C item 3): the case's prior report and
    DRAFTs, labelled as not evidence. Mode 3 recorded the policy and never applied it, so an
    informed run planned exactly as an independent one.
    """
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
        from nexus.langgraph.case_digest import lead_citation

        leads = build_leads(case_dir, write=False)
        if leads:
            lead_lines = "\n".join(
                f"- [{lead.kind}] {lead.subject}: {lead.detail[:160]}"
                f"{lead_citation(lead.to_dict())}"
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
                "(maps established activity to ATT&CK; ITM for an insider intake). Reply with ONE JSON object only: "
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
                + (f"{prior_context}\n\n" if prior_context else "")
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
        parsed = loads_model_json(raw[start:end + 1])
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
        parsed = loads_model_json(text[start:end + 1])
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
        parsed = loads_model_json(text[start:end + 1])
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
    # D208: what this evidence cannot answer, and the open questions the seat settled.
    raw_gaps = parsed.get("coverage_gaps")
    if isinstance(raw_gaps, list):
        out["coverage_gaps"] = [" ".join(str(item).split()) for item in raw_gaps if str(item).strip()]
    raw_qd = parsed.get("question_dispositions")
    if isinstance(raw_qd, list):
        out["question_dispositions"] = [
            {
                "question": str(d.get("question") or "").strip(),
                "status": str(d.get("status") or "").strip().lower(),
                "basis": " ".join(str(d.get("basis") or "").split())[:400],
                "audit_ids": [str(a) for a in (d.get("audit_ids") or []) if str(a)],
            }
            for d in raw_qd if isinstance(d, dict)
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
    prior_context: str = "",
) -> dict[str, Any]:
    """One seat's turn. ``prior_context`` is what an ``informed`` run adds, labelled as not evidence."""
    from nexus.langgraph.context_loop import LoopBudget, _call_model, run_context_loop
    from nexus.modes.multi_role import _investigative_extras, role_for

    role_name = str(spawn.get("role") or "evidence")
    # The verifier seat runs as the verifier. It was looked up among the claim seats only, so every
    # verifier call of Mode 3 run 2 (128 on 2026-10-15) went out as an evidence agent (D231).
    seat_kind = role_name if role_name in (*_SEATS, "verifier") else "evidence"
    role = role_for(seat_kind)
    family = str(spawn.get("family") or "")
    objective = str(spawn.get("question") or "")
    # Announce the seat before it works. The board only holds seats that have
    # *reported*, so without this an examiner watching a run cannot tell one
    # agent grinding from three - and the interaction timeline has no start.
    seat_agent_id = f"{seat_kind}:{family or 'unknown'}:{superstep}"
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
    seat_order = WorkOrder(
        order_id="seat",
        role=seat_kind,
        task=objective or "investigate",
        family=family,
        skill_refs=skill_refs,
        # IC-5: ATT&CK's method for the lead's techniques and the hunt list of the software it detected.
        techniques=tuple(techniques),
        software=tuple(str(s.get("id")) for s in (lead_extra.get("software") or [])
                       if isinstance(s, dict) and s.get("id")),
    )
    skill_block = _skill_procedure_block(seat_order, case_dir) + attack_method_block(seat_order, case_dir)
    # WO-R1F-M3 item 2: the verifier seat returns `verdicts`, not `claims`.
    # Use the right terminal key, or the loop never recognises the reply and
    # the verdicts are lost (the original defect in this seat path).
    is_verifier = role_name == "verifier"
    # A seat that settles a question or its lead without a new claim has still returned its object.
    terminal_keys = ("verdicts",) if is_verifier else (
        ("claims", "question_dispositions") + (("lead_disposition",) if spawn.get("lead") else ()))
    if is_verifier:
        question = (
            f"You are the {role_name} seat. Examiner objective: {objective}\n"
            f"{skill_block}\n"
            f"Board so far:\n{board_digest}\n\n"
            + (f"{prior_context}\n\n" if prior_context else "")
            + _investigative_extras(case_dir)
            + 'Return JSON {"verdicts":[{"subject":"<entity_type>=<entity_value>",'
            '"class":"confirmed|inferred|refuted","basis":"one clause",'
            '"audit_ids":["..."]}]}. '
            "A refuted verdict must name the counter-evidence (audit_ids required). "
            # D238: run 4's verifier confirmed lsass.exe on "30 Sysmon EventID-10" events its calls never returned.
            "A confirmed verdict's basis names only events (a log and event id) its audit_ids returned. "
            "Do not attribute an actor."
        )
    else:
        # Built as a list of parts, joined once. The prompt used to be one `+` chain with the
        # lead clause as `+ (clause) if lead else "" + tail`; a conditional expression binds
        # weaker than `+`, so every seat without a lead received only the tail sentence: no
        # objective, family, board or claims schema (D128, from f09d9d4).
        # The seat's output contract is said once and only here (D231): the system message is the
        # role's brief, with no return format of its own, and the corrective retry below points
        # back at this contract instead of restating a smaller one that had no dispositions.
        contract = [
            'Return JSON {"claims":[{"entity_type":"...","entity_value":"...",'
            '"claim_kind":"presence|absence|attribution|time_order","polarity":"affirm|deny",'
            '"value":"...","other_entity_type":"...","other_entity_value":"...",'
            '"audit_ids":["..."],"confidence":"LOW|MEDIUM|HIGH",'
            '"confidence_justification":"...","severity":"LOW|MEDIUM|HIGH|CRITICAL"}],"open_questions":["..."]}. ',
            # D227: a claim is rated as Mode 1's and Mode 2's are; a claim left unrated stages unrated.
            'severity is how much the claim matters to the investigation if it holds; leave it out when you '
            'cannot rate it. ',
            'A time_order claim sets value to "before" or "after" (the entity happened before or after the '
            'other_entity) and names that other entity, which the cited rows must contain. ',
            # D238: run 4 described 30 Security 4688 rows as "30 Sysmon 10 events", and other seats repeated it.
            'An event the value names (a log and event id, such as Security 4688) is one a call in its '
            'audit_ids returned; to state an event another seat found, cite that seat\'s audit_ids. A claim '
            'that names an event its calls did not return is refused. ',
            # D208: an open question is work for another seat, so it is only one this case's evidence can
            # answer; seats used to list what no seat could ever answer (a live host, other hosts,
            # artifacts never collected) and repeat questions already open, and the run could not settle.
            'An open question is one this case\'s indexed evidence can answer and that is not already open on '
            'the board; what this evidence cannot answer (another host, a live system, an artifact not '
            'collected or not parsed) goes in "coverage_gaps":["..."]. For an open question on the board that '
            'your work settles, return "question_dispositions":[{"question":"<its id>","status":"'
            'answered|unanswerable|duplicate","basis":"one clause","audit_ids":["..."]}]: answered cites the '
            'calls that answer it, duplicate names in basis the question it repeats. A question already '
            'on the board is settled through "question_dispositions", never raised again in '
            '"open_questions". ',
        ]
        spawned_for = _spawned_question_ids(spawn)
        if spawned_for:
            contract.append(
                f'You were spawned for open question{"s" if len(spawned_for) > 1 else ""} '
                f'{", ".join(spawned_for)}: return a disposition for each in "question_dispositions". '
            )
        if spawn.get("lead"):
            contract.append(
                'When investigating a lead, also return '
                '"lead_disposition":{"lead":"<subject>","status":"'
                'supported|refuted|benign|insufficient","basis":"one clause"}. '
            )
        contract.append("Every claim needs an audit_id from a tool call. Do not attribute an actor.")
        question = "".join([
            f"You are the {role_name} seat. Examiner objective: {objective}\n",
            f"Family: {family or '(cross-family)'}. Why you were spawned: {spawn.get('why') or ''}\n",
            f"{skill_block}\n",
            f"Board so far:\n{board_digest}\n\n",
            # D235: an informed run's prior analysis reaches every seat; it went to the model
            # supervisor only, which the agenda path bypasses whenever a lead is open.
            f"{prior_context}\n\n" if prior_context else "",
            _investigative_extras(case_dir),
            *contract,
        ])
    rounds = _env_int("NEXUS_MODE3_ROUNDS", 24, low=1, high=80)
    calls = _env_int("NEXUS_MODE3_CALLS", 48, low=1, high=200)
    seconds = float(_env_int("NEXUS_MODE3_SECONDS", 1800, low=30, high=7200))
    loop = run_context_loop(
        case_dir=case_dir,
        case_id=case_dir.name,
        question=question,
        model=model,
        system_prompt=role.brief or role.system_prompt,
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
        and not fields_parsed.get("question_dispositions")
        and reply_text.strip()
        and not _has_claims_key(reply_text)
        and str(loop.get("finish_reason") or "") not in ("model_error", "empty_model")
    ):
        try:
            corrected = _call_model(
                model,
                [
                    {"role": "system", "content": role.brief or role.system_prompt},
                    {
                        "role": "user",
                        "content": (
                            question
                            + "\n\nYour previous reply was not the JSON object asked for above. "
                            "Return ONLY that object, with every key that applies to your work "
                            '("claims", "open_questions", "question_dispositions", "coverage_gaps"'
                            + (', "lead_disposition"' if spawn.get("lead") else "")
                            + '). If nothing is supportable, return {"claims": []} with the '
                            "other keys that apply."
                        ),
                    },
                ],
            )
            if corrected.strip():
                entry["claims"] = _parse_claims(corrected)
                # The corrected reply is the seat's answer: its fields are read below. Its lead
                # disposition used to be set here and then replaced by the first reply's (none).
                fields_parsed = _parse_seat_fields(corrected)
                entry["corrective_retry_used"] = True
                # Kept beside the first reply's excerpt, which is recorded below; it used to be
                # written here and then overwritten by the first reply (D231).
                entry["corrected_excerpt"] = " ".join(str(corrected).split())[:600]
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
    fields = fields_parsed
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
    entry["coverage_gaps"] = fields.get("coverage_gaps", [])
    entry["question_dispositions"] = fields.get("question_dispositions", [])
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
    if entry["finish_reason"] == "model_error":
        # What the provider said, so a paused run names its cause (D209).
        entry["model_error"] = next(
            (str(s.get("detail") or "") for s in loop.get("stages") or []
             if isinstance(s, dict) and s.get("status") == "error"), "")
    # WO-R2F item 2: whether this seat actually read evidence rows. A seat that
    # CALLED an evidence tool and got nothing back (refused, failed or zero-hit)
    # is blind and must not disposition a lead, and the run must not settle on
    # a board of such seats (reviewer probe checks 5 and 6).
    #
    # A seat that never called an evidence tool is NOT blind: it worked from
    # the briefing and its own knowledge, and its lead dispositions are its
    # honest work. Blocking those too dropped every crit/high lead from the run
    # record and failed the mode3 probe's "the run record dispositions every
    # crit/high lead" check.
    entry["evidence_read"] = bool(loop.get("evidence_read"))
    entry["evidence_attempted"] = bool(loop.get("evidence_attempted"))
    if entry["evidence_attempted"] and not entry["evidence_read"]:
        entry["blocked"] = "no evidence call returned rows"
    # The seat's REAL tool-call count, from its own loop (item 7b's "add a real
    # tool-call budget"). Summed at the run level; without it the run cannot say
    # how much work it did or what the budget stopped.
    try:
        entry["tool_calls_used"] = len(loop.get("tool_calls") or [])
    except (TypeError, ValueError):
        entry["tool_calls_used"] = 0
    # WO-1C item 7 (KR4 / D58): this seat's executed evidence queries go to the
    # family ledger from the tool calls that ran, so the run's coverage is what
    # executed — a planned query that never ran is never credited.
    from nexus.modes.multi_role import _record_order_family_queries

    _record_order_family_queries(
        case_dir, run_id, list(loop.get("tool_calls") or []),
    )
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
    # What join and synthesize report to the run record (D129, D138). LangGraph drops any key
    # a node returns that is not declared here.
    gaps: list[str]
    roles_used: list[str]
    settle_blockers: list[str]
    family_ledger: dict[str, Any]
    candidates: list[dict[str, Any]]
    candidate_gaps: list[str]
    # IC-10: the settled claims the case was composed from, and the composed case.
    settled: list[dict[str, Any]]
    narrative: str
    case: dict[str, Any]
    absences: list[dict[str, Any]]
    # Why join paused the run when the model stopped answering (D209).
    pause_reason: str


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

    A question or pivot a seat has settled is not re-queued (WO-R1F-M3 item 4), and what settled it
    is read from the board itself (D208), so a resumed run knows it too: a question closes with a
    seat's disposition (answered, unanswerable, duplicate) or a seat spawned for it; a pivot closes
    with a seat spawned for it or a later superstep's seat working on the entity.
    """
    questions = [
        {"id": qid, "text": item["text"]}
        for qid, item in _question_ledger(board).items() if item["status"] == "open"
    ]

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

    return {
        "questions": questions,
        "crit_leads": crit_leads,
        "pivots": _pivot_entities(board),
    }


def _ground_confirmed_verdicts(entry: dict[str, Any], case_dir: Path | None, *, run_id: str, sink: Any) -> None:
    """A verifier seat's confirmation whose basis names an event its cited calls did not return is
    downgraded to unverifiable, so it adds no "Verifier:" basis to a candidate (D238)."""
    from nexus.langgraph.named_events import downgrade_ungrounded_confirmations

    for verdict in downgrade_ungrounded_confirmations(entry.get("verdicts") or [], case_dir):
        sink.emit(new_event(
            run_id, "verify.downgraded", actor="verifier", agent_id=str(entry.get("agent_id") or ""),
            detail=str(verdict.get("subject") or verdict.get("title") or "")[:160],
            data={"audit_ids": verdict.get("audit_ids") or [], "from": "confirmed"},
        ))


def _seat_settles(entry: Mapping[str, Any]) -> bool:
    """Whether a seat's work can settle what it was spawned for.

    Not a seat the model never answered (D209), and not a blind seat, one that called an evidence
    tool and read nothing (WO-R2F item 2).
    """
    if str(entry.get("finish_reason") or "") == "model_error":
        return False
    return not (entry.get("evidence_attempted") and not entry.get("evidence_read", True))


def _question_ledger(board: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Every open question raised on the board, by id, with how it was settled (D208).

    Settling needed a seat spawned with the question's exact wording, and nothing else closed it:
    Mode 3 run 1 (2026-10-15) raised 95 questions, a seat for at most five each superstep, and
    ended with 73 open, so the run could only stop at its budget. A question now closes with a
    seat's disposition, answered (citing calls), unanswerable from this evidence or a duplicate,
    or with a seat spawned for it that answered.
    """
    ledger: dict[str, dict[str, Any]] = {}
    for entry in board:
        if not isinstance(entry, dict):
            continue
        for raw in entry.get("open_questions") or []:
            text = " ".join(str(raw).split())
            # The board lists its questions by id, and seats name them by it. One that names a
            # question already on the board restates it: 23 of the 79 raised in Mode 3 run 2
            # ("Q8ce78f remains open: ...") each opened a new question, and the run could not
            # settle (D222).
            named = {"Q" + found[1:].lower() for found in _QUESTION_ID.findall(text)}
            if named & ledger.keys():
                continue
            qid = question_id(text)
            if text and qid not in ledger:
                ledger[qid] = {"text": text, "status": "open", "raised_by": str(entry.get("agent_id") or "")}
    for entry in board:
        if not isinstance(entry, dict) or not _seat_settles(entry):
            continue
        agent = str(entry.get("agent_id") or "")
        for disp in entry.get("question_dispositions") or []:
            if not isinstance(disp, dict):
                continue
            status = str(disp.get("status") or "").lower()
            if status not in QUESTION_STATUSES or (status == "answered" and not disp.get("audit_ids")):
                continue
            named = str(disp.get("question") or "")
            match = _QUESTION_ID.search(named)
            qid = ("Q" + match.group(0)[1:].lower()) if match else question_id(named)
            item = ledger.get(qid)
            if item is not None and item["status"] == "open":
                item.update(status=status, basis=str(disp.get("basis") or ""),
                            audit_ids=list(disp.get("audit_ids") or []), settled_by=agent)
        for qid in _spawned_question_ids(entry):
            item = ledger.get(qid)
            if item is not None and item["status"] == "open":
                item.update(status="investigated", basis="the seat spawned for it returned no disposition",
                            settled_by=agent)
    return ledger


def _spawned_question_ids(item: Mapping[str, Any]) -> list[str]:
    """The open questions a seat was spawned to settle; a board written before D222 names one."""
    ids = [str(q) for q in item.get("question_ids") or [] if str(q)]
    return ids or ([str(item["question_id"])] if item.get("question_id") else [])


#: Entity types worth a follow-up seat when first seen (item 7b (c)).
_PIVOT_ENTITIES = {
    "process": "its parent, persistence and network activity",
    "address": "the processes that connected and what they transferred",
    "registry": "what wrote it and what it launches",
    "file": "what wrote it and what it runs",
    "account": "how the account was used and from where",
}


def _pivot_entities(board: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Entities raised on the board that no later seat picked up.

    Picked up: a seat was spawned to pivot on the entity, or a seat of a later superstep, which read
    the board, worked on it. The set of picked-up entities used to be built and then discarded, so
    every entity ever claimed stayed a pivot (24 at the end of Mode 3 run 1, none seated after
    superstep 2) and the run could not settle (D208).
    """
    def step_of(entry: Mapping[str, Any]) -> int:
        try:
            return int(entry.get("superstep") or 0)
        except (TypeError, ValueError):
            return 0

    def entities(entry: Mapping[str, Any]) -> list[tuple[str, str]]:
        keys = [_claim_key(claim) for claim in entry.get("claims") or [] if isinstance(claim, dict)]
        return [(_norm_key(k[0]), _norm_key(k[1])) for k in keys if k and k[0] in _PIVOT_ENTITIES]

    consumed: set[tuple[str, str]] = set()
    first: dict[tuple[str, str], int] = {}
    for entry in board:
        if not isinstance(entry, dict):
            continue
        pivot = entry.get("pivot_entity")
        if isinstance(pivot, dict) and _seat_settles(entry):
            consumed.add((_norm_key(pivot.get("entity_type")), _norm_key(pivot.get("entity_value"))))
        for look in entities(entry):
            first[look] = min(first.get(look, step_of(entry)), step_of(entry))
    picked_up = {
        look for entry in board if isinstance(entry, dict)
        for look in entities(entry) if step_of(entry) > first[look]
    }
    return [
        {"entity_type": etype, "entity_value": evalue, "why": _PIVOT_ENTITIES[etype]}
        for (etype, evalue) in first
        if (etype, evalue) not in picked_up and (etype, evalue) not in consumed
    ]


def _board_gaps(board: list[dict[str, Any]]) -> list[str]:
    """What the seats said this evidence cannot answer (D208), for the run record's gaps.

    A seat's coverage gaps, an open question settled as unanswerable here, and one a seat spawned
    for it investigated without an answer.
    """
    gaps: list[str] = []
    for entry in board:
        if isinstance(entry, dict) and _seat_settles(entry):
            gaps += [f"coverage gap ({entry.get('agent_id') or 'seat'}): {gap}"
                     for gap in entry.get("coverage_gaps") or [] if str(gap).strip()]
    for qid, item in _question_ledger(board).items():
        if item["status"] == "unanswerable":
            gaps.append(f"open question {qid} not answerable from this evidence: {item['text']}"
                        + (f" ({item['basis']})" if item.get("basis") else ""))
        elif item["status"] == "investigated":
            gaps.append(f"open question {qid} investigated without an answer: {item['text']}")
    return gaps


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
            # The lead the seat was spawned for, when it has one. The model's echo of it carries
            # what the seat was shown, "<subject> [audit_id X]" since leads became citable, so a
            # disposition keyed by the echo never matched its lead, which was spawned again every
            # superstep (D198).
            dlead = str(entry.get("lead") or disp.get("lead") or "").strip()
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

    from nexus.langgraph.case_digest import lead_citation

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
            # The lead's own call: the seat can cite the rows that raised it.
            "question": f"{question}\nInvestigate the lead: {subject}{lead_citation(lead)}",
            "lead": subject,
            "lead_extra": lead_extra,
        })

    questions: list[dict[str, str]] = []
    for item in agenda.get("questions") or []:
        text = str(item.get("text") if isinstance(item, dict) else item or "")
        key = _norm_key(text)[:80]
        if not key or key in taken:
            continue
        taken.add(key)
        qid = str(item.get("id") or "") if isinstance(item, dict) else ""
        questions.append({"id": qid or question_id(text), "text": text})

    def pivot_seat(pivot: dict[str, Any]) -> dict[str, Any] | None:
        evalue = str(pivot.get("entity_value") or "")
        key = _norm_key(evalue)
        if not key or key in taken:
            return None
        taken.add(key)
        return {
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
        }

    # Open questions and pivots take turns for seats (D208), and the question seats share out every
    # open question (D222). A seat used to be spawned for one question while any seat can raise
    # several: Mode 3 run 3 (2026-10-15) seated three a superstep and stopped at its cap with 17 open,
    # down from 26 but level for the last five supersteps.
    queued_pivots = [p for p in agenda.get("pivots") or [] if isinstance(p, dict)]
    question_seats: list[dict[str, Any]] = []
    turn = 0
    while len(spawns) < max_agents and (len(question_seats) < len(questions) or queued_pivots):
        if turn % 2 == 0 and len(question_seats) < len(questions):
            seat_spec: dict[str, Any] | None = {"role": "evidence", "family": "",
                                               "why": "open questions from seats"}
            question_seats.append(seat_spec)
        else:
            seat_spec = pivot_seat(queued_pivots.pop(0)) if queued_pivots else None
        if seat_spec:
            spawns.append(seat_spec)
        turn += 1
    for n, seat_spec in enumerate(question_seats):
        share = questions[n::len(question_seats)]
        seat_spec["question_ids"] = [q["id"] for q in share]
        seat_spec["question"] = (f"{question}\nSeats asked these open questions; settle each one:\n"
                                 + "\n".join(f"- {q['id']}: {q['text']}" for q in share))

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
        domains = [
            low for low in _domain_order(indexed)
            if low not in lead_families and low not in {"correlation", "pattern"}
        ]
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


#: The evidence classes a first-superstep domain seat covers before the host families, memory first
#: (the design: "memory when `vol` exists, event logs, file system").
_DOMAIN_CLASSES = ("memory", "email", "network", "cloud", "siem", "linux", "disk_timeline")


def _domain_order(indexed: list[Any]) -> list[str]:
    """The families a first-superstep domain seat takes, in order (D204).

    One family for each evidence class present other than host, memory first, each the class's
    largest family; then the host families, largest first. The seats used to take the first
    families in name order: CASE-C5B04D31's Mode 3 run of 2026-10-15 spent three of six seats on
    amcache, appcompat and bits while the memory image went unread.
    """
    from nexus.langgraph.case_digest import _classify

    rows: dict[str, int] = {}
    for item in indexed or []:
        name, count = (item if isinstance(item, (list, tuple)) else (item, 0))[:2]
        low = str(name or "").lower().strip()
        if low:
            rows[low] = max(rows.get(low, 0), int(count or 0))
    classes = _classify(list(rows))
    ordered: list[str] = []
    for cls in _DOMAIN_CLASSES:
        members = sorted(classes.get(cls) or [], key=lambda f: (-rows.get(f, 0), f))
        if members:
            ordered.append(members[0])
    ordered += sorted((f for f in rows if f not in ordered), key=lambda f: (-rows[f], f))
    return ordered


def board_view(board: list[dict[str, Any]], limit: int = 0, whole_from: int = 0) -> str:
    """What a seat and the supervisor read of the board (D206).

    Every claim on one line, with the verifier's class, the calls it cites and the seat that made
    it; then the lead dispositions and the open questions. A claim from superstep ``whole_from`` on
    carries its value whole; an earlier one is a compact line without it (operator decision
    2026-10-15: earlier results travel compact), and a seat that needs the detail reads the cited
    rows. The board used to be sent as its JSON, every entry whole with its 600-character reply
    excerpt and skill references, to every seat on every round: 58 M of Mode 3 run 1's 130.7 M
    characters. With ``limit``, whole lines are kept and the rest counted, never a line cut.
    """
    verdicts: dict[str, str] = {}
    for entry in board:
        for verdict in entry.get("verdicts") or []:
            if isinstance(verdict, dict) and verdict.get("subject"):
                verdicts[_norm_key(verdict["subject"])] = str(verdict.get("class") or "")
    lines: list[str] = []
    for entry in board:
        if not isinstance(entry, dict):
            continue
        author = str(entry.get("agent_id") or entry.get("role") or "seat")
        try:
            whole = int(entry.get("superstep") or 0) >= whole_from
        except (TypeError, ValueError):
            whole = True
        for claim in entry.get("claims") or []:
            if not isinstance(claim, dict):
                continue
            subject = f"{claim.get('entity_type')}={claim.get('entity_value')}"
            line = f"- {subject} | {claim.get('claim_kind')}/{claim.get('polarity')}"
            if whole:
                line += f" | {' '.join(str(claim.get('value') or '').split())}"
            if claim.get("other_entity_value"):
                line += f" | {claim.get('other_entity_type')}={claim.get('other_entity_value')}"
            if verdicts.get(_norm_key(subject)):
                line += f" | verifier: {verdicts[_norm_key(subject)]}"
            if claim.get("audit_ids"):
                line += f" | cites {', '.join(str(a) for a in claim['audit_ids'])}"
            lines.append(line + f" | {author}")
        disp = entry.get("lead_disposition")
        if isinstance(disp, dict) and (entry.get("lead") or disp.get("lead")):
            lines.append(f"- lead {entry.get('lead') or disp.get('lead')}: {disp.get('status')} "
                         f"- {' '.join(str(disp.get('basis') or '').split())}")
    # Each question with its id, so a seat can settle it (D208); a settled one says how, so it is not
    # raised again.
    for qid, item in _question_ledger(board).items():
        if item["status"] == "open":
            lines.append(f"- open question {qid}: {item['text']}")
        else:
            lines.append(f"- question {qid} {item['status']}: {item['text']}")
    if not lines:
        return "(empty)"
    if limit > 0:
        kept: list[str] = []
        used = 0
        for line in lines:
            if used + len(line) + 1 > limit:
                break
            kept.append(line)
            used += len(line) + 1
        if len(kept) < len(lines):
            kept.append(f"({len(lines) - len(kept)} more line(s) on the board, not shown)")
        lines = kept
    return "\n".join(lines)


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
            ref = _verification_ref(claim)
            if not ref or ref in judged:
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
        ref = _verification_ref(claim)
        if not ref:
            continue
        # Named the way the verdict will name it back: the row subject, else the label (D154).
        etype = key[0] if key else (_norm_key(claim.get("entity_type")) or "entity")
        subjects.append(f"{etype}={ref}")
    return {
        "role": "verifier",
        "family": "",
        "why": f"verify {len(claims)} new claim(s) from superstep {superstep}",
        "question": (
            f"{question}\nRe-check these claims and classify each confirmed / "
            f"inferred / refuted: {', '.join(subjects) or '(see the board)'}"
        ),
    }


@egress_bound
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
    context_policy: str = "independent",
) -> dict[str, Any]:
    """Run one concurrent investigation. Returns the run record. Never stages.

    ``context_policy`` (WO-1C item 3) is recorded on the run record:
    ``independent`` (default) sees evidence only; ``informed`` may read the
    case's prior reports and DRAFT findings as labelled examiner context.
    """
    case_dir = Path(case_dir)
    run_id = run_id or f"M3-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}-{uuid4().hex[:6]}"
    from nexus.analysis.context_policy import normalize_policy
    from nexus.audit import AuditWriter
    from nexus.langgraph.pipeline_runs import (
        configured_model,
        mode_run_recovery_exists,
    )

    if mode_run_recovery_exists(case_dir, run_id):
        existing = read_run_record(case_dir, run_id)
        if existing is not None and existing.get("status") == "interrupted":
            return existing
        return {
            "run_id": run_id,
            "case_id": case_dir.name,
            "status": "failed",
            "stop_reason": "invalid_recovery_event",
            "error": "recovery marker exists but does not match this run record",
        }
    existing = read_run_record(case_dir, run_id)
    if existing is not None and resume_state is None:
        return {
            **existing,
            "error": "run id already exists; resume a paused run or start a new run id",
        }

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
        # WO-1C items 2/3: the model actually called and the context policy
        # this run used, so a report can say what produced a verdict and how
        # much prior context it saw.
        "model": configured_model(),
        "context_policy": normalize_policy(context_policy),
    }
    if resume_state is not None:
        existing = read_run_record(case_dir, run_id)
        if existing is not None and str(existing.get("status") or "") in {
            "completed", "failed", "stopped", "interrupted",
        }:
            return existing
        if existing is not None:
            record.update(existing)
            record["status"] = "running"
            record["stop_reason"] = ""
            record.pop("resume_state", None)
            record.pop("completed_at", None)
    # Dashboard runs execute in worker threads inside a long-lived server;
    # recording only its PID cannot expose a worker that exited unexpectedly.
    record["process_pid"] = os.getpid()
    record["process_thread_id"] = threading.get_native_id()
    # What an informed run adds, read once for every seat (D235): the case's report and pending DRAFTs,
    # labelled as not evidence. Empty for an independent run.
    from nexus.analysis.context_policy import context_sections

    prior_context = "\n\n".join(
        text for _pri, _name, text in context_sections(case_dir, str(record.get("context_policy") or "")))
    if not ready:
        record["status"] = "failed"
        record["stop_reason"] = "elasticsearch_required"
        _persist(case_dir, run_id, record)
        return record
    if model is None and seat_fn is None:
        # A Mode 3 run is an LLM run. With no model it used to spawn deterministic seats that
        # investigated nothing and still ended completed / settled (D132).
        record["status"] = "failed"
        record["stop_reason"] = "no model configured"
        record["error"] = record["stop_reason"]
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
                case_dir=case_dir,
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
        agenda = _open_agenda(case_dir, board)
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
                    board_digest=board_view(state.get("board") or [], whole_from=step - 1),
                    steering="\n".join(
                        f"- {str(line.get('text') or '')}" for line in steering[-3:]
                    ),
                    max_agents=max_agents,
                    prior_context=prior_context,
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
        # The last superstep's claims whole, earlier ones compact (D206).
        digest = board_view(board, whole_from=int(state.get("superstep") or 1) - 1)
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
                superstep=step, audit=run_audit, prior_context=prior_context,
            )
        else:
            entry = _fallback_entry(spawn, step)
            sink.emit(new_event(
                run_id, "board.entry", actor="agent", agent_id=entry["agent_id"],
                detail="deterministic seat",
            ))
        # Operator decision 2026-10-12: every seat's claims enter the board here (the model seat, an injected
        # seat and the deterministic seat alike), so each claim's subject is attached from the rows it cites,
        # never from the seat's entity labels (see _claim_key). The rows are read before the claim is
        # accepted: a claim that names an event its calls did not return is refused (D238).
        claims = [claim for claim in entry.get("claims") or [] if isinstance(claim, dict)]
        attach_subjects(claims, case_dir)
        kept = []
        refused = []
        for claim in claims:
            reason = accept_claim(claim)
            if reason:
                refused.append({"entity": str(claim.get("entity_value") or "")[:200],
                                "value": str(claim.get("value") or "")[:300],
                                "reason": reason, "audit_ids": _audit_ids(claim)})
            else:
                kept.append(claim)
        entry["claims"] = kept
        if refused:
            # Kept on the board's entry, so the run record says what the seat claimed and why it was refused.
            entry["refused_claims"] = refused
            for item in refused:
                sink.emit(new_event(
                    run_id, "claim.refused", actor="agent", agent_id=str(entry.get("agent_id") or ""),
                    detail=f"{item['reason']} | {item['value'][:160]}", data={"audit_ids": item["audit_ids"]},
                ))
        _ground_confirmed_verdicts(entry, case_dir, run_id=run_id, sink=sink)
        # WO-R1F-M3 item 3: record which lead this seat was spawned for, so a
        # seat that returns no claims still disposes its lead (the disposition
        # is the fact that it was investigated, even when it found nothing).
        if spawn.get("lead"):
            entry["lead"] = str(spawn.get("lead") or "")
        # D208: the question or pivot this seat was spawned to settle, so the board alone says what
        # is still open, in a resumed run as well.
        if _spawned_question_ids(spawn):
            entry["question_ids"] = _spawned_question_ids(spawn)
        if isinstance(spawn.get("pivot_entity"), dict):
            entry["pivot_entity"] = dict(spawn["pivot_entity"])
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
        agenda = _open_agenda(case_dir, board)
        open_items = (
            len(agenda.get("questions") or [])
            + len(agenda.get("crit_leads") or [])
            + len(agenda.get("pivots") or [])
        )
        stop_rule = ""
        pause_reason = ""
        # D209: a superstep in which no seat got an answer from the model means the model is gone.
        # On 2026-10-15 the provider answered "no left credit" from superstep 7, the run spent three
        # more supersteps on nothing and recorded "completed". It pauses instead, keeping what the
        # earlier supersteps found, and resumes when the model is back.
        step_seats = [e for e in board
                      if isinstance(e, dict) and str(e.get("superstep") or "") == str(step_no)]
        if (status not in {"stopped", "paused"} and step_seats
                and all(str(e.get("finish_reason") or "") == "model_error" for e in step_seats)):
            cause = next((str(e.get("model_error") or "") for e in step_seats if e.get("model_error")), "")
            pause_reason = (f"model unavailable from superstep {step_no}"
                            + (f": {cause}" if cause else "") + "; resume when it answers again")
            status, stop_rule = "paused", pause_reason
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
        # WO-1C item 7 (KR4): "settled" claims the evidence was examined. An
        # indexed, populated artifact family this run never successfully
        # queried is an unexamined artifact — record it as a gap on the record
        # rather than letting the run read as a full examination.
        # What join learns goes back to the graph in its return value, under keys Mode3State
        # declares. LangGraph keeps neither undeclared keys nor changes made to the input
        # state, so the blockers and gaps written onto `state` never reached the run record
        # (D129).
        settle_blockers: list[str] = []
        family_ledger: dict[str, Any] = {}
        run_gaps = list(state.get("gaps") or [])
        if status == "settled":
            with contextlib.suppress(Exception):
                from nexus.analysis.family_ledger import (
                    build_family_ledger,
                )
                from nexus.analysis.family_ledger import (
                    settle_blockers as _blockers,
                )

                settle_blockers = list(_blockers(
                    build_family_ledger(case_dir, run_id=run_id)))
                family_ledger = _run_family_ledger(case_dir, run_id)
            if settle_blockers:
                for b in settle_blockers:
                    note = f"unexamined artifact family (run-level): {b}"
                    if note not in run_gaps:
                        run_gaps.append(note)
                sink.emit(new_event(
                    run_id, "join.settle_blocked", actor="join",
                    detail=f"{len(settle_blockers)} unexamined artifact family(ies)",
                    data={"blockers": settle_blockers},
                ))
        # Settling is a claim that the investigation is done, so record which
        # roles actually contributed. A run where only evidence seats ever ran has
        # not cross-examined anything, and saying so is the point.
        roles_used = sorted({
            str((e or {}).get("role") or "") for e in board if (e or {}).get("role")
        })
        settled_keys: dict[str, Any] = {
            "gaps": run_gaps, "roles_used": roles_used,
            "settle_blockers": settle_blockers, "family_ledger": family_ledger,
        } if status == "settled" else {}
        if status == "settled" and len(set(roles_used) & set(_SEATS)) < len(_SEATS):
            missing = sorted(set(_SEATS) - set(roles_used))
            note = (
                f"settled after {step_no} superstep(s) with no {', '.join(missing)} "
                f"seat - those roles never contributed"
            )
            if note not in run_gaps:
                run_gaps.append(note)
            sink.emit(new_event(
                run_id, "join.role_gap", actor="join", detail=note,
                data={"roles_used": roles_used, "missing": missing,
                      "superstep": step_no},
            ))
            return {"disputes": disputes, "quiet": quiet, "last_fp": fp,
                    "status": status, **settled_keys}
        # The open items behind the decision (D208): a run that keeps going says what keeps it open.
        sink.emit(new_event(
            run_id, "join.decision", actor="join",
            detail=status,
            data={"disputes": len(disputes), "quiet": quiet, "open_items": open_items,
                  "open_questions": len(agenda.get("questions") or []),
                  "open_crit_leads": len(agenda.get("crit_leads") or []),
                  "pivots": len(agenda.get("pivots") or []), "superstep": step_no},
        ))
        for dispute in disputes:
            sink.emit(new_event(
                run_id, "dispute.opened", actor="join",
                detail=f"{dispute['entity_value']} {dispute['claim_kind']}",
            ))
        # The pivots and questions the seats settled are read from the board (D208); join used to
        # keep them in state from the spawns, whatever the seat returned, and a resume lost them.
        return {
            "disputes": disputes, "quiet": quiet, "last_fp": fp, "status": status,
            **({"pause_reason": pause_reason} if pause_reason else {}),
            # Which roles worked is part of every record, not only a settled one: Mode 3 run 2
            # stopped at its superstep budget and recorded none of its 60 seats' roles (D231).
            "roles_used": roles_used,
            **settled_keys,
        }

    def after_join(state: Mode3State) -> str:
        status = str(state.get("status") or "")
        if status in {"settled", "stopped", "paused", "capped"}:
            return "synthesize"
        return "supervisor"

    def synthesize(state: Mode3State) -> dict[str, Any]:
        # The one place candidates are built, with the case, so each carries the subject its
        # cited rows give (D138). The record used to rebuild them without the case and lose it.
        disputes = find_disputes(list(state.get("board") or []))
        candidates, candidate_gaps = settled_candidates(
            list(state.get("board") or []), list(disputes), case_dir=case_dir,
        )
        sink.emit(new_event(
            run_id, "synthesis.candidates", actor="synthesis",
            detail=f"{len(candidates)} candidate(s)",
        ))
        composed = compose_case(case_dir, run_id, question, candidates, list(disputes), model=model, sink=sink,
                                not_answered=_board_gaps(list(state.get("board") or [])))
        return {"candidates": composed["findings"], "settled": candidates,
                "candidate_gaps": candidate_gaps + composed["gaps"], "narrative": composed["narrative"],
                "case": composed["case"], "absences": composed["absences"]}

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
        restored = list(resume_state.get("board") or [])
        # A run saved before the join keyed on subjects holds claims with no subject. They get the subject
        # their rows give here, as they would have at their seat, so a resumed run compares them like the rest.
        attach_subjects(
            [claim for entry in restored if isinstance(entry, dict)
             for claim in entry.get("claims") or []
             if isinstance(claim, dict) and "subject" not in claim],
            case_dir,
        )
        seed.update({
            "board": restored,
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
    # WO-R2F item 2: a seat that CALLED an evidence tool and got nothing back
    # (refused, failed or zero-hit) is blocked. A seat that never called one is
    # not blind - it worked from its briefing. See ``evidence_attempted``.
    _blocked_seats = [
        e for e in _seats
        if e.get("evidence_attempted")
        and not e.get("evidence_read", True)
        and str(e.get("finish_reason") or "")
    ]
    _no_evidence_read = bool(_seats) and len(_blocked_seats) == len(_seats)
    _dead_model = _model_dead
    # A model that never answered: join pauses the run at the first superstep (D209), and a capped
    # run never settles, so both end here as failed; a model that died after answering pauses.
    if _dead_model and status in ("settled", "completed", "capped", "paused"):
        status = "failed"
        stop_reason = (
            f"model unavailable: {len(_seats)} seat(s) returned no claims"
        )
        # Set `error` as well as `stop_reason`: a consumer reading only `error`
        # would otherwise see a failed run with no reason on it. Mode 2 sets both
        # and the two runtimes should not disagree about what a failure looks like.
        record["error"] = stop_reason
    elif _no_evidence_read and status in ("settled", "completed", "capped"):
        # WO-R2F item 2: a run in which no seat read a single evidence row has
        # not investigated anything, whatever the graph's stop rule says. In 36c
        # every seat call was refused, the run hit the superstep budget, and the
        # record read `completed / budget: max supersteps`.
        status = "failed"
        stop_reason = (
            f"no evidence read: {len(_seats)} seat(s) ran and none returned "
            f"rows ({len(_blocked_seats)} blocked by a refused or empty evidence call)"
        )
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
        stop_reason = str(final.get("pause_reason") or "paused")
        if final.get("pause_reason"):
            record["error"] = stop_reason
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
    blocked_leads: list[str] = []
    for entry in (final.get("board") or []):
        if not isinstance(entry, dict):
            continue
        disp = entry.get("lead_disposition")
        spawn_lead = str(entry.get("lead") or "").strip()
        # WO-R2F item 2: a seat that CALLED an evidence tool and read nothing
        # dispositions nothing. Its leads stay open, and the run record says
        # which seats were blocked — in 36c eleven crit/high leads were
        # dispositioned "insufficient" by a seat whose every es_search had been
        # refused. A seat that never called an evidence tool is not blind: its
        # disposition is its honest work from the briefing.
        seat_blocked = bool(entry.get("evidence_attempted")) and not bool(
            entry.get("evidence_read", True)
        )
        if seat_blocked and spawn_lead and spawn_lead not in blocked_leads:
            blocked_leads.append(spawn_lead)
        if seat_blocked:
            continue
        if isinstance(disp, dict) and (disp.get("lead") or spawn_lead):
            # The spawn's lead first, as in `_dispositioned_keys` (D198).
            subject = str(spawn_lead or disp.get("lead") or "").strip()
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
    record["blocked_leads"] = blocked_leads
    # D208: how each open question was settled, and what was still open when the run stopped, so a
    # run that ends at its budget says what kept it open.
    ledger = _question_ledger(_board)
    record["question_dispositions"] = {qid: item for qid, item in ledger.items() if item["status"] != "open"}
    end_agenda = _open_agenda(case_dir, _board)
    record["open_agenda"] = {
        "questions": list(end_agenda.get("questions") or []),
        "crit_leads": [str(lead.get("subject") or "") for lead in end_agenda.get("crit_leads") or []],
        "pivots": list(end_agenda.get("pivots") or []),
    }

    # 36c: the run record carries the model that ran, so R2 knows which one
    # produced the findings. Derived from the object the seats called (D48), so
    # the record cannot disagree with the run; a deterministic (no-model) run
    # records "none".
    record["model"] = _recorded_model(model)

    record.update({
        "status": status,
        "stop_reason": stop_reason,
        # Named here as well so the record always carries the key: a consumer
        # reading `error` on a failed Mode 3 run must find the reason, not None.
        "error": str(record.get("error") or (stop_reason if status == "failed" else "")),
        "board": list(final.get("board") or []),
        "disputes": list(final.get("disputes") or []),
        "superstep": int(final.get("superstep") or 0),
        # WO-1C item 7 (KR4): the run's own family coverage and any unexamined
        # indexed family, from execution records only.
        "settle_blockers": list(final.get("settle_blockers") or []),
        "roles_used": list(final.get("roles_used") or []),
        "family_ledger": _run_family_ledger(case_dir, run_id),
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
    # The candidates synthesize built with the case (D138). A graph that ended before
    # synthesize has none, and they are built here the same way.
    if "candidates" in final:
        candidates = list(final.get("candidates") or [])
        candidate_gaps = list(final.get("candidate_gaps") or [])
        settled = list(final.get("settled") or [])
    else:
        # The graph ended before synthesis (paused or stopped): the settled claims go on the record, and
        # nothing is composed or staged from them (IC-10).
        candidates = []
        settled, candidate_gaps = settled_candidates(
            list(record.get("board") or []), list(record.get("disputes") or []),
            case_dir=case_dir,
        )
        candidate_gaps = [*candidate_gaps, "the run ended before synthesis: the case was not composed"]
    record["candidates"] = candidates
    record["settled_claims"] = settled
    record["case"] = dict(final.get("case") or {})
    record["absences"] = list(final.get("absences") or [])
    # The run's own gaps (unexamined families, roles that never contributed) and the
    # candidates' gaps are both kept; the second used to overwrite the first (D129).
    merged_gaps: list[str] = []
    for gap in [*(final.get("gaps") or []), *_board_gaps(_board), *candidate_gaps]:
        if gap and gap not in merged_gaps:
            merged_gaps.append(str(gap))
    record["gaps"] = merged_gaps
    # IC-10: the narrative is the synthesis seat's; the counts are the summary, never the narrative.
    record["narrative"] = str(final.get("narrative") or "")
    record["summary"] = (
        f"{len(settled)} settled claim(s), {len(candidates)} composed finding(s); "
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
    context_policy: str | None = None,
) -> dict[str, Any]:
    """Continue a paused run from its persisted board/superstep snapshot."""
    record = read_run_record(case_dir, run_id)
    if record is None:
        return {"error": "run not found", "run_id": run_id}
    status = str(record.get("status") or "")
    if status in {"stopped", "completed", "failed", "interrupted"}:
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
        context_policy=str(
            context_policy if context_policy is not None
            else (record.get("context_policy") or "independent")
        ),
    )


def stage_mode3(case_dir: Path, run_id: str) -> dict[str, Any]:
    """Examiner action. Stages the run's candidates through the shared staging path.

    The record is handed to ``stage_run_candidates`` in memory. It used to be copied into
    ``analysis/mode2_runs`` for that function to read, and every reader of that directory then
    took the Mode 3 run for a Mode 2 one: the cross-mode check counted run 4's 103 candidates
    as Mode 2 claims (D243).
    """
    record = read_run_record(case_dir, run_id)
    if record is None:
        return {"error": "run not found", "run_id": run_id, "staged": [], "skipped": []}
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
    return stage_run_candidates(case_dir, run_id, candidates=rows, record=payload)


# Re-export stop helper name used by the CLI. The Mode 3 sidecar is not used.
request_stop = request_stop_run
