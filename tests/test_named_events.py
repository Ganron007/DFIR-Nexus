"""D238: an event a claim names must be one a call it cites returned.

Mode 3 run 4 (CASE-C5B04D31, 2026-10-16) staged "30 Sysmon 10 events showing processes opening handles to
lsass.exe" on 30 Security 4688 rows of lsass.exe starting at boot; the case has no Sysmon log. The rows named
the subject, so every check passed, and the verifier confirmed the claim on the same rows. The texts and rows
below are those of the run, cut to what the check reads.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from _audit_rows import cite_rows

from nexus.langgraph.evidence_rows import cited_calls
from nexus.langgraph.named_events import (
    downgrade_ungrounded_confirmations,
    event_grounding,
    named_events,
)
from nexus.langgraph.subject import attach_subjects
from nexus.modes.multi_agent import accept_claim, run_mode3, settled_candidates

#: The claim and the verifier's basis as run 4 wrote them.
CLAIM = "30 Sysmon 10 events showing processes opening handles to lsass.exe with read-access masks on rd01"
LABEL = "LSASS.exe memory access (Sysmon EID 10)"
BASIS = ("30 Sysmon EventID-10 process-access events showing handles opened to lsass.exe with read-access "
         "masks on rd01")


def _lsass_start(line: int) -> dict[str, Any]:
    """A Hayabusa row of Security 4688, lsass.exe starting (hayabusa/evtx-timeline.csv:62445 and on)."""
    return {
        "time": "2022-08-31T17:39:21Z", "source": "hayabusa/hayabusa/evtx-timeline.csv",
        "loc": f"hayabusa/evtx-timeline.csv:{line}", "event_id": "4688",
        "provider": "Microsoft-Windows-Security-Auditing", "channel": "Security",
        "process": "C:\\Windows\\System32\\lsass.exe",
        "detail": "RuleTitle: Proc Exec · Details: Cmdline: ¦ Proc: C:\\Windows\\System32\\lsass.exe",
        "fields": {"Channel": "Sec", "EventID": "4688", "RuleTitle": "Proc Exec"},
    }


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-EVENTS"
    (case / "analysis").mkdir(parents=True)
    return case


def _claim(audit_id: str, *, value: str = CLAIM, polarity: str = "affirm", label: str = LABEL) -> dict[str, Any]:
    return {"entity_type": "process_access", "entity_value": label, "claim_kind": "presence",
            "polarity": polarity, "value": value, "audit_ids": [audit_id], "confidence": "HIGH",
            "confidence_justification": "30 distinct rows returned by the LSASS-access query"}


# ── what a text names ────────────────────────────────────────────────────────


def test_the_forms_a_claim_names_an_event_in():
    assert named_events(CLAIM) == [("sysmon", "10")]
    assert named_events(LABEL) == [("sysmon", "10")]
    assert named_events(BASIS) == [("sysmon", "10")]
    assert named_events("Sysmon-10 LSASS-access events") == [("sysmon", "10")]
    assert named_events("Security 4688 rows show lsass.exe") == [("security", "4688")]
    assert named_events("Task Scheduler events (EID 129 create, EID 200 execute)") == [("", "129"), ("", "200")]
    assert named_events("EventID 4624/4625 logons") == [("", "4624"), ("", "4625")]


def test_attacks_own_eventcode_form_names_an_event():
    """IC-14: ATT&CK's analytics write `EventCode=4698`; the method block now carries them to the seats."""
    assert named_events("WinEventLog:Security EventCode=4698 (Scheduled Job Creation)") == [("security", "4698")]
    assert named_events("Event Code 4624 logons") == [("", "4624")]


def test_whether_a_case_holds_an_event_is_asked_strictly(monkeypatch):
    """IC-14: a row naming no provider proves nothing about a named source when the question is whether the
    case holds the event at all (a provider-less event 10 made "Sysmon 10" read as present)."""
    from nexus.langgraph import named_events as ne

    lenient = ne.event_filter(("sysmon", "10"))["bool"]["filter"][1]["bool"]["should"]
    strict = ne.event_filter(("sysmon", "10"), strict=True)["bool"]["filter"][1]["bool"]["should"]
    assert len(lenient) == 3 and len(strict) == 2
    counts = {("sysmon", "10"): 0, ("", "4624"): 40}
    monkeypatch.setattr(ne, "_index_event_count", lambda _case, event: counts.get(event))
    assert ne.events_in_case("CASE-X", "LSASS access detected in Sysmon Event ID 10") is False
    assert ne.events_in_case("CASE-X", "logons, Event ID 4624") is True
    assert ne.events_in_case("CASE-X", "Known credential tools in Prefetch") is None


def test_an_absence_a_date_or_a_record_number_names_no_event():
    assert named_events("no Sysmon 10 events were logged on rd01") == []
    assert named_events("0 Sysmon 10 events") == []
    assert named_events("events 2023-01-25 14:56 to 15:07") == []
    assert named_events("Security record sequence 12965 to 12968; System 947 to 958") == []
    assert named_events("tdungan used wacsvc credentials (4648) to reach cifs/dev01") == []
    # Absences and conjectures from the informed run's board (M3-20261016T015542-599862).
    assert named_events("Searches for service-start (EID 7036), service-control (EID 7035) in the window "
                        "returned zero hits across evtxecmd") == []
    assert named_events("Zero EID-140 events are indexed; targeted searches for EID-140 returned no rows.") == []
    assert named_events("The trigger XML would have appeared in EID-140 details") == []
    assert named_events("No 7045 (service install) or Sysmon EID 7 (image load) event correlates") == []
    # A count after an id is not a second id.
    assert named_events("Defender alerts (hayabusa, EID 1116, 10 events)") == [("", "1116")]
    # The sentence that follows an absence is read on its own: run 4's claim restated the false events.
    assert named_events("No 4656 or 4663 events are indexed. The only handle events are 30 Sysmon EID-10 "
                        "process-access rows (board-confirmed).") == [("sysmon", "10")]


# ── what the cited calls returned ────────────────────────────────────────────


def test_rows_a_complete_call_returned_decide_the_event(tmp_path):
    case = _case(tmp_path)
    starts = cite_rows(case, [_lsass_start(62445), _lsass_start(62820)], total=2)
    calls = cited_calls(case, [starts])
    assert event_grounding(CLAIM, calls)["unrecorded"] == ["sysmon 10"]
    assert event_grounding("Security 4688 rows of lsass.exe", calls)["recorded"] == ["security 4688"]
    # Hayabusa's own abbreviation names the same log.
    assert event_grounding("Sec event 4688", calls)["recorded"] == ["sec 4688"]


def test_a_call_that_kept_fewer_rows_than_it_returned_is_asked_again(tmp_path):
    case = _case(tmp_path)
    query = {"wildcard": {"text.wc": {"value": "*lsass*"}}}
    starts = cite_rows(case, [_lsass_start(62445)], total=30, query=query)
    calls = cited_calls(case, [starts])
    asked: list[tuple[Any, Any]] = []

    def none_found(q, event):
        asked.append((q, event))
        return 0

    assert event_grounding(CLAIM, calls, replay=none_found)["unrecorded"] == ["sysmon 10"]
    assert asked == [(query, ("sysmon", "10"))]
    assert event_grounding(CLAIM, calls, replay=lambda q, e: 3)["recorded"] == ["sysmon 10"]
    # A call that cannot be run again leaves the event unknown: never unrecorded on a guess.
    assert event_grounding(CLAIM, calls, replay=lambda q, e: None)["unknown"] == ["sysmon 10"]
    assert event_grounding(CLAIM, calls)["unknown"] == ["sysmon 10"]


def test_a_row_that_names_no_source_cannot_contradict_one(tmp_path):
    case = _case(tmp_path)
    row = {"loc": "evtxecmd.csv:7", "event_id": "4648", "detail": "explicit credential logon"}
    calls = cited_calls(case, [cite_rows(case, [row], total=1)])
    assert event_grounding("Security 4648 events", calls)["recorded"] == ["security 4648"]


# ── Mode 3: the board ────────────────────────────────────────────────────────


def test_a_claim_naming_an_event_its_calls_did_not_return_is_refused(tmp_path):
    case = _case(tmp_path)
    starts = cite_rows(case, [_lsass_start(62445), _lsass_start(62820)], total=2)
    wrong = _claim(starts)
    right = _claim(starts, value="Security 4688 rows of lsass.exe starting", label="lsass.exe process start")
    absent = _claim(starts, value="Sysmon 10 process access to lsass.exe", polarity="deny")
    attach_subjects([wrong, right, absent], case)
    assert accept_claim(wrong).startswith("EV-1: the claim names sysmon 10")
    assert wrong["subject"]["value"] == "c:\\windows\\system32\\lsass.exe"  # the subject is right; the event is not
    assert accept_claim(right) == ""
    assert accept_claim(absent) == ""  # an absence names what is not there


def test_the_seat_path_keeps_the_refused_claim_on_the_record_and_stages_nothing_from_it(tmp_path):
    case = _case(tmp_path)
    starts = cite_rows(case, [_lsass_start(62445), _lsass_start(62820)], total=2)

    def seat(spawn, _board, step):
        role = spawn["role"]
        return {"entry_id": f"{role}-{step}", "agent_id": f"{role}-{step}", "role": role,
                "family": spawn.get("family") or "", "superstep": step,
                "claims": [_claim(starts)] if role == "evidence" else [], "open_questions": []}

    record = run_mode3(case, "Compromise suspected.", families=[("hayabusa", 2)], seat_fn=seat, es_ok=True)
    refused = [item for entry in record["board"] for item in entry.get("refused_claims") or []]
    assert refused and refused[0]["reason"].startswith("EV-1"), record["board"]
    assert refused[0]["audit_ids"] == [starts]
    assert not [c for entry in record["board"] for c in entry.get("claims") or []]
    candidates, _gaps = settled_candidates(record["board"], [], case_dir=case)
    assert candidates == []


def test_a_confirmation_whose_basis_names_an_event_its_calls_did_not_return_confirms_nothing(tmp_path):
    case = _case(tmp_path)
    starts = cite_rows(case, [_lsass_start(62445)], total=1)
    run4 = {"subject": "process=c:\\windows\\system32\\lsass.exe", "class": "confirmed", "basis": BASIS,
            "audit_ids": [starts]}
    grounded = {"subject": "process=c:\\windows\\system32\\lsass.exe", "class": "confirmed",
                "basis": "Security 4688 rows show lsass.exe starting under wininit.exe", "audit_ids": [starts]}
    changed = downgrade_ungrounded_confirmations([run4, grounded], case)
    assert changed == [run4]
    assert run4["class"] == "unverifiable" and run4["downgraded_from"] == "confirmed"
    assert "sysmon 10" in run4["basis"]
    assert grounded["class"] == "confirmed"


# ── L1.11: every mode's staged finding ───────────────────────────────────────


def _finding(audit_id: str, observation: str) -> dict[str, Any]:
    return {"id": "F-test-001", "title": f"c:\\windows\\system32\\lsass.exe - present: {observation}",
            "observation": observation, "audit_ids": [audit_id], "status": "DRAFT",
            "evidence": [_lsass_start(62445)]}


def test_l1_11_fails_the_run_4_finding_and_passes_one_that_names_its_rows(tmp_path):
    from nexus.analysis.claim_verification import verify_claim

    case = _case(tmp_path)
    starts = cite_rows(case, [_lsass_start(62445), _lsass_start(62820)], total=2)
    wrong = verify_claim(_finding(starts, CLAIM), case_dir=case)
    assert wrong["checks"]["L1.11"]["status"] == "fail", wrong["checks"]["L1.11"]
    assert "Security 4688" in wrong["checks"]["L1.11"]["detail"]
    assert wrong["verdict"] in {"UNSUPPORTED", "CONTRADICTED"}
    right = verify_claim(_finding(starts, "Security 4688 rows of lsass.exe starting"), case_dir=case)
    assert right["checks"]["L1.11"]["status"] == "pass", right["checks"]["L1.11"]
    plain = verify_claim(_finding(starts, "lsass.exe started under wininit.exe"), case_dir=case)
    assert plain["checks"]["L1.11"]["status"] == "skipped"


def test_l1_11_is_unverifiable_when_a_cited_call_kept_part_of_its_rows_and_cannot_run_again(tmp_path):
    from nexus.analysis.claim_verification import verify_claim

    case = _case(tmp_path)
    starts = cite_rows(case, [_lsass_start(62445)], total=30)
    result = verify_claim(_finding(starts, CLAIM), case_dir=case, event_replay=lambda q, e: None)
    assert result["checks"]["L1.11"]["status"] == "unverifiable"
