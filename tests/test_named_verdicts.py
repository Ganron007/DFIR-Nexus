"""D258: a claim that credits a baseline check is held to the calls it cites.

On CASE-C5B04D31 (fresh Mode 2 run M2-20261016T210141-b9e203) a work order wrote that check_file and check_lolbin
"confirm STUN.exe is a legitimate Windows component", citing one memory lead; no check_file call on STUN.exe had
run, and the one that ran later (nexus-claudebot-20261016-1765) answered UNKNOWN. Candidate 7 then wrote
"(check_file EXPECTED)" citing no check call at all. The note, the candidate and the audit entries are the run's,
verbatim (tests/fixtures/d258_*).
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from nexus.langgraph.evidence_rows import cited_calls
from nexus.langgraph.named_verdicts import named_verdicts, verdict_grounding

FIXTURES = Path(__file__).parent / "fixtures"
CLAIMS = json.loads((FIXTURES / "d258_claims.json").read_text(encoding="utf-8"))
NOTE, CANDIDATE = CLAIMS["note"], CLAIMS["candidate_7"]
STUN_CHECK = "nexus-claudebot-20261016-1765"


@pytest.fixture()
def case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-C5B04D31"
    (case / "audit").mkdir(parents=True)
    shutil.copy(FIXTURES / "d258_audit.jsonl", case / "audit" / "nexus.jsonl")
    return case


def test_the_checks_a_text_credits_and_the_verdicts_it_names():
    assert [(t, v) for t, v, _s in named_verdicts(NOTE["statement"])] == [("check_file", ()), ("check_lolbin", ())]
    credited = {t: v for t, v, _s in named_verdicts(CANDIDATE["observation"])}
    assert credited["check_file"] == ("EXPECTED",), credited
    assert credited["check_scheduled_task"] == ("UNKNOWN",), credited
    # Absence is not a credit, and "unknown" in prose is not a verdict.
    assert named_verdicts("check_file was not run on STUN.exe.") == []
    assert named_verdicts("check_file on STUN.exe: origin unknown.")[0][1] == ()


def test_a_note_that_credits_checks_it_does_not_cite_is_ungrounded(case):
    calls = cited_calls(case, NOTE["audit_ids"])
    assert {c["tool"] for c in calls.values()} == {"lead"}
    assert verdict_grounding(NOTE["statement"], calls)["ungrounded"] == [
        "check_file (it cites no check_file call)", "check_lolbin (it cites no check_lolbin call)"]


def test_a_verdict_the_cited_call_did_not_return_is_ungrounded_and_the_true_one_is_grounded(case):
    calls = cited_calls(case, [STUN_CHECK])
    assert calls[STUN_CHECK]["verdict"] == "UNKNOWN"
    said = r"STUN.exe is a legitimate Windows Defender Update component (check_file EXPECTED)."
    assert verdict_grounding(said, calls)["ungrounded"] == [
        "check_file EXPECTED (the cited check_file call returned UNKNOWN)"]
    true = r"check_file on C:\Windows\System32\STUN.exe returned UNKNOWN: no Windows build ships it."
    assert verdict_grounding(true, calls) == {"grounded": ["check_file UNKNOWN"], "ungrounded": []}


def test_the_call_on_the_value_the_sentence_names_answers(case):
    """Two check_file calls cited: the sentence about SRLUpdate.exe is held to the call on SRLUpdate.exe."""
    calls = cited_calls(case, [STUN_CHECK, "nexus-claudebot-20261016-1687"])
    assert verdict_grounding("check_file on SRLUpdate.exe returned EXPECTED.", calls)["ungrounded"] == [
        "check_file EXPECTED (the cited check_file call returned UNKNOWN)"]


def test_staging_l1_12_fails_the_candidate(case):
    from nexus.analysis.claim_verification import verify_claim

    res = verify_claim(CANDIDATE, case_dir=case)
    check = res["checks"]["L1.12"]
    assert check["status"] == "fail", check
    assert "check_file EXPECTED (it cites no check_file call)" in check["detail"]
    assert res["verdict"] != "PROVEN"


def test_mode2_marks_the_note_every_later_seat_reads(case):
    from nexus.modes.multi_role import _mark_ungrounded

    parsed = {"notes": [json.loads(json.dumps(NOTE))], "candidate_findings": []}
    assert _mark_ungrounded(parsed, case) == 1
    assert parsed["notes"][0]["ungrounded"] == [
        "credits check_file (it cites no check_file call)", "credits check_lolbin (it cites no check_lolbin call)"]


def test_mode2_verifier_downgrades_a_confirmation_resting_on_a_credited_check(case):
    from nexus.langgraph.named_events import downgrade_ungrounded_confirmations

    verdict = {"title": "STUN.exe", "class": "confirmed", "audit_ids": [STUN_CHECK],
               "basis": "STUN.exe is a legitimate Windows Defender Update component (check_file EXPECTED)."}
    assert downgrade_ungrounded_confirmations([verdict], case) == [verdict]
    assert verdict["class"] == "unverifiable" and verdict["downgraded_from"] == "confirmed"
    assert "the cited check_file call returned UNKNOWN" in verdict["basis"]


def test_mode3_refuses_the_claim(case):
    from nexus.langgraph.subject import attach_subjects
    from nexus.modes.multi_agent import accept_claim

    claim = {"audit_ids": NOTE["audit_ids"], "claim_kind": "presence", "polarity": "affirm",
             "value": NOTE["statement"], "confidence": "HIGH", "confidence_justification": "baseline checks"}
    attach_subjects([claim], case)
    assert accept_claim(claim).startswith("TV-1: the claim credits check_file (it cites no check_file call)")
