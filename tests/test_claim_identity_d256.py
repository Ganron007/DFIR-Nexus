"""D256: a claim's identity is what its rows are about, not which context calls it also cites.

Mode 1 run 15d8cd92 on CASE-C5B04D31 staged the same initial-access claim twice (F-claudebot-066, and F-072 restated
with one call fewer) and never staged its Defender-tampering claim, which was linked to F-066. The subject was
derived from the DRAFT's 12-row cut, whose make-up follows how many calls a claim cites, and the same-claim rule
(D223) linked any two claims of one subject that shared a single row. The audit entries are that case's, verbatim
(tests/fixtures/d256_audit); the three claims cite them as the run did.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from nexus.case_manager import _same_claim
from nexus.langgraph.evidence_rows import evidence_rows_for_audit_ids, subject_rows_for_audit_ids
from nexus.langgraph.subject import derive_subject

FIXTURE = Path(__file__).parent / "fixtures" / "d256_audit"
INITIAL_ACCESS = ["nexus-claudebot-20261016-1660", "nexus-gate-bot-20261014-090", "nexus-gate-bot-20261014-087",
                  "nexus-gate-bot-20261014-085"]
RESTATED = ["nexus-gate-bot-20261014-090", "nexus-gate-bot-20261014-087", "nexus-claudebot-20261016-1660"]
TAMPERING = ["nexus-gate-bot-20261014-080", "nexus-gate-bot-20261014-085", "nexus-gate-bot-20261014-088",
             "nexus-gate-bot-20261014-082", "nexus-gate-bot-20261014-083", "nexus-gate-bot-20261014-091",
             "nexus-gate-bot-20261014-101", "nexus-claudebot-20261016-1660"]


@pytest.fixture
def case_dir(tmp_path):
    case = tmp_path / "CASE-C5B04D31"
    shutil.copytree(FIXTURE, case / "audit")
    return case


def _staged(case: Path, ids: list[str]) -> dict:
    """The finding as staging builds it: the DRAFT's rows, and the subject of every cited row."""
    subject = derive_subject(subject_rows_for_audit_ids(case, ids))
    return {"entity": subject["entity"], "category": subject["category"],
            "evidence": evidence_rows_for_audit_ids(case, ids)[:12]}


def test_a_claim_restated_with_one_call_fewer_keeps_its_subject(case_dir):
    first, restated = _staged(case_dir, INITIAL_ACCESS), _staged(case_dir, RESTATED)
    assert first["entity"] and (first["entity"], first["category"]) == (restated["entity"], restated["category"])
    # The cut of rows, which the subject used to come from, did not agree.
    cut = [derive_subject(evidence_rows_for_audit_ids(case_dir, ids)) for ids in (INITIAL_ACCESS, RESTATED)]
    assert cut[0]["category"] != cut[1]["category"]


def test_the_restated_claim_is_the_same_claim(case_dir):
    first, restated = _staged(case_dir, INITIAL_ACCESS), _staged(case_dir, RESTATED)
    assert _same_claim(first, restated)


def test_a_claim_that_shares_context_calls_is_not_the_same_claim(case_dir):
    first, tampering = _staged(case_dir, INITIAL_ACCESS), _staged(case_dir, TAMPERING)
    # The same subject: the tampering claim's own calls name only the host, and the Terraform script comes from the
    # call it shares. What tells the two apart is how much of its evidence it shares.
    assert (tampering["entity"], tampering["category"]) == (first["entity"], first["category"])
    shared = {(e.get("source"), e.get("loc")) for e in tampering["evidence"]} & {
        (e.get("source"), e.get("loc")) for e in first["evidence"]}
    assert 0 < 2 * len(shared) < len(tampering["evidence"])
    assert not _same_claim(first, tampering)
    assert not _same_claim(tampering, first)
