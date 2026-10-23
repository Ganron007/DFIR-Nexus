"""D256: claim identity is stable across context and evidence-set size.

Mode 1 run 15d8cd92 on CASE-C5B04D31 staged the same initial-access claim twice (F-claudebot-066, and F-072 restated
with one call fewer) and never staged its Defender-tampering claim, which was linked to F-066. D325 removed the
12-row evidence cut; the verbatim audit fixture then exposes an order-dependent D256 comparison: the initial-access
and tampering claims have 21 and 44 distinct rows, with 15 shared. The audit entries are from that case
(tests/fixtures/d256_audit); the three claims cite them as the run did.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from nexus.case_manager import _evidence_row_identity, _same_claim
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
    """The finding as staging builds it: all cited evidence rows and the full-row subject."""
    subject = derive_subject(subject_rows_for_audit_ids(case, ids))
    return {"entity": subject["entity"], "category": subject["category"],
            "evidence": evidence_rows_for_audit_ids(case, ids)}


def test_a_claim_restated_with_one_call_fewer_keeps_its_subject(case_dir):
    first, restated = _staged(case_dir, INITIAL_ACCESS), _staged(case_dir, RESTATED)
    assert first["entity"] and (first["entity"], first["category"]) == (restated["entity"], restated["category"])
    assert len(first["evidence"]) > 12
    assert len(restated["evidence"]) > 12


def test_the_restated_claim_is_the_same_claim(case_dir):
    first, restated = _staged(case_dir, INITIAL_ACCESS), _staged(case_dir, RESTATED)
    shared = {_evidence_row_identity(e) for e in first["evidence"]} & {
        _evidence_row_identity(e) for e in restated["evidence"]}
    assert 4 * len(shared) >= len(first["evidence"]) + len(restated["evidence"])
    assert _same_claim(first, restated)
    assert _same_claim(restated, first), "claim identity must not depend on staging order"


def test_a_claim_that_shares_context_calls_is_not_the_same_claim(case_dir):
    first, tampering = _staged(case_dir, INITIAL_ACCESS), _staged(case_dir, TAMPERING)
    # The same subject; the claims share context, but less than half of their combined evidence.
    assert (tampering["entity"], tampering["category"]) == (first["entity"], first["category"])
    shared = {_evidence_row_identity(e) for e in tampering["evidence"]} & {
        _evidence_row_identity(e) for e in first["evidence"]}
    assert len(shared) > 0
    assert 4 * len(shared) < len(tampering["evidence"]) + len(first["evidence"])
    assert not _same_claim(first, tampering)
    assert not _same_claim(tampering, first)
