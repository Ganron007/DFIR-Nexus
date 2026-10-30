"""The report must use the same eligible verifier work as the agenda and context readers."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus.modes import multi_agent as mode3

CAPTURE = json.loads((Path(__file__).parent / "fixtures/mode3_report_verdict_r1.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("change", [{"evidence_attempted": True, "evidence_read": False},
                                    {"finish_reason": "model_error"}])
def test_ineligible_verifier_cannot_add_corroboration_to_a_candidate(change):
    claim, verdict = CAPTURE["claim_entry"], CAPTURE["verdict_entry"]
    # The claim/verdict are native model outputs, not ground truth. This checks
    # only whether a completed versus blind/error verifier is credited.
    valid, _ = mode3.settled_candidates([claim, verdict], [])
    assert len(valid) == 1 and "Verifier:" in valid[0]["interpretation"]
    ineligible = {**verdict, **change}
    candidates, _ = mode3.settled_candidates([claim, ineligible], [])
    assert len(candidates) == 1
    assert "Verifier:" not in candidates[0]["interpretation"]
    assert mode3._unverified_claims([claim, ineligible])
    assert "verifier:" not in mode3.board_view([claim, ineligible])
