"""WO-1C item 4 — one DRAFT per claim, with cross-mode lineage.

D5 = C: three modes run on one case. When Mode 2 proposes what Mode 1 already
staged as a DRAFT, that is the SAME finding — not a second copy. The existing
DRAFT keeps its id (and the examiner's place in the review queue) while its
lineage records that a second mode independently reached it. That record is
what makes "two modes agree" a measurable claim rather than a vibe.

Rules pinned here:
- a duplicate never mints a second finding id;
- ``modes`` is the sorted set of modes that produced the claim;
- ``run_ids`` keeps every run, first-seen first;
- an APPROVED or REJECTED finding is never merged into (a signed decision);
- a finding with a different title OR different evidence is NOT a duplicate.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.case_manager import CaseManager


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-TEST01"
    (case / "analysis").mkdir(parents=True)
    (case / "CASE.yaml").write_text("name: test\ncreated_by: ex\n", encoding="utf-8")
    (case / "evidence_registry.json").write_text("[]", encoding="utf-8")
    (case / "findings.json").write_text("[]", encoding="utf-8")
    # FD-001: a finding must cite a tool call that really happened, so the
    # audit log has to exist before the first record_finding.
    (case / "audit").mkdir(parents=True, exist_ok=True)
    with (case / "audit" / "audit_log.jsonl").open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "audit_id": "hayabusa-tester-20261009-001",
            "tool": "hayabusa", "source": "mcp",
            "ts": "2026-10-09T00:00:00+00:00",
        }) + "\n")
    return case


def _finding(**over):
    base = {
        "title": "Mimikatz executed on ws01",
        "observation": "lsass access observed",
        "interpretation": "credential dumping",
        "confidence": "HIGH",
        "confidence_justification": "two artifacts agree",
        "audit_ids": ["hayabusa-tester-20261009-001"],
        "evidence": [{"detail": "hayabusa row 1"}],
        "severity": "high",
        "run_id": "M1-20261009T120000-abc",
        "provenance": {"mode": 1},
    }
    base.update(over)
    return base


def test_first_proposal_stages_a_draft(tmp_path: Path):
    cm = CaseManager()
    case = _case(tmp_path)
    res = cm.record_finding(_finding(), case_dir=case)
    assert res.get("duplicate") is not True, res


def test_second_mode_links_instead_of_duplicating(tmp_path: Path):
    """The WO-1C item 4 rule: Mode 2 proposing Mode 1's claim links to it."""
    cm = CaseManager()
    case = _case(tmp_path)
    cm.record_finding(_finding(), case_dir=case)

    res = cm.record_finding(
        _finding(run_id="M2-20261009T130000-def", provenance={"mode": 2}),
        case_dir=case,
    )
    assert res.get("duplicate") is True, res
    assert res["status"] == "DUPLICATE", res

    findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert len(findings) == 1, "a second copy of the same claim was staged"
    f = findings[0]
    # One finding, two modes, two runs.
    assert f["modes"] == [1, 2], f.get("modes")
    assert f["run_ids"] == ["M1-20261009T120000-abc", "M2-20261009T130000-def"], f.get("run_ids")
    # The first mode that raised it is what `provenance.mode` says.
    assert f["provenance"]["mode"] == 1, f.get("provenance")


def test_all_three_modes_agree_records_all_three(tmp_path: Path):
    cm = CaseManager()
    case = _case(tmp_path)
    for run_id, mode in (("M1-a", 1), ("M2-b", 2), ("M3-c", 3)):
        cm.record_finding(_finding(run_id=run_id, provenance={"mode": mode}),
                          case_dir=case)
    findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert len(findings) == 1
    assert findings[0]["modes"] == [1, 2, 3]


def test_an_approved_finding_is_never_merged_into(tmp_path: Path):
    """A signed examiner decision is not a duplicate to link to."""
    cm = CaseManager()
    case = _case(tmp_path)
    cm.record_finding(_finding(), case_dir=case)
    findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    findings[0]["status"] = "APPROVED"
    (case / "findings.json").write_text(json.dumps(findings), encoding="utf-8")

    res = cm.record_finding(
        _finding(run_id="M2-b", provenance={"mode": 2}), case_dir=case
    )
    assert res.get("duplicate") is not True, "an APPROVED finding was merged into"
    findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert len(findings) == 2


def test_different_evidence_is_a_different_finding(tmp_path: Path):
    cm = CaseManager()
    case = _case(tmp_path)
    cm.record_finding(_finding(), case_dir=case)
    res = cm.record_finding(
        _finding(run_id="M2-b", provenance={"mode": 2},
                 evidence=[{"detail": "hayabusa row 1"}, {"detail": "prefetch entry"}]),
        case_dir=case,
    )
    assert res.get("duplicate") is not True
    findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert len(findings) == 2, "different evidence was collapsed into one finding"


def test_same_mode_twice_still_links(tmp_path: Path):
    """A re-run of the same mode is the same claim too (WO-R1F item 4)."""
    cm = CaseManager()
    case = _case(tmp_path)
    cm.record_finding(_finding(run_id="M1-a"), case_dir=case)
    res = cm.record_finding(
        _finding(run_id="M1-b", provenance={"mode": 1}), case_dir=case
    )
    assert res.get("duplicate") is True
    findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert len(findings) == 1
    assert findings[0]["modes"] == [1]
    assert findings[0]["run_ids"] == ["M1-a", "M1-b"]


def test_a_finding_without_a_mode_still_links_on_run_id(tmp_path: Path):
    """Legacy callers that pass no provenance must not crash or duplicate.

    The mode is still inferred from the run id (WO-1C items 2/4): an ``M2-``
    run is Mode 2 whether or not the caller also said so.
    """
    cm = CaseManager()
    case = _case(tmp_path)
    cm.record_finding(_finding(run_id="M1-a", provenance={}), case_dir=case)
    res = cm.record_finding(_finding(run_id="M2-b", provenance={}), case_dir=case)
    assert res.get("duplicate") is True
    findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert findings[0]["modes"] == [1, 2]


def test_an_unparseable_run_id_records_no_mode(tmp_path: Path):
    """The lineage must not invent agreement it cannot see."""
    cm = CaseManager()
    case = _case(tmp_path)
    cm.record_finding(_finding(run_id="legacy-1", provenance={}), case_dir=case)
    res = cm.record_finding(_finding(run_id="legacy-2", provenance={}), case_dir=case)
    assert res.get("duplicate") is True
    findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert findings[0]["modes"] == []
    assert findings[0]["run_ids"] == ["legacy-1", "legacy-2"]


def test_mode_infers_from_the_run_id_when_provenance_is_absent(tmp_path: Path):
    """WO-1C item 2/4: an M2- run is Mode 2 even if the caller said nothing."""
    cm = CaseManager()
    case = _case(tmp_path)
    cm.record_finding(_finding(run_id="M1-a"), case_dir=case)
    cm.record_finding(_finding(run_id="M2-20261009T130000-def"), case_dir=case)
    findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert findings[0]["modes"] == [1, 2], findings[0].get("modes")
