"""D223: one DRAFT per claim per case, across runs and modes, and a decided claim is not staged again.

The beacon was staged three times (034, 039, 046): each run worded it differently and cited a different
subset of the same detection rows, and the duplicate rule asked for the exact same rows. A claim is now
the same when its subject and category are the same and it shares a cited row. The rows below are the
evidence rows of CASE-C5B04D31's Defender detections (tests/fixtures/defender_rows.json), shaped as
staging attaches them.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph.ecs_normalize import normalize
from nexus.langgraph.es_native import _shape_hit
from nexus.langgraph.evidence_rows import evidence_rows_for_hits
from nexus.modes import multi_role as m2

ROWS = json.loads((Path(__file__).parent / "fixtures" / "defender_rows.json").read_text(encoding="utf-8"))


def _row(key: str, line: int) -> dict:
    row = ROWS[key]
    fields = row["fields"]
    doc = {"family": row["family"], "file": f"{row['family']}/out.csv", "line": str(line), "text": "",
           "fields": fields, "ecs": normalize(row["family"], fields),
           "event_id": str(fields.get("EventId") or fields.get("EventID") or "")}
    return evidence_rows_for_hits([_shape_hit(doc)])[0]


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-ONECLAIM"
    (case / "analysis").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "CASE.yaml").write_text("name: one claim\nstatus: active\n", encoding="utf-8")
    return case


def _audited(case: Path, rows: list[dict]) -> str:
    from nexus.audit import AuditWriter

    return AuditWriter("nexus", audit_dir=case / "audit").log(
        tool="es_search", params={"case_id": case.name, "query": {"match_all": {}}},
        result_summary={"total": len(rows), "evidence_rows": rows})


def _stage(case: Path, run_id: str, title: str, audit_id: str) -> dict:
    m2._persist_state(case, run_id, {
        "run_id": run_id, "case_id": case.name, "question": "q", "status": "completed", "orders": [],
        "order_index": 0, "results": [], "verdicts": [], "gaps": [],
        "candidates": [{"title": title, "observation": "o", "interpretation": "i", "confidence": "MEDIUM",
                        "confidence_justification": "detections cited", "audit_ids": [audit_id]}]})
    return m2.stage_run_candidates(case, run_id)


def _findings(case: Path) -> list[dict]:
    return json.loads((case / "findings.json").read_text(encoding="utf-8"))


def test_a_reworded_claim_on_some_of_the_same_rows_joins_the_draft(tmp_path):
    case = _case(tmp_path)
    beacon = [_row("evtxecmd_1116_behaviour_svchost", 10), _row("hayabusa_1116_behaviour_svchost", 11)]
    first = _stage(case, "M2-20261015T081007-aaaaaa", "Cobalt Strike behaviour in svchost.exe",
                   _audited(case, beacon))
    assert first["staged_count"] == 1
    again = _stage(case, "M3-20261015T180442-bbbbbb", "Defender detected a beacon running in svchost",
                   _audited(case, beacon[1:]))
    assert again["staged_count"] == 0
    assert "same claim as an existing DRAFT" in again["skipped"][0]["reason"]
    (draft,) = _findings(case)
    assert draft["run_ids"] == ["M2-20261015T081007-aaaaaa", "M3-20261015T180442-bbbbbb"]


def test_a_claim_the_examiner_decided_is_not_staged_again_and_the_decision_is_untouched(tmp_path):
    case = _case(tmp_path)
    beacon = [_row("evtxecmd_1116_behaviour_svchost", 10), _row("hayabusa_1116_behaviour_svchost", 11)]
    _stage(case, "M2-20261015T081007-aaaaaa", "Cobalt Strike behaviour in svchost.exe", _audited(case, beacon))
    findings = _findings(case)
    findings[0]["status"] = "REJECTED"
    (case / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    before = (case / "findings.json").read_text(encoding="utf-8")
    again = _stage(case, "M3-20261015T180442-bbbbbb", "Beacon in svchost.exe", _audited(case, beacon[:1]))
    assert again["staged_count"] == 0
    assert f"the examiner rejected this claim as {findings[0]['id']}" in again["skipped"][0]["reason"]
    assert (case / "findings.json").read_text(encoding="utf-8") == before


def test_another_subject_or_no_shared_row_is_another_claim(tmp_path):
    case = _case(tmp_path)
    svchost = _row("evtxecmd_1116_behaviour_svchost", 10)
    _stage(case, "M2-20261015T081007-aaaaaa", "Beacon in svchost.exe", _audited(case, [svchost]))
    # The same subject, other rows: a second detection of the same process is its own claim.
    other_rows = _stage(case, "M3-20261015T180442-bbbbbb", "Beacon in svchost.exe again",
                        _audited(case, [_row("hayabusa_1116_behaviour_svchost", 99)]))
    # Another subject on the same detection family.
    msedge = _stage(case, "M3-20261015T180442-cccccc", "Kekeo in msedge.exe",
                    _audited(case, [_row("evtxecmd_1116_amsi_msedge", 20)]))
    assert other_rows["staged_count"] == 1 and msedge["staged_count"] == 1
    assert len(_findings(case)) == 3
