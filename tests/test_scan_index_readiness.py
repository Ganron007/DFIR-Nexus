"""The needle scan must not run against an empty index and call it a clean result.

Found on the live real-corpus run, and it is the exact failure class this project
forbids - a silent false negative presented as success.

Mode 1's full-run reads the case index. Run it while the index is empty or stale
and every needle reports zero hits, so the run completes with `stage="nothing to
promote"` and `status="complete"`. On the real G1 case that produced:

    needles_scanned  198      <- the scan really did run
    needles_hit_total  0      <- every needle "missed"
    drafts             0
    status        complete

from a case holding 81,115 indexed rows. Re-scanning the same case once the index
was present produced 17 needles and 16 drafts. Nothing in the record said the
index had been empty; the stated reason was "no playbook needles matched any
evidence", which points the examiner at their evidence rather than at the index.

The guard now verifies the index, rebuilds it when stale, and **refuses** with an
honest reason when it cannot be made usable.
"""
from __future__ import annotations

import ast
import pathlib

APP = pathlib.Path("src/nexus/dashboard/app.py")


def _src() -> str:
    return APP.read_text(encoding="utf-8")


def _fn(name: str) -> str:
    tree = ast.parse(_src())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(_src(), node) or ""
    return ""


def test_the_repair_runs_before_the_scan_and_the_verdict_after():
    """Repair the index first; judge whether the scan was possible afterwards.

    Preparing first is what lets a stale index be rebuilt instead of scanned
    empty. Judging afterwards is what tells a scan that found nothing from a scan
    that never had a corpus - guessing the backend up front got that wrong in
    both directions.
    """
    src = _src()
    assert "_prepare_scan_index" in src and "_scan_had_a_corpus" in src
    worker = _fn("_mode1_full_run_worker")
    prep = worker.find("_prepare_scan_index(")
    scan = worker.find("case_briefing(")
    verdict = worker.find("_scan_had_a_corpus(")
    assert 0 < prep < scan < verdict, (prep, scan, verdict)


def test_a_stale_index_is_rebuilt_rather_than_skipped():
    body = _fn("_prepare_scan_index")
    assert "index_stale(" in body
    assert "index_case(" in body, "a stale index must be rebuilt, not scanned empty"


def test_an_unusable_index_refuses_the_run():
    """Refusing is the contract: scanning nothing must not report success."""
    full_run = _fn("_mode1_full_run_worker")
    assert 'record["status"] = "failed"' in full_run, (
        "a scan with no corpus must fail the run, not complete it"
    )
    assert "index not ready" in full_run
    assert "Scan not run" in full_run


def test_the_refusal_reason_names_the_index_not_the_evidence():
    """The old reason sent the examiner looking at their evidence."""
    body = _fn("_scan_had_a_corpus")
    assert "no corpus to read" in body
    assert "index problem" in body and "absence of" in body, body


def test_every_inability_to_scan_returns_a_note():
    """Every early return must carry a note, or a refusal would be silent."""
    body = _fn("_prepare_scan_index")
    tree = ast.parse(body)
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
            elts = node.value.elts
            assert len(elts) == 2, ast.dump(node.value)
            first, second = elts
            if isinstance(first, ast.Constant) and first.value is False:
                assert not (isinstance(second, ast.Constant) and second.value == ""), (
                    "a refusal with an empty reason is a silent failure"
                )


def test_the_scan_is_reached_and_then_judged():
    full_run = _fn("_mode1_full_run_worker")
    guard_call = full_run.find("_scan_had_a_corpus(")
    assert guard_call > 0
    after = full_run[guard_call:]
    assert "if _blocked:" in after
    assert "return" in after.split("if _blocked:")[1][:500], (
        "a scan with no corpus must return before staging anything"
    )


def test_a_successful_scan_still_reports_nothing_to_promote_when_truly_empty():
    """The genuine empty case must keep working - the guard is not a blanket stop."""
    full_run = _fn("_mode1_full_run_worker")
    assert 'record["stage"] = "nothing to promote"' in full_run
    assert "no playbook needles matched any evidence" in full_run


def test_a_scan_that_read_rows_is_never_refused():
    """`scanned_needles > 0` means the scan had a corpus, so an empty result is real."""
    body = _fn("_scan_had_a_corpus")
    assert "scanned > 0" in body
    assert 'return ""' in body


def test_nothing_registered_is_not_an_index_problem():
    """A case with no evidence has genuinely nothing to scan."""
    body = _fn("_scan_had_a_corpus")
    assert "evidence_count <= 0" in body
