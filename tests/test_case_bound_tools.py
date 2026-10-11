"""Case-bound tools read the run's own case, never the active pointer (WO-R2F item 1, D41; 2026-10-11).

Reproduced on the real path: the Mode 2 run on CASE-C5B04D31 made 39 run_record calls while the active pointer named
CASE-D6B93BF1, and every one was refused with "case_id 'CASE-C5B04D31' is not the active case". The context loop bound
the case for run_record, but _run_record_call (backbone.py) dropped it, so do_run_record resolved the case through the
pointer. The same path was open for index_mappings, es_fields and es_sample: the loop bound only five names, and the
rest resolved through the pointer. A model-named case that matched the pointer read the pointer's ledger silently.

The rule now: an in-process call on a case-bound tool carries its run's case folder. Without one it is refused, never
answered from the pointer. An external MCP caller that binds nothing still goes through the active-case gate.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from nexus.config import settings
from nexus.langgraph.backbone import CASE_BOUND_TOOLS

RUN_CASE = "CASE-RUNBOUND"
POINTER_CASE = "CASE-POINTERCASE"


def _case(root: Path, case_id: str) -> Path:
    case = root / case_id
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {case_id}\n", encoding="utf-8")
    return case


def _setup() -> Path:
    root = settings.cases_root  # redirected to a temporary root by tests/conftest.py
    run_dir = _case(root, RUN_CASE)
    _case(root, POINTER_CASE)
    Path(os.environ["NEXUS_ACTIVE_CASE_FILE"]).write_text(str(root / POINTER_CASE), encoding="utf-8")
    return run_dir


def _audit(run_dir: Path):
    from nexus.audit import AuditWriter

    return AuditWriter("case-bound-test", audit_dir=run_dir / "audit")


def test_a_bound_run_reads_its_own_case_while_another_case_is_active():
    from nexus.langgraph.backbone import backbone_call

    run_dir = _setup()

    result = backbone_call("run_record", audit=_audit(run_dir), case_id=RUN_CASE, case_dir=run_dir)

    assert "error" not in result, result


def test_a_bound_run_refuses_a_different_case_named_by_the_model():
    from nexus.langgraph.backbone import backbone_call

    run_dir = _setup()

    result = backbone_call("run_record", audit=_audit(run_dir), case_id=POINTER_CASE, case_dir=run_dir)

    assert "error" in result, result
    assert "does not match the bound case" in result["error"], result


def test_an_unbound_external_call_is_still_gated_to_the_active_case():
    from nexus.tools.evidence_index import do_run_record

    _setup()

    result = do_run_record(case_id=RUN_CASE, audit=None)

    assert "error" in result, result
    assert "is not the active case" in result["error"], result


def test_a_bound_run_reads_its_own_index_mappings_while_another_case_is_active():
    from nexus.langgraph.backbone import backbone_call

    run_dir = _setup()

    result = backbone_call("index_mappings", audit=_audit(run_dir), case_id=RUN_CASE, case_dir=run_dir)

    assert "error" not in result, result
    assert result["case_id"] == RUN_CASE, result


@pytest.mark.parametrize("name", sorted(CASE_BOUND_TOOLS))
def test_a_case_bound_tool_without_a_bound_case_is_refused_not_answered_from_the_pointer(name):
    from nexus.langgraph.backbone import backbone_call

    run_dir = _setup()

    result = backbone_call(name, audit=_audit(run_dir), case_id=POINTER_CASE)

    assert "error" in result, (name, result)
    assert "no case is bound" in result["error"] or "needs the run's own case" in result["error"], (name, result)


def test_bind_case_args_binds_only_the_case_bound_tools():
    from nexus.langgraph.backbone import CASE_BOUND_TOOLS, bind_case_args

    run_dir = Path("RUN")
    for name in CASE_BOUND_TOOLS:
        bound = bind_case_args(name, {"query": {}}, case_id="CASE-X", case_dir=run_dir)
        assert bound == {"query": {}, "case_id": "CASE-X", "case_dir": run_dir}, name
    untouched = bind_case_args("forensic_rag_search", {"query": "x"}, case_id="CASE-X", case_dir=run_dir)
    assert untouched == {"query": "x"}


def test_the_context_loop_binds_every_case_bound_tool_through_the_one_helper():
    """Wiring pin: the loop's injection is backbone.bind_case_args, not a second hand-kept list."""
    src = Path("src/nexus/langgraph/context_loop.py").read_text(encoding="utf-8")

    assert "payload = bind_case_args(name, clean_args, case_id=case_id, case_dir=case_dir)" in src
    assert 'if name in ("es_mappings", "es_search", "es_aggregate", "sample_rows", "run_record")' not in src


def test_every_in_process_caller_of_a_case_bound_tool_passes_its_case_folder():
    """Static guard: a backbone_call on a case-bound tool name must carry case_dir (or **kwargs that might)."""
    from nexus.langgraph.backbone import CASE_BOUND_TOOLS

    unbound = []
    for path in Path("src/nexus").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            callee = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            first = node.args[0]
            if callee != "backbone_call" or not isinstance(first, ast.Constant):
                continue
            if first.value not in CASE_BOUND_TOOLS:
                continue
            keywords = {kw.arg for kw in node.keywords}
            if "case_dir" not in keywords and None not in keywords:
                unbound.append(f"{path.as_posix()}:{node.lineno} {first.value}")

    assert not unbound, unbound
