"""Model egress writes its token map into the run's own case, never the active pointer (WO-R2F item 1, D41; 2026-10-11).

The egress wrapper decides the case folder at call time. Before this fix, a model call with no bound run fell back to the
global active-case pointer, so a Mode 1 run's tokens went into whatever case the examiner had active. Only the context
loop bound a case, so Mode 1 (interpret_loop) and the other entry points had no binding at all.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from nexus.config import settings

POINTER_CASE = "CASE-EGRESSPOINTER"


def test_an_unbound_model_call_does_not_use_the_active_case():
    root = settings.cases_root  # redirected to a temporary root by tests/conftest.py
    (root / POINTER_CASE / "audit").mkdir(parents=True)
    (root / POINTER_CASE / "CASE.yaml").write_text(f"case_id: {POINTER_CASE}\n", encoding="utf-8")
    Path(os.environ["NEXUS_ACTIVE_CASE_FILE"]).write_text(str(root / POINTER_CASE), encoding="utf-8")
    from nexus.llm.egress import _bound_case_dir

    assert _bound_case_dir() is None


def test_egress_case_binds_the_run_and_restores_the_outer_binding():
    from nexus.llm.egress import _bound_case_dir, egress_case

    outer, inner = Path("CASE-OUTER"), Path("CASE-INNER")
    with egress_case(outer):
        assert _bound_case_dir() == outer
        with egress_case(inner):
            assert _bound_case_dir() == inner
        assert _bound_case_dir() == outer
    assert _bound_case_dir() is None


_RUN_ENTRIES = [
    ("src/nexus/langgraph/interpret_loop.py", "run_interpret_loop"),
    ("src/nexus/modes/multi_role.py", "run_mode2"),
    ("src/nexus/modes/multi_agent.py", "run_mode3"),
    ("src/nexus/modes/llm_guided.py", "run_iterative_loop"),
    ("src/nexus/langgraph/steer_agent.py", "run_steer_agent"),
    ("src/nexus/langgraph/context_loop.py", "run_context_loop"),
]


@pytest.mark.parametrize("path, fn", _RUN_ENTRIES)
def test_each_run_entry_binds_its_case_for_egress(path, fn):
    """Wiring pin: every in-process run entry point is wrapped by egress_bound, which binds its case_dir."""
    tree = ast.parse(Path(path).read_text(encoding="utf-8"), filename=path)
    func = next(n for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fn)
    decorators = {getattr(d, "id", "") for d in func.decorator_list}

    assert "egress_bound" in decorators, f"{path}:{fn} does not bind its case for egress"
