"""Evidence a case-based pipeline run must inherit.

A run on an existing case used to receive evidence paths ONLY from CLI
arguments, so `pipeline --from-case X --mode tools` (and, because the guard was
scoped to `tools`/`interpret`, `--mode coverage` too) handed the planner an
empty list: the Windows/triage planner scheduled nothing - EvtxECmd, Hayabusa,
Chainsaw, DeepBlueCLI and Zircolite were never invoked - and the pass reported
`status: clear, findings: 0` over evidence it had never read.

The fix keeps the decision in one function with no mode parameter, so no mode
can be forgotten again. These tests pin that.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph.llm_pipeline import (
    _case_evidence_paths,
    inherit_evidence_paths,
)


def _case_with_evidence(tmp_path: Path, case_id: str, paths: list[Path]) -> Path:
    """Register *paths* on a case under the redirected cases_root."""
    from nexus.config import settings

    case_dir = Path(settings.cases_root) / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "evidence.json").write_text(
        json.dumps([
            {"name": p.name, "path": str(p), "sha256": "a" * 64} for p in paths
        ]),
        encoding="utf-8",
    )
    return case_dir


def test_a_case_run_inherits_its_registered_local_evidence(tmp_path):
    ev1 = tmp_path / "Security.evtx"
    ev2 = tmp_path / "System.evtx"
    for p in (ev1, ev2):
        p.write_text("x", encoding="utf-8")
    _case_with_evidence(tmp_path, "CASE-T1", [ev1, ev2])

    paths = _case_evidence_paths("CASE-T1")
    assert sorted(paths) == sorted([str(ev1), str(ev2)])


def test_sift_hosted_paths_are_not_handed_to_the_local_planner(tmp_path):
    """`/evidence/x` is a path on the SIFT host, not on this machine."""
    _case_with_evidence(tmp_path, "CASE-T2", [])
    local = tmp_path / "local.evtx"
    local.write_text("x", encoding="utf-8")
    case_dir = tmp_path / "unused"
    del case_dir
    from nexus.config import settings

    (Path(settings.cases_root) / "CASE-T2" / "evidence.json").write_text(
        json.dumps([
            {"name": "Security.evtx", "path": "/evidence/Security.evtx", "sha256": "b" * 64},
            {"name": "local.evtx", "path": str(local), "sha256": "c" * 64},
        ]),
        encoding="utf-8",
    )
    paths = _case_evidence_paths("CASE-T2")
    assert paths == [str(local)], paths


def test_the_caller_supplied_paths_always_win(tmp_path):
    ev = tmp_path / "a.evtx"
    ev.write_text("x", encoding="utf-8")
    _case_with_evidence(tmp_path, "CASE-T3", [ev])

    assert inherit_evidence_paths("CASE-T3", "", ["/supplied"]) == ["/supplied"]
    assert inherit_evidence_paths("CASE-T3", "/supplied", None) is None


def test_no_case_means_nothing_to_inherit():
    assert inherit_evidence_paths("", "", None) is None
    assert _case_evidence_paths("") == []


def test_inheritance_cannot_be_gated_on_a_mode(tmp_path):
    """The function takes no mode, so no mode can be left out of it again.

    This is the regression that shipped: the guard was scoped to `tools` and
    `interpret`, while Mode 1 runs `coverage` - so the mode that K1 measures had
    an empty lane plan while `tools` looked fine.
    """
    import inspect

    params = list(inspect.signature(inherit_evidence_paths).parameters)
    assert params == ["case_id", "evidence_path", "evidence_paths"], params


def test_an_unknown_case_yields_nothing_rather_than_raising():
    assert _case_evidence_paths("CASE-DOES-NOT-EXIST") == []


def test_a_corrupt_registry_does_not_kill_the_run(tmp_path):
    from nexus.config import settings

    case_dir = Path(settings.cases_root) / "CASE-T4"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "evidence.json").write_text("{not json", encoding="utf-8")
    assert _case_evidence_paths("CASE-T4") == []
