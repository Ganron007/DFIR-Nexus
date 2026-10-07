"""Step 0 hygiene (WO-R1F): case deletion, the prune guard, and case reuse.

Three defects found while doing the reviewer's step 0:

* `nexus case clean` globbed `CASE-*` only (so `INC-*` survived), left ES
  indexes behind and could not remove read-only evidence copies;
* `scripts/prune_cases.py` swallowed read-only failures with
  `ignore_errors=True` and touched neither the DB nor ES;
* the prune pattern `^CASE-[0-9A-Fa-f]{8}$` matches `CASE-D6B93BF1` — the SC1
  development case, 15.6 GB of evidence — so `--apply` would have deleted it.

And the step 0c defect: a pipeline run whose `--case` was an existing case
DIRECTORY minted a second case (`INC-20261007063311`).
"""

from __future__ import annotations

import json
from pathlib import Path

# ---------------------------------------------------------------------------
# delete_case_data — one implementation for the CLI and the prune script
# ---------------------------------------------------------------------------

def test_delete_case_data_removes_folder_and_db_rows(tmp_path: Path):
    from nexus.case import CaseManager
    from nexus.case.cleanup import delete_case_data

    cases_root = tmp_path / "cases"
    case_dir = cases_root / "INC-20260101010101"
    case_dir.mkdir(parents=True)

    mgr = CaseManager(cases_root / "cases.db")
    mgr.create_case(
        name="throwaway", created_by="test", case_id="INC-20260101010101"
    )
    assert mgr.get_case("INC-20260101010101") is not None

    res = delete_case_data(
        "INC-20260101010101", cases_root=cases_root, drop_indexes=False
    )
    assert res.ok, res.parts
    assert not case_dir.exists()
    assert CaseManager(cases_root / "cases.db").get_case("INC-20260101010101") is None
    parts = dict((name, good) for name, good, _d in res.parts)
    assert parts["folder"] is True and parts["db rows"] is True


def test_delete_case_data_clears_readonly_evidence(tmp_path: Path):
    """A read-only file cannot be unlinked on Windows; rmtree raises.

    `shutil.copy2` carries the corpus .evtx ReadOnly attribute into the case,
    which is the failure `ignore_errors=True` used to swallow.
    """
    import os
    import stat

    from nexus.case.cleanup import delete_case_data

    cases_root = tmp_path / "cases"
    case_dir = cases_root / "TEST-readonly"
    nested = case_dir / "extractions"
    nested.mkdir(parents=True)
    locked = nested / "a.evtx"
    locked.write_bytes(b"evtx")
    os.chmod(locked, stat.S_IREAD)

    res = delete_case_data("TEST-readonly", cases_root=cases_root, drop_indexes=False)
    assert not case_dir.exists(), res.parts
    folder = next(p for p in res.parts if p[0] == "folder")
    assert folder[1] is True, folder


def test_delete_case_data_missing_case_is_not_an_error(tmp_path: Path):
    from nexus.case.cleanup import delete_case_data

    res = delete_case_data("CASE-absent", cases_root=tmp_path, drop_indexes=False)
    assert res.ok
    assert dict((n, g) for n, g, _d in res.parts)["folder"] is True


# ---------------------------------------------------------------------------
# raw_slots / prune guard — a name is not proof
# ---------------------------------------------------------------------------

def test_prune_pattern_matches_the_real_sc1_case():
    """The pattern alone cannot tell a throwaway hex id from a real case.

    `CASE-D6B93BF1` is the SC1 development case. If this assertion ever fails
    the pattern was tightened — keep both this and the has_real_data guard.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "prune_cases", Path(__file__).resolve().parent.parent / "scripts" / "prune_cases.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    assert mod.is_dummy("CASE-D6B93BF1", set()) is True
    # …so the guard must protect it.
    real = Path(__file__).resolve().parent.parent / "cases" / "CASE-D6B93BF1"
    if real.is_dir():
        assert mod.has_real_data(real) is True


def test_has_real_data_detects_evidence_and_findings(tmp_path: Path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "prune_cases", Path(__file__).resolve().parent.parent / "scripts" / "prune_cases.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    empty = tmp_path / "CASE-00000000"
    empty.mkdir()
    (empty / "evidence.json").write_text("[]", encoding="utf-8")
    (empty / "findings.json").write_text("[]", encoding="utf-8")
    assert mod.has_real_data(empty) is False

    with_evidence = tmp_path / "CASE-00000001"
    with_evidence.mkdir()
    (with_evidence / "evidence.json").write_text(
        json.dumps([{"path": "H:\\", "sha256": "x"}]), encoding="utf-8"
    )
    assert mod.has_real_data(with_evidence) is True

    with_findings = tmp_path / "CASE-00000002"
    with_findings.mkdir()
    (with_findings / "findings.json").write_text(
        json.dumps({"findings": [{"id": "F-1"}]}), encoding="utf-8"
    )
    assert mod.has_real_data(with_findings) is True

    # Unreadable is "has data" — never delete on doubt.
    broken = tmp_path / "CASE-00000003"
    broken.mkdir()
    (broken / "evidence.json").write_text("{not json", encoding="utf-8")
    assert mod.has_real_data(broken) is True


# ---------------------------------------------------------------------------
# step 0c — a run on an existing case directory must not mint a new case
# ---------------------------------------------------------------------------

def test_case_option_given_a_case_dir_reuses_it(tmp_path: Path, monkeypatch):
    """`--case <…/CASE-ID>` is a run ON that case, not new evidence.

    Without the check the run took the create path, minted `INC-<ts>` and named
    it "LangGraph Investigation - <id>" (WO-R1F step 0c).
    """
    from typer.testing import CliRunner

    from nexus.cli.main import app

    case_dir = tmp_path / "CASE-D6B93BF1"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text(
        "case_id: CASE-D6B93BF1\nstatus: created\n", encoding="utf-8"
    )

    captured: dict[str, object] = {}

    async def fake_run_pipeline(**kwargs):
        captured.update(kwargs)

    import nexus.langgraph.llm_pipeline as lp

    monkeypatch.setattr(lp, "run_pipeline", fake_run_pipeline)

    res = CliRunner().invoke(
        app, ["pipeline", "--case", str(case_dir), "--mode", "interpret"]
    )
    assert res.exit_code == 0, res.output
    assert captured.get("case_id") == "CASE-D6B93BF1", captured
    assert "existing case directory" in res.output
