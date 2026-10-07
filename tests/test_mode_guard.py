"""WO-R1F item 3 — one mode per case, with lineage.

The API enforced it; the CLI did not, so SC1 ran all three modes on one case and
staged its findings repeatedly. These tests pin the shared rule and the stamp.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def _case(tmp_path: Path, mode: int | None = None) -> Path:
    case = tmp_path / "CASE-TEST0001"
    case.mkdir()
    body = "case_id: CASE-TEST0001\nstatus: created\n"
    if mode is not None:
        body += f"investigation_mode: '{mode}'\nmode_scheme: canonical\n"
    (case / "CASE.yaml").write_text(body, encoding="utf-8")
    return case


def test_an_unset_mode_is_stamped_at_the_first_run(tmp_path: Path):
    from nexus.case.mode_guard import check_mode, stored_mode

    case = _case(tmp_path)
    assert stored_mode(case) is None

    check_mode(case, 1)

    assert stored_mode(case) == 1


def test_the_same_mode_is_allowed(tmp_path: Path):
    from nexus.case.mode_guard import check_mode

    case = _case(tmp_path, mode=2)
    check_mode(case, 2)  # no raise


def test_a_different_mode_is_refused_with_the_sibling_case_way(tmp_path: Path):
    from nexus.case.mode_guard import ModeConflictError, check_mode

    case = _case(tmp_path, mode=1)
    with pytest.raises(ModeConflictError) as exc:
        check_mode(case, 2)
    message = str(exc.value)
    assert exc.value.stored == 1
    assert exc.value.expected == 2
    assert "SIBLING case" in message
    assert "cross-mode" in message


def test_stamp_mode_is_idempotent(tmp_path: Path):
    from nexus.case.mode_guard import stamp_mode, stored_mode

    case = _case(tmp_path)
    assert stamp_mode(case, 1) is True
    assert stamp_mode(case, 2) is False          # already stamped; never overwritten
    assert stored_mode(case) == 1


def test_stamp_preserves_the_rest_of_the_case_yaml(tmp_path: Path):
    import yaml

    from nexus.case.mode_guard import stamp_mode

    case = _case(tmp_path)
    with (case / "CASE.yaml").open("a", encoding="utf-8") as fh:
        fh.write("name: SC1 base-rd-01\nseverity: medium\n")
    stamp_mode(case, 3)
    meta = yaml.safe_load((case / "CASE.yaml").read_text(encoding="utf-8"))
    assert meta["name"] == "SC1 base-rd-01"
    assert meta["severity"] == "medium"
    assert meta["investigation_mode"] == 3


def test_legacy_mode_scheme_resolves(tmp_path: Path):
    """An older case stored the legacy numbering; resolution must still work."""
    from nexus.case.mode_guard import stored_mode

    case = tmp_path / "CASE-LEGACY01"
    case.mkdir()
    (case / "CASE.yaml").write_text(
        "case_id: CASE-LEGACY01\ninvestigation_mode: '2'\nmode_scheme: legacy\n",
        encoding="utf-8",
    )
    # legacy 2 -> canonical 1 (LLM). The exact value is the mapping's business;
    # what matters is that it resolves rather than raising.
    assert stored_mode(case) is not None


def test_a_case_without_a_yaml_is_left_alone(tmp_path: Path):
    from nexus.case.mode_guard import check_mode, stamp_mode, stored_mode

    missing = tmp_path / "CASE-NOYAML1"
    missing.mkdir()
    assert stored_mode(missing) is None
    assert stamp_mode(missing, 1) is False
    check_mode(missing, 2)  # no raise, nothing to stamp


def test_mode_conflict_message_names_both_modes(tmp_path: Path):
    from nexus.case.mode_guard import ModeConflictError
    from nexus.langgraph.mode_mapping import mode_label

    exc = ModeConflictError(3, 1)
    assert mode_label(3) in str(exc)
    assert mode_label(1) in str(exc)
