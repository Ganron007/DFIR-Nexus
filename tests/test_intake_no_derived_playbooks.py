"""D45: the intake holds only what the examiner set.

The reviewer found 7 derived hunt playbooks written into SC1's `CASE.yaml`
(`external_compromise`, `log_tampering`, `suspicious_execution`, `remote_access`,
`suspicious_autorun`, `powershell_anomaly`, `credential_access`) after 36c had
recorded "no playbooks". `persist_case_intake` derived them from the hypothesis
keyword table in `extra_playbook_names` and stored them beside
`set_by: operator`, so the file misrepresented who decided what.

Playbook *selection* is a runtime act, not a stored fact: `tool_context`,
`playbook_terms_for_families` and the hunt node all call
`extra_playbook_names` on the live context and get the same names without them
ever being attributed to the examiner.
"""
from __future__ import annotations

import yaml

from nexus.langgraph.case_intake import (
    extra_playbook_names,
    persist_case_intake,
)


def _intake_of(case_dir) -> dict:
    return (yaml.safe_load((case_dir / "CASE.yaml").read_text(encoding="utf-8"))
            or {})["intake"]


def test_a_derived_playbook_is_never_persisted(tmp_path):
    case_dir = tmp_path / "INC-1"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: INC-1\n", encoding="utf-8")
    written = persist_case_intake(case_dir, {
        "question": "Compromise suspected.",
        "hypothesis": "external compromise malware persistence",
        "set_by": "operator",
    })
    assert written.get("playbooks") is None, (
        f"the intake stored a playbook the examiner never named: {written.get('playbooks')}")
    assert "playbooks" not in _intake_of(case_dir)


def test_the_hypothesis_is_stored_but_never_translated(tmp_path):
    """The examiner's own words stay; the product's reading of them does not."""
    case_dir = tmp_path / "INC-2"
    case_dir.mkdir()
    persist_case_intake(case_dir, {
        "hypothesis": "insider-threat USB staging",
        "set_by": "operator",
    })
    intake = _intake_of(case_dir)
    assert intake["hypothesis"] == "insider-threat USB staging"
    assert "playbooks" not in intake
    # The same hypothesis still drives selection at runtime, on the live context.
    names = extra_playbook_names(intake)
    assert "usb_activity" in names and "data_staging" in names


def test_an_examiner_named_playbook_is_stored_verbatim(tmp_path):
    case_dir = tmp_path / "INC-3"
    case_dir.mkdir()
    persist_case_intake(case_dir, {"playbooks": "unusual_logon", "set_by": "operator"})
    assert _intake_of(case_dir)["playbooks"] == "unusual_logon"


def test_a_stored_playbook_is_not_augmented_by_the_keyword_table(tmp_path):
    """Merging must not silently extend a list the examiner wrote."""
    case_dir = tmp_path / "INC-4"
    case_dir.mkdir()
    persist_case_intake(case_dir, {
        "playbooks": "unusual_logon",
        "hypothesis": "external compromise malware persistence",
        "set_by": "operator",
    })
    assert _intake_of(case_dir)["playbooks"] == "unusual_logon"


def test_an_earlier_derived_playbook_is_dropped_on_the_next_write(tmp_path):
    """A case written before the fix must not keep its derived list forever."""
    case_dir = tmp_path / "INC-5"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text(
        yaml.dump({"case_id": "INC-5", "intake": {
            "question": "Compromise suspected.",
            "playbooks": "external_compromise,log_tampering",
            "set_by": "operator",
        }}), encoding="utf-8")
    persist_case_intake(case_dir, {"question": "Compromise suspected."})
    assert "playbooks" not in _intake_of(case_dir)
