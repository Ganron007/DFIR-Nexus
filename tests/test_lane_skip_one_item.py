"""`nexus lane skip --item TOOL` records an examiner skip for that tool's unprocessed items only.

The gate keeps every other unprocessed item pending, so the case stays blocked until those are
decided too. The examiner's password is the examiner's: the test stands in for the prompt.
"""
import json
from pathlib import Path

from typer.testing import CliRunner


def _case(tmp_path: Path) -> Path:
    case_dir = tmp_path / "CASE-SKIP0001"
    (case_dir / "analysis").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("case_id: CASE-SKIP0001\nexaminer: tester\n", encoding="utf-8")
    gate = {
        "schema": 1,
        "status": "blocked",
        "unprocessed": [
            {"tool": "logfileparser", "purpose": "NTFS $LogFile (H)", "reason": "no output"},
            {"tool": "wxtcmd", "purpose": "ActivitiesCache", "reason": "failed"},
        ],
        "waiting_sift": [],
        "not_applicable": [],
        "jobs": [],
    }
    (case_dir / "analysis" / "lane_gate.json").write_text(json.dumps(gate), encoding="utf-8")
    return case_dir


def test_one_tool_is_skipped_and_the_other_unprocessed_item_stays_pending(tmp_path, monkeypatch):
    import getpass

    import nexus.auth as auth
    from nexus.cli.main import app

    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "pw")
    monkeypatch.setattr(auth, "verify_password", lambda who, pw: True)
    case_dir = _case(tmp_path)

    result = CliRunner().invoke(app, [
        "lane", "skip", "--case", str(case_dir), "--item", "logfileparser", "--reason", "approved",
    ])

    assert result.exit_code == 0, result.output
    gate = json.loads((case_dir / "analysis" / "lane_gate.json").read_text(encoding="utf-8"))
    assert [s["tool"] for s in gate["examiner_skips"]] == ["logfileparser"]
    assert gate["examiner_skips"][0]["reason"] == "approved"
    assert gate["status"] == "blocked", "wxtcmd is still unprocessed, so the case stays blocked"


def test_an_item_that_matches_nothing_is_refused_before_the_password_prompt(tmp_path, monkeypatch):
    import getpass

    from nexus.cli.main import app

    def _must_not_prompt(prompt=""):
        raise AssertionError("no password should be asked for when no item matches")

    monkeypatch.setattr(getpass, "getpass", _must_not_prompt)
    case_dir = _case(tmp_path)

    result = CliRunner().invoke(app, [
        "lane", "skip", "--case", str(case_dir), "--item", "nosuchtool", "--reason", "x",
    ])

    assert result.exit_code == 1, result.output
    assert "No unprocessed item for tool(s): nosuchtool" in result.output
