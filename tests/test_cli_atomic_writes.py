"""WO-19: CLI reject/todo writes are atomic (temp + replace) and locked."""
from __future__ import annotations

import contextlib
import json


def _case(root, name="CASE-CLI00001", findings=()):
    case = root / name
    case.mkdir(parents=True, exist_ok=True)
    (case / "CASE.yaml").write_text(
        f"case_id: {name}\nstatus: open\n", encoding="utf-8"
    )
    if findings is not None:
        (case / "findings.json").write_text(json.dumps(list(findings)), encoding="utf-8")
    return case


def test_reject_is_atomic_and_a_failed_replace_keeps_the_original(tmp_path, monkeypatch):
    from nexus.cli.main import _reject_finding

    case = _case(tmp_path, findings=[{"id": "F1", "status": "DRAFT", "title": "t"}])
    result = _reject_finding(case, "F1", "analyst", "reason")
    assert result["status"] == "REJECTED"
    rows = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert rows[0]["status"] == "REJECTED"

    other = _case(tmp_path / "two", name="CASE-CLI00002",
                  findings=[{"id": "F1", "status": "DRAFT", "title": "t"}])

    def _boom(src, dst, *a, **k):
        raise OSError("disk full")

    monkeypatch.setattr("os.replace", _boom)
    with contextlib.suppress(OSError):
        _reject_finding(other, "F1", "analyst", "reason")
    rows = json.loads((other / "findings.json").read_text(encoding="utf-8"))
    assert rows[0]["status"] == "DRAFT", (
        "a failure between the temp write and the replace must leave the original intact"
    )


def test_todo_cli_add_and_complete_write_back(tmp_path):
    from typer.testing import CliRunner

    from nexus.cli.todo import app as todo_app

    case = _case(tmp_path, findings=None)
    (case / "todos.json").write_text("[]", encoding="utf-8")
    runner = CliRunner()

    r = runner.invoke(todo_app, ["add", "collect the CD", "--case", str(case)])
    assert r.exit_code == 0, r.output
    todos = json.loads((case / "todos.json").read_text(encoding="utf-8"))
    assert len(todos) == 1 and todos[0]["status"] == "open"

    tid = todos[0]["todo_id"]
    r = runner.invoke(todo_app, ["complete", tid, "--case", str(case)])
    assert r.exit_code == 0, r.output
    todos = json.loads((case / "todos.json").read_text(encoding="utf-8"))
    assert todos[0]["status"] == "completed"
    assert todos[0]["completed_at"]
