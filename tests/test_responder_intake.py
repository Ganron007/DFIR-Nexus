"""D224: the responders' own tools and acquisition window, set by the examiner, reach every mode.

Every mode read the acquisition as the incident: F-Response removing its own firewall rules
(`C:\\Windows\\subject_srv.exe`, "F-Response LM.SUB.EXA") was staged as anti-forensics (DRAFT 042) and
Mode 3 seats asked whether F-Response was attacker tooling. The statement comes from the examiner's
intake only; nothing is inferred from the evidence.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

TOOLS = "F-Response (C:\\Windows\\subject_srv.exe, service F-Response Subject)"
WINDOW = "2023-01-25 14:00-16:00 UTC"


def _case(tmp_path: Path, monkeypatch) -> Path:
    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", tmp_path)
    case = tmp_path / "CASE-RESPONDER"
    (case / "analysis").mkdir(parents=True)
    (case / "CASE.yaml").write_text(yaml.safe_dump({"case_id": case.name, "status": "created"}), encoding="utf-8")
    return case


def test_the_examiner_sets_the_responders_through_intake(tmp_path, monkeypatch):
    from nexus.cli.case_cmd import app

    case = _case(tmp_path, monkeypatch)
    result = CliRunner().invoke(app, ["intake", "--case", case.name, "--responder-tools", TOOLS,
                                      "--acquisition-window", WINDOW])
    assert result.exit_code == 0, result.output
    intake = yaml.safe_load((case / "CASE.yaml").read_text(encoding="utf-8"))["intake"]
    assert intake["responder_tools"] == TOOLS and intake["acquisition_window"] == WINDOW
    assert intake["set_by"] == "operator"


def test_every_mode_is_told_what_the_responders_did(tmp_path, monkeypatch):
    from nexus.langgraph.case_digest import render_digest_markdown
    from nexus.langgraph.case_intake import persist_case_intake
    from nexus.modes.multi_agent import _seat_with_model

    case = _case(tmp_path, monkeypatch)
    intake = persist_case_intake(case, {"responder_tools": TOOLS, "acquisition_window": WINDOW,
                                        "set_by": "operator"})
    # Mode 1: the digest.
    digest = render_digest_markdown({"intake": intake})
    assert "## Responder activity (examiner intake, set by operator):" in digest and TOOLS in digest

    # Modes 2 and 3: the shared context of every prompt, seen in a real seat call.
    sent: list[str] = []

    class Model:
        model_name = "scripted"
        provider = "test"

        def invoke(self, messages):
            sent.append("\n".join(str(m.get("content") or "") for m in messages))

            class Reply:
                content = json.dumps({"claims": []})
            return Reply()

    class Sink:
        def emit(self, event):
            return None

    monkeypatch.setenv("NEXUS_MODE3_ROUNDS", "1")
    _seat_with_model({"role": "evidence", "family": "evtxecmd", "why": "domain seat",
                      "question": "Compromise suspected."}, case_dir=case, model=Model(), run_id="M3-resp",
                     sink=Sink(), board_digest="(empty)", superstep=1)
    assert "RESPONDER ACTIVITY (examiner intake, set by operator):" in sent[0]
    assert f"acquisition window: {WINDOW}" in sent[0]


def test_nothing_is_said_when_the_examiner_set_nothing(tmp_path, monkeypatch):
    from nexus.langgraph.case_intake import responder_block
    from nexus.modes.multi_role import _investigative_extras

    case = _case(tmp_path, monkeypatch)
    assert responder_block(case) == ""
    assert "RESPONDER ACTIVITY" not in _investigative_extras(case)
