"""Pre-rename case artifacts: chat action ids, saved answers, run options.

The final mode numbering renamed the persisted labels, but existing case data
is never rewritten. These tests pin the read fallbacks that keep old cases
working and the canonical names new writes use.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.case.chat import append_chat, canonical_action, load_chat
from nexus.case.run_options import load_run_options, run_options_path, save_run_options
from nexus.case.saved_answers import (
    append_saved_answer,
    load_saved_answers,
    saved_answers_path,
)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-LEGACY"
    (case / "analysis").mkdir(parents=True)
    return case


def test_canonical_action_maps_both_legacy_families():
    assert canonical_action("mode2_iter0") == "mode1_iter0"
    assert canonical_action("mode2_proposal") == "mode1_proposal"
    assert canonical_action("mode2_done") == "mode1_done"
    assert canonical_action("mode3_plan") == "mode2_plan"
    assert canonical_action("mode3_execute") == "mode2_execute"
    assert canonical_action("mode3_draft_finding") == "mode2_draft_finding"
    assert canonical_action("steer_answer") == "steer_answer"
    assert canonical_action("answer_saved") == "answer_saved"


def test_append_chat_writes_canonical_action(tmp_path):
    case = _case(tmp_path)
    entry = append_chat(case, "llm", "mode2_proposal", "text")
    assert entry["action"] == "mode1_proposal"
    raw = (case / "chat.jsonl").read_text(encoding="utf-8")
    assert '"action": "mode1_proposal"' in raw


def test_load_chat_normalizes_historical_entries(tmp_path):
    case = _case(tmp_path)
    (case / "chat.jsonl").write_text(
        '{"ts": "t1", "role": "llm", "action": "mode3_plan", "text": "p"}\n'
        '{"ts": "t2", "role": "llm", "action": "mode2_iter0", "text": "i"}\n'
        '{"ts": "t3", "role": "examiner", "action": "ask", "text": "q"}\n',
        encoding="utf-8",
    )
    actions = [e["action"] for e in load_chat(case, limit=0)]
    assert actions == ["mode2_plan", "mode1_iter0", "ask"]


def test_saved_answers_canonical_and_legacy_merge(tmp_path):
    case = _case(tmp_path)
    (case / "analysis" / "mode2_saved_answers.json").write_text(
        json.dumps([{"ts": "t1", "question": "legacy"}]), encoding="utf-8"
    )
    assert [r["ts"] for r in load_saved_answers(case)] == ["t1"]

    merged = append_saved_answer(case, {"ts": "t2", "question": "new"})
    assert saved_answers_path(case).is_file()
    assert [r["ts"] for r in merged] == ["t2", "t1"]

    # Re-saving a legacy row is idempotent; the legacy file is never touched.
    again = append_saved_answer(case, {"ts": "t1", "question": "again"})
    assert [r["ts"] for r in again] == ["t2", "t1"]
    legacy = json.loads(
        (case / "analysis" / "mode2_saved_answers.json").read_text(encoding="utf-8")
    )
    assert legacy == [{"ts": "t1", "question": "legacy"}]


def test_run_options_canonical_write_and_legacy_read(tmp_path):
    case = _case(tmp_path)
    (case / "analysis" / "mode2_run_options.json").write_text(
        json.dumps({"interpret_rounds": 2, "context_window": 16000}), encoding="utf-8"
    )
    assert load_run_options(case)["interpret_rounds"] == 2

    save_run_options(case, {"interpret_rounds": 4, "context_window": 32000})
    assert run_options_path(case).is_file()
    # Canonical wins over the legacy file once it exists.
    assert load_run_options(case)["interpret_rounds"] == 4
    legacy = json.loads(
        (case / "analysis" / "mode2_run_options.json").read_text(encoding="utf-8")
    )
    assert legacy["interpret_rounds"] == 2
