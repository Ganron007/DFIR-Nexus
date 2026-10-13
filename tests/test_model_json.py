r"""Model JSON with Windows paths written with single backslashes (2026-10-14).

A 10,160-character Mode 1 plan failed to parse at ``"C:\Windows\System32\..."`` because ``\W`` is
not a JSON escape; the run read it as "no plan". The repair doubles only the backslashes that do
not begin a valid escape, so the text the model meant survives exactly.
"""
from __future__ import annotations

import json

import pytest

from nexus.langgraph.model_json import loads_model_json, repair_invalid_escapes


def test_a_windows_path_with_single_backslashes_reads_as_the_path():
    text = r'{"path": "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"}'
    with pytest.raises(json.JSONDecodeError):
        json.loads(text)
    assert loads_model_json(text) == {
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}


def test_valid_escapes_are_left_as_they_are():
    text = r'{"a": "line\nbreak", "q": "say \"hi\"", "b": "x\\y", "u": "\u00e9", "s": "a\/b"}'
    assert loads_model_json(text) == json.loads(text)
    assert repair_invalid_escapes(text) == text


def test_an_escaped_backslash_is_never_split():
    # \\W is an escaped backslash followed by W: valid, and must stay one backslash.
    assert loads_model_json(r'{"p": "C:\\Windows"}') == {"p": "C:\\Windows"}


def test_a_bad_unicode_escape_is_repaired_as_text():
    # \users is not a \uXXXX escape: in a path it is a backslash and "users".
    assert loads_model_json(r'{"p": "C:\users\x"}') == {"p": "C:\\users\\x"}


def test_a_reply_broken_another_way_still_fails():
    with pytest.raises(json.JSONDecodeError):
        loads_model_json('{"a": 1,,}')


def test_the_interpret_loop_reads_a_plan_with_windows_paths():
    from nexus.langgraph.interpret_loop import _normalize_plan, _parse_json_blob

    reply = ('Plan:\n{"hypotheses": [{"id": "H1", "statement": "PowerShell ran from '
             r'C:\Windows\System32\WindowsPowerShell"}], "queries": [{"es": {"query": '
             r'{"wildcard": {"text.wc": {"value": "*C:\Windows\Temp*"}}}}, "why": "x"}]}')
    plan = _normalize_plan(_parse_json_blob(reply))
    assert len(plan["hypotheses"]) == 1 and len(plan["items"]) == 1


def test_findings_with_windows_paths_are_candidates():
    from nexus.langgraph.hunt_parser import parse_hunt_candidates

    reply = ('```json\n[{"title": "Encoded PowerShell", "observation": "ran '
             r'C:\Windows\System32\cmd.exe", "interpretation": "x"}]' '\n```')
    candidates = parse_hunt_candidates([{"role": "assistant", "content": reply}])
    assert candidates and "C:\\Windows\\System32\\cmd.exe" in candidates[0]["observation"]
