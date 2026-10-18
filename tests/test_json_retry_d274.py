"""D274: a corrective retry shows the model where its JSON broke.

On sample S03 (2026-10-18) Muse Spark closed a nested query clause one brace short in its round-1 notes, the retry
said only "could not be read", the second reply had the same mistake, and the Mode 1 loop stopped after one round with
no notes. The reply is that run's, verbatim (tests/fixtures/d274_s03_notes_reply.txt).
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from nexus.langgraph.interpret_loop import run_interpret_loop
from nexus.langgraph.model_json import json_error_note

BROKEN = (Path(__file__).parent / "fixtures" / "d274_s03_notes_reply.txt").read_text(encoding="utf-8")


class _Model:
    def __init__(self, replies: list[str]):
        self.replies = list(replies)
        self.sent: list[str] = []

    async def ainvoke(self, messages):
        self.sent.append(str(messages[-1].get("content") or ""))
        return SimpleNamespace(content=self.replies.pop(0) if self.replies else "[]")


def _plan() -> str:
    return json.dumps({"hypotheses": [{"id": "H1", "statement": "a web download", "why": "zeek http"}],
                       "queries": [{"dsl": "wget", "why": "the download"}]})


def _notes() -> str:
    return json.dumps({"notes": [{"hypothesis": "H1", "status": "confirmed", "evidence": "zeek http row",
                                  "family": "zeek"}], "next": []})


def _findings() -> str:
    return json.dumps([{"title": "Wget download", "observation": "GET /", "interpretation": "download",
                        "confidence": "LOW", "confidence_justification": "one row",
                        "audit_ids": ["n4_query-test-20260918-001"]}])


async def _execute(name: str, payload: dict) -> dict:
    return {"count": 1, "provenance": {"audit_id": "n4_query-test-20260918-001"},
            "hits": [{"family": "zeek", "ts": "2016-07-12T14:50:00Z", "text": "Wget/1.16 GET /"}]}


def test_the_note_names_the_place_the_reply_broke():
    note = json_error_note(BROKEN)
    assert note.startswith("Expecting property name enclosed in double quotes at character 798")
    assert '"case_insensitive": true}}, <<HERE>>{"range"' in note
    assert json_error_note(_notes()) == ""


def test_the_verification_retry_shows_the_place_and_the_loop_goes_on(tmp_path):
    model = _Model([_plan(), BROKEN, _notes(), _findings()])
    result = asyncio.run(run_interpret_loop(
        case_dir=tmp_path, case_id="CASE-TEST", model=model,
        state={"case_context": {"interpret_rounds": "1"}},
        digest={"alerts": []}, digest_md="# Digest", sections=[], execute=_execute,
    ))
    retry = next(s for s in model.sent if "could not be read as the notes JSON" in s)
    assert "<<HERE>>" in retry and "at character 798" in retry and "close every { and [ you open" in retry
    assert result.get("stop_reason") != "verify_reply_unparsed"
