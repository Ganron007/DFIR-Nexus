"""D230: an independent run's traced prompts are checked for earlier runs' results and reviews."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "fresh_run_check", Path(__file__).resolve().parents[1] / "devtools" / "fresh_run_check.py")
fresh = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(fresh)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-FRESH"
    (case / "analysis").mkdir(parents=True)
    (case / "findings.json").write_text(json.dumps([
        {"id": "F-ex-001", "run_id": "M2-20261015T081007-bcdcf9", "status": "REJECTED",
         "title": "Defender CobaltStrike behavioral detections anchored to SRLUpdate.exe"},
        {"id": "F-ex-002", "run_id": "M3-20261015T180442-ce3ab5", "status": "DRAFT",
         "title": "The checked run's own candidate is not an earlier result"},
    ]), encoding="utf-8")
    (case / "analysis" / "examiner_review.md").write_text(
        "- 044 REJECTED: the Metasploit label is wrong, the detection names Cobalt Strike\n", encoding="utf-8")
    return case


def _trace(path: Path, *contents: str) -> Path:
    path.write_text("".join(json.dumps({"seq": n, "messages": [{"role": "user", "content": c}]}) + "\n"
                            for n, c in enumerate(contents, 1)), encoding="utf-8")
    return path


def test_an_earlier_finding_or_review_in_a_prompt_is_reported(tmp_path):
    case = _case(tmp_path)
    trace = _trace(tmp_path / "t.jsonl",
                   "Board so far: evtxecmd rows 1116 Behavior:Win32/CobaltStrike.E!sms",
                   "Prior context: F-ex-001 was rejected by the examiner",
                   "Earlier review:\n- 044 REJECTED: the Metasploit label is wrong,   the detection names Cobalt Strike")
    markers = fresh.earlier_markers(case, "M3-20261015T180442-ce3ab5")
    assert "F-ex-002" not in markers, "the checked run's own results are not earlier ones"
    hits = fresh.scan(trace, markers)
    assert [h["call"] for h in hits] == [2, 3]
    assert hits[0]["markers"] == ["finding id F-ex-001"] and hits[1]["markers"] == ["examiner review"]


def test_a_clean_trace_exits_zero(tmp_path):
    case = _case(tmp_path)
    trace = _trace(tmp_path / "t.jsonl", "evtxecmd rows only")
    assert fresh.main(["--case", str(case), "--trace", str(trace), "--run-id", "M3-20261015T180442-ce3ab5"]) == 0
