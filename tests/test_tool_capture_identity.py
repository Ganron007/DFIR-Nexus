"""D515: real tool exports remain citable when captures share a clock tick."""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from nexus.case import outputs

FIXTURES = Path(__file__).parent / "fixtures" / "d289_tool_headers"


class _FrozenClock:
    @staticmethod
    def now(tz=None):
        return datetime(2026, 10, 31, 1, 43, 48, tzinfo=UTC)


def _capture(case, ordinal):
    # Both bodies are existing verbatim real JLECmd exports, not invented events.
    source = FIXTURES / ("jlecmd-auto.csv" if ordinal % 2 == 0 else "jlecmd-custom.csv")
    body = source.read_text(encoding="utf-8-sig")
    result = outputs.persist_tool_output(
        tool_key="jlecmd",
        stdout=body,
        command=f"jlecmd --csv {source.name}",
        purpose=source.name,
        case_dir=case,
        extractions_root=case / "runs" / "capture-test" / "extractions",
    )
    return result, body


def _assert_retained(captures):
    paths = [item["path"] for result, _ in captures for item in result["output_files"]]
    assert len(set(paths)) == len(paths), "one invocation replaced another capture"
    for result, body in captures:
        assert not result["warning"]
        by_kind = {item["kind"]: item for item in result["output_files"]}
        assert set(by_kind) == {"stdout", "meta"}
        assert Path(by_kind["stdout"]["path"]).read_text(encoding="utf-8") == body
        for item in by_kind.values():
            assert hashlib.sha256(Path(item["path"]).read_bytes()).hexdigest() == item["sha256"]
        metadata = json.loads(Path(by_kind["meta"]["path"]).read_text(encoding="utf-8"))
        assert metadata["stdout_path"] == by_kind["stdout"]["path"]
        assert metadata["stdout_sha256"] == by_kind["stdout"]["sha256"]
        # Existing suffix consumers (SIFT materialization and RECmd timezone discovery).
        assert Path(by_kind["meta"]["path"]).name.endswith("_jlecmd_meta.json")
        assert Path(by_kind["stdout"]["path"]).with_name(
            Path(by_kind["stdout"]["path"]).name.removesuffix("_stdout.txt") + "_meta.json"
        ) == Path(by_kind["meta"]["path"])


def test_sequential_same_tick_captures_keep_their_contents_and_hashes(tmp_path, monkeypatch):
    monkeypatch.setattr(outputs, "datetime", _FrozenClock)
    _assert_retained([_capture(tmp_path, n) for n in range(2)])


def test_concurrent_same_tick_captures_keep_their_contents_and_hashes(tmp_path, monkeypatch):
    monkeypatch.setattr(outputs, "datetime", _FrozenClock)
    with ThreadPoolExecutor(max_workers=8) as pool:
        captures = list(pool.map(lambda n: _capture(tmp_path, n), range(32)))
    _assert_retained(captures)
