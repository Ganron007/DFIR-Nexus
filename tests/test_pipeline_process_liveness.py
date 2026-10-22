from __future__ import annotations

import ctypes
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


class _FakeFunction:
    def __init__(self, result):
        self.result = result
        self.restype = None

    def __call__(self, *_args):
        return self.result


def _mock_windows_probe(monkeypatch, *, open_result, error=0, exit_query_result=1):
    from nexus.langgraph import pipeline_runs

    kernel32 = SimpleNamespace(
        OpenProcess=_FakeFunction(open_result),
        GetExitCodeProcess=_FakeFunction(exit_query_result),
        CloseHandle=_FakeFunction(1),
    )
    monkeypatch.setattr(pipeline_runs, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda *_args, **_kwargs: kernel32,
        raising=False,
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: error, raising=False)
    return pipeline_runs


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (5, True),   # ERROR_ACCESS_DENIED: the PID may still be alive.
        (87, False), # ERROR_INVALID_PARAMETER: a positive PID is absent.
        (6, True),   # ERROR_INVALID_HANDLE/other failures are ambiguous.
    ],
)
def test_windows_openprocess_failure_only_reaps_confirmed_absence(
    monkeypatch, error, expected
):
    pipeline_runs = _mock_windows_probe(monkeypatch, open_result=0, error=error)

    assert pipeline_runs.process_alive(24680) is expected


def test_windows_exit_code_query_failure_is_conservatively_live(monkeypatch):
    pipeline_runs = _mock_windows_probe(
        monkeypatch, open_result=123, exit_query_result=0,
    )

    assert pipeline_runs.process_alive(24680) is True


def test_access_denied_does_not_reap_run_manifest(tmp_path: Path, monkeypatch):
    from nexus.langgraph import pipeline_runs

    case = tmp_path / "CASE-REAPER"
    run = pipeline_runs.create_run(case, "tools")
    manifest_path = run.path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["pid"] = 24680
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    _mock_windows_probe(monkeypatch, open_result=0, error=5)

    assert pipeline_runs.reap_dead_runs(case) == []
    after = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert after["status"] == "running"


def test_posix_ambiguous_oserror_is_conservatively_live(monkeypatch):
    from nexus.langgraph import pipeline_runs

    def fail_to_probe(_pid, _sig):
        raise OSError("process probe unavailable")

    monkeypatch.setattr(
        pipeline_runs,
        "os",
        SimpleNamespace(name="posix", kill=fail_to_probe),
    )

    assert pipeline_runs.process_alive(24680) is True


def test_new_pipeline_run_reaps_confirmed_dead_case_runs_first(monkeypatch):
    from nexus.config import settings
    from nexus.langgraph import pipeline_runs
    from nexus.langgraph.llm_pipeline import register_evidence

    case_id = "CASE-RECOVERY"
    case_dir = settings.cases_root / case_id
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(f"case_id: {case_id}\n", encoding="utf-8")
    old_run = pipeline_runs.create_run(case_dir, "tools")
    monkeypatch.setattr(pipeline_runs, "process_alive", lambda _pid: False)

    # This reused-case path has no awaited tool calls. Drive it directly so the
    # regression does not need Windows asyncio's self-pipe socketpair; if a
    # future change awaits external I/O here, the test fails instead of hanging.
    recovery = register_evidence({
        "case_id": case_id,
        "pipeline_mode": "tools",
        "case_context": {},
        "evidence_path": "",
        "evidence_paths": [],
    }, {"case_init": object()})
    try:
        recovery.send(None)
    except StopIteration as completed:
        result = completed.value
    else:
        recovery.close()
        pytest.fail("no-tool recovery path unexpectedly awaited external I/O")

    old_manifest = json.loads((old_run.path / "manifest.json").read_text(encoding="utf-8"))
    new_manifest = json.loads(
        (settings.cases_root / case_id / "runs" / result["run_id"] / "manifest.json")
        .read_text(encoding="utf-8")
    )
    assert old_manifest["status"] == "interrupted"
    assert new_manifest["status"] == "running"
    assert result["run_id"] != old_run.run_id
    assert any(old_run.run_id in step and "interrupted" in step for step in result["step_log"])
