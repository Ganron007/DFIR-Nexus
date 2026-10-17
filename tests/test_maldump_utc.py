"""D259: maldump's quarantine times are UTC, whatever the zone of the host that runs it.

On CASE-C5B04D31 the lane host is at +05:30. maldump writes each quarantine time with ``datetime.fromtimestamp``
(maldump/parsers/windef_parser.py:37), the local time of the host running it, with no offset, and the index read it
as UTC: quarantine.csv said 06:11:57 for SRLUpdate.exe and the task file, where Defender's own 1117 for the same
action (EvtxECmd record 6402) is 2023-01-25 00:41:57Z. 1674607317 is that second. The lane's wrapper runs maldump in a
process whose zone is UTC; these tests give the parent a +05:30 zone so they hold on a host in any zone.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

WRAPPER = Path(__file__).resolve().parents[1] / "tools" / "windows" / "extra" / "maldump" / "run-maldump.py"
QUARANTINED = 1674607317  # 2023-01-25 00:41:57Z, Defender 1117 record 6402
PRINT_IT = f"import datetime; print(datetime.datetime.fromtimestamp({QUARANTINED}))"


@pytest.fixture
def wrapper():
    spec = importlib.util.spec_from_file_location("run_maldump", WRAPPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def lane_host_zone(monkeypatch):
    monkeypatch.setenv("TZ", "IST-5:30")


def _child(code: str, env=None) -> str:
    return subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True,
                          check=True).stdout.strip()


def test_a_process_in_the_lane_hosts_zone_prints_the_shifted_time(lane_host_zone):
    """The control: what quarantine.csv held."""
    assert _child(PRINT_IT) == "2023-01-25 06:11:57"


def test_the_process_maldump_runs_in_prints_utc(lane_host_zone, wrapper):
    assert _child(PRINT_IT, env=wrapper.utc_env()) == "2023-01-25 00:41:57"


def test_maldumps_own_conversion_gives_utc_in_that_process(lane_host_zone, wrapper):
    if importlib.util.find_spec("maldump") is None:
        pytest.skip("maldump is not installed here (pip maldump==0.5.0)")
    code = f"from maldump.parsers import windef_parser as w; print(w.dt.fromtimestamp({QUARANTINED}))"
    assert _child(code, env=wrapper.utc_env()) == "2023-01-25 00:41:57"


def test_the_wrapper_runs_maldump_in_that_process(wrapper, monkeypatch):
    seen = {}

    def run(argv, env=None, **_kw):
        seen.update(argv=argv, env=env)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(wrapper, "_is_admin", lambda: True)
    monkeypatch.setattr(wrapper.subprocess, "run", run)
    assert wrapper.main(["C:/triage", "-m", "-d", "C:/out"]) == 0
    assert seen["argv"] == [sys.executable, "-m", "maldump", "C:/triage", "-m", "-d", "C:/out"]
    assert seen["env"]["TZ"] == "UTC0"


def test_an_unelevated_session_still_reads_nothing(wrapper, monkeypatch):
    monkeypatch.setattr(wrapper, "_is_admin", lambda: False)
    monkeypatch.setattr(wrapper.subprocess, "run", lambda *a, **k: pytest.fail("maldump ran unelevated"))
    assert wrapper.main(["C:/triage", "-m", "-d", "C:/out"]) == 2
