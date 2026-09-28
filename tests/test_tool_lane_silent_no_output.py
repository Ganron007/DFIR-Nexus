"""A parser that writes nothing must not be recorded as OK.

Found by the debug-mode format sweep: 10 LNK files produced 10 LECmd jobs, all
statused **OK**, and zero evidence. The bundled LECmd 1.5 prints "Administrator
privileges not found" and exits 0 without writing a CSV. The ledger said the
evidence was parsed when it was not — a silent coverage gap, which is the exact
failure class the ledger exists to prevent.
"""
from __future__ import annotations

from nexus.langgraph.tool_lane import (
    ToolJob,
    _produced_expected_output,
    _soft_fail_reason,
)


def _job(argv: list[str]) -> ToolJob:
    return ToolJob(host="windows", tool="lecmd", argv=argv, purpose="LNK", timeout=300)


def test_clean_exit_with_no_output_file_is_not_ok(tmp_path):
    out = tmp_path / "lecmd"
    out.mkdir()
    job = _job(["lecmd", "-f", str(tmp_path / "a.lnk"), "--csv", str(out), "--csvf", "a.csv"])
    assert _produced_expected_output(job) is False


def test_written_csv_counts_as_produced(tmp_path):
    out = tmp_path / "lecmd"
    out.mkdir()
    (out / "a.csv").write_text("h1,h2\nv1,v2\n", encoding="utf-8")
    job = _job(["lecmd", "-f", str(tmp_path / "a.lnk"), "--csv", str(out), "--csvf", "a.csv"])
    assert _produced_expected_output(job) is True


def test_empty_output_file_is_not_produced(tmp_path):
    out = tmp_path / "lecmd"
    out.mkdir()
    (out / "a.csv").write_text("", encoding="utf-8")
    job = _job(["lecmd", "-f", str(tmp_path / "a.lnk"), "--csv", str(out), "--csvf", "a.csv"])
    assert _produced_expected_output(job) is False


def test_admin_privilege_warning_alone_is_not_a_soft_failure(tmp_path):
    """That warning is noise, not a failure signal.

    The bundled Zimmerman 1.5 tools print it whether or not they then write a
    valid CSV - a real prefetch run showed it *and* produced 24 correct CSVs.
    Trusting stdout here would fail jobs that succeeded, so the decision rests
    on whether output landed (see the other tests in this file).
    """
    out = tmp_path / "pecmd"
    out.mkdir()
    (out / "a.csv").write_text("h1,h2\nv1,v2\n", encoding="utf-8")
    result = {
        "stdout": "PECmd version 1.5.0.0\n\nWarning: Administrator privileges not found!\n",
        "output_saved_to": str(out / "a.csv"),
    }
    assert _soft_fail_reason(result) == ""


def test_clean_stdout_is_not_a_soft_failure(tmp_path):
    out = tmp_path / "lecmd"
    out.mkdir()
    (out / "a.csv").write_text("h1\nv1\n", encoding="utf-8")
    result = {
        "stdout": "LECmd version 2026.5.0\nProcessed 1 file\n",
        "output_saved_to": str(out / "a.csv"),
    }
    assert _soft_fail_reason(result) == ""


def test_output_saved_to_counts_as_produced(tmp_path):
    saved = tmp_path / "stdout.txt"
    saved.write_text("some output", encoding="utf-8")
    job = _job(["lecmd", "-f", "a.lnk"])
    job.output_saved_to = str(saved)
    assert _produced_expected_output(job) is True


def test_directory_target_with_any_output_counts(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "something.json").write_text("{}", encoding="utf-8")
    job = _job(["tool", "--csv", str(out), "input.lnk"])
    assert _produced_expected_output(job) is True


def test_positional_directory_with_csv_counts(tmp_path):
    """A tool that writes into a directory passed positionally is still a success."""
    out = tmp_path / "out"
    out.mkdir()
    (out / "result.csv").write_text("h\nv\n", encoding="utf-8")
    job = _job(["tool", "-d", str(out), "input.lnk"])
    assert _produced_expected_output(job) is True


def test_dash_out_target_must_have_bytes(tmp_path):
    """DeepBlueCLI names its target `-Out` (capital O, single dash).

    The check matched flags case-sensitively, so it never looked at the target
    and accepted the stdout capture instead: the lane recorded OK on a run whose
    JSON was 0 bytes and whose capture held a Get-WinEvent error.
    """
    out = tmp_path / "deepblue.json"
    out.write_text("", encoding="utf-8")
    job = _job(["run-deepblue.ps1", "-Evtx", str(tmp_path), "-Out", str(out)])
    assert _produced_expected_output(job) is False


def test_dash_out_target_with_records_is_produced(tmp_path):
    out = tmp_path / "deepblue.json"
    out.write_text('[{"EventID": 4625}]', encoding="utf-8")
    job = _job(["run-deepblue.ps1", "-Evtx", str(tmp_path), "-Out", str(out)])
    assert _produced_expected_output(job) is True


def test_output_flag_is_matched_case_insensitively(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "a.json").write_text("[]", encoding="utf-8")
    job = _job(["tool", "--Output", str(out), "input"])
    assert _produced_expected_output(job) is True


def test_output_dir_with_only_empty_files_is_not_produced(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "a.json").write_text("", encoding="utf-8")
    job = _job(["tool", "--Output", str(out), "input"])
    assert _produced_expected_output(job) is False
