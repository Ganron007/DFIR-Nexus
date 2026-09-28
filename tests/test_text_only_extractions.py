"""Text-only extractions must reach the index, and history is investigative text.

Both defects were found on the real corpus, not by reading code.

**History was not recognised.** `srl-h-ConsoleHost_history.txt` - PSReadLine
history, the primary record of what the user typed - produced a single
`(discovery) SKIP — No recognized evidence shape` row. The case indexed 0 docs
and staged 0 findings and reported success. The matcher required the name to
equal `ConsoleHost_history.txt`, but an examiner exporting one user's history
names the file after the user, so the real artifact never matched.

**stdout-only output was unreachable.** The indexer skips `*_stdout.txt` as
scratch, which is right when a structured CSV sits beside it and wrong when it
does not. `strings`, `sigcheck` and the setupapi route produce stdout and nothing
else, so setupapi, rdp and samples each parsed, recorded OK, and contributed zero
rows - the silent-gap shape this project forbids.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from nexus.langgraph.tool_lane import (
    ToolJob,
    _is_history_text,
    _plan_single_artifact,
    _promote_stdout,
    _structured_output_present,
    is_host_evidence,
)

# ---------------------------------------------------------------- history

REAL_HISTORY = [
    "srl-h-ConsoleHost_history.txt",           # the actual corpus file
    "ConsoleHost_history.txt",
    "PSReadLine/ConsoleHost_history.txt",
    "fredr-ConsoleHost_history.txt",
    ".bash_history",
    "bash_history",
    "root-bash_history.txt",
    "zsh_history",
    "user.zsh_history",
    "powershell_transcript.txt",
]

NOT_HISTORY = [
    "random.txt", "notes.md", "readme.txt", "webcache.csv", "mystery.bin",
    "history_of_the_world.pdf", "bashtool.exe", "zshrc_backup.bak",
]


@pytest.mark.parametrize("name", REAL_HISTORY)
def test_console_and_shell_history_is_recognised(tmp_path, name):
    f = tmp_path / Path(name).name
    f.write_text("Get-ChildItem -Recurse\n", encoding="utf-8")
    assert is_host_evidence(f) is True, name
    jobs = _plan_single_artifact(f, tmp_path / "ex")
    assert jobs, f"{name} recognised but nothing scheduled"
    assert jobs[0].status != "SKIP" or jobs[0].reason


@pytest.mark.parametrize("name", NOT_HISTORY)
def test_the_history_match_is_not_a_catch_all(name):
    assert _is_history_text(name) is False, name


def test_history_is_staged_verbatim_so_its_content_is_reachable(tmp_path):
    """No parser exists, so the content must be staged or it is never read."""
    f = tmp_path / "srl-h-ConsoleHost_history.txt"
    f.write_text("Invoke-Mimikatz\n", encoding="utf-8")
    jobs = _plan_single_artifact(f, tmp_path / "ex")
    assert len(jobs) == 1
    assert jobs[0].tool == "strings", jobs[0].tool
    assert str(f) in jobs[0].argv


# ------------------------------------------------------ stdout promotion

def _job(**extra) -> ToolJob:
    j = ToolJob(host="windows", tool="strings",
                argv=["strings64", "-nobanner", "C:/ev/setupapi.dev.log"],
                purpose="Device install log", timeout=300)
    for k, v in extra.items():
        setattr(j, k, v)
    return j


def test_a_stdout_only_job_has_its_capture_promoted(tmp_path):
    """The extraction is the stdout here, so it must be indexed under its own name."""
    saved = tmp_path / "20260101_strings_stdout.txt"
    saved.write_text("Device Install: USB\\VID_0781\n", encoding="utf-8")
    job = _job(output_saved_to=str(saved), output_files=[str(saved)])

    assert _structured_output_present(job) is False
    promoted = _promote_stdout(job, str(saved))
    assert promoted, "nothing was promoted"
    p = Path(promoted)
    assert p.is_file()
    assert "_stdout" not in p.name, "the promoted name would be skipped by the indexer"
    # _stem strips the extension, so the source is named by its stem plus a
    # path-derived hash - enough to tell two same-named sources apart.
    assert "setupapi.dev" in p.name, "the source is not identifiable from the name"
    assert p.read_text(encoding="utf-8") == saved.read_text(encoding="utf-8")


def test_a_job_with_a_real_csv_is_left_alone(tmp_path):
    """Scratch stays scratch when there is a structured artifact beside it."""
    out = tmp_path / "lecmd"
    out.mkdir()
    (out / "a.csv").write_text("h\nv\n", encoding="utf-8")
    saved = tmp_path / "lecmd_stdout.txt"
    saved.write_text("LECmd version 2026.5.0\nProcessed 1 file\n", encoding="utf-8")

    job = _job(tool="lecmd", output_saved_to=str(saved),
               output_files=[str(out / "a.csv"), str(saved)])
    # The caller only promotes when this is False, so with a real CSV present
    # the stdout capture stays scratch.
    assert _structured_output_present(job) is True


def test_promotion_of_a_missing_file_is_a_no_op(tmp_path):
    assert _promote_stdout(_job(), "") == ""
    assert _promote_stdout(_job(), str(tmp_path / "nope.txt")) == ""


def test_promotion_of_an_empty_capture_is_a_no_op(tmp_path):
    """An empty capture is not an extraction, and promoting it would fake one."""
    saved = tmp_path / "empty_stdout.txt"
    saved.write_text("", encoding="utf-8")
    assert _promote_stdout(_job(), str(saved)) == ""


def test_promotion_is_idempotent(tmp_path):
    """A re-run must not produce a second copy under a different name."""
    saved = tmp_path / "20260101_strings_stdout.txt"
    saved.write_text("content\n", encoding="utf-8")
    job = _job()
    a = _promote_stdout(job, str(saved))
    b = _promote_stdout(job, str(saved))
    assert a == b
    assert len(list(tmp_path.glob("strings-*.txt"))) == 1


def test_promotion_targets_the_run_dir_when_one_is_known(tmp_path):
    """The MCP tool saves stdout under the *case* dir; the indexer walks the *run*
    dir. Promoting beside the source produced 60 correctly-named task-XML
    artifacts that nothing read - the files existed, the ledger said OK, and the
    index stayed at 3 files.
    """
    src = tmp_path / "case" / "extractions" / "strings"
    src.mkdir(parents=True)
    saved = src / "20260928T031606_strings_stdout.txt"
    saved.write_text("Task SID S-1-5-21-528816539\n", encoding="utf-8")
    run_ext = tmp_path / "case" / "runs" / "RUN-1" / "extractions"
    run_ext.mkdir(parents=True)

    promoted = _promote_stdout(_job(), str(saved), dest=run_ext)
    assert promoted, "nothing promoted"
    p = Path(promoted)
    assert run_ext in p.parents, f"promoted outside the run dir: {p}"
    assert p.is_file()
    # And the source is left alone - the audit trail points at it.
    assert saved.is_file()


def test_promotion_still_works_with_no_destination(tmp_path):
    """Without a resolved run dir it falls back to beside the source: visible in
    the wrong place beats lost."""
    saved = tmp_path / "strings_stdout.txt"
    saved.write_text("content\n", encoding="utf-8")
    promoted = _promote_stdout(_job(), str(saved), dest=None)
    assert promoted and Path(promoted).is_file()


def test_the_promoted_name_is_filesystem_safe(tmp_path):
    saved = tmp_path / "s_stdout.txt"
    saved.write_text("x\n", encoding="utf-8")
    job = _job(argv=["strings64", "-nobanner", "C:/ev/a file (1).log"])
    promoted = _promote_stdout(job, str(saved))
    name = Path(promoted).name
    assert not any(ch in name for ch in '<>:"/\\|?*')


def test_the_indexer_would_not_have_skipped_the_promoted_name():
    """The whole point: the promoted name must not be in _SKIP_SUFFIXES."""
    from nexus.langgraph.query_pack import _SKIP_SUFFIXES

    promoted = "strings-setupapi.dev.log-1a2b3c4d.txt"
    assert not promoted.endswith(tuple(_SKIP_SUFFIXES)), (
        "the promoted artifact would be skipped by the indexer"
    )
