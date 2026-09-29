"""A staged extraction must land where the indexer walks.

Found live in the examiner walkthrough of R1, step 3, and it is the second half
of the stdout-promotion fix from earlier today.

The MCP command tool saves stdout under the **case** dir
(`<case>/extractions/<tool>/`). The indexer walks the **run** dir
(`<case>/runs/RUN-.../extractions/`). I promoted the stdout capture beside its
source, which produced sixty correctly-named task-XML artifacts that nothing ever
read:

    ledger: 60 strings rows, all OK, each with 3 output_files
    index : 3 files, 81,107 docs      <- only the three EVTX CSVs
    case  : extractions/strings/ 152 files, none indexed

The files existed, the ledger said OK, and the evidence contributed zero rows.
The ledger cannot catch this: it records that a file was written, not that
anything reads it.

Promotion now targets the run extraction dir, resolved through
`resolve_tools_extractions` - the same call the indexer makes, so the two cannot
disagree. Verified live: six task definitions produced 293 indexed docs from six
files, named `strings-<task>-<hash>.txt`.

Also fixes the discovery SKIP message, which listed the accepted evidence shapes
and had gone stale - task definitions, history files and the WMI repository are
all recognised now and none were named. An examiner reading it would go looking
for the wrong problem.

And routes the WMI repository: `wmi/OBJECTS.DATA` (31 MB, the other anchor
artifact of R1) was skipped as an unrecognised blob. No WMI parser exists in the
catalogue, so its content is staged with strings - which is what surfaces
`__EventFilter`, `CommandLineEventConsumer` and `ActiveScriptEventConsumer`, the
canonical WMI persistence.
"""
from __future__ import annotations

import pathlib

from nexus.langgraph.tool_lane import (
    ToolJob,
    _is_wmi_repository,
    _owned_extraction_dir,
    _plan_single_artifact,
    _promote_stdout,
    is_host_evidence,
)

WMI = ["OBJECTS.DATA", "INDEX.BTR", "MAPPING1.MAP", "MAPPING2.MAP", "MAPPING3.MAP"]
NOT_WMI = ["objects.datax", "notes.txt", "random.bin", "OBJECTS.DAT", "mapping.map"]


def _job(**extra) -> ToolJob:
    j = ToolJob(host="windows", tool="strings",
                argv=["strings64", "-nobanner", "C:/ev/OBJECTS.DATA"],
                purpose="WMI repository", timeout=900)
    for k, v in extra.items():
        setattr(j, k, v)
    return j


def test_the_wmi_repository_files_are_recognised(tmp_path):
    for name in WMI:
        f = tmp_path / name
        f.write_bytes(b"\x0b\xad" * 16)
        assert is_host_evidence(f) is True, name


def test_the_wmi_match_is_by_exact_name():
    for name in NOT_WMI:
        assert _is_wmi_repository(name) is False, name


def test_the_wmi_repository_is_staged_in_both_encodings(tmp_path):
    """OBJECTS.DATA mixes ASCII and UTF-16 and neither pass is a superset.

    Measured on the real 31 MB repository: plain found __EventFilter 4x and
    CommandLineEventConsumer 14x, `-u` found neither. Running only `-u` - which I
    did first, reasoning from the task XML - hid every persistence class the
    routing exists to surface, while the ledger said OK and the index held 22,883
    rows. Both jobs cost one extra pass and remove the guess.
    """
    f = tmp_path / "OBJECTS.DATA"
    f.write_bytes(b"\x0b\xad" * 16)
    jobs = _plan_single_artifact(f, tmp_path / "ex")
    tools = [j.tool for j in jobs]
    assert tools == ["strings", "strings"], tools
    assert sum(1 for j in jobs if "-u" in j.argv) == 1, (
        f"expected exactly one utf16 pass: {[j.argv for j in jobs]}"
    )
    assert sum(1 for j in jobs if "-u" not in j.argv) == 1, (
        f"expected exactly one plain-ascii pass: {[j.argv for j in jobs]}"
    )


def test_promotion_targets_the_run_extraction_dir(tmp_path):
    src = tmp_path / "case" / "extractions" / "strings"
    src.mkdir(parents=True)
    saved = src / "20260928T031606_strings_stdout.txt"
    saved.write_text("__EventFilter CommandLineEventConsumer\n", encoding="utf-8")
    run_ext = tmp_path / "case" / "runs" / "RUN-1" / "extractions"
    run_ext.mkdir(parents=True)

    promoted = _promote_stdout(_job(), str(saved), dest=run_ext)
    assert promoted
    p = pathlib.Path(promoted)
    assert run_ext in p.parents, f"promoted outside the run dir: {p}"
    assert saved.is_file(), "the audit-trail target must be left alone"


def test_promotion_falls_back_beside_the_source(tmp_path):
    """No destination resolved: visible in the wrong place beats lost."""
    saved = tmp_path / "strings_stdout.txt"
    saved.write_text("x\n", encoding="utf-8")
    promoted = _promote_stdout(_job(), str(saved), dest=None)
    assert promoted and pathlib.Path(promoted).is_file()


def test_owned_extraction_dir_resolves_the_indexer_root():
    """The two must agree or the promoted file is written where nothing reads."""
    import nexus.config as cfg
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions


    real = cfg.settings.cases_root
    try:
        case = next((p for p in pathlib.Path(real).glob("CASE-*")), None)
        if case is None:
            return
        got = _owned_extraction_dir(case.name)
        assert got == resolve_tools_extractions(case), (got, resolve_tools_extractions(case))
    finally:
        cfg.settings.cases_root = real


def test_an_unknown_case_resolves_to_none():
    assert _owned_extraction_dir("CASE-DOES-NOT-EXIST") is None


def test_the_discovery_message_names_what_is_actually_accepted():
    """A stale guidance message sends the examiner after the wrong problem.

    The message is assembled from adjacent string literals, so the source text has
    line breaks and quotes inside it. Reconstruct the rendered text rather than
    searching the raw source, or this test fails on formatting instead of content.
    """
    import re

    src = pathlib.Path("src/nexus/langgraph/tool_lane.py").read_text(encoding="utf-8")
    i = src.find("No recognized evidence shape under")
    seg = src[i:i + 1600]
    rendered = re.sub(r'["\s]+', " ", seg)
    for named in ("scheduled-task definition", "WMI repository",
                  "console or shell history", "thumbcache", "setupapi"):
        assert named in rendered, (
            f"the discovery message does not mention {named!r}; an examiner "
            f"reading it would look for the wrong problem"
        )

def test_two_passes_over_one_file_get_two_names(tmp_path):
    """The WMI repository is staged in both encodings; neither pass may overwrite
    the other. A source-derived name made them collide, so the 587,443-line ASCII
    pass was replaced by the 22,883-line UTF-16 pass and only the smaller one
    reached the index - the same defect as a shared --csvf name, one layer down.
    """
    src = tmp_path / "case" / "extractions" / "strings"
    src.mkdir(parents=True)
    a = src / "20260928T031606_strings_stdout.txt"
    b = src / "20260928T031607_strings_stdout.txt"
    a.write_text("__EventFilter CommandLineEventConsumer\n", encoding="utf-8")
    b.write_text("sparse utf16 fragments\n", encoding="utf-8")
    run_ext = tmp_path / "RUN-1" / "extractions"
    run_ext.mkdir(parents=True)

    job_ascii = ToolJob(host="windows", tool="strings",
                        argv=["strings64", "-nobanner", "C:/ev/OBJECTS.DATA"],
                        purpose="WMI ascii", timeout=900)
    job_u = ToolJob(host="windows", tool="strings",
                    argv=["strings64", "-u", "-nobanner", "C:/ev/OBJECTS.DATA"],
                    purpose="WMI utf16", timeout=900)

    first = _promote_stdout(job_ascii, str(a), dest=run_ext)
    second = _promote_stdout(job_u, str(b), dest=run_ext)
    assert first and second
    assert first != second, "the two passes share one output name and one is lost"
    assert pathlib.Path(first).is_file() and pathlib.Path(second).is_file()
    names = {pathlib.Path(first).name, pathlib.Path(second).name}
    assert len(names) == 2
