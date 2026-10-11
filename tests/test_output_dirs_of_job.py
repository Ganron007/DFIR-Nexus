"""A job's before/after snapshot covers every folder it names under the run's extractions (D77, 2026-10-11).

The mftecmd body job wrote a 199 MB file into the folder its --body flag named. That folder was not watched, so the
ledger row listed only the console log, and the body file was in no record of the run.
"""

from __future__ import annotations

from nexus.langgraph import tool_lane
from nexus.langgraph.tool_lane import ToolJob


def test_the_folder_a_job_names_under_the_run_is_watched(tmp_path):
    extractions = tmp_path / "extractions"
    body_dir = extractions / "mftecmd-body"
    job = ToolJob(host="windows", tool="mftecmd",
                  argv=["mftecmd", "-f", r"H:\C\$MFT", "--body", str(body_dir), "--bdl", "C"],
                  purpose="MFT bodyfile for mactime (FOR508)")
    watched = [path.resolve() for path in tool_lane._output_dirs_of(job, extractions)]
    assert body_dir.resolve() in watched


def test_a_folder_outside_the_run_is_not_watched(tmp_path):
    extractions = tmp_path / "extractions"
    elsewhere = tmp_path / "elsewhere"
    job = ToolJob(host="windows", tool="mftecmd",
                  argv=["mftecmd", "-f", r"H:\C\$MFT", "--body", str(elsewhere)], purpose="body")
    assert elsewhere.resolve() not in [p.resolve() for p in tool_lane._output_dirs_of(job, extractions)]


def test_a_body_file_written_into_the_named_folder_is_recorded(tmp_path):
    extractions = tmp_path / "extractions"
    body_dir = extractions / "mftecmd-body"
    body_dir.mkdir(parents=True)
    job = ToolJob(host="windows", tool="mftecmd", argv=["mftecmd", "--body", str(body_dir)], purpose="body")
    dirs = tool_lane._output_dirs_of(job, extractions)
    before = tool_lane._snapshot(dirs)
    (body_dir / "20261011110601_MFTECmd_$MFT_Output.body").write_text("0|x\n", encoding="utf-8")
    recorded = tool_lane._new_output_files(dirs, before)
    assert any("_MFTECmd_$MFT_Output.body" in str(entry) for entry in recorded)
