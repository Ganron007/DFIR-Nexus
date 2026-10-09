"""D44: a tool's own output is one family, never a per-file pseudo-family.

The reviewer counted 148 "families" on SC1 where there are 24. Two root causes,
both in `_family()`:

1. A promoted stdout capture is named `{tool}-{stem}-{digest}.txt` by
   `_promote_stdout` (`tool_lane.py:4080`) and lands at the extraction ROOT, so
   `path.parent.name` is the literal `extractions`. 120 of SC1's pseudo-families
   were exactly that: `deepbluecli-<channel>-<hash>.txt` x124, plus `lecmd-…txt`,
   `sqlecmd-…txt`, `bmc-tools-…txt`, `mftecmd-C-…txt`.
2. A tool that writes a per-run subdirectory (LogFileParser's
   `LogFile_<timestamp>\`) leaves its own name in the PATH, not in the file name,
   so `path.parent.name` was the timestamp — one pseudo-family per run.

Both are fixed by recovering the owning tool from the file name and then from the
path components, before the `path.parent.name` fallback.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from nexus.langgraph.query_pack import _family  # noqa: E402

CASE = REPO / "_case_root_under_test"

#: (relative path under the case root, the family the index must derive)
SIDE_CARS = {
    # 1. promoted stdout captures at the extraction root
    "runs/RUN-1/extractions/deepbluecli-Security-a1b2c3d4.txt": "deepbluecli",
    "runs/RUN-1/extractions/deepbluecli-Application-71258ffa.txt": "deepbluecli",
    "runs/RUN-1/extractions/lecmd-Administrator-recent-lnk-1b05d8ca.txt": "lecmd",
    "runs/RUN-1/extractions/sqlecmd-sqlecmd-79fcbc26.txt": "sqlecmd",
    "runs/RUN-1/extractions/bmc-tools-tiles-00bf2c84.txt": "bmc-tools",
    "runs/RUN-1/extractions/mftecmd-C-879df97e.txt": "mftecmd",
    "extractions/hindsight-hst-1a2b3c4d.txt": "hindsight",
    # 2. a tool's own per-run subdirectory
    "extractions/logfileparser/LogFile_2026-10-07_14-29-35/LogFile_RCRD.csv": "logfileparser",
    "extractions/logfileparser/LogFile_2026-10-08_09-00-00/LogFile_Mft.csv": "logfileparser",
    # 3. a tool-named directory is still the tool's own family
    "extractions/recmd/Kroll_Batch/SYSTEM.csv": "recmd",
    "extractions/evtxecmd/20261007084854_EvtxECmd_Output.csv": "evtxecmd",
    "extractions/rbcmd/20261007085815_RBCmd_Output.csv": "rbcmd",
}


@pytest.mark.parametrize("rel,want", sorted(SIDE_CARS.items()))
def test_a_tool_output_is_one_family_not_one_per_file(rel, want):
    got = _family(CASE / rel, CASE)
    assert got == want, f"{rel} derived as {got!r}, expected {want!r}"


def test_no_family_is_the_literal_extractions_directory():
    """`extractions` is a directory name, never a family.

    Every file that lands at an extraction root is either a tool's own output
    (recovered from the name or an ancestor component) or something the indexer
    deliberately skips. A census reporting the family `extractions` is D44's
    signature.
    """
    from nexus.langgraph.query_pack import _TOOL_FAMILIES

    assert _TOOL_FAMILIES, "the tool list must not be empty, or every root file is 'extractions'"
    for rel in SIDE_CARS:
        assert _family(CASE / rel, CASE) != "extractions"


def test_an_unowned_file_still_falls_back_to_its_directory():
    """The fallback stays honest for files no tool produced.

    Dropping it outright would silently re-attribute examiner-supplied evidence.
    """
    rel = "extractions/examiner-notes/notes.txt"
    assert _family(CASE / rel, CASE) == "examiner-notes"
