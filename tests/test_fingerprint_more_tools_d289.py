"""D289: the Zimmerman tools' registered CSVs keep their tool's family (2026-10-18).

Sample S09 registers the examiner's processed outputs; only six tools were recognised, so LECmd, JLECmd, RBCmd, WxTCmd
and PECmd's timeline were read as generic rows (S09: 626,255 rows under `generic_csv`). The fixtures are the header
lines of real outputs, byte for byte: the ES-Mapping outputs (2026 builds), a lane run's AmcacheParser output, and
S09's PECmd timeline (a 2020 build).
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from nexus.ingest.fingerprint import family_for_csv_header, place_recognized_csv
from nexus.langgraph.lane_gate import import_row
from nexus.langgraph.timeline_merge import ingest_into_case

HEADERS = Path(__file__).parent / "fixtures" / "d289_tool_headers"
EXPECTED = {
    "lecmd.csv": "lecmd", "jlecmd-auto.csv": "jlecmd", "jlecmd-custom.csv": "jlecmd", "sbecmd.csv": "sbecmd",
    "rbcmd.csv": "rbcmd", "wxtcmd-activity.csv": "wxtcmd", "wxtcmd-packageids.csv": "wxtcmd",
    "srum-networkusages.csv": "srum", "srum-apptimeline.csv": "srum", "appcompat.csv": "appcompat",
    "amcache-fileentries.csv": "amcache", "amcache-devicepnps.csv": "amcache", "pecmd-timeline.csv": "pecmd",
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_a_real_header_names_its_tool(name):
    header = (HEADERS / name).read_text(encoding="utf-8-sig").splitlines()[0]
    assert family_for_csv_header(header) == EXPECTED[name]


def test_the_families_are_the_lane_s_folder_names(tmp_path):
    src = tmp_path / "processed" / "RBCmd_Output.csv"
    src.parent.mkdir()
    shutil.copy(HEADERS / "rbcmd.csv", src)
    assert place_recognized_csv(src, tmp_path / "ingest").parent.name == "rbcmd"


def test_a_tool_output_with_its_header_only_is_a_result_not_a_file_left_unread(tmp_path):
    case = tmp_path / "CASE-S09"
    (case / "audit").mkdir(parents=True)
    src = tmp_path / "processed" / "RBCmd_Output.csv"
    src.parent.mkdir()
    shutil.copy(HEADERS / "rbcmd.csv", src)
    info = ingest_into_case(src, case)
    assert (info["source"], info["artifacts"]) == ("rbcmd", 0)
    row = import_row(src, info)
    assert (row["status"], row["reason"]) == ("OK", "a rbcmd output with no records")
