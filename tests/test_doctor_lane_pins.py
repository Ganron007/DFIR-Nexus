"""`nexus doctor` reports the lane tools as pinned: version and licence (WO-TA item 0).

It reads tools/windows/VERSIONS.txt and runs nothing. A pinned line is tab-separated with a SHA-256 in its
fourth field. Other lines are not pins and are not reported.
"""
from pathlib import Path

from nexus.cli.doctor_cmd import _lane_tool_pins


def test_a_pinned_tool_is_reported_with_its_version_and_licence(tmp_path: Path):
    record = tmp_path / "VERSIONS.txt"
    record.write_text(
        "memprocfs-win\t5.19\thttps://example.invalid/memprocfs.zip\t" + "a" * 64 + "\tAGPL-3.0\n"
        "report\tdeepbluecli\tFETCHED\tmaster archive\n",
        encoding="utf-8",
    )

    rows = _lane_tool_pins(record)

    assert rows == [("pinned memprocfs-win 5.19", True, "licence AGPL-3.0")]


def test_a_missing_record_is_reported_as_missing(tmp_path: Path):
    rows = _lane_tool_pins(tmp_path / "nope.txt")

    assert rows and rows[0][1] is False
