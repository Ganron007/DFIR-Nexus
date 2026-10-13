"""D118 (2026-10-13): a MemProcFS YARA report is one record per match, with its rule and its process context together.

These tests read the case's own run, which is evidence and is never committed. They skip in a clean checkout. On the
run of 2026-10-13 the report holds 9 matches, which the line-based reader had split into 374 documents.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from nexus.langgraph.case_index import _index_header, _open_text_auto, iter_indexable_rows

YARA = (
    Path(__file__).resolve().parents[1] / "cases" / "CASE-C5B04D31" / "runs"
    / "RUN-20261011T110426201672Z-tools-5618aeb2" / "extractions"
    / "memprocfs" / "SRL_Evidence-rd01-memory-39e55fe9.img" / "forensic" / "findevil" / "yara.txt"
)

pytestmark = pytest.mark.skipif(not YARA.is_file(), reason="the case run is not present in this checkout")


def _matches() -> list[tuple[int, str, dict[str, str]]]:
    header = _index_header(YARA)
    with _open_text_auto(YARA) as fh:
        return list(iter_indexable_rows(YARA, fh, header, file_label=YARA.name))


def test_each_match_is_one_record():
    matches = _matches()
    assert len(matches) == 9
    assert all(fields.get("Rule") for _n, _text, fields in matches)


def test_a_match_keeps_its_rule_and_its_process_together():
    first = next(m for m in _matches() if m[2].get("MatchIndex") == "0")
    _line, text, fields = first
    assert fields["Rule"] == "Windows_Trojan_CobaltStrike_8d5963a2"
    assert fields["PID"] == "692"
    assert fields["ProcessName"] == "lsass.exe"
    assert fields["User"] == "SYSTEM"
    assert "Matches:" in text  # the block keeps its hexdump evidence as text
