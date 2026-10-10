"""Real EvtxECmd output: a BOM-prefixed header is recognised (R12), and two
different files with one basename are both kept (R11).

The header line below is the verbatim first line of EvtxECmd 2026.5 output
(`Evidence-files/ES-Mapping/outputs/evtxecmd`), byte for byte, including its
UTF-8 byte-order mark and CRLF ending. No data row is written by hand.
"""
from __future__ import annotations

from nexus.ingest.fingerprint import family_for_csv_header, place_recognized_csv

REAL_EVTXECMD_HEADER = (
    b"\xef\xbb\xbfRecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,"
    b"ProcessId,ThreadId,Computer,ChunkNumber,UserId,MapDescription,UserName,RemoteHost,"
    b"PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,"
    b"ExecutableInfo,HiddenRecord,SourceFile,Keywords,ExtraDataOffset,Payload\r\n"
)


def test_bom_prefixed_real_header_is_recognised_as_evtxecmd(tmp_path):
    source = tmp_path / "in" / "20260822131246_EvtxECmd_Output.csv"
    source.parent.mkdir()
    source.write_bytes(REAL_EVTXECMD_HEADER + b"7989,7989,2026-08-22 05:26:47.0428511\r\n")
    placed = place_recognized_csv(source, tmp_path / "extractions")
    assert placed is not None
    assert placed.parent.name == "evtxecmd"


def test_quoted_column_with_a_comma_is_still_one_column():
    header = '"Payload,Json",RecordNumber,MapDescription'
    assert family_for_csv_header(header) is None
    assert family_for_csv_header(
        '﻿RecordNumber,EventRecordId,TimeCreated,MapDescription,PayloadData1'
    ) == "evtxecmd"


def test_two_files_with_one_basename_are_both_kept(tmp_path):
    host_a = tmp_path / "hostA" / "parsed.csv"
    host_b = tmp_path / "hostB" / "parsed.csv"
    host_a.parent.mkdir()
    host_b.parent.mkdir()
    header = "ExecutableName,RunCount,LastRun\n"
    host_a.write_text(header + "a.exe,1,2026-01-01\n", encoding="utf-8")
    host_b.write_text(header + "b.exe,2,2026-01-02\n", encoding="utf-8")
    root = tmp_path / "extractions"
    first = place_recognized_csv(host_a, root)
    second = place_recognized_csv(host_b, root)
    assert first is not None and second is not None
    assert first != second
    assert "a.exe" in first.read_text(encoding="utf-8")
    assert "b.exe" in second.read_text(encoding="utf-8")


def test_equal_bytes_under_one_name_are_one_copy(tmp_path):
    one = tmp_path / "x" / "prefetch.csv"
    two = tmp_path / "y" / "prefetch.csv"
    one.parent.mkdir()
    two.parent.mkdir()
    body = "ExecutableName,RunCount,LastRun\nc.exe,1,2026-01-01\n"
    one.write_text(body, encoding="utf-8")
    two.write_text(body, encoding="utf-8")
    root = tmp_path / "extractions"
    first = place_recognized_csv(one, root)
    second = place_recognized_csv(two, root)
    assert first == second
    assert len(list((root / "pecmd").iterdir())) == 1
