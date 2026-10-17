"""The importer pass (I1) on the sample sets (2026-10-18): every row stored, workbooks read, the gate told,
yearless times dated by the case's own evidence.

* D263: rows past 20,000 per file were dropped (NEXUS_INGEST_MAX_ARTIFACTS defaulted to 20,000).
* S02's SRUM-DUMP workbook was read by no importer; its duration columns are named like times.
* S03 (a capture and three logs, no Windows image) was gated "blocked" with nothing unprocessed: the gate was written
  before the importer pass, which it never counted.
* D262: S03's syslog read 2026 beside its BIND queries of 2016.

The lines and cells are the samples', verbatim.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from nexus.ingest import base as ingest_base
from nexus.langgraph.lane_gate import (
    import_row,
    read_lane_gate,
    record_import_results,
    write_lane_gate,
)
from nexus.langgraph.timeline_merge import anchor_assumed_years, ingest_into_case

SMTP = [
    "Jul 12 09:50:56 services dovecot: imap-login: Login: user=<ecoli>, method=PLAIN, rip=10.10.10.44, "
    "lip=10.10.10.5, mpid=23796, session=<sTZ6ZXE3R8AKCgos>",
    "Jul 12 09:51:10 services dovecot: imap-login: Login: user=<ecoli>, method=PLAIN, rip=10.10.10.44, "
    "lip=10.10.10.5, mpid=23812, session=<fqRNZnE3ScAKCgos>",
    "Jul 12 09:51:36 services dovecot: imap-login: Login: user=<tburr>, method=PLAIN, rip=10.10.10.42, "
    "lip=10.10.10.5, mpid=23842, session=<PxrWZ3E3KMAKCgoq>",
]
BIND = [
    "12-Jul-2016 09:45:59.115 client 10.10.10.5#42935 (google.com): query: google.com IN A +E (10.10.10.5)",
    "12-Jul-2016 09:49:46.413 client 10.10.10.44#61936 (isatap.pwnd.biz): query: isatap.pwnd.biz IN A + "
    "(10.10.10.5)",
    "12-Jul-2016 09:49:46.604 client 10.10.10.44#56345 (_ldap._tcp.dc._msdcs.pwnd.biz): query: "
    "_ldap._tcp.dc._msdcs.pwnd.biz IN SRV + (10.10.10.5)",
]
# S02's SRUM-DUMP workbook, sheet "Network Connections": its header and first two rows.
NETWORK_CONNECTIONS = [
    ("SRUM Entry ID", "SRUM Entry Creation", "Application", "User SID", "InterfaceLuid", "L2ProfileId",
     "ConnectedTime", "ConnectStartTime", "L2ProfileFlags"),
    (5171, datetime(2019, 10, 27, 16, 19), None, None, "IF_TYPE_IEEE80211", "somethingclever", 734739,
     datetime(2019, 10, 19, 4, 13, 20, 634000), 0),
    (5172, datetime(2019, 10, 27, 16, 19), None, None, "IF_TYPE_ETHERNET_CSMACD", None, 734743,
     datetime(2019, 10, 19, 4, 13, 16, 975000), 0),
]


@pytest.fixture
def case(tmp_path):
    case_dir = tmp_path / "CASE-SAMPLE"
    (case_dir / "audit").mkdir(parents=True)
    return case_dir


def _write(folder: Path, name: str, lines: list[str]) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _stored(case_dir: Path) -> list[dict]:
    store = case_dir / "ingest" / "artifacts.jsonl"
    return [json.loads(line) for line in store.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_every_row_of_a_file_is_stored_streamed_in_batches(case, tmp_path, monkeypatch):
    monkeypatch.delenv("NEXUS_INGEST_MAX_ARTIFACTS", raising=False)
    batches: list[int] = []
    real = ingest_base.Importer.ingest

    def small_batches(self, path, limit=0, on_batch=None, batch_size=5000):
        def counted(batch):
            batches.append(len(batch))
            on_batch(batch)
        return real(self, path, limit=limit, on_batch=counted if on_batch else None, batch_size=2)

    monkeypatch.setattr(ingest_base.Importer, "ingest", small_batches)
    info = ingest_into_case(_write(tmp_path / "ev", "bind.log", BIND), case)
    assert info["success"] and info["artifacts"] == 3 and not info["artifacts_capped"]
    assert batches == [2, 1], "rows reach the store in batches, not as one list"
    assert len(_stored(case)) == 3


def test_an_examiner_cap_still_caps_and_says_so(case, tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_INGEST_MAX_ARTIFACTS", "2")
    info = ingest_into_case(_write(tmp_path / "ev", "bind.log", BIND), case)
    assert info["artifacts"] == 2 and info["artifacts_capped"]


def test_a_workbook_is_read_sheet_by_sheet_with_its_date_cell_as_the_time(case, tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = "Network Connections"
    for row in NETWORK_CONNECTIONS:
        sheet.append(row)
    path = tmp_path / "ev" / "SRUM_DUMP_OUTPUT.xlsx"
    path.parent.mkdir(parents=True)
    book.save(path)
    info = ingest_into_case(path, case)
    assert info["source"] == "spreadsheet" and info["artifacts"] == 2
    first = _stored(case)[0]
    # The row's date cell, not ConnectedTime (a duration of 734739 s, which read as an epoch dated it 1970).
    assert first["timestamp"].startswith("2019-10-27T16:19:00")
    assert not first.get("ts_synthesized")
    assert first["raw"]["sheet"] == "Network Connections" and first["raw"]["ConnectedTime"] == "734739"


def test_the_importer_pass_counts_in_the_gate(case, tmp_path):
    # S03's tool lane: no Windows shape, so the only lane row is the discovery skip.
    write_lane_gate(case, "RUN-1", [{"tool": "(discovery)", "purpose": "locate evidence", "status": "SKIP",
                                     "reason": "No recognized evidence shape"}])
    assert read_lane_gate(case)["status"] == "blocked"
    ev = tmp_path / "ev"
    placeholder = ev / "zeeklogs" / ".placeholder"  # S03's empty zeeklogs/.placeholder
    placeholder.parent.mkdir(parents=True)
    placeholder.write_bytes(b"")
    rows = [import_row(p, ingest_into_case(p, case)) for p in
            (_write(ev, "bind.log", BIND), _write(ev, "smtp.log", SMTP), placeholder)]
    gate = record_import_results(case, rows)
    assert gate["status"] == "clear" and not gate["unprocessed"]
    assert [r["status"] for r in rows] == ["OK", "OK", "OK"] and rows[2]["reason"] == "empty file"


def test_a_file_no_importer_reads_is_unprocessed(case, tmp_path):
    write_lane_gate(case, "RUN-1", [{"tool": "(discovery)", "purpose": "locate evidence", "status": "SKIP",
                                     "reason": "No recognized evidence shape"}])
    notes = _write(tmp_path / "ev", "notes.dat", ["\x01\x02 not a format any importer reads"])
    row = import_row(notes, ingest_into_case(notes, case))
    gate = record_import_results(case, [row])
    assert row["status"] == "FAIL" and gate["status"] == "blocked"
    assert gate["unprocessed"] == [{"tool": row["tool"], "purpose": f"import {notes}", "reason": row["reason"]}]


def test_a_yearless_syslog_time_takes_the_year_of_the_cases_dated_evidence(case, tmp_path):
    ev = tmp_path / "ev"
    ingest_into_case(_write(ev, "bind.log", BIND), case)
    ingest_into_case(_write(ev, "smtp.log", SMTP), case)
    assumed = [r for r in _stored(case) if r.get("ts_year_assumed")]
    assert len(assumed) == 3 and all(not r["timestamp"].startswith("2016") for r in assumed)
    result = anchor_assumed_years(case)
    assert result["anchored"] == 3 and result["unresolved"] == 0
    smtp = [r for r in _stored(case) if r.get("ts_year_assumed")]
    assert [r["timestamp"][:19] for r in smtp] == ["2016-07-12T09:50:56", "2016-07-12T09:51:10", "2016-07-12T09:51:36"]
    assert all(r["ts_year_from"].startswith("the case's dated rows 2016-07-12") for r in smtp)
    # Run again (a re-run of the lane): nothing moves and nothing doubles.
    assert anchor_assumed_years(case)["anchored"] == 0 and len(_stored(case)) == 6


def test_a_yearless_time_with_nothing_dated_beside_it_is_left_flagged(case, tmp_path):
    ingest_into_case(_write(tmp_path / "ev", "smtp.log", SMTP), case)
    assert anchor_assumed_years(case) == {"anchored": 0, "unresolved": 3}
    assert all(r.get("ts_year_assumed") and not r.get("ts_year_from") for r in _stored(case))
