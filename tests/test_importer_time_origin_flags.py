"""Timezone-origin metadata follows existing published source records and files.

Reuse the verbatim OSSEC/RFC3164 fixtures and the already published captured
USB Detective workbook's actual ZIP directory. No new forensic record or
archive member is authored or extracted.
"""
from __future__ import annotations

import base64
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nexus.ingest.base import Importer
from nexus.ingest.linux.authlog import AuthLogImporter
from nexus.ingest.linux.syslog import SyslogImporter
from nexus.langgraph.case_index import iter_index_docs
from nexus.langgraph.timeline_merge import ingest_into_case

FIXTURES = Path(__file__).parent / "fixtures"


def _stored(case):
    return [json.loads(line) for line in (case / "ingest/artifacts.jsonl").read_text(encoding="utf-8").splitlines()]


def test_verbatim_forwarded_local_clocks_remain_explicitly_assumed_in_store_and_index(tmp_path):
    source = FIXTURES / "d284_ossec_winevtlog.log"
    case = tmp_path / "CASE-LOCAL-CLOCK"
    (case / "audit").mkdir(parents=True)
    result = ingest_into_case(source, case)
    assert result["artifacts"] == 2
    records = _stored(case)
    assert all(row["ts_tz_assumed"] and not row["ts_synthesized"] for row in records)
    original_lines = [line for line in source.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [row["raw"]["full_log"] for row in records] == original_lines
    documents = list(iter_index_docs(case))
    assert len(documents) == len(records)
    assert all(doc["ts_tz_assumed"] and doc["fields"]["ts_tz_assumed"] == "true" for doc in documents)


def test_existing_real_zip_directory_times_are_assumed_without_extracting_members(tmp_path):
    workbook = FIXTURES / "d518_USB_Detective_Timeline.xlsx"
    source = tmp_path / "encoded-workbook.txt"
    source.write_bytes(base64.b64encode(workbook.read_bytes()))
    with zipfile.ZipFile(workbook) as archive:
        directory = archive.infolist()
    case = tmp_path / "CASE-ZIP-CLOCK"
    (case / "audit").mkdir(parents=True)
    result = ingest_into_case(source, case)
    assert result["artifacts"] == 1 + len(directory)
    parent, *members = _stored(case)
    assert parent["ts_synthesized"] and not parent["ts_tz_assumed"]
    assert len(members) == len(directory) > 0
    for record, original in zip(members, directory, strict=True):
        expected = datetime(*original.date_time, tzinfo=UTC)
        assert record["timestamp"] == expected.isoformat()
        assert record["ts_tz_assumed"] and not record["ts_synthesized"]
        assert record["raw"]["member"] == original.filename
        assert not (case / original.filename).exists()
    documents = list(iter_index_docs(case))
    assert len(documents) == result["artifacts"]
    assert sum(bool(doc.get("ts_tz_assumed")) for doc in documents) == len(directory)


@pytest.mark.parametrize("importer", [SyslogImporter, AuthLogImporter])
def test_published_rfc3164_source_clock_retains_both_year_and_zone_assumptions(importer):
    source = FIXTURES / "d514_authlog/gw01/secure"
    records = list(importer().parse(source))
    assert len(records) == 8
    assert all(row.ts_year_assumed and row.ts_tz_assumed and not row.ts_synthesized for row in records)


def test_aware_and_epoch_clock_inputs_do_not_assume_a_timezone():
    now = datetime.now(UTC)
    for value in (now, now.isoformat(), now.timestamp()):
        resolved, flags = Importer.normalize_timestamp_ex(value)
        assert resolved is not None and resolved.tzinfo is not None
        assert not flags.get("tz_assumed", False)
