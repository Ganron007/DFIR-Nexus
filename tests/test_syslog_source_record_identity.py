"""Syslog raw text and source positions survive the existing content-key store.

Inputs are unchanged, already-published D514 fixture bytes. Copies are byte-exact;
no forensic record is authored or edited here.
"""
import json
import shutil
from collections import Counter
from pathlib import Path

import pytest

from nexus.ingest.linux.authlog import AuthLogImporter
from nexus.ingest.linux.syslog import SyslogImporter
from nexus.langgraph.timeline_merge import append_ingest_artifacts

FIXTURE = Path(__file__).parent / "fixtures/d514_authlog/gw01/secure"


@pytest.fixture(params=[SyslogImporter, AuthLogImporter])
def importer_type(request):
    return request.param


def _copy(root: Path, name: str) -> Path:
    path = root / name / "secure"
    path.parent.mkdir(parents=True)
    shutil.copyfile(FIXTURE, path)
    assert path.read_bytes() == FIXTURE.read_bytes()
    return path


def _source_lines(path: Path) -> list[tuple[int, str]]:
    return [(number, line) for number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1) if line.strip()]


def _ingest(source: Path, case: Path, importer_type) -> None:
    result = importer_type().ingest(
        source, on_batch=lambda rows: append_ingest_artifacts(case, rows), batch_size=3,
    )
    assert result.success and result.parsed_lines == len(_source_lines(source))


def _stored(case: Path) -> list[dict]:
    return [json.loads(line) for line in (case / "ingest/artifacts.jsonl").read_text(
        encoding="utf-8").splitlines() if line.strip()]


def test_raw_records_are_verbatim_from_the_published_fixture(importer_type):
    expected = [line for _, line in _source_lines(FIXTURE)]
    records = list(importer_type().parse(FIXTURE))
    assert [record.raw["line"] for record in records] == expected


def test_raw_records_keep_their_actual_source_positions(importer_type):
    records = list(importer_type().parse(FIXTURE))
    assert [(record.raw["source_file"], record.raw["source_line"]) for record in records] == [
        (str(FIXTURE.resolve()), number) for number, _ in _source_lines(FIXTURE)
    ]


def test_two_verbatim_source_copies_keep_both_record_sequences(tmp_path, importer_type):
    first, second = _copy(tmp_path, "first"), _copy(tmp_path, "second")
    case = tmp_path / "case"
    _ingest(first, case, importer_type)
    _ingest(second, case, importer_type)
    records = _stored(case)
    expected = Counter(line for _, line in _source_lines(FIXTURE))
    assert len(records) == 2 * sum(expected.values())
    assert Counter(record["raw"]["line"] for record in records) == expected + expected
    assert len({(record["raw"]["source_file"], record["raw"]["source_line"])
                for record in records}) == len(records)


def test_reimport_of_the_same_source_positions_remains_idempotent(tmp_path, monkeypatch, importer_type):
    from nexus.langgraph import timeline_merge

    source = _copy(tmp_path, "original")
    case = tmp_path / "case"
    _ingest(source, case, importer_type)
    before = (case / "ingest/artifacts.jsonl").read_bytes()
    _ingest(source, case, importer_type)
    assert (case / "ingest/artifacts.jsonl").read_bytes() == before
    monkeypatch.setattr(timeline_merge, "_STORE_KEYS", {})
    _ingest(source, case, importer_type)
    assert (case / "ingest/artifacts.jsonl").read_bytes() == before
