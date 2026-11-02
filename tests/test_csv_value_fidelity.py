"""CSV fidelity regressions use only fixtures already published before D521."""
import csv
import gzip
import io
from pathlib import Path

import pytest

from nexus.langgraph.case_index import (
    _index_header,
    _open_text_auto,
    iter_index_doc_batches,
    iter_indexable_rows,
)
from nexus.langgraph.pipeline_runs import create_run

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(params=[False, True], ids=["csv", "gzip"])
def native_csv(request, tmp_path):
    # Both inputs already exist on origin/master at 0504811. No newly captured
    # case data is needed to exercise the reader and literal-cell contracts.
    source = FIXTURES / "cs1b_evtx_real_rows.csv"
    payload = source.read_bytes()
    with source.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        header = reader.fieldnames
        original = list(reader)
    case = tmp_path / "CASE-DA521001"
    case.mkdir()
    run = create_run(case, "tools", evidence_paths=[str(source)])
    directory = case / "runs" / run.run_id / "extractions/evtxecmd"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (source.name + (".gz" if request.param else ""))
    path.write_bytes(gzip.compress(payload) if request.param else payload)
    return case, run.run_id, path, header, original, request.param


def test_parsed_cells_equal_original_published_csv(native_csv):
    _case, _run, path, header, original, _compressed = native_csv
    with _open_text_auto(path) as stream:
        projected = [fields for _line, _text, fields in iter_indexable_rows(path, stream, _index_header(path))]
    assert len(projected) == len(original) == 14
    assert _index_header(path) == header
    for actual, expected in zip(projected, original, strict=True):
        assert actual == {key: value for key, value in expected.items() if value and not key.startswith("_")}


def test_shared_reader_retains_published_native_crlf_bytes(native_csv):
    from nexus.langgraph.query_pack import _open_text

    case, _run, _path, _header, _original, compressed = native_csv
    payload = (FIXTURES / "d518_RBCmd_Output.csv").read_bytes()
    assert b"\r\n" in payload
    path = case / ("published-native.csv.gz" if compressed else "published-native.csv")
    path.write_bytes(gzip.compress(payload) if compressed else payload)
    for opener in (_open_text_auto, _open_text):
        with opener(path) as stream:
            assert stream.read() == payload.decode("utf-8-sig")


def test_indexed_fields_and_text_keep_published_whitespace(native_csv):
    case, run_id, _path, header, original, _compressed = native_csv
    docs = [doc for batch in iter_index_doc_batches(case, run_id=run_id) for doc in batch]
    assert len(docs) == len(original) == 14
    expected = original[0]["PayloadData2"]
    assert expected.endswith(" ") and expected != expected.strip()
    assert docs[0]["fields"]["PayloadData2"] == expected
    (record,) = csv.reader(io.StringIO(docs[0]["text"], newline=""))
    assert dict(zip(header, record, strict=True))["PayloadData2"] == expected


def test_csv_search_and_export_preserve_the_indexed_record(native_csv):
    from nexus.langgraph.query_pack import _hits_from_file, _iter_matching_rows

    case, run_id, path, header, original, _compressed = native_csv
    root = path.parent.parent
    ranked, _limited = _hits_from_file(
        path, root, "evtxecmd", [], set(), None, None, match_all=True, case_dir=case,
    )
    streamed = list(_iter_matching_rows(
        path, root, "evtxecmd", [], None, None, match_all=True, header=header,
    ))
    docs = [doc for batch in iter_index_doc_batches(case, run_id=run_id) for doc in batch]
    assert len(ranked) == len(streamed) == len(docs) == len(original) == 14
    for hit, expected in zip(ranked, original, strict=True):
        (record,) = csv.reader(io.StringIO(hit["text"], newline=""))
        decoded = dict(zip(header, record, strict=True))
        # The existing source-path placeholder policy is independent of literal
        # evidence cells. Every other decoded cell remains source-exact.
        assert {key: value for key, value in decoded.items() if key != "SourceFile"} == {
            key: value for key, value in expected.items() if key != "SourceFile"
        }
    assert [hit["text"] for hit in ranked] == [text for _line, _terms, text in streamed] == [doc["text"] for doc in docs]
