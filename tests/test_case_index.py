"""N3 case index — same N4 hit shape as the CSV pack."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from nexus.langgraph.case_index import (
    WILDCARD_IGNORE_ABOVE,
    IndexMissing,
    _bulk_ndjson,
    index_name,
    iter_index_docs,
    query_index,
)
from nexus.langgraph.query_pack import (
    build_query_pack_markdown,
    collect_query_terms,
    n4_hits,
    parse_window,
    scan_extractions,
)


def _case(tmp_path: Path) -> Path:
    ext = tmp_path / "extractions" / "pecmd"
    ext.mkdir(parents=True)
    (ext / "prefetch_Timeline.csv").write_text(
        "RunTime,ExecutableName\n"
        "2020-11-14 04:49:43,ACRORD32.EXE\n"
        "2020-11-14 13:42:11,sdelete.exe\n",
        encoding="utf-8",
    )
    mft = tmp_path / "extractions" / "mftecmd"
    mft.mkdir(parents=True)
    # Pretend-large file is skipped by CSV pack; indexer keeps matching rows
    # when we force size via monkeypatch in the large-file test.
    (mft / "mft.csv").write_text(
        "path\nC:\\Windows\\System32\\notepad.exe\nC:\\Tools\\sdelete.exe\n",
        encoding="utf-8",
    )
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  playbooks: data_staging\n  question: what was staged or wiped\n",
        encoding="utf-8",
    )
    return tmp_path


def test_index_name_sanitizes():
    assert index_name("INC-20260813063432") == "nexus-case-inc-20260813063432"
    assert WILDCARD_IGNORE_ABOVE >= 4096


def test_index_docs_match_csv_pack_prefetch(tmp_path: Path):
    case = _case(tmp_path)
    docs = iter_index_docs(case)
    texts = " ".join(d["text"] for d in docs)
    assert "sdelete" in texts.lower()
    pack = build_query_pack_markdown(case, ledger=[])
    assert "sdelete" in pack.lower()
    assert "ACRORD32" not in pack


def test_n4_hits_csv_backend(tmp_path: Path):
    case = _case(tmp_path)
    terms = collect_query_terms({"playbooks": "data_staging"})
    hits, backend = n4_hits(case, terms, (None, None), backend="csv")
    assert backend == "csv"
    assert any("sdelete" in h["text"].lower() for h in hits)


def test_query_index_missing_raises():
    with patch("nexus.langgraph.case_index.es_url", return_value="http://127.0.0.1:9200"), \
            patch("nexus.langgraph.case_index._client") as client_factory:
        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = False
        client.head.return_value.status_code = 404
        client_factory.return_value = client
        try:
            query_index(Path("/tmp/no-case"), ["sdelete"], (None, None))
            raise AssertionError("expected IndexMissing")
        except IndexMissing:
            pass


def test_bulk_ndjson_roundtrip():
    body = _bulk_ndjson("nexus-case-x", [{"file": "a.csv", "line": 2, "text": "sdelete.exe"}])
    lines = [ln for ln in body.strip().splitlines() if ln]
    assert len(lines) == 2
    assert json.loads(lines[0])["index"]["_index"] == "nexus-case-x"
    assert "sdelete" in json.loads(lines[1])["text"]


def test_scan_and_docs_same_sdelete_file(tmp_path: Path):
    case = _case(tmp_path)
    start, end = parse_window("")
    hits = scan_extractions(case, ["sdelete"], (start, end))
    docs = iter_index_docs(case)
    assert any("sdelete" in h["text"].lower() for h in hits)
    assert any("sdelete" in d["text"].lower() for d in docs)
