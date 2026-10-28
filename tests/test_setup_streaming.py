"""D451: preserve indexed fields and census rows without materializing them."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.mark.parametrize("retrieval", ["stream", "materialized"])
def test_index_hit_preserves_stored_fields(retrieval, monkeypatch):
    from nexus.langgraph.case_index import _shape_es_hit

    # Retained real importer row; stored fields must survive the query boundary.
    retained = json.loads((Path(__file__).parent / "fixtures/memprocfs_eventlog_rows.json").read_text(encoding="utf-8"))
    assert retained
    # This test exercises transport only; no case verdict is inferred.
    fields = next(iter(retained.values()))
    source = {"family": "memprocfs", "file": "eventlog.json", "line": 1,
              "text": "indexed row", "fields": fields}
    if retrieval == "stream":
        hit = _shape_es_hit({"_source": source}, None, None, [], set(), None, True, True, set())
    else:
        from unittest.mock import MagicMock

        from nexus.langgraph import case_index

        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = False
        client.head.return_value.status_code = 200
        client.post.return_value.status_code = 200
        client.post.return_value.json.return_value = {"hits": {"hits": [{"_source": source}]}}
        monkeypatch.setattr(case_index, "_client", lambda: client)
        monkeypatch.setattr(case_index, "_schema_version_cached", lambda _: case_index.INDEX_SCHEMA_VERSION)
        monkeypatch.setattr(case_index, "fields_property_names", lambda _: list(fields))
        hits = case_index.query_index(Path("CASE-STREAM"), [], (None, None), match_all=True)
        assert len(hits) == 1
        hit = hits[0]
    assert hit is not None
    assert hit.get("fields") == source["fields"]


def test_n4_tool_does_not_reparse_indexed_fields(tmp_path, monkeypatch):
    from nexus.langgraph import query_pack
    from nexus.tools import evidence_index

    fields = {"User": "alice", "Computer": "WS01"}
    raw_hit = {"family": "memprocfs", "file": "not-present.csv", "line": "2",
               "text": "stored text", "fields": fields}
    monkeypatch.setattr(evidence_index, "_resolve_active_case", lambda _: (tmp_path, ""))
    monkeypatch.setattr(query_pack, "n4_query", lambda *args, **kwargs: {
        "backend": "elasticsearch", "hits": [raw_hit], "count": 1, "complete": True,
    })
    reparsed = []
    original = query_pack._split_csv_row

    def record_reparse(*args, **kwargs):
        reparsed.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(query_pack, "_split_csv_row", record_reparse)
    result = evidence_index.do_n4_query(case_id=tmp_path.name, dsl="", limit=None, match_all=True)
    assert result["hits"][0]["fields"] == fields
    assert reparsed == [], "indexed fields must not be reconstructed from source files"


def test_hash_substring_exclusion_is_global_across_examiner_texts():
    from nexus.langgraph.ti_context import extract_iocs

    short = "a" * 32
    longer = short + "b" * 32
    result = extract_iocs([short, longer])
    assert result["sha256"] == [longer]
    assert result["md5"] == []


def test_setup_census_is_the_typed_inventory_of_its_case(monkeypatch):
    """Part 12 FM-2: the census reads typed fields; it no longer streams and pattern-types every row."""
    from nexus.config import settings
    from nexus.langgraph import case_census, query_pack, typed_entities

    case = settings.cases_root / "CASE-CENSUS"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: CASE-CENSUS\n", encoding="utf-8")
    typed = {"source": "typed", "fields": {}, "host": [{"value": "ws01", "count": 3}]}
    asked = []
    monkeypatch.setattr(typed_entities, "case_entities", lambda case_id: asked.append(case_id) or typed)
    monkeypatch.setattr(query_pack, "iter_all_hits",
                        lambda *a, **k: pytest.fail("the census must not stream every row"))
    assert case_census.build_setup_census("CASE-CENSUS") == {"entity_inventory": typed}
    assert asked == ["CASE-CENSUS"]


def test_setup_census_propagates_a_failed_typed_search(monkeypatch):
    from nexus.config import settings
    from nexus.langgraph import case_census, typed_entities

    case = settings.cases_root / "CASE-CENSUS"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: CASE-CENSUS\n", encoding="utf-8")

    def failed(case_id):
        raise RuntimeError("typed-field search failed: 503")

    monkeypatch.setattr(typed_entities, "case_entities", failed)
    with pytest.raises(RuntimeError, match="typed-field search failed"):
        case_census.build_setup_census("CASE-CENSUS")


def test_stream_identity_dedup_is_exact_and_temporary_files_close(tmp_path, monkeypatch):
    import tempfile

    from nexus.langgraph import case_index

    scratch = tmp_path / "query-keys"
    scratch.mkdir()
    root_before = set(tmp_path.iterdir())
    original = tempfile.TemporaryDirectory
    monkeypatch.setattr(case_index.tempfile, "TemporaryDirectory", lambda **kwargs: original(dir=scratch, **kwargs))
    with case_index._bounded_hit_keys() as seen:
        seen.add(("same.csv", "1"))
        seen.add(("same.csv", "1"))
        seen.add(("same.csv", "2"))
        assert ("same.csv", "1") in seen
        assert ("same.csv", "2") in seen
        assert ("other.csv", "1") not in seen
        assert list(scratch.iterdir())
    assert not list(scratch.iterdir())
    assert set(tmp_path.iterdir()) == root_before


def test_setup_census_is_retained_in_its_run_before_enrichment(tmp_path):
    from nexus.langgraph.case_census import persist_setup_census
    from nexus.langgraph.pipeline_runs import create_run

    case = tmp_path / "CASE-CENSUS"
    case.mkdir()
    run = create_run(case, mode="interpret")
    census = {"ti_selection": {"leads": 1, "lead_rows": 2, "rows_found": 2, "iocs": {"ipv4": ["8.8.8.8"]}},
              "entity_inventory": {"process": [{"value": "powershell.exe", "count": 2}]}}
    path = persist_setup_census(case, run.run_id, census)
    assert path == run.analysis / "setup_census.json"
    assert json.loads(path.read_text(encoding="utf-8")) == census
    original = path.read_bytes()
    assert persist_setup_census(case, run.run_id, census) == path
    assert path.read_bytes() == original
    with pytest.raises(ValueError, match="different setup census"):
        persist_setup_census(case, run.run_id, {"different": True})
    assert path.read_bytes() == original


@pytest.mark.parametrize("active", ["absent", "other"])
def test_setup_census_binds_its_run_case_without_the_global_pointer(active, monkeypatch):
    from nexus.config import settings
    from nexus.langgraph import case_census, typed_entities

    case = settings.cases_root / "CASE-CENSUS"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: CASE-CENSUS\n", encoding="utf-8")
    if active == "other":
        import os

        Path(os.environ["NEXUS_ACTIVE_CASE_FILE"]).write_text("CASE-OTHER", encoding="utf-8")
    asked = []
    monkeypatch.setattr(typed_entities, "case_entities", lambda case_id: asked.append(case_id) or {})
    case_census.build_setup_census(case.name)
    assert asked == ["CASE-CENSUS"]


def test_setup_census_rejects_an_invalid_case_without_reading(monkeypatch):
    from nexus.langgraph import case_census, typed_entities

    monkeypatch.setattr(typed_entities, "case_entities",
                        lambda case_id: pytest.fail("an invalid case reached the index"))
    with pytest.raises(ValueError):
        case_census.build_setup_census("../CASE-OTHER")


@pytest.mark.parametrize("empty_fields", [False, True])
def test_every_enrichment_caller_preserves_captured_stored_fields(empty_fields, tmp_path, monkeypatch):
    from nexus.langgraph import pipeline_runs, query_pack

    captured = json.loads((Path(__file__).parent / "fixtures/t22_indexed_device_row.json").read_text(encoding="utf-8"))
    fields = {} if empty_fields else captured["indexed_fields"]
    hit = {"file": captured["file"], "line": captured["line"], "text": captured["text"],
           "fields": fields, "host": ""}

    def forbidden(*args, **kwargs):
        raise AssertionError("stored indexed fields must not reopen or parse their source")

    monkeypatch.setattr(pipeline_runs, "resolve_tools_extractions", forbidden)
    result = query_pack.attach_hit_fields(tmp_path, [hit])
    assert result == [hit]
    assert result[0]["fields"] == fields
    assert result[0]["host"] == ""
    assert "device" not in [result[0]["host"], *result[0]["fields"].keys()]
