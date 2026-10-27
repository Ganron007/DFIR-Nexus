"""D451: preserve indexed fields and census rows without materializing them."""
from __future__ import annotations

import json
import weakref
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
    original = query_pack.attach_hit_fields

    def record_reparse(*args, **kwargs):
        reparsed.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(query_pack, "attach_hit_fields", record_reparse)
    result = evidence_index.do_n4_query(case_id=tmp_path.name, dsl="", limit=None, match_all=True)
    assert result["hits"][0]["fields"] == fields
    assert reparsed == [], "indexed fields must not be reconstructed from source files"


@pytest.mark.parametrize("builder", ["ti", "entities"])
def test_census_consumes_each_hit_without_retaining_the_input_rows(builder):
    from nexus.langgraph.entity_inventory import build_entity_inventory
    from nexus.langgraph.ti_context import sweep_case_iocs

    class TrackedHit(dict):
        pass

    refs = []
    peak = 0

    def hits():
        nonlocal peak
        for _index in range(200):
            hit = TrackedHit(text="powershell.exe 8.8.8.8", fields={"User": "alice"})
            refs.append(weakref.ref(hit))
            peak = max(peak, sum(ref() is not None for ref in refs))
            yield hit

    build = sweep_case_iocs if builder == "ti" else build_entity_inventory
    result = build("CASE-STREAM", hits=hits())
    assert result["hits_scanned"] == 200
    assert peak <= 3, f"retained {peak} input rows instead of folding the stream"
    if builder == "ti":
        assert result["iocs"]["ipv4"] == ["8.8.8.8"]
    else:
        assert result["network"]["ipv4"] == ["8.8.8.8"]
        assert result["processes"] == [{"value": "powershell.exe", "count": 200}]


def test_ti_and_entity_network_keep_their_existing_evidence_scopes():
    from nexus.langgraph.entity_inventory import build_entity_inventory
    from nexus.langgraph.ti_context import sweep_case_iocs

    hits = [{"text": "powershell.exe 8.8.8.8", "fields": {"RemoteAddress": "1.1.1.1"}}]
    ti = sweep_case_iocs("CASE-STREAM", hits=iter(hits))
    inv = build_entity_inventory("CASE-STREAM", hits=iter(hits))
    assert ti["iocs"]["ipv4"] == ["1.1.1.1", "8.8.8.8"]
    assert inv["network"]["ipv4"] == ["8.8.8.8"]


def test_hash_substring_exclusion_is_global_across_stream_rows():
    from nexus.langgraph.ti_context import sweep_case_iocs

    short = "a" * 32
    longer = short + "b" * 32
    hits = ({"text": text} for text in (short, longer))
    result = sweep_case_iocs("CASE-STREAM", hits=hits)
    assert result["iocs"]["sha256"] == [longer]
    assert result["iocs"]["md5"] == []


def test_setup_census_shares_one_complete_hit_stream(monkeypatch):
    from nexus.langgraph import case_census
    from nexus.langgraph.entity_inventory import build_entity_inventory
    from nexus.langgraph.ti_context import sweep_case_iocs

    rows = [{"text": "powershell.exe 8.8.8.8", "fields": {"User": "alice", "RemoteAddress": "1.1.1.1"}}]
    expected_ti = sweep_case_iocs("CASE-STREAM", hits=rows)
    expected_entities = build_entity_inventory("CASE-STREAM", hits=rows)
    scans = []

    def stream(case_id):
        scans.append(case_id)
        yield from rows

    monkeypatch.setattr(case_census, "iter_case_hits", stream)
    result = case_census.build_setup_census("CASE-STREAM")
    assert scans == ["CASE-STREAM"]
    assert result["ti_sweep"] == expected_ti
    assert result["entity_inventory"] == expected_entities


def test_setup_census_propagates_a_failed_stream_instead_of_refetching(monkeypatch):
    from nexus.langgraph import case_census

    scans = []

    def stream(case_id):
        scans.append(case_id)
        yield {"text": "8.8.8.8"}
        raise RuntimeError("exhaustive search failed: retained transport failure")

    monkeypatch.setattr(case_census, "iter_case_hits", stream)
    with pytest.raises(RuntimeError, match="exhaustive search failed"):
        case_census.build_setup_census("CASE-STREAM")
    assert scans == ["CASE-STREAM"]


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
    census = {"ti_sweep": {"hits_scanned": 2, "iocs": {"ipv4": ["8.8.8.8"]}},
              "entity_inventory": {"processes": [{"value": "powershell.exe", "count": 2}]}}
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
def test_setup_stream_binds_its_run_case_without_the_global_pointer(active, monkeypatch):
    from nexus.config import settings
    from nexus.langgraph import case_census, query_pack

    case = settings.cases_root / "CASE-CENSUS"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: CASE-CENSUS\n", encoding="utf-8")
    if active == "other":
        import os

        Path(os.environ["NEXUS_ACTIVE_CASE_FILE"]).write_text("CASE-OTHER", encoding="utf-8")
    observed = []
    row = {"text": "8.8.8.8", "fields": {"Computer": "WS01"}}

    def stream(bound, *args, **kwargs):
        observed.append((bound, kwargs))
        yield row

    monkeypatch.setattr(query_pack, "iter_all_hits", stream)
    assert list(case_census.iter_case_hits(case.name)) == [row]
    assert observed == [(case, {"match_all": True})]


def test_setup_stream_rejects_an_invalid_case_without_reading(monkeypatch):
    from nexus.langgraph import case_census, query_pack

    def forbidden(*args, **kwargs):
        pytest.fail("invalid case reached the evidence stream")

    monkeypatch.setattr(query_pack, "iter_all_hits", forbidden)
    with pytest.raises(ValueError):
        list(case_census.iter_case_hits("../CASE-OTHER"))
