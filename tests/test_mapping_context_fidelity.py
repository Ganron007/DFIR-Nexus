"""The mapping handed to a seat must retain types and measured population."""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph import context_loop, es_native, field_catalog
from tests.test_es_native import _FakeClient, _Resp


def test_native_mapping_and_model_summary_keep_nested_types_and_population(monkeypatch):
    from nexus.knowledge import query_validation
    from nexus.langgraph import case_index

    class MappingClient(_FakeClient):
        def get(self, path):
            response = super().get(path)
            name = path.strip("/").split("/")[0]
            response._payload[name]["mappings"]["properties"]["ecs"] = {
                "properties": {"source": {"properties": {"ip": {"type": "ip"}}}},
            }
            return response

        def post(self, path, json=None):
            if "families" in (json or {}).get("aggs", {}):
                return _Resp(200, {"aggregations": {"families": {"buckets": [
                    {"key": "evtxecmd", "doc_count": 3},
                ]}}})
            if "pop" in (json or {}).get("aggs", {}):
                return _Resp(200, {"aggregations": {"pop": {"buckets": {
                    path: {"doc_count": 3 if path == "fields.Channel" else 0}
                    for path in json["aggs"]["pop"]["filters"]["filters"]
                }}}})
            return super().post(path, json)

    monkeypatch.setattr(case_index, "es_available", lambda: True)
    monkeypatch.setattr(case_index, "_client", MappingClient)
    # A column not declared for this family still exists in its real mapping.
    monkeypatch.setattr(query_validation, "load_field_registry", lambda: {})
    request = json.loads((Path(__file__).parent / "fixtures/t19_mode3_mapping_request.json").read_text())
    native = es_native.es_fields(**request["params"])
    summary = context_loop._result_summary("es_mappings", native)
    assert summary["core_fields"] == native["core_fields"]
    assert summary["parsed_columns"] == native["parsed_columns"]
    assert summary["populated_columns"] == {"evtxecmd": {"Channel": 3}}
    assert summary["population_note"] == native["population_note"]
    assert summary["field_types"]["ecs.source.ip"] == "ip"
    assert summary["field_types"]["fields.Channel"] == "text"
    assert summary["field_types"]["fields.Channel.kw"] == "keyword"
    assert summary["family_rows"] == {"evtxecmd": 3}
    assert summary["populated_fields"] == {"evtxecmd": {"fields.Channel": 3}}
    assert "fields.Channel.kw" not in summary["populated_fields"]["evtxecmd"]
    observation = context_loop._append_tool_observation(
        tool_calls=[], all_hits=[], aggregations=[], name="es_mappings", args={},
        why="inspect actual mapping", result=native, elapsed_ms=0,
    )
    packed = context_loop._observations_block([observation])
    assert '"ecs.source.ip": "ip"' in packed
    assert '"fields.Channel.kw": "keyword"' in packed
    assert '"populated_columns": {"evtxecmd": {"Channel": 3}}' in packed


def test_validation_and_model_catalog_use_the_same_mapping_walk(monkeypatch):
    from nexus.langgraph import case_index

    monkeypatch.setattr(case_index, "es_available", lambda: True)
    monkeypatch.setattr(case_index, "_client", _FakeClient)
    case_id = "CASE-MAPPING-WALK"
    es_native._mapping_types_cache.pop(case_id, None)
    assert es_native.es_fields(case_id)["field_types"] == es_native._field_types(case_id)


def test_compact_field_lists_do_not_claim_omitted_populated_columns_are_empty(monkeypatch, tmp_path):
    columns = {f"Column{i:02}": 1 for i in range(12)}
    monkeypatch.setattr(es_native, "es_fields", lambda _: {
        "families": {"evtxecmd": 1}, "populated_columns": {"evtxecmd": columns},
    })
    monkeypatch.setattr(field_catalog, "_populated_ecs", lambda _: {})
    sheet = field_catalog.field_sheet_block(tmp_path)
    catalog = field_catalog.field_catalog_block(tmp_path, cap=10)
    for block in (sheet, catalog):
        assert "fields.Column00" in block and "fields.Column11" not in block
        assert "absent here is not filled" not in block
        assert "subset" in block and "es_mappings" in block


def test_population_request_failure_is_visible_instead_of_claiming_empty(monkeypatch):
    import pytest

    from nexus.langgraph import case_index

    class FailedPopulation(_FakeClient):
        def post(self, path, json=None):
            if "families" in (json or {}).get("aggs", {}):
                return _Resp(200, {"aggregations": {"families": {"buckets": [
                    {"key": "evtxecmd", "doc_count": 3},
                ]}}})
            return _Resp(500, {"error": "measurement failed"})

    monkeypatch.setattr(case_index, "es_available", lambda: True)
    monkeypatch.setattr(case_index, "_client", FailedPopulation)
    with pytest.raises(es_native.ESQueryError, match="field population failed for evtxecmd: 500"):
        es_native.es_fields("CASE-MEASUREMENT-FAILURE")


def test_partial_population_response_cannot_claim_unmeasured_columns_are_empty(monkeypatch):
    import pytest

    from nexus.langgraph import case_index

    class PartialPopulation(_FakeClient):
        def post(self, path, json=None):
            if "families" in (json or {}).get("aggs", {}):
                return _Resp(200, {"aggregations": {"families": {"buckets": [
                    {"key": "evtxecmd", "doc_count": 3},
                ]}}})
            return _Resp(200, {"aggregations": {"pop": {"buckets": {}}}})

    monkeypatch.setattr(case_index, "es_available", lambda: True)
    monkeypatch.setattr(case_index, "_client", PartialPopulation)
    with pytest.raises(es_native.ESQueryError, match="field population incomplete"):
        es_native.es_fields("CASE-MEASUREMENT-PARTIAL")
