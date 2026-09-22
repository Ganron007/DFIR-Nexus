"""T4 schema v5: shipped field registry + explicit typed fields.* + P1 honesty."""

from __future__ import annotations

import pytest


def test_registry_loads_and_covers_key_families():
    from nexus.langgraph.field_registry import (
        load_field_registry,
        merged_columns,
        registry_summary,
    )

    doc = load_field_registry()
    assert int(doc.get("version") or 0) >= 1
    cols = merged_columns()
    assert len(cols) > 500
    summary = registry_summary()
    assert summary["families"] >= 55
    assert summary["columns"] == len(cols)
    families = doc.get("families") or {}
    for name in ("evtxecmd", "recmd", "srumecmd", "vol", "hayabusa", "plaso", "mftecmd"):
        assert name in families, name


def test_conflict_policy_resolutions():
    from nexus.langgraph.field_registry import merged_columns

    cols = merged_columns()
    # ports/process ids are truly numeric -> typed long (malformed skipped)
    assert cols["dest_port"]["type"] == "long"
    assert cols["source_port"]["type"] == "long"
    assert cols["process_id"]["type"] == "long"
    # GUID-ish ids stay searchable everywhere -> text
    assert cols["AppId"]["type"] == "text"
    # temporal names resolve to date even when one catalog said text
    assert cols["Date"]["type"] == "date"
    assert cols["timestamp"]["type"] == "date"
    assert cols["CreatedOn"]["type"] == "date"


def test_es_property_shapes():
    from nexus.langgraph.field_registry import es_property

    text_prop = es_property({"type": "text"})
    assert text_prop["type"] == "text"
    assert text_prop["fields"]["kw"]["type"] == "keyword"

    date_prop = es_property({"type": "date"})
    assert date_prop["type"] == "date"
    assert "yyyy-MM-dd HH:mm:ss" in date_prop["format"]
    assert "epoch_millis" in date_prop["format"]

    assert es_property({"type": "long"}) == {"type": "long"}
    assert es_property({"type": "keyword"})["type"] == "keyword"


def test_mapping_body_is_schema_v5_with_explicit_fields():
    from nexus.langgraph.case_index import INDEX_SCHEMA_VERSION, _mapping_body

    assert INDEX_SCHEMA_VERSION == 5
    body = _mapping_body()
    assert body["settings"]["index.mapping.ignore_malformed"] is True
    assert body["settings"]["index.mapping.total_fields.limit"] >= 5000
    mappings = body["mappings"]
    assert mappings["_meta"]["schema_version"] == 5
    assert mappings["date_detection"] is False
    assert mappings["numeric_detection"] is False
    props = mappings["properties"]["fields"]["properties"]
    assert len(props) > 500
    assert props["dest_port"]["type"] == "long"
    # unknown columns still land through the dynamic template as text+kw
    assert any(
        t["fields_strings"]["path_match"] == "fields.*"
        for t in mappings["dynamic_templates"]
    )


def test_missing_registry_falls_back_to_object_only(monkeypatch, tmp_path):
    from nexus.langgraph import field_registry
    from nexus.langgraph.case_index import _mapping_body

    monkeypatch.setenv("NEXUS_FIELD_REGISTRY", str(tmp_path / "nope.yaml"))
    field_registry._load.cache_clear()
    try:
        assert field_registry.merged_columns() == {}
        assert field_registry.registry_summary()["version"] == 0
        body = _mapping_body()
        assert body["mappings"]["properties"]["fields"] == {"type": "object"}
    finally:
        field_registry._load.cache_clear()


def test_failed_field_refs_unknown_and_type_mismatch(monkeypatch):
    from nexus.langgraph import es_native

    monkeypatch.setattr(
        es_native, "_mapping_field_types",
        lambda case_id: {
            "fields.HivePath.kw": "keyword",
            "fields.BytesSent": "long",
            "ts": "date",
        },
    )
    failed = es_native.failed_field_refs("CASE-X", {"term": {"fields.Ghost": "x"}})
    assert failed and failed[0]["field"] == "fields.Ghost"
    assert failed[0]["reason"] == "unknown_field"

    failed2 = es_native.failed_field_refs(
        "CASE-X", {"range": {"fields.BytesSent": {"gte": "not-a-number"}}}
    )
    assert failed2 and "cannot be a long" in failed2[0]["reason"]

    assert es_native.failed_field_refs(
        "CASE-X", {"term": {"fields.HivePath.kw": "Security"}}
    ) == []
    assert es_native.failed_field_refs(
        "CASE-X", {"range": {"ts": {"gte": "2026-01-01"}}}
    ) == []


def test_es_search_degrades_instead_of_silent_zero(monkeypatch):
    from nexus.langgraph import es_native

    monkeypatch.setattr(es_native, "_mapping_field_types", lambda case_id: {"ts": "date"})
    out = es_native.es_search("CASE-X", {"term": {"fields.Ghost": "x"}})
    assert out["degraded"] is True
    assert out["total"] == 0
    assert "cannot match" in out["error"]
    assert out["failed_terms"][0]["field"] == "fields.Ghost"


def test_should_clause_failure_is_optional_not_fatal(monkeypatch):
    from nexus.langgraph import es_native

    monkeypatch.setattr(
        es_native, "_mapping_field_types",
        lambda case_id: {"family": "keyword", "text": "text", "fields.Channel.kw": "keyword"},
    )
    query = {
        "bool": {
            "filter": [{"term": {"family": "hayabusa"}}],
            # the alias clause has no mapping; the bool can still match via the
            # text clause, so this must NOT degrade the whole query
            "should": [
                {"term": {"channel": "security"}},
                {"match_phrase": {"text": "security"}},
            ],
        }
    }
    fatal, optional = es_native.failed_field_refs_detail("CASE-X", query)
    assert fatal == []
    assert optional and optional[0]["field"] == "channel"

    # a failed ref in a required context stays fatal
    fatal2, _ = es_native.failed_field_refs_detail(
        "CASE-X", {"bool": {"filter": [{"term": {"fields.Ghost": "x"}}]}}
    )
    assert fatal2 and fatal2[0]["field"] == "fields.Ghost"


def test_term_clause_is_lenient_over_typed_fields():
    from nexus.langgraph.case_index import _term_clause

    clause = _term_clause("sdelete", search_fields=True)
    mm = next(
        c["multi_match"] for c in clause["bool"]["should"] if "multi_match" in c
    )
    assert mm["lenient"] is True
    assert mm["fields"] == ["fields.*"]

    # numeric terms keep the phrase clause only (no wildcard noise)
    numeric = _term_clause("1102")
    assert all("wildcard" not in c for c in numeric["bool"]["should"])


def test_with_lenient_patches_multi_match_copies():
    from nexus.langgraph.es_native import _with_lenient

    query = {
        "bool": {
            "should": [
                {"multi_match": {"query": "x", "fields": ["fields.*"]}},
                {"term": {"family": "hayabusa"}},
            ]
        }
    }
    out = _with_lenient(query)
    assert out["bool"]["should"][0]["multi_match"]["lenient"] is True
    assert "lenient" not in out["bool"]["should"][1]["term"]
    # the caller's query is not mutated
    assert "lenient" not in query["bool"]["should"][0]["multi_match"]


def test_registry_has_no_path_like_column_names():
    from nexus.langgraph.field_registry import merged_columns

    cols = list(merged_columns())
    assert not [c for c in cols if "\\" in c]
    assert not [
        c for c in cols
        if c.lower().endswith((".db", ".csv", ".json", ".exe", ".dll", ".evtx"))
    ]


def test_mode1_type_mismatch_is_hard_error():
    from nexus.langgraph.case_index import _filter_to_es
    from nexus.langgraph.query_dsl import QuerySyntaxError

    numeric = {"hits": {"name": "Hits", "type": "long", "has_kw": False, "path": "fields.Hits"}}
    clauses = _filter_to_es({"name": "hits", "op": "gt", "value": "10"}, numeric)
    assert clauses == [{"range": {"fields.Hits": {"gt": 10}}}]

    textish = {"label": {"name": "Label", "type": "text", "has_kw": True, "path": "fields.Label"}}
    with pytest.raises(QuerySyntaxError):
        _filter_to_es({"name": "label", "op": "gt", "value": "x"}, textish)
