"""WP 4j.30/4j.31/4j.32 — schema v2 doc fields, AST→ES translation, agg field map."""
from __future__ import annotations


def test_row_fields_parses_csv_and_caps():
    from nexus.langgraph.case_index import _row_fields

    header = ["TimeCreated", "EventID", "Computer", "User", "CommandLine"]
    line = '"2026-01-01 10:00:00",4688,WS01,IEUser,"powershell -enc AAAA"'
    fields = _row_fields(line, header)
    assert fields["EventID"] == "4688"
    assert fields["Computer"] == "WS01"
    assert fields["CommandLine"] == "powershell -enc AAAA"


def test_host_user_event_extraction():
    from nexus.langgraph.case_index import _host_user_event

    host, user, event = _host_user_event(
        {"Computer": "WS01", "TargetUser": "CORP\\bob", "EventID": "4624"}
    )
    assert host == "WS01"
    assert user == "CORP\\bob"
    assert event == "4624"


def test_ast_to_es_fields_and_booleans():
    from nexus.langgraph.case_index import ast_to_es
    from nexus.langgraph.query_dsl import parse_query

    q = parse_query("sdelete AND host:WS01 NOT setup.exe family:evtx event:4688")
    es = ast_to_es(q)
    assert "bool" in es
    # bare term → any-of group; host:/event: → filter; NOT → must_not
    assert "sdelete" in str(es["bool"]["should"])
    assert es["bool"]["minimum_should_match"] == 1
    filt_flat = str(es["bool"]["filter"]).replace("'", '"')
    assert '"term": {"family": "evtx"}' in filt_flat
    assert '"event_id"' in filt_flat
    assert '"host"' in filt_flat
    assert "setup.exe" in str(es["bool"]["must_not"])


def test_ast_to_es_regex_and_terms_only():
    from nexus.langgraph.case_index import ast_to_es
    from nexus.langgraph.query_dsl import parse_query

    es = ast_to_es(parse_query(r"regex:sdelete.*\.exe"))
    assert "regexp" in str(es)

    es2 = ast_to_es(None, terms=["sdelete", "rundll32"])
    assert es2["bool"]["minimum_should_match"] == 1
    assert len(es2["bool"]["should"]) == 2

    assert ast_to_es(None, terms=[], match_all=True) == {"match_all": {}}


def test_resolve_agg_field_direct_and_parsed(monkeypatch):
    from nexus.langgraph import case_index

    assert case_index._resolve_agg_field("CASE-X", "host") == "host"
    assert case_index._resolve_agg_field("CASE-X", "machine") == "host"
    assert case_index._resolve_agg_field("CASE-X", "event") == "event_id"
    monkeypatch.setattr(
        case_index, "fields_property_names", lambda _cid: ["EventID", "CommandLine"]
    )
    assert case_index._resolve_agg_field("CASE-X", "commandline") == "fields.CommandLine.kw"
    assert case_index._resolve_agg_field("CASE-X", "nope") is None


def test_es_aggregate_uses_cardinality_for_distinct(monkeypatch, tmp_path):
    from nexus.langgraph import case_index

    captured = {}

    class Response:
        status_code = 200
        text = ""

        def json(self):
            return {
                "hits": {"total": {"value": 500}},
                "aggregations": {
                    "v": {"buckets": [
                        {"key": "host-a", "doc_count": 20},
                        {"key": "host-b", "doc_count": 10},
                    ]},
                    "distinct": {"value": 257},
                },
            }

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def post(self, path, json):
            captured["path"] = path
            captured["body"] = json
            return Response()

    monkeypatch.setattr(case_index, "es_available", lambda: True)
    monkeypatch.setattr(case_index, "_schema_version_cached", lambda _case_id: 2)
    monkeypatch.setattr(case_index, "_resolve_agg_field", lambda _case_id, _field: "host")
    monkeypatch.setattr(case_index, "_client", lambda: Client())

    result = case_index.es_aggregate(tmp_path / "CASE-X", field="host", top=2, match_all=True)
    assert result is not None
    assert result["distinct"] == 257
    assert result["distinct_approximate"] is True
    assert len(result["top"]) == 2
    assert "cardinality" in captured["body"]["aggs"]["distinct"]


def test_doc_shape_includes_structured_fields(tmp_path):
    """A CSV extraction doc carries host/user/event_id/fields (schema v2)."""
    from nexus.langgraph.case_index import iter_index_docs
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    case = tmp_path / "CASE-SHAPE"
    target = resolve_tools_extractions(case)
    target.mkdir(parents=True, exist_ok=True)
    (target / "hayabusa_timeline.csv").write_text(
        "TimeCreated,EventID,Computer,User,RuleTitle\n"
        "2026-01-01T10:00:00,4688,WS01,CORP\\bob,Suspicious Sdelete\n",
        encoding="utf-8",
    )
    docs = iter_index_docs(case, [])
    assert docs, "expected one doc from the hayabusa CSV"
    doc = docs[0]
    assert doc["family"] == "hayabusa"
    assert doc.get("host") == "ws01"
    assert doc.get("user") == "corp\\bob"
    assert doc.get("event_id") == "4688"
    assert doc.get("fields", {}).get("RuleTitle") == "Suspicious Sdelete"
