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


def test_term_clause_searches_parsed_fields_when_enabled():
    """Schema-v2 parsed columns are searchable: a term that only lives in
    fields.* must match (imported evidence with compact lines)."""
    from nexus.langgraph.case_index import _term_clause, ast_to_es

    plain = str(_term_clause("alice"))
    assert "multi_match" not in plain
    assert "match_phrase" in plain and "text.wc" in plain

    with_fields = str(_term_clause("alice", search_fields=True))
    assert "multi_match" in with_fields
    assert "fields.*" in with_fields

    es = ast_to_es(None, terms=["alice"], search_fields=True)
    assert "fields.*" in str(es)
    es_off = ast_to_es(None, terms=["alice"])
    assert "fields.*" not in str(es_off)


def test_ast_to_es_terms_not_truncated():
    """A 60+-needle scan must be representable — the retrieval layer chunks,
    it never silently drops terms (that turned 'checked, absent' into a lie
    when needle #41+ — e.g. rdp/mstsc — was never queried)."""
    from nexus.langgraph.case_index import ast_to_es

    terms = [f"needle{i:02d}" for i in range(61)]
    es = ast_to_es(None, terms=terms)
    assert len(es["bool"]["should"]) == 61
    assert "needle60" in str(es)


class _Resp:
    def __init__(self, code: int, payload: dict):
        import json as _json

        self.status_code = code
        self._payload = payload
        self.text = _json.dumps(payload)

    def json(self) -> dict:
        return self._payload


def _terms_from_body(body: dict) -> list[str]:
    out: list[str] = []
    for clause in body.get("query", {}).get("bool", {}).get("should", []):
        try:
            out.append(clause["bool"]["should"][0]["match_phrase"]["text"])
        except (KeyError, IndexError, TypeError):
            continue
    return out


class _FakeES:
    """Fails any query whose chunk exceeds ``max_terms`` (like real ES)."""

    def __init__(self, max_terms: int = 40):
        self.max_terms = max_terms
        self.queries: list[list[str]] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def head(self, path):
        return _Resp(200, {})

    def post(self, path, json=None, content=None, headers=None, params=None):
        if path.endswith("/_search") or path == "_search":
            terms = _terms_from_body(json or {})
            self.queries.append(terms)
            if len(terms) > self.max_terms:
                return _Resp(400, {"error": {"reason": "Query rewrite failed: too many clauses"}})
            hits = [
                {"_source": {"text": f"{t} happened", "family": "hayabusa",
                             "file": f"{t}.csv", "line": 1}}
                for t in terms
            ]
            return _Resp(200, {"hits": {"hits": hits}})
        return _Resp(200, {})


def _patch_v2(monkeypatch, client, case_dir):
    from nexus.langgraph import case_index

    monkeypatch.setattr(case_index, "_client", lambda: client)
    monkeypatch.setattr(case_index, "_schema_version_cached", lambda _cid: 2)
    monkeypatch.setattr(case_index, "fields_property_names", lambda _cid: [])


def test_query_index_chunks_large_term_scans(monkeypatch, tmp_path):
    """165 needles => chunked ES queries, ALL terms covered, merged results."""
    from nexus.langgraph.case_index import query_index

    client = _FakeES(max_terms=40)
    _patch_v2(monkeypatch, client, tmp_path)
    terms = [f"n{i:03d}" for i in range(165)]
    stats: dict = {}
    hits = query_index(tmp_path / "CASE-CHUNK", terms, (None, None), stats=stats)

    assert stats["terms_requested"] == 165
    assert stats["terms_queried"] == 165          # nothing dropped
    assert stats["terms_failed"] == []
    assert stats["chunk_queries"] == 5            # ceil(165/40)
    assert all(len(q) <= 40 for q in client.queries)
    assert {t for q in client.queries for t in q} == set(terms)
    assert len(hits) == 165
    # sample doc passed the row-side re-check with its own needle
    assert any(h["file"] == "n164.csv" for h in hits)


def test_query_index_splits_on_clause_limit(monkeypatch, tmp_path):
    """If a chunk still trips the ES clause limit it is split and retried —
    the scan never gives up on terms while a smaller query can succeed."""
    from nexus.langgraph.case_index import query_index

    client = _FakeES(max_terms=10)
    _patch_v2(monkeypatch, client, tmp_path)
    terms = [f"t{i:02d}" for i in range(25)]
    stats: dict = {}
    hits = query_index(tmp_path / "CASE-SPLIT", terms, (None, None), stats=stats)

    assert stats["terms_queried"] == 25
    assert stats["terms_failed"] == []
    assert stats["chunks_split"] >= 1
    # every successful (<= limit) query together covers all 25 terms
    assert sum(len(q) for q in client.queries if len(q) <= 10) == 25
    assert len(hits) == 25


def test_query_index_records_unqueryable_terms(monkeypatch, tmp_path):
    """A term that cannot be queried at all is recorded — never reported as
    'checked, 0 hits'."""
    from nexus.langgraph.case_index import query_index

    client = _FakeES(max_terms=0)  # every query fails, even single-term
    _patch_v2(monkeypatch, client, tmp_path)
    stats: dict = {}
    hits = query_index(tmp_path / "CASE-FAIL", ["rdp", "mstsc"], (None, None), stats=stats)

    assert hits == []
    assert stats["terms_queried"] == 0
    assert sorted(stats["terms_failed"]) == ["mstsc", "rdp"]


def test_n4_hits_csv_stats_show_full_coverage(tmp_path):
    """CSV backend scans every term; stats must say so (no false negatives)."""
    from nexus.langgraph.query_pack import n4_hits

    case = tmp_path / "CASE-CSVCON"
    ext = case / "extractions"
    ext.mkdir(parents=True)
    (ext / "hayabusa_rdp.csv").write_text(
        "TimeCreated,Computer,RuleTitle\n"
        "2024-11-23 04:06:23,WS01,RDP Logon\n",
        encoding="utf-8",
    )
    stats: dict = {}
    hits, backend = n4_hits(case, ["rdp", "notpresent"], (None, None),
                            backend="csv", stats=stats)
    assert backend == "csv"
    assert hits, "RDP needle must match the CSV row"
    assert stats["terms_requested"] == 2
    assert stats["terms_queried"] == 2
    assert stats["terms_failed"] == []


def test_row_matches_extra_text_parity():
    """ES matches fields.*; the row-side re-check must accept the same values
    or every fields-only hit would be silently dropped (parity guard)."""
    from nexus.langgraph.query_dsl import parse_query, row_matches

    q = parse_query("host:WS01 AND alice")
    line = "ts,computer,4624,logon"  # raw line does NOT contain alice
    ok, _ = row_matches(q, line_lower=line.lower(), family="hayabusa",
                        file_rel="f.csv", extra_text="User=alice Computer=WS01")
    assert ok is True

    ok2, _ = row_matches(q, line_lower=line.lower(), family="hayabusa",
                         file_rel="f.csv")
    assert ok2 is False  # without the parsed values the term is absent

    # Numeric terms keep the hex-boundary guard over extra text too.
    qn = parse_query("4688")
    ok3, _ = row_matches(qn, line_lower="deadbeef4688deadbeef".lower(),
                         extra_text="")
    assert ok3 is False


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

def test_trim_hit_preserves_structured_envelope():
    """MCP consumers (timeline rendering, field filters) need ts/user/event_id
    through the trim — they were silently dropped before."""
    from nexus.tools.evidence_index import _trim_hit

    hit = _trim_hit({
        "family": "hayabusa", "file": "f.csv", "line": 2,
        "text": "2026-01-01 10:00:00,4688,WS01,CORP\\\\bob,powershell",
        "host": "WS01", "user": "CORP\\\\bob", "event_id": "4688",
        "ts": "2026-01-01T10:00:00", "terms": "powershell",
        "fields": {"RuleTitle": "Suspicious Sdelete"},
    })
    assert hit["host"] == "WS01"
    assert hit["user"] == "CORP\\\\bob"
    assert hit["event_id"] == "4688"
    assert hit["ts"] == "2026-01-01T10:00:00"
    assert hit["fields"]["RuleTitle"] == "Suspicious Sdelete"
