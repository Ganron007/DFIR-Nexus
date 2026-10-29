"""The vocabulary audit reads only registered tiny indexes and flags missing grouping."""
from pathlib import Path
from unittest.mock import MagicMock

from devtools.runbook import family_vocab
from nexus.ingest.generic.jsonl import JSONLImporter
from nexus.langgraph.case_index import index_name, iter_index_docs
from nexus.langgraph.timeline_merge import append_ingest_artifacts

FIXTURE = Path(__file__).parent / "fixtures/tshark_ek_public.jsonl"


def test_audit_uses_registered_cases_and_real_indexed_groups(tmp_path, monkeypatch):
    case = tmp_path / "CASE-TINY-AUDIT"
    result = JSONLImporter().ingest(FIXTURE)
    assert result.artifacts and not result.errors
    append_ingest_artifacts(case, result.artifacts)
    docs = iter_index_docs(case)
    manifest = tmp_path / "tiny.yaml"
    manifest.write_text("cases:\n  T01:\n    case_id: CASE-TINY-AUDIT\n", encoding="utf-8")
    monkeypatch.setattr(family_vocab, "TINY", manifest)
    total = len(docs)
    payload = {"_shards": {"failed": 0}, "hits": {"total": {"value": total, "relation": "eq"}},
               "aggregations": {
                   "f": {"sum_other_doc_count": 0, "buckets": [{"key": "generic_jsonl", "doc_count": total}]},
                   "g": {"sum_other_doc_count": 0, "buckets": [{"key": docs[0]["evidence_group"], "doc_count": total}]},
                   "missing": {"doc_count": 0},
               }}
    response = MagicMock(status_code=200)
    response.json.return_value = payload
    client = MagicMock()
    client.__enter__.return_value.post.return_value = response
    monkeypatch.setattr(family_vocab, "_client", lambda: client)
    produced, groups, missing = family_vocab.tiny_snapshot()
    assert produced == {"generic_jsonl": {index_name(case.name)}}
    assert groups == [{"generic_jsonl"}] and not missing
    assert client.__enter__.return_value.post.call_args.args[0] == f"/{index_name(case.name)}/_search"

    # An older index without this field is reported as incomplete, not covered.
    payload["aggregations"]["g"]["buckets"] = []
    payload["aggregations"]["missing"]["doc_count"] = total
    _, groups, missing = family_vocab.tiny_snapshot()
    assert not groups and missing == {case.name: total}


def test_unmatched_declaration_never_exits_successfully(monkeypatch):
    monkeypatch.setattr(family_vocab, "tiny_snapshot", lambda: ({"generic_jsonl": {"index"}}, [], {}))
    monkeypatch.setattr(family_vocab, "declared_families", lambda: {"not-a-produced-family": {"skill:test"}})
    assert family_vocab.main() == 1
