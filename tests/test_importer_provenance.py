"""Importer identity must survive shared sources and delegated parsing."""
from pathlib import Path
from unittest.mock import MagicMock
from zipfile import ZipFile

import pytest

from nexus.ingest.generic.archive import ArchiveImporter
from nexus.ingest.generic.jsonl import JSONLImporter
from nexus.ingest.provenance import LEDGER_REL, artifact_key, ledger_path, load_provenance
from nexus.ingest.schemas import Artifact
from nexus.knowledge.family_registry import hit_evidence_families
from nexus.langgraph.briefing import _family_inventory
from nexus.langgraph.case_index import (
    _index_file_digests,
    _index_file_mtimes,
    _mapping_body,
    _shape_es_hit,
    index_stale,
    iter_index_docs,
    write_index_state,
)
from nexus.langgraph.es_native import _shape_hit, knowledge_evidence_groups
from nexus.langgraph.query_pack import _present_families, iter_ingest_hits
from nexus.langgraph.timeline_merge import append_ingest_artifacts

FIXTURE = Path(__file__).parent / "fixtures/tshark_ek_public.jsonl"


def test_streamed_importer_records_concrete_class():
    batches = []
    result = JSONLImporter().ingest(FIXTURE, on_batch=batches.extend, batch_size=4)
    assert result.parsed_lines and not result.errors
    assert batches and all(a.importer_chain == ["nexus.ingest.generic.jsonl.JSONLImporter"] for a in batches)
    assert Artifact.from_dict(batches[0].to_dict()).importer_chain == batches[0].importer_chain


def test_parser_input_cannot_supply_its_own_provenance():
    importer = JSONLImporter()
    artifact = next(importer.parse(FIXTURE))
    artifact.importer_chain = ["nexus.ingest.generic.email_import.EmailImporter"]
    result = next(importer.with_provenance(iter([artifact])))
    assert result.importer_chain == ["nexus.ingest.generic.jsonl.JSONLImporter"]


def test_archive_records_outer_and_inner_importers(tmp_path):
    archive = tmp_path / "fixture.zip"
    with ZipFile(archive, "w") as bundle:
        bundle.write(FIXTURE, "real.jsonl")
    result = ArchiveImporter().ingest(archive)
    assert result.parsed_lines and not result.errors
    assert all(a.importer_chain == [
        "nexus.ingest.generic.archive.ArchiveImporter",
        "nexus.ingest.generic.jsonl.JSONLImporter",
    ] for a in result.artifacts)


def test_real_importer_output_keeps_identity_through_store_and_index(tmp_path):
    result = JSONLImporter().ingest(FIXTURE)
    assert result.artifacts and not result.errors
    append_ingest_artifacts(tmp_path, result.artifacts)
    docs = iter_index_docs(tmp_path)
    expected = "nexus.ingest.generic.jsonl.JSONLImporter"
    assert docs
    assert all(d["family"] == "generic_jsonl" for d in docs)
    assert all(d["importer_leaf"] == [expected] and d["importer_chain"] == [expected] for d in docs)
    assert _shape_hit(docs[0])["importer_leaf"] == [expected]
    n4 = _shape_es_hit({"_source": docs[0]}, None, None, [], set(), None, True, False, set())
    assert n4 and n4["importer_leaf"] == [expected]
    csv_hit = next(iter_ingest_hits(tmp_path, [], None, None, match_all=True))
    assert csv_hit["importer_leaf"] == [expected]
    assert hit_evidence_families([csv_hit]) == {"generic_jsonl"}
    assert _family_inventory(tmp_path)["generic_jsonl"]["importer_classes"] == [expected]
    assert _present_families(tmp_path) == ["generic_jsonl"]
    props = _mapping_body()["mappings"]["properties"]
    assert props["importer_leaf"]["type"] == props["importer_chain"]["type"] == "keyword"


def test_indexed_groups_are_resolved_from_actual_importer_identity(tmp_path, monkeypatch):
    from nexus.langgraph import es_native

    result = JSONLImporter().ingest(FIXTURE)
    assert result.artifacts and not result.errors
    append_ingest_artifacts(tmp_path, result.artifacts)
    docs = iter_index_docs(tmp_path)
    group = docs[0]["evidence_group"]
    response = MagicMock(status_code=200)
    response.json.return_value = {"_shards": {"failed": 0},
                                  "hits": {"total": {"value": len(docs), "relation": "eq"}}, "aggregations": {
        "groups": {"sum_other_doc_count": 0, "buckets": [{"key": group, "doc_count": len(docs)}]},
        "missing": {"doc_count": 0},
    }}
    client = MagicMock()
    client.__enter__.return_value.post.return_value = response
    monkeypatch.setattr(es_native, "_client_and_index", lambda case_id: (lambda: client, "index"))
    groups = knowledge_evidence_groups("CASE-TEST")
    assert groups[0]["source"] == "generic_jsonl"
    assert groups[0]["families"] == ["generic_jsonl"]
    assert groups[0]["rows"] == len(docs)
    response.json.return_value["aggregations"]["missing"]["doc_count"] = 1
    with pytest.raises(es_native.ESQueryError, match="incomplete"):
        knowledge_evidence_groups("CASE-TEST")


def test_reimport_enriches_legacy_row_without_rewriting_or_duplicating_it(tmp_path):
    result = JSONLImporter().ingest(FIXTURE)
    assert result.artifacts and not result.errors
    actual = result.artifacts[0]
    # This is an authentic parsed row; the old store format had no parser metadata.
    legacy = Artifact.from_dict(actual.to_dict())
    legacy.importer_chain = []
    store = append_ingest_artifacts(tmp_path, [legacy])
    before = store.read_bytes()
    prior_digests = _index_file_digests(tmp_path)
    append_ingest_artifacts(tmp_path, [actual])
    ledger_before = ledger_path(tmp_path).read_bytes()
    append_ingest_artifacts(tmp_path, [actual])
    assert store.read_bytes() == before
    assert ledger_path(tmp_path).read_bytes() == ledger_before
    assert LEDGER_REL not in prior_digests
    assert LEDGER_REL in _index_file_digests(tmp_path)
    assert LEDGER_REL in _index_file_mtimes(tmp_path)
    docs = iter_index_docs(tmp_path)
    assert len(docs) == 1
    assert docs[0]["importer_leaf"] == ["nexus.ingest.generic.jsonl.JSONLImporter"]


def test_corrupt_provenance_is_not_silently_ignored(tmp_path):
    ledger_path(tmp_path).parent.mkdir()
    ledger_path(tmp_path).write_text('{"key":"broken"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid importer provenance"):
        load_provenance(tmp_path)


def test_new_provenance_immediately_marks_the_index_stale(tmp_path):
    actual = JSONLImporter().ingest(FIXTURE).artifacts[0]
    legacy = Artifact.from_dict(actual.to_dict())
    legacy.importer_chain = []
    append_ingest_artifacts(tmp_path, [legacy])
    write_index_state(tmp_path, {"docs": 1, "index": "nexus-case-test"})
    assert not index_stale(tmp_path)[0]
    append_ingest_artifacts(tmp_path, [actual])
    assert index_stale(tmp_path)[0]


def test_same_real_record_keeps_distinct_direct_and_archive_provenance(tmp_path):
    direct = JSONLImporter().ingest(FIXTURE)
    archive = tmp_path / "fixture.zip"
    with ZipFile(archive, "w") as bundle:
        bundle.write(FIXTURE, "real.jsonl")
    nested = ArchiveImporter().ingest(archive)
    assert direct.artifacts and nested.artifacts and not direct.errors and not nested.errors
    assert artifact_key(direct.artifacts[0].to_dict()) == artifact_key(nested.artifacts[0].to_dict())
    case = tmp_path / "case"
    store = append_ingest_artifacts(case, [direct.artifacts[0]])
    original = store.read_bytes()
    append_ingest_artifacts(case, [nested.artifacts[0]])
    assert store.read_bytes() == original
    docs = iter_index_docs(case)
    assert len(docs) == 1
    assert len(docs[0]["importer_paths"]) == 2
    assert docs[0]["importer_leaf"] == ["nexus.ingest.generic.jsonl.JSONLImporter"]
    assert "nexus.ingest.generic.archive.ArchiveImporter" in docs[0]["importer_chain"]
