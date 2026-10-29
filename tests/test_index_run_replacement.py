"""A new tools run replaces the index in one step (index speed, 2026-10-11).

Before this change the lane's first pass over a new run deleted the superseded run's documents file by
file, a delete per 100 files over millions of documents. A changed source now drops the whole index and
rebuilds it. The same run keeps the incremental pass, and an empty resolution is still refused.
"""

from __future__ import annotations

import json

import pytest


class _Resp:
    def __init__(self, code: int = 200, payload: dict | None = None):
        self.status_code = code
        self._payload = payload or {}
        self.text = json.dumps(self._payload)

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, docs: int):
        self.docs = docs
        self.calls: list[tuple] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def head(self, path):
        self.calls.append(("HEAD", path))
        return _Resp(200, {})

    def delete(self, path, timeout=None):
        self.calls.append(("DELETE", path))
        return _Resp(200, {})

    def post(self, path, json=None, params=None, content=None, headers=None, timeout=None):
        if "_delete_by_query" in path:
            self.calls.append(("DELETE_BY_QUERY", path, json))
            return _Resp(200, {"deleted": self.docs})
        if "_count" in path:
            self.calls.append(("COUNT", path))
            return _Resp(200, {"count": self.docs})
        if "_bulk" in path:
            self.calls.append(("BULK", path))
            return _Resp(200, {"errors": False, "items": []})
        if "_refresh" in path:
            self.calls.append(("REFRESH", path))
            return _Resp(200, {})
        return _Resp(200, {})


@pytest.fixture
def indexer(tmp_path, monkeypatch):
    from nexus.ingest import fingerprint
    from nexus.langgraph import case_index, lane_gate

    recreated: list[str] = []

    def fake_ensure(case_id):
        recreated.append(case_id)
        return f"nexus-case-{case_id.lower()}"

    monkeypatch.setattr(case_index, "ensure_index", fake_ensure)
    monkeypatch.setattr(case_index, "write_index_state", lambda *args, **kwargs: None)
    monkeypatch.setattr(fingerprint, "place_loose_csvs", lambda *args, **kwargs: None)
    monkeypatch.setattr(lane_gate, "reconcile_after_index", lambda *args, **kwargs: None)

    def one_batch(case_dir, *args, **kwargs):
        yield [{"case_id": "CASE-RUN", "family": "t", "file": "n.csv", "line": 1, "text": "row"}]

    monkeypatch.setattr(case_index, "iter_index_doc_batches", one_batch)
    case = tmp_path / "CASE-RUN"
    (case / "analysis").mkdir(parents=True)
    return case_index, case, recreated


def _prior(case, *, source: str, mtimes: dict, docs: int) -> None:
    (case / "analysis" / "index_state.json").write_text(
        json.dumps({"file_mtimes": mtimes, "file_sha256s": {k: "old" for k in mtimes},
                    "source_extractions": source, "docs": docs}),
        encoding="utf-8",
    )


def test_a_changed_run_drops_the_index_and_rebuilds_it(indexer, monkeypatch):
    case_index, case, recreated = indexer
    _prior(case, source="RUN-OLD/extractions", mtimes={"n.csv": 1.0}, docs=1)
    fake = _FakeClient(docs=1)
    monkeypatch.setattr(case_index, "_client", lambda: fake)
    monkeypatch.setattr(case_index, "_source_extractions_text", lambda case_dir, run_id="": "RUN-NEW/extractions")
    monkeypatch.setattr(case_index, "_index_file_mtimes", lambda case_dir, run_id="": {"n.csv": 2.0})
    monkeypatch.setattr(case_index, "_index_file_digests", lambda case_dir, run_id="": {"n.csv": "new"})

    case_index.index_case(case, incremental=True, run_id="RUN-NEW")

    kinds = [call[0] for call in fake.calls]
    assert ("DELETE", "/nexus-case-case-run") in fake.calls, "the index is dropped in one request"
    assert "DELETE_BY_QUERY" not in kinds, "no file-by-file delete over the superseded run"
    assert recreated == ["CASE-RUN", "CASE-RUN"], "the index is recreated with its mapping after the drop"
    assert kinds.index("BULK") > 0


def test_the_same_run_keeps_the_incremental_pass(indexer, monkeypatch):
    case_index, case, recreated = indexer
    _prior(case, source="RUN-SAME/extractions", mtimes={"n.csv": 1.0}, docs=1)
    fake = _FakeClient(docs=1)
    monkeypatch.setattr(case_index, "_client", lambda: fake)
    monkeypatch.setattr(case_index, "_source_extractions_text", lambda case_dir, run_id="": "RUN-SAME/extractions")
    monkeypatch.setattr(case_index, "_index_file_mtimes", lambda case_dir, run_id="": {"n.csv": 2.0})
    monkeypatch.setattr(case_index, "_index_file_digests", lambda case_dir, run_id="": {"n.csv": "new"})

    case_index.index_case(case, incremental=True, run_id="RUN-SAME")

    assert not any(call[0] == "DELETE" for call in fake.calls), "the same run never drops the index"
    assert any(call[0] == "DELETE_BY_QUERY" for call in fake.calls), "the changed file is replaced by its own terms"
    assert recreated == ["CASE-RUN"], "only the top-of-call ensure, no recreate"


def test_new_provenance_reindexes_the_store_without_treating_ledger_as_evidence(indexer, monkeypatch):
    from nexus.ingest.provenance import LEDGER_REL

    case_index, case, _ = indexer
    store = "ingest/artifacts.jsonl"
    _prior(case, source="RUN-SAME/extractions", mtimes={store: 1.0}, docs=1)
    fake = _FakeClient(docs=1)
    monkeypatch.setattr(case_index, "_client", lambda: fake)
    monkeypatch.setattr(case_index, "_source_extractions_text", lambda case_dir, run_id="": "RUN-SAME/extractions")
    monkeypatch.setattr(case_index, "_index_file_mtimes", lambda case_dir, run_id="": {store: 1.0, LEDGER_REL: 2.0})
    monkeypatch.setattr(case_index, "_index_file_digests", lambda case_dir, run_id="": {store: "old", LEDGER_REL: "new"})
    selected = []

    def batches(case_dir, *args, **kwargs):
        selected.append(kwargs.get("only_files"))
        return iter(())

    monkeypatch.setattr(case_index, "iter_index_doc_batches", batches)
    meta = case_index.index_case(case, incremental=True, run_id="RUN-SAME")
    deletes = [call[2] for call in fake.calls if call[0] == "DELETE_BY_QUERY"]
    assert deletes == [{"query": {"terms": {"file": [store]}}}]
    assert selected == [{store}]
    assert meta["provenance_changed"] is True


def test_an_empty_resolution_still_refuses_to_drop_the_index(indexer, monkeypatch):
    case_index, case, recreated = indexer
    _prior(case, source="RUN-OLD/extractions", mtimes={"n.csv": 1.0}, docs=1)
    fake = _FakeClient(docs=1)
    monkeypatch.setattr(case_index, "_client", lambda: fake)
    monkeypatch.setattr(case_index, "_source_extractions_text", lambda case_dir, run_id="": "")
    monkeypatch.setattr(case_index, "_index_file_mtimes", lambda case_dir, run_id="": {})

    meta = case_index.index_case(case, incremental=True, run_id="RUN-NONE")

    assert meta["purge_refused"] is True
    assert not any(call[0] == "DELETE" for call in fake.calls), "nothing resolved, so nothing is dropped"
    assert recreated == ["CASE-RUN"], "only the top-of-call ensure, no recreate"


def test_the_build_records_its_own_duration(indexer, monkeypatch):
    case_index, case, _recreated = indexer
    monkeypatch.setattr(case_index, "_client", lambda: _FakeClient(docs=0))
    monkeypatch.setattr(case_index, "_index_file_mtimes", lambda case_dir, run_id="": {"n.csv": 1.0})

    meta = case_index.index_case(case)

    written = json.loads((case / "analysis" / "es_index.json").read_text(encoding="utf-8"))
    assert written["index_started_at"] == meta["index_started_at"]
    assert written["index_seconds"] == meta["index_seconds"] >= 0
