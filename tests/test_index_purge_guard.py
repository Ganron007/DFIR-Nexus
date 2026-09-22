"""Index purge guard: an empty resolution must never wipe a populated index.

Live incident (2026-09-22, CASE-12E50AF8): a ``--from-case`` coverage run
re-pointed the tools run pointer at a run that owns no extractions. The
incremental/full reindex then resolved zero files and purged 128k docs.
"""

from __future__ import annotations

import json


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
        self.deletes: list[dict] = []
        self.bulk_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def head(self, path):
        return _Resp(200, {})

    def get(self, path):
        return _Resp(200, {})

    def post(self, path, json=None, params=None, content=None, headers=None):
        if "_delete_by_query" in path:
            self.deletes.append(json or {})
            return _Resp(200, {"deleted": self.docs})
        if "_count" in path:
            return _Resp(200, {"count": self.docs})
        if "_bulk" in path:
            self.bulk_calls += 1
            return _Resp(200, {"errors": False, "items": []})
        return _Resp(200, {})


def _case(tmp_path, name="CASE-GUARD"):
    case = tmp_path / name
    (case / "analysis").mkdir(parents=True)
    (case / "analysis" / "index_state.json").write_text(
        json.dumps({"file_mtimes": {"hayabusa-timeline.csv": 1.0}, "docs": 5}),
        encoding="utf-8",
    )
    return case


def test_full_rebuild_refuses_purge_on_empty_resolution(tmp_path, monkeypatch):
    from nexus.langgraph import case_index

    case = _case(tmp_path)
    fake = _FakeClient(docs=5)
    monkeypatch.setattr(case_index, "_client", lambda: fake)
    monkeypatch.setattr(case_index, "ensure_index", lambda case_id: f"nexus-case-{case_id.lower()}")
    monkeypatch.setattr(case_index, "_index_file_mtimes", lambda case_dir: {})

    meta = case_index.index_case(case)

    assert meta["purge_refused"] is True
    assert meta["docs"] == 5
    assert fake.deletes == [], "purge must not run on an empty resolution"
    assert "purge refused" in meta["purge_refused_reason"]


def test_fresh_case_stale_index_is_still_cleared(tmp_path, monkeypatch):
    """No prior state → the stale-index clear keeps working (old contract)."""
    from nexus.langgraph import case_index

    case = tmp_path / "CASE-FRESH"
    case.mkdir()
    fake = _FakeClient(docs=5)  # index holds docs but the case never indexed
    monkeypatch.setattr(case_index, "_client", lambda: fake)
    monkeypatch.setattr(case_index, "ensure_index", lambda case_id: f"nexus-case-{case_id.lower()}")
    monkeypatch.setattr(case_index, "_index_file_mtimes", lambda case_dir: {})

    meta = case_index.index_case(case)

    assert meta["purge_refused"] is False
    assert fake.deletes, "a fresh case must clear a stale index"
    assert meta["docs"] == 0


def test_full_rebuild_purges_when_files_resolve(tmp_path, monkeypatch):
    from nexus.langgraph import case_index

    case = _case(tmp_path, "CASE-OK")
    fake = _FakeClient(docs=5)
    monkeypatch.setattr(case_index, "_client", lambda: fake)
    monkeypatch.setattr(case_index, "ensure_index", lambda case_id: f"nexus-case-{case_id.lower()}")
    monkeypatch.setattr(case_index, "_index_file_mtimes", lambda case_dir: {"b.csv": 2.0})

    meta = case_index.index_case(case)

    assert meta["purge_refused"] is False
    assert fake.deletes, "a real rebuild must clear the index"
    assert meta["docs"] == 0  # no batches materialized from the fake case dir
