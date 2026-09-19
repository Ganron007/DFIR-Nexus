"""EH-10 — bottleneck work: shared wide scan, incremental reindex, lane
concurrency knob, and off-loop hashing/report helpers (behavior-level)."""
from __future__ import annotations

import json
import json as _json
from pathlib import Path

# ── B5: shared wide scan ────────────────────────────────────────────────

def test_entity_inventory_uses_provided_hits(monkeypatch):
    from nexus.langgraph import entity_inventory as ei

    def _boom(*a, **k):
        raise AssertionError("do_n4_query must not be called when hits are provided")

    monkeypatch.setattr("nexus.tools.evidence_index.do_n4_query", _boom)
    hits = [{
        "family": "hayabusa", "file": "f.csv", "line": "2",
        "text": "powershell.exe ran C:\\Tools\\m.exe",
        "host": "ws01", "fields": {"Computer": "WS01", "User": "alice"},
    }]
    inv = ei.build_entity_inventory("CASE-X", hits=hits)
    assert any("powershell.exe" in p["value"] for p in inv["processes"])
    assert any(h["value"] == "ws01" for h in inv["hosts"])


def test_ti_sweep_uses_provided_hits(monkeypatch):
    from nexus.langgraph import ti_context

    def _boom(*a, **k):
        raise AssertionError("do_n4_query must not be called when hits are provided")

    monkeypatch.setattr("nexus.tools.evidence_index.do_n4_query", _boom)
    hits = [{
        "family": "suricata", "file": "ingest/artifacts.jsonl", "line": "1",
        "text": "flow to 8.8.8.8 and evil.example.com",
    }]
    sweep = ti_context.sweep_case_iocs("CASE-X", hits=hits)
    assert sweep["hits_scanned"] == 1
    assert "8.8.8.8" in (sweep["iocs"].get("ipv4") or []) or \
        "8.8.8.8" in str(sweep["iocs"])


# ── B6: incremental reindex ─────────────────────────────────────────────

def _mkcase(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-IDX"
    ext = case / "extractions"
    ext.mkdir(parents=True)
    (ext / "hayabusa_a.csv").write_text(
        "TimeCreated,Computer,RuleTitle\n2024-01-01,WS01,RDP Logon\n",
        encoding="utf-8",
    )
    (ext / "evtxecmd_b.csv").write_text(
        "TimeCreated,Computer,EventId\n2024-01-02,WS01,4624\n",
        encoding="utf-8",
    )
    return case


def test_iter_index_docs_only_files_filter(tmp_path):
    from nexus.langgraph.case_index import iter_index_docs

    case = _mkcase(tmp_path)
    all_docs = iter_index_docs(case)
    files = {d["file"] for d in all_docs}
    assert files == {"hayabusa_a.csv", "evtxecmd_b.csv"}

    only = iter_index_docs(case, only_files={"hayabusa_a.csv"})
    assert only
    assert {d["file"] for d in only} == {"hayabusa_a.csv"}


def test_index_file_mtimes_keys_match_doc_files(tmp_path):
    from nexus.langgraph.case_index import _index_file_mtimes, iter_index_docs

    case = _mkcase(tmp_path)
    mtimes = _index_file_mtimes(case)
    docs = iter_index_docs(case)
    assert set(mtimes) >= {d["file"] for d in docs}


def test_lane_concurrency_knob(monkeypatch):
    from nexus.langgraph.tool_lane import _lane_concurrency

    monkeypatch.delenv("NEXUS_TOOL_LANE_CONCURRENCY", raising=False)
    assert _lane_concurrency() == 1
    monkeypatch.setenv("NEXUS_TOOL_LANE_CONCURRENCY", "3")
    assert _lane_concurrency() == 3
    monkeypatch.setenv("NEXUS_TOOL_LANE_CONCURRENCY", "99")
    assert _lane_concurrency() == 4
    monkeypatch.setenv("NEXUS_TOOL_LANE_CONCURRENCY", "junk")
    assert _lane_concurrency() == 1


class _FakeES:
    """Minimal stateful ES double for index_case()."""

    def __init__(self):
        self.docs: dict[str, dict] = {}
        self.deleted_file_terms: list[list[str]] = []
        self.cleared = 0
        self.bulk_batches = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    class _Resp:
        def __init__(self, code: int, payload: dict):
            self.status_code = code
            self._p = payload
            self.text = json.dumps(payload)

        def json(self):
            return self._p

    def head(self, path):
        return self._Resp(200, {})

    def put(self, path, json=None):
        return self._Resp(200, {"acknowledged": True})

    def post(self, path, json=None, content=None, headers=None, params=None):
        if path.endswith("/_count"):
            return self._Resp(200, {"count": len(self.docs)})
        if path.endswith("/_refresh"):
            return self._Resp(200, {})
        if path.endswith("/_delete_by_query"):
            query = (json or {}).get("query", {})
            if "match_all" in query:
                self.cleared += 1
                self.docs.clear()
            elif "terms" in query and "file" in (query["terms"] or {}):
                batch = [str(f) for f in query["terms"]["file"]]
                self.deleted_file_terms.append(batch)
                wanted = set(batch)
                self.docs = {
                    k: v for k, v in self.docs.items()
                    if str(v.get("file") or "") not in wanted
                }
            return self._Resp(200, {"deleted": 1})
        if path == "/_bulk":
            self.bulk_batches += 1
            for line in (content or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                if "index" in obj:
                    doc_id = obj["index"].get("_id")
                    pending = doc_id
                    self._pending = pending
                else:
                    doc_id = getattr(self, "_pending", None)
                    if doc_id:
                        self.docs[doc_id] = obj
            return self._Resp(200, {"errors": False, "items": [{"index": {}}]})
        return self._Resp(200, {})


def _patch_es(monkeypatch, fake):
    from nexus.langgraph import case_index

    monkeypatch.setattr(case_index, "_client", lambda: fake)
    monkeypatch.setattr(case_index, "ensure_index", lambda _cid: "nexus-case-x")
    monkeypatch.setattr(case_index, "es_url", lambda: "http://localhost:9200")
    monkeypatch.setattr(case_index, "_newest_extraction_mtime", lambda _cd: 0.0)


def test_index_case_incremental_only_reindexes_changed_files(tmp_path, monkeypatch):
    from nexus.langgraph import case_index

    case = _mkcase(tmp_path)
    fake = _FakeES()
    _patch_es(monkeypatch, fake)

    # first run: no prior state → full rebuild
    meta1 = case_index.index_case(case, incremental=True)
    assert meta1["incremental"] is False
    assert meta1["docs"] == 2
    assert fake.cleared == 1
    assert len(fake.docs) == 2

    # touch ONE file (bump mtime far into the future to be fs-resolution safe)
    target = case / "extractions" / "hayabusa_a.csv"
    target.write_text(
        "TimeCreated,Computer,RuleTitle\n2024-02-02,WS01,RDP Logon\n"
        "2024-02-03,WS01,RDP Logon\n",
        encoding="utf-8",
    )
    import os
    import time

    future = time.time() + 5
    os.utime(target, (future, future))

    meta2 = case_index.index_case(case, incremental=True)
    assert meta2["incremental"] is True
    assert meta2["files_reindexed"] == ["hayabusa_a.csv"]
    assert fake.cleared == 1  # no second full clear
    assert fake.deleted_file_terms == [["hayabusa_a.csv"]]
    # unchanged file's docs survived; changed file re-indexed (2 rows)
    files = sorted(str(d.get("file")) for d in fake.docs.values())
    assert files.count("evtxecmd_b.csv") == 1
    assert files.count("hayabusa_a.csv") == 2

    # removing a file purges its docs
    (case / "extractions" / "evtxecmd_b.csv").unlink()
    meta3 = case_index.index_case(case, incremental=True)
    assert "evtxecmd_b.csv" in meta3["files_removed"]
    assert not any(
        str(d.get("file")) == "evtxecmd_b.csv" for d in fake.docs.values()
    )


def test_write_index_state_records_file_mtimes(tmp_path):
    from nexus.langgraph.case_index import write_index_state

    case = _mkcase(tmp_path)
    write_index_state(case, {"docs": 3, "index": "nx"}, file_mtimes={"a/b.csv": 123.0})
    state = json.loads((case / "analysis" / "index_state.json").read_text(encoding="utf-8"))
    assert state["file_mtimes"] == {"a/b.csv": 123.0}
    assert state["docs"] == 3
