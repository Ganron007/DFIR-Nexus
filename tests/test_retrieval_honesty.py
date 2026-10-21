"""N4 retrieval is exhaustive; only explicit response pagination limits a page."""
from __future__ import annotations

from nexus.langgraph.query_pack import (
    iter_extraction_files,
    scan_extractions,
)


def _mkcase(tmp_path, name="CASE-HONEST"):
    case = tmp_path / name
    ext = case / "extractions"
    ext.mkdir(parents=True)
    return case, ext


def test_iter_extraction_files_returns_every_file(tmp_path):
    case, ext = _mkcase(tmp_path)
    for i in range(3):
        (ext / f"hayabusa_{i}.csv").write_text(
            "TimeCreated,Computer\n2024-01-01,WS01\n", encoding="utf-8"
        )
    stats: dict = {}
    files = iter_extraction_files(case, stats=stats)
    assert len(files) == 3
    assert stats["files_total"] == 3
    assert stats["files_scanned"] == 3


def test_iter_extraction_files_reads_large_file(tmp_path):
    case, ext = _mkcase(tmp_path)
    (ext / "big_hayabusa.csv").write_text("x" * 5000, encoding="utf-8")
    stats: dict = {}
    files = iter_extraction_files(case, stats=stats)
    assert len(files) == 1
    assert stats["files_total"] == 1
    assert stats["files_scanned"] == 1


def test_scan_extractions_returns_every_row_in_one_file(tmp_path):
    case, ext = _mkcase(tmp_path)
    rows = "\n".join(f"2024-01-01,WS01,sdelete row {i}" for i in range(450))
    (ext / "hayabusa_big.csv").write_text(
        "TimeCreated,Computer,Detail\n" + rows + "\n", encoding="utf-8"
    )
    stats: dict = {}
    hits = scan_extractions(case, ["sdelete"], (None, None), stats=stats)
    assert len(hits) == 450
    assert stats["files_scanned"] == 1
    assert stats["hits_collected"] == 450
    assert stats["hits_returned"] == 450
    # structured matched terms survive (comma-safe display string aside)
    assert hits[0]["terms_list"] == ["sdelete"]


def test_scan_extractions_returns_every_row_across_files(tmp_path):
    case, ext = _mkcase(tmp_path)
    for f in range(11):
        rows = "\n".join(f"2024-01-01,WS01,needle row {i}" for i in range(60))
        (ext / f"hayabusa_{f:02d}.csv").write_text(
            "TimeCreated,Computer,Detail\n" + rows + "\n", encoding="utf-8"
        )
    stats: dict = {}
    hits = scan_extractions(case, ["needle"], (None, None), stats=stats)
    assert len(hits) == 660
    assert stats["hits_collected"] == 660
    assert stats["hits_returned"] == 660
    assert stats["hits_capped"] is False
    assert stats["files_scanned"] == 11


def test_scan_extractions_comma_needle_survives_round_trip(tmp_path):
    """A needle containing a comma must not split into phantom terms."""
    case, ext = _mkcase(tmp_path)
    (ext / "hayabusa_c.csv").write_text(
        "TimeCreated,Computer,Detail\n2024-01-01,WS01,ran sc.exe, net.exe now\n",
        encoding="utf-8",
    )
    stats: dict = {}
    hits = scan_extractions(case, ["sc.exe, net.exe"], (None, None), stats=stats)
    assert len(hits) == 1
    assert hits[0]["terms_list"] == ["sc.exe, net.exe"]
    # display string keeps the needle intact as one item for this row
    assert hits[0]["terms"] == "sc.exe, net.exe"


def test_es_scan_pages_until_every_row_is_returned(monkeypatch, tmp_path):
    """A full ES response batch has a continuation cursor, not a result cap."""
    import json as _json

    from nexus.langgraph import case_index

    class _Resp:
        def __init__(self, code: int, payload: dict):
            self.status_code = code
            self._payload = payload
            self.text = _json.dumps(payload)

        def json(self):
            return self._payload

    class _FullPageClient:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def head(self, path):
            return _Resp(200, {})

        def post(self, path, json=None, content=None, headers=None, params=None):
            after = (json or {}).get("search_after")
            start = int(after[0]) + 1 if after else 0
            end = min(start + 400, 450)
            hits = [
                {"_source": {"text": f"rdp row {i}", "family": "hayabusa",
                             "file": f"f{i}.csv", "line": 1}, "sort": [i]}
                for i in range(start, end)
            ]
            return _Resp(200, {"hits": {"hits": hits}})

    monkeypatch.setattr(case_index, "_client", lambda: _FullPageClient())
    monkeypatch.setattr(case_index, "_schema_version_cached", lambda _cid: case_index.INDEX_SCHEMA_VERSION)
    monkeypatch.setattr(case_index, "fields_property_names", lambda _cid: [])

    stats: dict = {}
    hits = case_index.query_index(
        tmp_path / "CASE-ESCAP", ["rdp", "mstsc"], (None, None), stats=stats
    )
    assert stats["hits_fetched"] == 450
    assert stats["hits_capped"] is False
    assert stats["search_pages"] == 2
    assert len(hits) == 450

def test_attach_hit_fields_ingest_uses_cached_line_index(tmp_path):
    """EH-10: N ingest hits must not re-scan artifacts.jsonl N times."""
    import json as _json

    from nexus.langgraph import query_pack
    from nexus.langgraph.query_pack import attach_hit_fields

    case = tmp_path / "CASE-INGEST"
    store = case / "ingest"
    store.mkdir(parents=True)
    lines = [
        _json.dumps({
            "timestamp": "2024-01-01T00:00:00+00:00", "source": "suricata",
            "artifact_type": "network", "description": f"flow {i}",
        })
        for i in range(60)
    ]
    (store / "artifacts.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    hits = [
        {"family": "suricata", "file": "ingest/artifacts.jsonl", "line": str(i + 1),
         "text": f"flow {i}", "terms": "rdp", "terms_list": ["rdp"]}
        for i in range(0, 60, 5)
    ]
    query_pack._ingest_line_cache.clear()  # global cache — other tests may have filled it
    out = attach_hit_fields(case, hits)
    assert out and out[0]["fields"]["source"] == "suricata"
    assert out[-1]["fields"]["description"] == "flow 55"
    assert len(query_pack._ingest_line_cache) == 1
    # second call reuses the cache (no second entry for the same store)
    snapshot = dict(query_pack._ingest_line_cache)
    attach_hit_fields(case, hits)
    assert query_pack._ingest_line_cache == snapshot
