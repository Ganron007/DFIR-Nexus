"""Phase 4k EH-1 — retrieval honesty: caps and skipped files are reported.

The rule under test: a truncated or skipped retrieval may lower-bound the
counts, but it must never read as "checked, absent" without a flag.
"""
from __future__ import annotations

from nexus.langgraph.query_pack import (
    _MAX_HITS_PER_FILE,
    _MAX_HITS_TOTAL,
    iter_extraction_files,
    scan_extractions,
)


def _mkcase(tmp_path, name="CASE-HONEST"):
    case = tmp_path / name
    ext = case / "extractions"
    ext.mkdir(parents=True)
    return case, ext


def test_iter_extraction_files_reports_family_cap(tmp_path):
    case, ext = _mkcase(tmp_path)
    for i in range(3):
        (ext / f"hayabusa_{i}.csv").write_text(
            "TimeCreated,Computer\n2024-01-01,WS01\n", encoding="utf-8"
        )
    stats: dict = {}
    files = iter_extraction_files(case, max_files_per_family=2, stats=stats)
    assert len(files) == 2
    assert stats["files_total"] == 3
    assert stats["files_scanned"] == 2
    assert stats["files_skipped_family_cap"] == 1
    assert stats["families_capped"] == ["hayabusa"]


def test_iter_extraction_files_reports_size_skip(tmp_path):
    case, ext = _mkcase(tmp_path)
    (ext / "big_hayabusa.csv").write_text("x" * 5000, encoding="utf-8")
    stats: dict = {}
    files = iter_extraction_files(case, max_bytes=1000, stats=stats)
    assert files == []
    assert stats["files_total"] == 1
    assert stats["files_skipped_size"] == 1


def test_scan_extractions_flags_per_file_cap(tmp_path):
    case, ext = _mkcase(tmp_path)
    rows = "\n".join(f"2024-01-01,WS01,sdelete row {i}" for i in range(60))
    (ext / "hayabusa_big.csv").write_text(
        "TimeCreated,Computer,Detail\n" + rows + "\n", encoding="utf-8"
    )
    stats: dict = {}
    hits = scan_extractions(case, ["sdelete"], (None, None), stats=stats)
    assert len(hits) == _MAX_HITS_PER_FILE
    assert stats["files_capped"] == 1
    assert stats["files_scanned"] == 1
    assert stats["families_capped"] == []
    # structured matched terms survive (comma-safe display string aside)
    assert hits[0]["terms_list"] == ["sdelete"]


def test_scan_extractions_flags_total_cap(tmp_path):
    case, ext = _mkcase(tmp_path)
    for f in range(11):
        rows = "\n".join(f"2024-01-01,WS01,needle row {i}" for i in range(60))
        (ext / f"hayabusa_{f:02d}.csv").write_text(
            "TimeCreated,Computer,Detail\n" + rows + "\n", encoding="utf-8"
        )
    stats: dict = {}
    hits = scan_extractions(case, ["needle"], (None, None), stats=stats)
    assert len(hits) == _MAX_HITS_TOTAL
    assert stats["hits_collected"] > _MAX_HITS_TOTAL
    assert stats["hits_capped"] is True
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


def test_es_scan_reports_fetch_cap(monkeypatch, tmp_path):
    """A chunk that fills its 400-doc page means counts are lower bounds."""
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
            # every query answers with a FULL 400-doc page of matching rows
            hits = [
                {"_source": {"text": f"rdp row {i}", "family": "hayabusa",
                             "file": f"f{i}.csv", "line": 1}}
                for i in range(400)
            ]
            return _Resp(200, {"hits": {"hits": hits}})

    monkeypatch.setattr(case_index, "_client", lambda: _FullPageClient())
    monkeypatch.setattr(case_index, "_schema_version_cached", lambda _cid: 2)
    monkeypatch.setattr(case_index, "fields_property_names", lambda _cid: [])

    stats: dict = {}
    hits = case_index.query_index(
        tmp_path / "CASE-ESCAP", ["rdp", "mstsc"], (None, None), stats=stats
    )
    assert stats["hits_fetched"] == 400
    assert stats["hits_capped"] is True
    assert len(hits) == 400

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
