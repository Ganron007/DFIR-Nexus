"""Re-audit (wiring gaps) regressions — every fixed gap gets a test."""
from __future__ import annotations

import json
from pathlib import Path


# ── ES path: terms_list + merged-cap honesty ───────────────────────────

class _Resp:
    def __init__(self, code: int, payload: dict):
        self.status_code = code
        self._p = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._p


class _FakeSearch:
    """Returns 150 unique hits for every chunk query (merges to 450 → cap)."""

    def __init__(self, per_query: int = 150):
        self.per_query = per_query
        self.counter = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def head(self, path):
        return _Resp(200, {})

    def post(self, path, json=None, content=None, headers=None, params=None):
        hits = []
        for _ in range(self.per_query):
            self.counter += 1
            hits.append({"_source": {
                "text": f"rdp row {self.counter}",
                "family": "hayabusa", "file": f"f{self.counter}.csv", "line": 1,
            }})
        return _Resp(200, {"hits": {"hits": hits}})


def test_es_hits_carry_terms_list_and_merged_cap(monkeypatch, tmp_path):
    from nexus.langgraph import case_index

    fake = _FakeSearch(per_query=150)
    monkeypatch.setattr(case_index, "_client", lambda: fake)
    monkeypatch.setattr(case_index, "_schema_version_cached", lambda _c: 2)
    monkeypatch.setattr(case_index, "fields_property_names", lambda _c: [])
    stats: dict = {}
    # 121 terms → 4 ES chunks × 150 = 600 merged → trimmed to the 400 total cap
    terms = ["rdp"] + [f"t{i:03d}" for i in range(120)]
    hits = case_index.query_index(
        tmp_path / "CASE-ES", terms, (None, None), stats=stats
    )
    assert hits and hits[0].get("terms_list"), "ES hits must carry terms_list"
    # 3 chunks x 150 = 450 merged, finalize trims to 400 → lower bound
    assert stats["hits_fetched"] == 600
    assert stats["hits_capped"] is True
    assert stats["hits_returned"] == 400


# ── ingest scan: terms_list + collect cap flag ─────────────────────────

def test_ingest_scan_terms_list_and_cap(tmp_path, monkeypatch):
    from nexus.langgraph import query_pack

    case = tmp_path / "CASE-ING"
    store = case / "ingest"
    store.mkdir(parents=True)
    rows = [
        json.dumps({"timestamp": "2024-01-01T00:00:00+00:00", "source": "suricata",
                    "artifact_type": "network", "description": f"rdp row {i}"})
        for i in range(260)
    ]
    (store / "artifacts.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")
    stats: dict = {}
    hits = query_pack.scan_extractions(case, ["rdp"], (None, None), stats=stats)
    assert hits and hits[0]["terms_list"] == ["rdp"]
    assert stats.get("ingest_capped") is True  # 260 matched, collect cap 200
    assert len([h for h in hits if h["file"] == "ingest/artifacts.jsonl"]) == 200


# ── n4_query surfaces coverage ─────────────────────────────────────────

def test_n4_query_reports_lower_bound(tmp_path):
    from nexus.langgraph.query_pack import n4_query

    case = tmp_path / "CASE-Q"
    ext = case / "extractions"
    ext.mkdir(parents=True)
    rows = "\n".join(f"2024-01-01,WS01,rdp row {i}" for i in range(450))
    (ext / "hayabusa_big.csv").write_text(
        "TimeCreated,Computer,Detail\n" + rows + "\n", encoding="utf-8"
    )
    (case / "CASE.yaml").write_text("intake:\n  query_extra: rdp\n", encoding="utf-8")
    result = n4_query(case, "rdp", limit=400, backend="csv")
    # one file × 450 matching rows → per-file cap keeps 40; the count is a
    # LOWER BOUND and the reasons say why (was silent before EH-1 re-audit)
    assert result["count"] == 40
    assert result["count_lower_bound"] is True
    assert result["capped_reasons"]
    assert result["stats"]["files_capped"] == 1


# ── timeline keeps the ts flags through the merge ──────────────────────

def test_timeline_merge_keeps_ts_flags():
    from nexus.langgraph.timeline_merge import merge_events

    hit_ev = {
        "file": "ingest/artifacts.jsonl", "line": "3",
        "timestamp": "2026-01-01T00:00:00", "terms": "rdp",
        "fields": {"ts_synthesized": True},
    }
    ingest_ev = {
        "file": "ingest/artifacts.jsonl", "line": "3",
        "timestamp": "2026-01-01T00:00:00", "terms": "rdp",
        "ts_synthesized": True, "ts_year_assumed": True,
    }
    merged = merge_events([hit_ev], [ingest_ev])
    assert len(merged) == 1
    assert merged[0]["ts_synthesized"] is True
    assert merged[0]["ts_year_assumed"] is True


# ── from_dict preserves ingested_at ────────────────────────────────────

def test_artifact_from_dict_preserves_ingested_at():
    from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity
    from datetime import UTC, datetime

    art = Artifact(
        id="a", artifact_type=ArtifactType.NETWORK, source=ArtifactSource.ZEEK,
        timestamp=datetime.now(UTC), severity=Severity.LOW,
        ingested_at=datetime(2020, 1, 1, tzinfo=UTC),
    )
    round_tripped = Artifact.from_dict(art.to_dict())
    assert round_tripped.ingested_at.year == 2020


# ── linkage: generic path tokens must not false-link ───────────────────

def test_linkage_does_not_false_link_on_shared_roots(tmp_path):
    from nexus.langgraph.audit_linkage import is_linked

    case = tmp_path / "CASE-ROOT"
    (case / "audit").mkdir(parents=True)
    (case / "audit" / "nexus.jsonl").write_text(json.dumps({
        "tool": "ingest_auto", "audit_id": "ingest_auto-tester-20260919-001",
        "params": {"path": "D:/evidence/caseA/mft/$MFT"},
        "result_summary": {"source": "mftecmd"},
    }) + "\n", encoding="utf-8")
    # a zeek finding under the same evidence root must NOT link this audit
    assert is_linked(
        case, "ingest_auto-tester-20260919-001", {"zeek"},
        ["D:/evidence/caseB/zeek/conn.log"],
    ) is False
    # but the actual family does link
    assert is_linked(
        case, "ingest_auto-tester-20260919-001", {"mftecmd"}, [],
    ) is True


# ── ingest_into_case writes a case-scoped audit entry ──────────────────

def test_ingest_into_case_writes_audit(tmp_path, monkeypatch):
    from nexus.ingest import registry as registry_mod
    from nexus.ingest.schemas import ArtifactSource
    from nexus.langgraph import timeline_merge

    case = tmp_path / "CASE-AUD"
    case.mkdir()

    class _Result:
        success = True
        source = ArtifactSource.ZEEK
        artifacts = []
        errors: list = []

    class _FakeRegistry:
        def import_path(self, path, source=None, limit=0):
            return _Result()

    monkeypatch.setattr(registry_mod, "get_registry", lambda: _FakeRegistry())
    monkeypatch.setattr(
        "nexus.ingest.detect.resolve_ingest_source",
        lambda path, source=None: (ArtifactSource.ZEEK, None),
    )
    out = timeline_merge.ingest_into_case(case / "conn.log", case)
    assert out["success"] is True
    audit_log = case / "audit" / "nexus.jsonl"
    assert audit_log.is_file()
    entries = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert any(
        e.get("tool") == "ingest_auto"
        and (e.get("result_summary") or {}).get("source") == "zeek"
        for e in entries
    )


# ── single comma needle survives the newline encoding ──────────────────

def test_single_comma_needle_round_trips_via_trailing_newline():
    from nexus.langgraph.query_pack import _parse_needles

    raw = "sc.exe, net.exe\n"
    assert _parse_needles(raw) == ["sc.exe, net.exe"]


# ── needle → DSL quoting ───────────────────────────────────────────────

def test_needle_dsl_quotes_multiword_terms():
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from nexus.dashboard.app import _needle_dsl

    assert _needle_dsl("sdelete") == "sdelete"
    assert _needle_dsl("sc.exe, net.exe") == '"sc.exe, net.exe"'
    assert _needle_dsl("my drive") == '"my drive"'


# ── provenance: no scope with existing ids must not grade FULL ─────────

def test_score_provenance_no_scope_is_partial(tmp_path):
    from nexus.case_manager import CaseManager

    case = tmp_path / "CASE-PROV"
    (case / "audit").mkdir(parents=True)
    (case / "audit" / "nexus.jsonl").write_text(json.dumps({
        "tool": "hayabusa", "audit_id": "hayabusa-tester-20260919-001",
    }) + "\n", encoding="utf-8")
    mgr = CaseManager()
    scored = mgr._score_provenance(
        {"title": "x", "audit_ids": ["hayabusa-tester-20260919-001"]}, case
    )
    assert scored["grade"] == "PARTIAL"
    assert "linkage unverifiable" in scored["detail"]
