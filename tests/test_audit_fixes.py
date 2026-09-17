"""Regression tests for the full-suite audit fixes (2026-09-17).

Each test pins a bug that was found by the four-agent audit:
duplicate audit ids, fast-plan intent loss, ES aggregation window/empty-DSL
drift, artifact-store dedupe data loss, .gz silent failure, tshark JSON
misroute, legacy stage-flag paths, and ImportResult.success honesty.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

# ── audit ids ──────────────────────────────────────────────────────────────

def test_audit_ids_unique_across_concurrent_writers(tmp_path):
    from nexus.audit import AuditWriter

    ids: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        writer = AuditWriter("nexus", audit_dir=tmp_path)
        for _ in range(3):
            aid = writer.log(tool="t")
            with lock:
                ids.append(str(aid))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(ids) == 12
    assert len(set(ids)) == 12, "concurrent writers minted duplicate audit ids"


# ── fast-path planner ──────────────────────────────────────────────────────

def test_fast_plan_keeps_specific_intent_for_the_llm():
    from nexus.langgraph.steer_agent import _fast_plan

    # Named executables / named users / quoted phrases → LLM planner.
    assert _fast_plan("Which hosts ran powershell.exe and when?") is None
    assert _fast_plan("Did user bob access the exe?") is None
    assert _fast_plan('Find "faulting application" events') is None
    # Generic list asks still take the shortcut.
    assert _fast_plan("List all exe involved in this case") == ["exe"]
    users = _fast_plan("List all users and machines involved")
    assert users is not None and users[0] == "AGG:match_all|field:user"
    # IOCs are specific but safely expressible.
    assert _fast_plan("Is the file 534a7ea9c67bab3e8f2d41977bf43d41dfe951cf malicious?") == [
        "534a7ea9c67bab3e8f2d41977bf43d41dfe951cf"
    ]


# ── ES aggregation semantics ───────────────────────────────────────────────

def test_es_aggregate_refuses_empty_dsl_without_match_all(monkeypatch):
    from nexus.langgraph import case_index

    monkeypatch.setattr(case_index, "es_available", lambda: True)
    monkeypatch.setattr(case_index, "_schema_version_cached", lambda _cid: 2)
    result = case_index.es_aggregate(
        Path("CASE-X"), dsl="", field="host", match_all=False
    )
    assert result is None, "empty DSL must keep the intake-term (Python) semantics"


def test_es_aggregate_applies_intake_window(monkeypatch):
    from datetime import UTC, datetime

    from nexus.langgraph import case_index

    captured: dict = {}

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return None

        def post(self, path, json):
            captured["body"] = json

            class R:
                status_code = 200

                @staticmethod
                def json():
                    return {"hits": {"total": {"value": 0}}, "aggregations": {"v": {"buckets": []}}}

            return R()

    monkeypatch.setattr(case_index, "es_available", lambda: True)
    monkeypatch.setattr(case_index, "_schema_version_cached", lambda _cid: 2)
    monkeypatch.setattr(case_index, "_resolve_agg_field", lambda _cid, _f: "host")
    monkeypatch.setattr(case_index, "_client", lambda: Client())

    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 1, 2, tzinfo=UTC)
    case_index.es_aggregate(
        Path("CASE-X"), dsl="alert", field="host", match_all=False,
        window=(start, end),
    )
    body_text = json.dumps(captured["body"])
    assert "range" in body_text and "2026-01-01" in body_text, (
        "aggregation must be scoped to the intake window like the row query"
    )


def test_es_aggregate_bucket_keys_match_csv_format(monkeypatch):
    from nexus.langgraph import case_index

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return None

        def post(self, path, json):
            class R:
                status_code = 200

                @staticmethod
                def json():
                    return {
                        "hits": {"total": {"value": 2}},
                        "aggregations": {"v": {"buckets": [
                            {"key_as_string": "2026-01-01T10:00:00.000Z", "doc_count": 2},
                        ]}},
                    }

            return R()

    monkeypatch.setattr(case_index, "es_available", lambda: True)
    monkeypatch.setattr(case_index, "_schema_version_cached", lambda _cid: 2)
    monkeypatch.setattr(case_index, "_resolve_agg_field", lambda _cid, _f: "host")
    monkeypatch.setattr(case_index, "_client", lambda: Client())

    result = case_index.es_aggregate(
        Path("CASE-X"), dsl="alert", field="host", bucket="hour",
    )
    assert result and "2026-01-01T10:00" in result["buckets"]


# ── ingest artifact dedupe ─────────────────────────────────────────────────

def test_artifact_key_keeps_distinct_events_and_stable_for_synthesized_ts(tmp_path):
    from nexus.ingest.schemas import Artifact
    from nexus.langgraph.timeline_merge import append_ingest_artifacts

    case = tmp_path / "CASE-ART"
    case.mkdir()
    base = {
        "source": "suricata", "artifact_type": "http", "severity": "informational",
        "timestamp": "2026-08-11T23:10:37+00:00", "source_ip": "10.0.0.5",
        "dest_ip": "10.0.0.6", "source_port": 5000, "dest_port": 80,
        "protocol": "tcp",
    }
    a1 = Artifact.from_dict({**base, "id": "1", "description": "GET /a"})
    a2 = Artifact.from_dict({**base, "id": "2", "description": "GET /b"})
    append_ingest_artifacts(case, [a1, a2])
    lines = (case / "ingest" / "artifacts.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2, "two different events collapsed into one store row"

    # Same events re-ingested → no duplicates.
    append_ingest_artifacts(case, [a1, a2])
    lines = (case / "ingest" / "artifacts.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2


def test_artifact_key_stable_when_timestamp_synthesized(tmp_path):
    from nexus.ingest.schemas import Artifact
    from nexus.langgraph.timeline_merge import append_ingest_artifacts

    case = tmp_path / "CASE-ART2"
    case.mkdir()

    def make() -> Artifact:
        from datetime import UTC, datetime

        return Artifact.from_dict({
            "id": "x", "source": "generic_jsonl", "artifact_type": "unknown",
            "severity": "informational",
            "timestamp": datetime.now(UTC).isoformat(),
            "description": "alpha", "raw": {"message": "alpha"},
        })

    append_ingest_artifacts(case, [make()])
    append_ingest_artifacts(case, [make()])
    lines = (case / "ingest" / "artifacts.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1, "synthesized timestamps duplicated a re-ingested record"


# ── detection routing ──────────────────────────────────────────────────────

def test_tshark_json_routes_to_wireshark_not_elastic(tmp_path):
    from nexus.ingest.detect import detect_format
    from nexus.ingest.schemas import ArtifactSource

    path = tmp_path / "export.json"
    path.write_text(json.dumps([{
        "_index": "packets",
        "_source": {"layers": {"frame": {"frame.time_epoch": "1"}, "ip": {"ip.src": "1.1.1.1"}}},
    }]), encoding="utf-8")
    assert detect_format(path) == ArtifactSource.WIRESHARK


def test_unsupported_gz_is_honest_not_silent(tmp_path):
    from nexus.ingest.detect import detect_format
    from nexus.ingest.registry import get_registry
    from nexus.ingest.schemas import ArtifactSource

    path = tmp_path / "eve.json.gz"
    path.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 32)
    assert detect_format(path) is None, "gzip JSON has no importer — say so"
    resolved = get_registry().resolve(ArtifactSource.GENERIC_JSONL, path)
    assert resolved is None, "shared-lane fallback must not claim an unsupported file"


def test_import_result_success_is_false_with_errors():
    from nexus.ingest.base import ImportResult
    from nexus.ingest.schemas import ArtifactSource

    result = ImportResult(source=ArtifactSource.SURICATA)
    result.errors.append("mid-parse failure")
    assert result.success is False


# ── cockpit stage flags ────────────────────────────────────────────────────

def test_case_artifact_flags_match_real_writer_paths(tmp_path):
    from nexus.dashboard.app import _case_artifact_flags

    case = tmp_path / "CASE-FLAGS"
    run = case / "runs" / "RUN-1"
    (run / "reports").mkdir(parents=True)
    (run / "reports" / "TOOL-RUN.md").write_text("x", encoding="utf-8")
    (case / "reports").mkdir(parents=True)
    (case / "reports" / "REPORT.md").write_text("x", encoding="utf-8")

    flags = _case_artifact_flags(case)
    assert flags["pipeline_complete"] is True
    assert flags["report_exists"] is True
