"""Imported evidence must be searchable in N4 (ES docs + CSV parity) and visible.

Regression: importer routing worked after the detection fix, but the artifact
store was never indexed — n4_query/Chat/Briefing saw 0 network events.
"""
from __future__ import annotations

import json
from pathlib import Path


def _mkcase(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-INGEST"
    (case / "ingest").mkdir(parents=True)
    (case / "analysis").mkdir(parents=True)
    rows = [
        {
            "id": "uuid-1", "artifact_type": "alert", "source": "suricata",
            "timestamp": "2026-08-11T23:10:37+00:00", "severity": "high",
            "host": "sensor-1", "user": None, "source_ip": "192.168.77.55",
            "source_port": 58316, "dest_ip": "192.168.77.50", "dest_port": 9200,
            "protocol": "tcp", "description": "ET SCAN Possible Scanner",
            "technique_ids": ["T1046"], "iocs": ["192.168.77.50"],
        },
        {
            "id": "uuid-2", "artifact_type": "http", "source": "suricata",
            "timestamp": "2026-08-11T23:10:38+00:00", "severity": "informational",
            "host": "sensor-1", "source_ip": "192.168.77.55", "dest_ip": "192.168.77.50",
            "protocol": "tcp", "description": "Suricata http",
        },
    ]
    (case / "ingest" / "artifacts.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )
    return case


def test_scan_extractions_sees_ingest_rows(tmp_path):
    from nexus.langgraph.query_pack import scan_extractions

    case = _mkcase(tmp_path)
    hits = scan_extractions(case, ["ET SCAN"], (None, None))
    assert hits, "suricata alert must be searchable in the CSV backend"
    assert hits[0]["family"] == "suricata"
    assert hits[0]["file"] == "ingest/artifacts.jsonl"


def test_index_docs_include_ingest_rows(tmp_path):
    from nexus.langgraph.case_index import iter_index_docs

    case = _mkcase(tmp_path)
    docs = iter_index_docs(case, [])
    ingest_docs = [d for d in docs if d.get("file") == "ingest/artifacts.jsonl"]
    assert len(ingest_docs) == 2
    assert {d["family"] for d in ingest_docs} == {"suricata"}
    assert any(d.get("ts") for d in ingest_docs)
    # the raw store JSONL is not indexed — only the clean projection
    assert all("uuid" not in d["text"] for d in ingest_docs)


def test_attach_hit_fields_ingest_projection(tmp_path):
    from nexus.langgraph.query_pack import attach_hit_fields, scan_extractions

    case = _mkcase(tmp_path)
    hits = scan_extractions(case, ["ET SCAN"], (None, None))
    enriched = attach_hit_fields(case, hits)
    fields = enriched[0]["fields"]
    assert fields.get("artifact_type") == "alert"
    assert fields.get("severity") == "high"
    assert fields.get("dest_ip") == "192.168.77.50"
    assert enriched[0]["host"] == "sensor-1"


def test_family_inventory_includes_ingest_sources(tmp_path):
    from nexus.langgraph.briefing import _family_inventory

    case = _mkcase(tmp_path)
    inv = _family_inventory(case)
    assert "suricata" in inv
    assert inv["suricata"]["rows"] == 2
