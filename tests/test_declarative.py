"""Tests for declarative custom importers — JSON spec framework."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from nexus.ingest.declarative import (
    DeclarativeImporter,
    load_declarative_specs,
)

SAMPLE_SPEC = {
    "name": "test_custom_scanner",
    "source": "custom",
    "detect": {
        "filename_patterns": ["test_scan.json", "*.custom"],
        "content_keys": ["scan_id", "findings"],
    },
    "format": "json",
    "records_path": "findings",
    "fields": {
        "timestamp": "detected_at",
        "host": "hostname",
        "description": "message",
        "severity": "risk_level",
        "file_hash_sha256": "sha256",
    },
    "severity_map": {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    },
    "technique_field": "mitre_id",
    "ioc_fields": ["sha256", "src_ip"],
}


class TestDeclarativeImporter:
    def test_create_from_spec(self) -> None:
        imp = DeclarativeImporter(SAMPLE_SPEC)
        assert imp._name == "test_custom_scanner"
        assert imp._format == "json"

    def test_can_handle_by_filename(self) -> None:
        imp = DeclarativeImporter(SAMPLE_SPEC)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "test_scan.json"
            p.write_text(json.dumps({"scan_id": "123", "findings": []}))
            assert imp.can_handle_spec(p)

    def test_can_handle_by_content_keys(self) -> None:
        imp = DeclarativeImporter(SAMPLE_SPEC)
        data = {"scan_id": "123", "findings": []}
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            p = Path(f.name)
        assert imp.can_handle_spec(p)

    def test_parse_json(self) -> None:
        imp = DeclarativeImporter(SAMPLE_SPEC)
        data = {
            "scan_id": "test-001",
            "findings": [
                {
                    "detected_at": "2026-01-15T10:30:00",
                    "hostname": "dc01.corp",
                    "message": "Suspicious process",
                    "risk_level": "high",
                    "sha256": "abc123" * 10 + "1234",
                    "mitre_id": "T1059.001",
                    "src_ip": "10.0.0.5",
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            p = Path(f.name)
        artifacts = list(imp.parse(p))
        assert len(artifacts) == 1
        assert artifacts[0].host == "dc01.corp"
        assert artifacts[0].severity.value == "high"
        assert "T1059.001" in artifacts[0].technique_ids

    def test_parse_jsonl(self) -> None:
        spec = {**SAMPLE_SPEC, "format": "jsonl"}
        imp = DeclarativeImporter(spec)
        lines = [
            json.dumps({"detected_at": "2026-01-15T10:30:00", "hostname": "h1", "message": "test", "risk_level": "low"}),
            json.dumps({"detected_at": "2026-01-15T10:31:00", "hostname": "h2", "message": "test2", "risk_level": "medium"}),
        ]
        with tempfile.NamedTemporaryFile(suffix=".jsonl", mode="w", delete=False) as f:
            f.write("\n".join(lines))
            p = Path(f.name)
        artifacts = list(imp.parse(p))
        assert len(artifacts) == 2

    def test_parse_csv(self) -> None:
        spec = {**SAMPLE_SPEC, "format": "csv"}
        imp = DeclarativeImporter(spec)
        content = "detected_at,hostname,message,risk_level\n2026-01-15,h1,found malware,high\n"
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False) as f:
            f.write(content)
            p = Path(f.name)
        artifacts = list(imp.parse(p))
        assert len(artifacts) == 1
        assert artifacts[0].host == "h1"

    def test_load_specs_from_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spec_path = Path(tmp) / "test_spec.json"
            spec_path.write_text(json.dumps(SAMPLE_SPEC))
            specs = load_declarative_specs(Path(tmp))
            assert len(specs) == 1
            assert specs[0]["name"] == "test_custom_scanner"

    def test_empty_dir_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            specs = load_declarative_specs(Path(tmp))
            assert len(specs) == 0
