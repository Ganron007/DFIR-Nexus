"""Tests for auto-format detection."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from nexus.ingest.detect import detect_format, ingest_auto
from nexus.ingest.schemas import ArtifactSource


class TestAutoDetect:
    def test_evtx_by_filename(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as f:
            f.write(b"\x00" * 100)
            p = Path(f.name)
        assert detect_format(p) == ArtifactSource.EVTX

    def test_syslog_by_content(self) -> None:
        content = "Jan 15 12:34:56 hostname sshd[1234]: Accepted password for user\n"
        with tempfile.NamedTemporaryFile(suffix=".log", mode="w", delete=False) as f:
            f.write(content)
            p = Path(f.name)
        result = detect_format(p)
        assert result == ArtifactSource.SYSLOG

    def test_authlog_by_content(self) -> None:
        content = "Jan 15 12:34:56 hostname sshd[1234]: Failed password for root\n"
        with tempfile.NamedTemporaryFile(prefix="auth", suffix=".log", mode="w", delete=False) as f:
            f.write(content)
            p = Path(f.name)
        result = detect_format(p)
        assert result == ArtifactSource.AUTHLOG

    def test_cloudtrail_by_json_keys(self) -> None:
        data = {"Records": [{"eventTime": "2026-01-01", "eventName": "CreateUser"}]}
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            p = Path(f.name)
        result = detect_format(p)
        assert result == ArtifactSource.CLOUDTRAIL

    def test_velociraptor_by_json_keys(self) -> None:
        data = {"Artifact": "Windows.System.Pslist", "Records": []}
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(data, f)
            p = Path(f.name)
        result = detect_format(p)
        assert result == ArtifactSource.VELOCIRAPTOR

    def test_generic_csv_fallback(self) -> None:
        content = "col1,col2,col3\nval1,val2,val3\nval4,val5,val6\n"
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False) as f:
            f.write(content)
            p = Path(f.name)
        result = detect_format(p)
        assert result == ArtifactSource.GENERIC_CSV

    def test_unknown_file_returns_none(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\xff\xfe\xfd\xfc" * 100)
            p = Path(f.name)
        result = detect_format(p)
        assert result is None

    def test_nonexistent_file_returns_none(self) -> None:
        result = detect_format(Path("/nonexistent/file.log"))
        assert result is None

    def test_ingest_auto_unknown(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\xff\xfe" * 100)
            p = Path(f.name)
        result = ingest_auto(p)
        assert result["success"] is False

    def test_ingest_auto_source_override(self) -> None:
        from nexus.ingest.detect import resolve_ingest_source

        content = "col1,col2,col3\nval1,val2,val3\nval4,val5,val6\n"
        with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False) as f:
            f.write(content)
            p = Path(f.name)
        resolved, err = resolve_ingest_source(p, "generic_csv")
        assert err is None
        assert resolved == ArtifactSource.GENERIC_CSV
        result = ingest_auto(p, source="generic_csv")
        assert result["success"] is True
        assert result["source"] == "generic_csv"

    def test_ingest_auto_bad_source(self) -> None:
        result = ingest_auto(Path("x.csv"), source="not-a-source")
        assert result["success"] is False
        assert "Unknown source" in result["error"]
