"""Importer detection robustness — tail captures and NDJSON must not fall to CSV.

Regression: an `eve-tail.json` capture whose first line is a truncated JSON
fragment was misrouted to `generic_csv` and the Suricata parser never ran.
"""
from __future__ import annotations

from pathlib import Path


def _write_eve_tail(tmp_path: Path) -> Path:
    path = tmp_path / "eve-tail.json"
    path.write_text(
        'ort":9200,"url":"/_bulk","http_user_agent":"Elastic-filebeat/9.4.4"}\n'
        '{"timestamp":"2026-08-11T23:10:37.266305+0000","flow_id":1683091442593974,'
        '"event_type":"http","src_ip":"192.168.77.55","src_port":58312,'
        '"dest_ip":"192.168.77.50","dest_port":9200,"proto":"TCP"}\n'
        '{"timestamp":"2026-08-11T23:10:37.958771+0000","flow_id":1568926415090696,'
        '"event_type":"alert","src_ip":"192.168.77.55","dest_ip":"192.168.77.50",'
        '"proto":"TCP","alert":{"signature":"ET SCAN Possible Scanner","severity":2}}\n',
        encoding="utf-8",
    )
    return path


def test_detect_format_tail_ndjson_routes_suricata(tmp_path):
    from nexus.ingest.detect import detect_format
    from nexus.ingest.schemas import ArtifactSource

    path = _write_eve_tail(tmp_path)
    assert detect_format(path) == ArtifactSource.SURICATA


def test_suricata_can_handle_skips_truncated_first_line(tmp_path):
    from nexus.ingest.network.suricata import SuricataImporter

    path = _write_eve_tail(tmp_path)
    assert SuricataImporter.can_handle(path) is True


def test_resolve_and_parse_suricata_tail(tmp_path):
    from nexus.ingest.detect import resolve_ingest_source
    from nexus.ingest.registry import get_registry
    from nexus.ingest.schemas import ArtifactSource

    path = _write_eve_tail(tmp_path)
    resolved, err = resolve_ingest_source(path, None)
    assert err is None
    assert resolved == ArtifactSource.SURICATA

    result = get_registry().import_path(path, source=resolved)
    assert result.success, result.errors
    assert len(result.artifacts) == 2  # the truncated line is skipped, not fatal
    types = {a.to_dict()["artifact_type"] for a in result.artifacts}
    assert types == {"http", "alert"}
    dest_ips = {a.to_dict().get("dest_ip") for a in result.artifacts}
    assert dest_ips == {"192.168.77.50"}


def test_unknown_ndjson_is_not_csv(tmp_path):
    from nexus.ingest.detect import detect_format
    from nexus.ingest.schemas import ArtifactSource

    path = tmp_path / "mystery.json"
    path.write_text('{"foo": 1, "bar": "x"}\n{"foo": 2, "bar": "y"}\n', encoding="utf-8")
    assert detect_format(path) == ArtifactSource.GENERIC_JSONL


def test_plain_csv_still_generic_csv(tmp_path):
    from nexus.ingest.detect import detect_format
    from nexus.ingest.schemas import ArtifactSource

    path = tmp_path / "table.csv"
    path.write_text("a,b,c\n1,2,3\n4,5,6\n", encoding="utf-8")
    assert detect_format(path) == ArtifactSource.GENERIC_CSV


def test_append_ingest_artifacts_dedupes_reprocess(tmp_path):
    from nexus.ingest.network.suricata import SuricataImporter
    from nexus.langgraph.timeline_merge import append_ingest_artifacts

    ev = _write_eve_tail(tmp_path)
    arts = list(SuricataImporter().parse(ev))
    assert len(arts) == 2

    case_dir = tmp_path / "CASE-DEDUPE"
    case_dir.mkdir()
    append_ingest_artifacts(case_dir, arts)
    append_ingest_artifacts(case_dir, arts)  # reprocess the same log
    store = case_dir / "ingest" / "artifacts.jsonl"
    lines = [ln for ln in store.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == len(arts)
