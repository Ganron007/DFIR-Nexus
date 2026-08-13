"""Regression tests for the 2026-08-07 ingest audit fixes.

Covers:
- B1: registry source-map clobbering (shared ArtifactSource lanes)
- B2: detect_format substring-hint misrouting ("sam" in "*sample*")
- G1-class: NDJSON content with a plain .json extension
- Wrapped TheHive/IRIS export shapes
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus.ingest.detect import detect_format
from nexus.ingest.registry import get_registry
from nexus.ingest.schemas import ArtifactSource


@pytest.fixture()
def registry():
    return get_registry()


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


class TestRegistryDisambiguation:
    """B1: shared ArtifactSource values must not clobber each other."""

    def test_suricata_lane_resolves_suricata_for_eve(self, registry, tmp_path):
        eve = _write(
            tmp_path,
            "eve.json",
            '{"event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2",'
            '"alert":{"severity":1,"signature":"x"}}\n',
        )
        cls = registry.resolve(ArtifactSource.SURICATA, eve)
        assert cls.__name__ == "SuricataImporter"

    def test_syslog_lane_resolves_journald_for_journal(self, registry, tmp_path):
        journal = _write(
            tmp_path,
            "journal-export.json",
            '{"PRIORITY":"6","__REALTIME_TIMESTAMP":"1700000000000000",'
            '"MESSAGE":"ok","_HOSTNAME":"h"}\n',
        )
        cls = registry.resolve(ArtifactSource.SYSLOG, journal)
        assert cls.__name__ == "JournaldImporter"

    def test_generic_jsonl_lane_resolves_archive_for_zip(self, registry, tmp_path):
        z = tmp_path / "bundle.zip"
        z.write_bytes(b"PK\x03\x04")
        cls = registry.resolve(ArtifactSource.GENERIC_JSONL, z)
        assert cls.__name__ == "ArchiveImporter"

    def test_generic_jsonl_lane_resolves_email_for_eml(self, registry, tmp_path):
        eml = _write(tmp_path, "phishing.eml", "From: a@b\nSubject: hi\n\nbody")
        cls = registry.resolve(ArtifactSource.GENERIC_JSONL, eml)
        assert cls.__name__ == "EmailImporter"

    def test_thehive_lane_resolves_iris_for_iris_name(self, registry, tmp_path):
        iris = _write(tmp_path, "iris-case.json", '{"case": {}, "iocs": []}')
        cls = registry.resolve(ArtifactSource.THEHIVE, iris)
        assert cls.__name__ == "IRISImporter"

    def test_all_shared_sources_keep_first_registered_primary(self, registry):
        for source in (
            ArtifactSource.SURICATA,
            ArtifactSource.SYSLOG,
            ArtifactSource.GENERIC_JSONL,
            ArtifactSource.THEHIVE,
            ArtifactSource.ELASTIC,
            ArtifactSource.AZURE,
        ):
            cands = registry.candidates(source)
            assert len(cands) >= 2, f"{source} lost its shared importers"
            assert registry.get(source) is cands[0]


class TestDetectFilenameHints:
    """B2: short hint tokens must not match as substrings."""

    def test_sample_name_not_routed_to_registry(self, tmp_path):
        p = _write(
            tmp_path,
            "cloudtrail-sample.json",
            json.dumps({"Records": [{"eventSource": "s3.amazonaws.com"}]}),
        )
        assert detect_format(p) == ArtifactSource.CLOUDTRAIL

    def test_vt_sample_not_routed_to_registry(self, tmp_path):
        p = _write(
            tmp_path, "vt-sample.json", json.dumps({"data": {"attributes": {}}})
        )
        assert detect_format(p) == ArtifactSource.VIRUSTOTAL

    def test_vr_hunt_sample_not_routed_to_registry(self, tmp_path):
        p = _write(
            tmp_path,
            "hunt-sample.jsonl",
            '{"Artifact":"Windows.System.Pslist","_Source":"vr"}\n',
        )
        assert detect_format(p) == ArtifactSource.VELOCIRAPTOR

    def test_security_evtx_still_evtx(self, tmp_path):
        p = tmp_path / "Security-sample.evtx"
        p.write_bytes(b"ElfFile\x00" + b"\x00" * 64)
        assert detect_format(p) == ArtifactSource.EVTX

    def test_exact_sam_hive_still_registry(self, tmp_path):
        p = tmp_path / "sam"
        p.write_bytes(b"\x00" * 16)
        assert detect_format(p) == ArtifactSource.WINDOWS_REGISTRY

    def test_binary_pcap_not_routed_to_csv(self, tmp_path):
        p = tmp_path / "capture.pcap"
        p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 64)
        assert detect_format(p) != ArtifactSource.GENERIC_CSV


class TestTsharkJsonDetection:
    """convert_pcap output (pretty-printed tshark JSON) must route to wireshark."""

    def test_tshark_json_by_content(self, tmp_path):
        p = tmp_path / "capture.tshark.json"
        p.write_text(
            '[\n  {\n    "_index": "packets-0001",\n'
            '    "_source": {\n      "layers": {\n'
            '        "frame": {"frame.time_epoch": "1700000000"}\n'
            "      }\n    }\n  }\n]\n",
            encoding="utf-8",
        )
        assert detect_format(p) == ArtifactSource.WIRESHARK

    def test_tshark_json_suffix_hint(self, tmp_path):
        p = tmp_path / "weird-name.tshark.json"
        p.write_text("not json at all", encoding="utf-8")
        assert detect_format(p) == ArtifactSource.WIRESHARK


class TestNdjsonWithJsonExtension:
    """G1-class: NDJSON content behind a .json extension must parse."""

    def test_journald_ndjson_in_json_file(self, tmp_path):
        p = _write(
            tmp_path,
            "journal.json",
            '{"PRIORITY":"3","__REALTIME_TIMESTAMP":"1700000000000000",'
            '"MESSAGE":"err","_HOSTNAME":"h1"}\n'
            '{"PRIORITY":"6","__REALTIME_TIMESTAMP":"1700000001000000",'
            '"MESSAGE":"info","_HOSTNAME":"h1"}\n',
        )
        from nexus.ingest.linux.journald import JournaldImporter

        result = JournaldImporter().ingest(p)
        assert len(result.artifacts) == 2

    def test_wazuh_ndjson_in_json_file(self, tmp_path):
        p = _write(
            tmp_path,
            "wazuh.json",
            '{"rule":{"level":10,"id":"5710","description":"x"},"agent":{"name":"a"}}\n'
            '{"rule":{"level":3,"id":"5711","description":"y"},"agent":{"name":"a"}}\n',
        )
        from nexus.ingest.siem.wazuh import WazuhImporter

        result = WazuhImporter().ingest(p)
        assert len(result.artifacts) == 2

    def test_velociraptor_ndjson_hunt_export(self, tmp_path):
        p = _write(
            tmp_path,
            "hunt-sample.jsonl",
            '{"Artifact":"Windows.System.Pslist","Name":"a.exe"}\n'
            '{"Artifact":"Windows.System.Pslist","Name":"b.exe"}\n',
        )
        from nexus.ingest.df.velociraptor import VelociraptorImporter

        result = VelociraptorImporter().ingest(p)
        assert len(result.artifacts) == 2


class TestWrappedCaseExports:
    """TheHive/IRIS exports wrapped as {"case": {...}, "iocs"/"artifacts": [...]}."""

    def test_thehive_wrapped_shape(self, tmp_path):
        p = _write(
            tmp_path,
            "thehive-case.json",
            json.dumps(
                {
                    "case": {"title": "t", "severity": 3, "tlp": 2},
                    "artifacts": [{"dataType": "ip", "data": "203.0.113.9"}],
                }
            ),
        )
        from nexus.ingest.df.thehive import TheHiveImporter

        result = TheHiveImporter().ingest(p)
        assert len(result.artifacts) == 2  # case summary + observable

    def test_iris_wrapped_shape(self, tmp_path):
        p = _write(
            tmp_path,
            "iris-case.json",
            json.dumps(
                {
                    "case": {"name": "c", "description": "d"},
                    "iocs": [{"ioc_value": "203.0.113.9", "ioc_type": "ip"}],
                }
            ),
        )
        from nexus.ingest.df.iris import IRISImporter

        result = IRISImporter().ingest(p)
        assert len(result.artifacts) == 2  # case summary + ioc


class TestZeekJsonLogging:
    """Zeek 8+ default JSON spool (CADRE monitor) must not require #fields."""

    def test_json_conn_detect_and_parse(self, tmp_path):
        line = json.dumps({
            "ts": 1754920000.1,
            "uid": "Cabcdef",
            "id.orig_h": "192.168.77.62",
            "id.orig_p": 49812,
            "id.resp_h": "192.168.77.10",
            "id.resp_p": 88,
            "proto": "tcp",
        })
        p = _write(tmp_path, "conn.log", line + "\n")
        assert detect_format(p) == ArtifactSource.ZEEK
        from nexus.ingest.network.zeek import ZeekImporter

        arts = list(ZeekImporter().parse(p))
        assert len(arts) == 1
        assert arts[0].source == ArtifactSource.ZEEK
        assert arts[0].source_ip == "192.168.77.62"

    def test_rotated_kerberos_name_hint(self, tmp_path):
        line = json.dumps({
            "ts": 1754920000.1,
            "uid": "Ckerb",
            "id.orig_h": "192.168.77.62",
            "id.orig_p": 1,
            "id.resp_h": "192.168.77.10",
            "id.resp_p": 88,
        })
        p = _write(tmp_path, "kerberos-20260804.log", line + "\n")
        assert detect_format(p) == ArtifactSource.ZEEK


class TestVolatility3JsonLane:
    """vol3 -r json dumps must not be misrouted to generic CSV."""

    def test_windows_psscan_filename_hint(self, tmp_path):
        p = _write(tmp_path, "windows.psscan.json", "not even json")
        assert detect_format(p) == ArtifactSource.VOLATILITY

    def test_truncated_pretty_json_not_csv(self, tmp_path):
        # Mimic sniff-window truncation: leading newline + partial array.
        body = (
            "\n[\n  {\n    \"CreateTime\": \"2022-06-03T09:12:59+00:00\",\n"
            "    \"ImageFileName\": \"System\",\n    \"Offset(V)\": 123,\n"
            "    \"PID\": 4,\n    \"PPID\": 0\n  },\n  {\n    \"PID\": "
        )
        p = tmp_path / "memory-dump.json"
        p.write_text(body, encoding="utf-8")
        assert detect_format(p) == ArtifactSource.VOLATILITY

    def test_ingest_auto_psscan(self):
        from nexus.ingest.detect import ingest_auto

        p = Path(__file__).resolve().parents[1] / "Evidence-files" / "02-memory" / "rocba-508" / "vol3-amadey" / "windows.psscan.json"
        if not p.is_file():
            pytest.skip("psscan fixture not staged")
        result = ingest_auto(p)
        assert result.get("success")
        assert result.get("source") == "volatility"
        assert int(result.get("artifacts") or 0) > 0


class TestRegistryUtf16RegExport:
    def test_utf16_reg_export(self, tmp_path):
        from nexus.ingest.df.registry import WindowsRegistryImporter

        text = (
            "Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n"
            '"Evil"="C:\\\\Temp\\\\evil.exe"\r\n'
        )
        p = tmp_path / "run.reg"
        p.write_bytes(text.encode("utf-16"))
        assert WindowsRegistryImporter.can_handle(p)
        result = WindowsRegistryImporter().ingest(p)
        assert result.success
        assert any("evil.exe" in (a.description or "").lower() or "evil.exe" in str(a.raw).lower()
                   for a in result.artifacts)


class TestBrowserHistoryKapeNames:
    def test_chrome_history_can_handle(self):
        from nexus.ingest.df.browser_history import BrowserHistoryImporter

        p = Path(__file__).resolve().parents[1] / "Evidence-files" / "01-windows" / "rocba-fredr" / "browser" / "Chrome-History"
        if not p.is_file():
            pytest.skip("Chrome-History not staged")
        assert BrowserHistoryImporter.can_handle(p)
        result = BrowserHistoryImporter().ingest(p)
        assert result.success
        assert len(result.artifacts) > 0
