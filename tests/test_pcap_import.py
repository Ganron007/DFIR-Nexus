"""Raw PCAP support — routing, tshark conversion, packet mapping."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


def _pcap(tmp_path: Path, name: str = "capture.pcap") -> Path:
    path = tmp_path / name
    # classic little-endian pcap magic + junk header
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 60)
    return path


def _tshark_json(path: Path) -> None:
    packets = [
        {"_index": "packets", "_source": {"layers": {
            "frame": {"frame.time_epoch": "1755000000.000", "frame.number": "1"},
            "ip": {"ip.src": "192.168.77.55", "ip.dst": "192.168.77.50"},
            "tcp": {"tcp.srcport": "58312", "tcp.dstport": "9200", "tcp.flags": "0x18"},
            "http": {"http.request.method": "GET", "http.request.uri": "/_bulk"},
        }}},
        {"_index": "packets", "_source": {"layers": {
            "frame": {"frame.time_epoch": "1755000001.000", "frame.number": "2"},
            "ip": {"ip.src": "192.168.77.55", "ip.dst": "8.8.8.8"},
            "udp": {"udp.srcport": "52345", "udp.dstport": "53"},
            "dns": {"dns.qry.name": "evil-c2.example"},
        }}},
    ]
    path.write_text(json.dumps(packets), encoding="utf-8")


def test_can_handle_extensions_and_magic(tmp_path):
    from nexus.ingest.network.pcap import PcapImporter

    assert PcapImporter.can_handle(_pcap(tmp_path, "a.pcap"))
    assert PcapImporter.can_handle(_pcap(tmp_path, "b.pcapng"))
    assert PcapImporter.can_handle(_pcap(tmp_path, "c.cap"))
    assert PcapImporter.can_handle(_pcap(tmp_path, "noext"))
    assert not PcapImporter.can_handle(tmp_path / "x.json")


def test_detect_format_pcap_is_wireshark_lane(tmp_path):
    from nexus.ingest.detect import detect_format
    from nexus.ingest.schemas import ArtifactSource

    assert detect_format(_pcap(tmp_path)) == ArtifactSource.WIRESHARK


def test_parse_converts_and_maps_packets(tmp_path, monkeypatch):
    from nexus.ingest.network import pcap as pcap_mod

    src = _pcap(tmp_path)

    def fake_convert(src_path, out_path, *, display_filter="", max_packets=0, timeout=None):
        _tshark_json(Path(out_path))

    monkeypatch.setattr(pcap_mod, "convert_pcap_to_json", fake_convert)
    arts = list(pcap_mod.PcapImporter().parse(src))
    assert len(arts) == 2
    first = arts[0].to_dict()
    assert first["artifact_type"] == "http"
    assert first["source_ip"] == "192.168.77.55"
    assert first["dest_ip"] == "192.168.77.50"
    second = arts[1].to_dict()
    assert second["artifact_type"] == "dns"


def test_parse_raises_without_tshark(tmp_path, monkeypatch):
    from nexus.ingest.base import ImporterError
    from nexus.ingest.network import pcap as pcap_mod

    monkeypatch.setattr(pcap_mod, "find_tshark", lambda: None)
    src = _pcap(tmp_path)
    with pytest.raises(ImporterError) as exc:
        list(pcap_mod.PcapImporter().parse(src))
    assert "tshark" in str(exc.value).lower()


def test_registry_import_path_picks_pcap_importer(tmp_path, monkeypatch):
    from nexus.ingest.network import pcap as pcap_mod
    from nexus.ingest.registry import get_registry
    from nexus.ingest.schemas import ArtifactSource

    def fake_convert(src_path, out_path, *, display_filter="", max_packets=0, timeout=None):
        _tshark_json(Path(out_path))

    monkeypatch.setattr(pcap_mod, "convert_pcap_to_json", fake_convert)
    src = _pcap(tmp_path)
    result = get_registry().import_path(src, source=ArtifactSource.WIRESHARK)
    assert result.success, result.errors
    assert len(result.artifacts) == 2
