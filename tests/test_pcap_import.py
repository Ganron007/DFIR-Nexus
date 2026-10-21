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


def test_parse_reads_what_tshark_ek_really_writes(tmp_path, monkeypatch):
    """D249: the pcap path converts with `tshark -T ek` (EH-14), but the parser read only `-T json`'s shape.

    The fixture is tshark 4.6.9's verbatim `-T ek` output for the first packets of two public captures
    (tcpreplay smallFlows, sha256 77d06d3f...; Wireshark's dhcp sample, sha256 2471b542...): `layers` at the
    top, keys flattened to `ip_ip_src`, and an `{"index": ...}` bulk line before each packet. Read the old way,
    every address, port and time was empty and each bulk line became a row of its own.
    """
    import shutil

    from nexus.ingest.network import pcap as pcap_mod

    fixture = Path(__file__).parent / "fixtures" / "tshark_ek_public.jsonl"

    def real_ek(src_path, out_path, *, display_filter="", timeout=None):
        shutil.copyfile(fixture, out_path)

    monkeypatch.setattr(pcap_mod, "convert_pcap_to_json", real_ek)
    arts = [a.to_dict() for a in pcap_mod.PcapImporter().parse(_pcap(tmp_path))]
    assert len(arts) == 5  # 5 packets; the 5 bulk lines are not rows
    first = arts[0]
    assert (first["source_ip"], first["source_port"], first["dest_ip"], first["dest_port"]) == (
        "192.168.3.131", 57011, "72.14.213.138", 80)
    assert first["protocol"] == "tcp" and first["artifact_type"] == "http"
    assert first["timestamp"].startswith("2011-01-25T18:52:22") and not first["ts_synthesized"]
    assert "ACK PSH" in first["description"]
    assert "SYN" in arts[2]["description"]
    dhcp = arts[3]
    assert (dhcp["source_port"], dhcp["dest_port"], dhcp["protocol"]) == (68, 67, "udp")
    assert all(a["source_ip"] for a in arts)


def test_parse_converts_and_maps_packets(tmp_path, monkeypatch):
    from nexus.ingest.network import pcap as pcap_mod

    src = _pcap(tmp_path)

    def fake_convert(src_path, out_path, *, display_filter="", timeout=None):
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

    def fake_convert(src_path, out_path, *, display_filter="", timeout=None):
        _tshark_json(Path(out_path))

    monkeypatch.setattr(pcap_mod, "convert_pcap_to_json", fake_convert)
    src = _pcap(tmp_path)
    result = get_registry().import_path(src, source=ArtifactSource.WIRESHARK)
    assert result.success, result.errors
    assert len(result.artifacts) == 2
