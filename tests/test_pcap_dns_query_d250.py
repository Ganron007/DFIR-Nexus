"""D250: an imported capture's DNS packets carry their query name to the index (2026-10-18).

The Wireshark importer typed a DNS packet `dns` but kept its query name only inside the raw packet, so
`ecs.dns.question.name` was never set for a capture and the DNS steps read nothing from one. The fixture is
tshark 4.6.9's verbatim `-T ek` output for the first two DNS packets of tcpreplay's public smallFlows capture
(sha256 77d06d3f...), the capture the D249 fixture comes from.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from nexus.langgraph.ecs_normalize import normalize

FIXTURE = Path(__file__).parent / "fixtures" / "tshark_ek_dns_public.jsonl"


def _pcap(tmp_path: Path) -> Path:
    path = tmp_path / "capture.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    return path


def test_a_dns_packet_names_its_query(tmp_path, monkeypatch):
    from nexus.ingest.network import pcap as pcap_mod

    def real_ek(src_path, out_path, *, display_filter="", max_packets=0, timeout=None):
        shutil.copyfile(FIXTURE, out_path)

    monkeypatch.setattr(pcap_mod, "convert_pcap_to_json", real_ek)
    arts = [a.to_dict() for a in pcap_mod.PcapImporter().parse(_pcap(tmp_path))]
    assert [a["raw"].get("dns_query") for a in arts] == ["messenger.hotmail.com", "login.live.com"]
    assert arts[0]["artifact_type"] == "dns" and "DNS query messenger.hotmail.com" in arts[0]["description"]
    # As the ingest projection hands an importer row to the ECS map.
    slots = {"source": "wireshark", "dns_query": arts[0]["raw"]["dns_query"], "source_ip": arts[0]["source_ip"]}
    assert normalize("wireshark", slots, importer=True)["dns"]["question"]["name"] == "messenger.hotmail.com"


def test_the_ingest_projection_carries_the_query(tmp_path, monkeypatch):
    """The index's projection of the importer store puts `dns_query` among a row's fields."""
    from nexus.ingest.network import pcap as pcap_mod
    from nexus.langgraph.query_pack import iter_ingest_records
    from nexus.langgraph.timeline_merge import ingest_into_case

    def real_ek(src_path, out_path, *, display_filter="", max_packets=0, timeout=None):
        shutil.copyfile(FIXTURE, out_path)

    monkeypatch.setattr(pcap_mod, "convert_pcap_to_json", real_ek)
    case = tmp_path / "CASE-PCAP"
    (case / "audit").mkdir(parents=True)
    ingest_into_case(_pcap(tmp_path), case)
    records = [rec for *_rest, rec in iter_ingest_records(case)]
    assert [(r.get("raw") or {}).get("dns_query") for r in records] == ["messenger.hotmail.com", "login.live.com"]
    stored = [json.loads(line) for line in (case / "ingest" / "artifacts.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all("DNS query" in s["description"] for s in stored)
