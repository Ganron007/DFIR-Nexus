"""Wireshark JSON exporter importer.

Parses Wireshark's JSON export format (File > Export Packet Dissections >
As JSON). Each top-level object is a packet with a `_source.layers` tree.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.ingest.base import Importer
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    NetworkProtocol,
    Severity,
)

log = logging.getLogger(__name__)


class WiresharkImporter(Importer):
    """Parser for Wireshark JSON exports."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.WIRESHARK

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: JSON with _source.layers (Wireshark shape)."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if not (name.endswith(".json") or name.endswith(".jsonl")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)
        except OSError:
            return False
        return (
            "_source" in head
            and "layers" in head
            and ("frame" in head.lower() or "ip" in head or "tcp" in head)
        )

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per Wireshark packet.

        Accepts classic ``-T json`` (a JSON array / object) and tshark's
        ``-T ek`` NDJSON export (EH-14: one object per line, stream-parsed so
        a multi-GB capture does not need to fit in memory).
        """
        with path.open("r", encoding="utf-8", errors="replace") as f:
            head = f.read(1)
            f.seek(0)
            if head.strip() in {"[", "{"}:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    f.seek(0)
                else:
                    packets = self._extract_packets(data)
                    if packets:
                        for packet in packets:
                            yield self._packet_to_artifact(packet)
                        return
            skipped = 0
            for line in f:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    packet = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue
                # `-T ek` writes an Elasticsearch bulk header (`{"index": ...}`) before each packet; it is
                # not a packet, and reading it as one made an empty row per packet (D249).
                if isinstance(packet, dict) and self._layers(packet):
                    yield self._packet_to_artifact(packet)
            if skipped:
                log.warning(
                    "%s: skipped %d malformed NDJSON packet line(s)", path.name, skipped
                )

    @staticmethod
    def _extract_packets(data: Any) -> list[dict[str, Any]]:
        """Pull packets from various Wireshark export shapes."""
        if isinstance(data, list):
            return [p for p in data if isinstance(p, dict)]
        if isinstance(data, dict):
            for key in ("packets", "_packets", "data"):
                if key in data and isinstance(data[key], list):
                    return [p for p in data[key] if isinstance(p, dict)]
            if "_source" in data and "layers" in data.get("_source", {}):
                return [data]
        return []

    @staticmethod
    def _layers(packet: dict[str, Any]) -> dict[str, Any]:
        """The dissection tree: `-T json` nests it under `_source.layers`, `-T ek` puts `layers` on top."""
        source = packet.get("_source")
        if isinstance(source, dict) and isinstance(source.get("layers"), dict):
            return source["layers"]
        layers = packet.get("layers")
        return layers if isinstance(layers, dict) else {}

    @staticmethod
    def _field(layer: Any, proto: str, name: str) -> Any:
        """A dissector field by its name (`ip.src`, `-T json`) or by `-T ek`'s flattened key (`ip_ip_src`).

        EH-14 moved the pcap path to `-T ek`, whose keys are `<protocol>_<field with dots as underscores>`;
        read only as `ip.src`, every address, port and time of an imported capture was empty (D249).
        """
        if not isinstance(layer, dict):
            return None
        if name in layer:
            return layer[name]
        return layer.get(f"{proto}_{name.replace('.', '_')}")

    def _packet_to_artifact(self, packet: dict[str, Any]) -> Artifact:
        """Map a Wireshark packet to an Artifact."""
        layers = self._layers(packet)

        # Frame / timestamp (`-T ek` also carries the capture time, in ms, as the packet's `timestamp`)
        frame = layers.get("frame", {})
        ts_str = (self._field(frame, "frame", "frame.time_epoch") or packet.get("timestamp")
                  or self._field(frame, "frame", "frame.time_relative"))
        ts = self.normalize_timestamp(ts_str)
        ts_synthesized = ts is None
        if ts is None:
            ts = datetime.now(UTC)

        # IP layer
        ip, ip6 = layers.get("ip", {}), layers.get("ipv6", {})
        src_ip = self._field(ip, "ip", "ip.src") or self._field(ip6, "ipv6", "ipv6.src")
        dst_ip = self._field(ip, "ip", "ip.dst") or self._field(ip6, "ipv6", "ipv6.dst")

        # TCP / UDP
        tcp = layers.get("tcp", {})
        udp = layers.get("udp", {})
        if tcp:
            protocol = NetworkProtocol.TCP
            src_port = self._safe_int(self._field(tcp, "tcp", "tcp.srcport"))
            dst_port = self._safe_int(self._field(tcp, "tcp", "tcp.dstport"))
            # `tcp.flags` is a hex mask; `tcp.flags.str` ("·······A··S·") names the set flags in both shapes.
            shown = str(self._field(tcp, "tcp", "tcp.flags.str") or "")
            flags = " ".join(name for letter, name in (("S", "SYN"), ("A", "ACK"), ("P", "PSH"), ("R", "RST"),
                                                        ("F", "FIN")) if letter in shown)
        elif udp:
            protocol = NetworkProtocol.UDP
            src_port = self._safe_int(self._field(udp, "udp", "udp.srcport"))
            dst_port = self._safe_int(self._field(udp, "udp", "udp.dstport"))
            flags = ""
        else:
            protocol = None
            src_port = dst_port = None
            flags = ""

        # Higher-layer protocol hints
        artifact_type = ArtifactType.NETWORK
        if "http" in layers or "http2" in layers:
            artifact_type = ArtifactType.HTTP
        elif "dns" in layers:
            artifact_type = ArtifactType.DNS
        elif "tls" in layers or "ssl" in layers:
            artifact_type = ArtifactType.TLS
        elif "smtp" in layers:
            artifact_type = ArtifactType.SMTP
        elif "ssh" in layers:
            artifact_type = ArtifactType.SSH
        elif "rdp" in layers:
            artifact_type = ArtifactType.RDP

        # D250 (2026-10-18): a DNS packet's query name (`dns.qry.name`; `dns_dns_qry_name` in `-T ek`, a list when the
        # packet asks several). It reaches the index as the record's `dns_query`, beside the packet as tshark wrote it.
        dns_query = ""
        if "dns" in layers:
            names = self._field(layers.get("dns", {}), "dns", "dns.qry.name")
            names = names if isinstance(names, list) else [names] if names else []
            dns_query = ", ".join(str(n) for n in names if n)

        # Severity: suspicious ports/flags
        severity = Severity.INFORMATIONAL
        if dst_port in (4444, 31337, 1337, 6667, 6668, 6669):
            severity = Severity.HIGH
        if flags and ("SYN" in flags and "ACK" not in flags and dst_port not in (80, 443, 22, 53)):
            severity = max(severity, Severity.LOW, key=lambda s: ["informational", "low", "medium", "high", "critical"].index(s.value))

        endpoints = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        description = (f"Wireshark {protocol.value if protocol else 'unknown'} {endpoints}"
                       + (f" [{flags}]" if flags else "") + (f" DNS query {dns_query}" if dns_query else ""))
        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.WIRESHARK,
            timestamp=ts,
            ts_synthesized=ts_synthesized,
            severity=severity,
            source_ip=src_ip,
            source_port=src_port,
            dest_ip=dst_ip,
            dest_port=dst_port,
            protocol=protocol,
            description=description,
            raw={**packet, "dns_query": dns_query} if dns_query else packet,
            tags=["wireshark", f"proto.{protocol.value}" if protocol else "wireshark"],
        )

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
