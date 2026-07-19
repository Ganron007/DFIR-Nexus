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
        """Yield one Artifact per Wireshark packet."""
        with path.open("r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        packets = self._extract_packets(data)
        for packet in packets:
            yield self._packet_to_artifact(packet)

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

    def _packet_to_artifact(self, packet: dict[str, Any]) -> Artifact:
        """Map a Wireshark packet to an Artifact."""
        layers = packet.get("_source", {}).get("layers", {})

        # Frame / timestamp
        frame = layers.get("frame", {})
        ts_str = frame.get("frame.time_epoch") or frame.get("frame.time_relative")
        ts = self.normalize_timestamp(ts_str) or datetime.now(UTC)

        # IP layer
        ip = layers.get("ip", {}) or layers.get("ipv6", {})
        src_ip = ip.get("ip.src") or ip.get("ipv6.src")
        dst_ip = ip.get("ip.dst") or ip.get("ipv6.dst")

        # TCP / UDP
        tcp = layers.get("tcp", {})
        udp = layers.get("udp", {})
        if tcp:
            protocol = NetworkProtocol.TCP
            src_port = self._safe_int(tcp.get("tcp.srcport"))
            dst_port = self._safe_int(tcp.get("tcp.dstport"))
            flags = tcp.get("tcp.flags", "")
        elif udp:
            protocol = NetworkProtocol.UDP
            src_port = self._safe_int(udp.get("udp.srcport"))
            dst_port = self._safe_int(udp.get("udp.dstport"))
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

        # Severity: suspicious ports/flags
        severity = Severity.INFORMATIONAL
        if dst_port in (4444, 31337, 1337, 6667, 6668, 6669):
            severity = Severity.HIGH
        if flags and ("SYN" in flags and "ACK" not in flags and dst_port not in (80, 443, 22, 53)):
            severity = max(severity, Severity.LOW, key=lambda s: ["informational", "low", "medium", "high", "critical"].index(s.value))

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.WIRESHARK,
            timestamp=ts,
            severity=severity,
            source_ip=src_ip,
            source_port=src_port,
            dest_ip=dst_ip,
            dest_port=dst_port,
            protocol=protocol,
            description=f"Wireshark {protocol.value if protocol else 'unknown'} {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{flags}]" if flags else f"Wireshark {protocol.value if protocol else 'unknown'} {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
            raw=packet,
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
