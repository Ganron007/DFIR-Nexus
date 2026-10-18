"""AWS VPC Flow Logs importer.

A flow log file is a header line naming its fields, then one space-separated record per flow, as VPC writes them to
S3 (AWS VPC User Guide, "Flow log records"). The default (version 2) fields are ``version account-id interface-id
srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status``; a custom format names others, and
the header is read so any of them maps by name. ``start`` and ``end`` are Unix seconds; ``protocol`` is the IANA
number; ``-`` is an unset field (a NODATA or SKIPDATA record).

Before this importer the flow logs of sample S07 were read by no importer (2026-10-18).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from nexus.ingest.base import Importer
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, NetworkProtocol, Severity

_REQUIRED = ("srcaddr", "dstaddr", "start")
_PROTOCOLS = {"6": NetworkProtocol.TCP, "17": NetworkProtocol.UDP, "1": NetworkProtocol.ICMP}


def _header(line: str) -> list[str] | None:
    fields = line.split()
    return fields if all(f in fields for f in _REQUIRED) else None


class VpcFlowLogImporter(Importer):
    """Parser for AWS VPC flow log files (the S3 text format)."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.AWS_VPC_FLOW

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        if not path.is_file():
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                return _header(f.readline()) is not None
        except OSError:
            return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        header: list[str] | None = None
        for _n, line in self.read_lines(path):
            if header is None:
                header = _header(line)
                continue
            values = line.split()
            if len(values) != len(header):
                continue
            row = {k: v for k, v in zip(header, values, strict=True) if v != "-"}
            yield self._artifact(row, line)

    @staticmethod
    def _artifact(row: dict[str, str], line: str) -> Artifact:
        start = row.get("start")
        synthesized = not (start and start.isdigit())
        ts = datetime.fromtimestamp(int(start), tz=UTC) if not synthesized else datetime.now(UTC)
        action = row.get("action") or row.get("log-status") or ""

        def port(key: str) -> int | None:
            value = row.get(key)
            return int(value) if value and value.isdigit() else None

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.NETWORK,
            source=ArtifactSource.AWS_VPC_FLOW,
            timestamp=ts,
            ts_synthesized=synthesized,
            severity=Severity.INFORMATIONAL,
            source_ip=row.get("srcaddr"),
            source_port=port("srcport"),
            dest_ip=row.get("dstaddr"),
            dest_port=port("dstport"),
            protocol=_PROTOCOLS.get(row.get("protocol", "")),
            action=action.lower() or None,
            description=(f"VPC flow {row.get('srcaddr')}:{row.get('srcport', '-')} -> {row.get('dstaddr')}:"
                         f"{row.get('dstport', '-')} proto {row.get('protocol', '-')} {action} "
                         f"({row.get('packets', '-')} packets, {row.get('bytes', '-')} bytes) on "
                         f"{row.get('interface-id', '-')}"),
            raw={"line": line, **row},
            tags=["aws", "vpc-flow", f"action.{action.lower()}"] if action else ["aws", "vpc-flow"],
        )
