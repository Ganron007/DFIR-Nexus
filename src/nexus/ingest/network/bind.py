"""BIND 9 query log importer (named's ``queries`` category).

One line per DNS query the server answered, as BIND 9 writes it::

    12-Jul-2016 09:45:59.115 client 10.10.10.5#42935 (google.com): query: google.com IN A +E (10.10.10.5)

with, in later releases, a category/severity prefix (``queries: info:``) and the client object's address
(``client @0x7f...``). The fields are the client address and port, the query name, class and type, the
flags (``+`` recursion desired, ``E`` EDNS, ``T`` TCP, ``D`` DO, ``C`` CD, ``S`` signed) and the server address
that received it (BIND 9 Administrator Reference Manual, "The query log"). BIND writes the time in the
server's local zone with no offset; by the index's policy a naive time is UTC.

Before this importer a BIND query log was read by no importer and left out of the case (sample S03,
2026-10-18).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from nexus.ingest.base import Importer
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, NetworkProtocol, Severity

log = logging.getLogger(__name__)

QUERY_RE = re.compile(
    r"^(?P<ts>\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?:[\w-]+: (?:\w+: )?)?"
    r"client (?:@0x[0-9a-fA-F]+ )?(?P<ip>[0-9A-Fa-f:.]+)#(?P<port>\d+)"
    r"(?: \([^)]*\))?: (?:view [^:]+: )?"
    r"query: (?P<qname>\S+) (?P<qclass>\S+) (?P<qtype>\S+) (?P<flags>[+\-][A-Z]*(?:\(\d+\))?[A-Z]*)"
    r"(?: \((?P<server>[^)]*)\))?"
)


class BindQueryLogImporter(Importer):
    """Parser for BIND 9 query logs."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.BIND

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Most of the first non-empty lines are BIND query lines."""
        if not path.is_file():
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                lines = [ln for ln in (f.readline() for _ in range(20)) if ln.strip()]
        except OSError:
            return False
        if not lines:
            return False
        return bool(QUERY_RE.match(lines[0])) and sum(1 for ln in lines if QUERY_RE.match(ln)) * 2 > len(lines)

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one DNS artifact per query line; other lines are not queries and are not rows."""
        for _n, line in self.read_lines(path):
            m = QUERY_RE.match(line)
            if m is None:
                continue
            yield self._artifact(m, line)

    @staticmethod
    def _artifact(m: re.Match[str], line: str) -> Artifact:
        stamp = m.group("ts")
        fmt = "%d-%b-%Y %H:%M:%S.%f" if "." in stamp else "%d-%b-%Y %H:%M:%S"
        synthesized = False
        try:
            ts = datetime.strptime(stamp, fmt).replace(tzinfo=UTC)
        except ValueError:
            ts, synthesized = datetime.now(UTC), True
        flags = m.group("flags")
        qname, qtype = m.group("qname"), m.group("qtype")
        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.DNS,
            source=ArtifactSource.BIND,
            timestamp=ts,
            ts_synthesized=synthesized,
            severity=Severity.INFORMATIONAL,
            source_ip=m.group("ip"),
            source_port=int(m.group("port")),
            dest_ip=m.group("server") or None,
            # The T flag marks a query that came over TCP; without it the query came over UDP (ARM).
            protocol=NetworkProtocol.TCP if "T" in flags else NetworkProtocol.UDP,
            action="query",
            description=f"DNS query {qname} {m.group('qclass')} {qtype} from {m.group('ip')}",
            raw={"line": line, "query": qname, "qclass": m.group("qclass"), "qtype": qtype, "flags": flags},
            tags=["bind", "dns", f"qtype.{qtype.lower()}"],
        )
