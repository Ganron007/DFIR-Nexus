"""Zeek log importer.

Parses Zeek TSV logs (conn.log, dns.log, http.log, notice.log, ssl.log, etc.)
Zeek logs are tab-separated, with a `#fields` header line defining the columns.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

from nexus.ingest.base import Importer
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    NetworkProtocol,
    Severity,
)

log = logging.getLogger(__name__)


class ZeekImporter(Importer):
    """Parser for Zeek TSV (`#fields`) and Zeek 8+ JSON-lines logs.

    Handles all standard Zeek log types: conn, dns, http, ssl, notice, ssh,
    smtp, rdp, files, kerberos, etc.
    """

    # Known Zeek log types and their corresponding artifact types
    LOG_TYPE_MAP: ClassVar[dict[str, ArtifactType]] = {
        "conn": ArtifactType.NETWORK,
        "dns": ArtifactType.DNS,
        "http": ArtifactType.HTTP,
        "ssl": ArtifactType.TLS,
        "smtp": ArtifactType.SMTP,
        "ssh": ArtifactType.SSH,
        "rdp": ArtifactType.RDP,
        "notice": ArtifactType.ALERT,
        "files": ArtifactType.FILE,
        "pe": ArtifactType.MALWARE,
        "x509": ArtifactType.TLS,
        "kerberos": ArtifactType.AUTH,
        "ntlm": ArtifactType.AUTH,
        "smb_files": ArtifactType.FILE,
        "snmp": ArtifactType.NETWORK,
        "radius": ArtifactType.AUTH,
    }

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.ZEEK

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: file has a `#fields` header line (Zeek TSV)."""
        if not path.is_file():
            return False
        name = path.name.lower()
        # Common Zeek log naming: conn.log, dns.log, http.00:00:00-01:00:00.log.gz
        if not (name == "conn.log" or name.endswith(".log") or name.endswith(".log.gz")):
            return False
        try:
            import gzip
            opener = gzip.open if name.endswith(".gz") else open
            with opener(path, "rt", encoding="utf-8", errors="replace") as f:
                for _ in range(20):
                    line = f.readline()
                    if not line:
                        break
                    if line.startswith("#fields"):
                        return True
                    # Zeek 8+ default JSON logging (CADRE monitor spool)
                    if line.lstrip().startswith("{"):
                        if '"uid"' in line and ("id.orig_h" in line or "id.resp_h" in line or '"ts"' in line):
                            return True
        except OSError:
            return False
        return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a Zeek TSV log file."""
        import gzip

        name = path.name.lower()
        opener = gzip.open if name.endswith(".gz") else open
        fields: list[str] = []
        log_type = self._detect_log_type(path)
        artifact_type = self.LOG_TYPE_MAP.get(log_type, ArtifactType.NETWORK)

        try:
            with opener(path, "rt", encoding="utf-8", errors="replace") as f:
                while True:
                    try:
                        line = f.readline()
                        if not line:
                            break
                    except (OSError, EOFError, Exception) as exc:
                        log.warning("Zeek log read/decompression error in %s: %s", path, exc)
                        if hasattr(self, "skipped_lines"):
                            self.skipped_lines += 1
                        break
                    line = line.rstrip("\n\r")
                    if not line.strip():
                        continue
                    if line.lstrip().startswith("{"):
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            if hasattr(self, "skipped_lines"):
                                self.skipped_lines += 1
                            continue
                        if not isinstance(rec, dict):
                            continue
                        record = {str(k): "" if v is None else str(v) for k, v in rec.items()}
                        yield self._record_to_artifact(record, log_type, artifact_type, path)
                        continue
                    if line.startswith("#fields"):
                        fields = line.split("\t")[1:]
                        continue
                    if line.startswith("#"):
                        continue  # comment / metadata
                    if not fields:
                        continue
                    values = line.split("\t")
                    if len(values) != len(fields):
                        if hasattr(self, "skipped_lines"):
                            self.skipped_lines += 1
                        continue  # malformed line
                    record = dict(zip(fields, values, strict=True))
                    yield self._record_to_artifact(record, log_type, artifact_type, path)
        except OSError as e:
            log.warning("Could not open Zeek log %s: %s", path, e)

    def _detect_log_type(self, path: Path) -> str:
        """Detect the Zeek log type from the file name or a header line."""
        name = path.name.lower().replace(".log.gz", "").replace(".log", "")
        # Strip timestamp suffixes
        for sep in (".", "_"):
            if sep in name:
                # The first part is the log type
                name = name.split(sep)[0]
        if name in self.LOG_TYPE_MAP:
            return name
        # Fall back to log_type from header
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("#log_type"):
                        return line.split("\t")[1].strip() if "\t" in line else ""
                    if line.startswith("#fields"):
                        break
        except OSError:
            pass
        return "conn"

    def _record_to_artifact(
        self,
        record: dict[str, str],
        log_type: str,
        artifact_type: ArtifactType,
        path: Path,
    ) -> Artifact:
        """Map a single Zeek record to an Artifact."""
        # Zeek timestamps are Unix epoch seconds
        ts_str = record.get("ts", "")
        ts = None
        if ts_str and ts_str != "-":
            try:
                ts = self.normalize_timestamp(float(ts_str))
            except (ValueError, TypeError):
                if hasattr(self, "skipped_lines"):
                    self.skipped_lines += 1
        if ts is None:
            ts = datetime.now(UTC)

        # Protocol
        proto_str = record.get("proto", "").upper()
        proto_map = {
            "TCP": NetworkProtocol.TCP,
            "UDP": NetworkProtocol.UDP,
            "ICMP": NetworkProtocol.ICMP,
            "ICMPV6": NetworkProtocol.ICMP,
        }
        protocol = proto_map.get(proto_str)

        # Severity (for notice.log)
        severity = Severity.INFORMATIONAL
        if log_type == "notice":
            severity = self._zeek_severity_to_enum(record.get("severity", ""))

        # Description
        description_parts = [f"Zeek {log_type}"]
        if log_type == "notice":
            msg = record.get("msg", "")
            if msg:
                description_parts.append(msg)
        elif log_type == "http":
            method = record.get("method", "")
            host = record.get("host", "")
            uri = record.get("uri", "")
            if method and host:
                description_parts.append(f"{method} {host}{uri}")

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.ZEEK,
            timestamp=ts,
            severity=severity,
            host=path.stem.split(".")[0] if "." in path.stem else None,
            source_ip=record.get("id.orig_h") or record.get("src_ip"),
            source_port=self._safe_int(record.get("id.orig_p") or record.get("src_port")),
            dest_ip=record.get("id.resp_h") or record.get("dst_ip"),
            dest_port=self._safe_int(record.get("id.resp_p") or record.get("dst_port")),
            protocol=protocol,
            process_name=record.get("process_name"),
            file_path=record.get("filename"),
            file_hash_md5=record.get("md5") or None,
            file_hash_sha1=record.get("sha1") or None,
            file_hash_sha256=record.get("sha256") or None,
            action=record.get("action"),
            description=" - ".join(description_parts) if len(description_parts) > 1 else description_parts[0],
            raw=record,
            tags=[f"zeek.{log_type}"],
        )

    @staticmethod
    def _safe_int(value: str | None) -> int | None:
        if not value or value == "-":
            return None
        try:
            return int(value)
        except ValueError:
            return None

    @staticmethod
    def _zeek_severity_to_enum(value: str) -> Severity:
        """Map Zeek notice severity (1-3) to Severity enum."""
        try:
            v = int(value)
        except (ValueError, TypeError):
            return Severity.INFORMATIONAL
        if v <= 1:
            return Severity.CRITICAL
        if v == 2:
            return Severity.HIGH
        if v == 3:
            return Severity.MEDIUM
        return Severity.LOW
