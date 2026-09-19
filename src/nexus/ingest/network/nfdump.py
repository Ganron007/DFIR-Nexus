"""nfdump / NetFlow (nfcapd) importer — EH-14b network depth.

Two input shapes, one artifact:
- **binary** ``nfcapd.*`` / ``*.nfdump`` — converted with ``nfdump -r <file> -o csv``
  (the nfdump binary is required; absence is an honest ImporterError).
- **CSV export** — an nfdump ``-o csv`` / ``-o fmt`` file already on disk.

Rows become NETFLOW artifacts (src/dst ip:port, protocol, packets/bytes) so
flow evidence is searchable, timeline-mergeable and report-citable without a
second parser.
"""
from __future__ import annotations

import csv
import io
import logging
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

from nexus.ingest.base import Importer, ImporterError
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    NetworkProtocol,
    Severity,
)

log = logging.getLogger(__name__)

_NFDUMP_SUFFIXES = {".nfcapd", ".nfdump", ".nf"}
# Distinctive nfdump csv columns; a generic CSV will not carry most of these.
_CSV_HINTS = frozenset(
    {"ts", "te", "td", "sa", "da", "sp", "dp", "pr", "flg", "ipkt", "ibyt",
     "opkt", "obyt", "in", "out", "sseq", "dseq", "tos"}
)
_PROTO_MAP = {6: NetworkProtocol.TCP, 17: NetworkProtocol.UDP, 1: NetworkProtocol.ICMP}


def find_nfdump() -> str | None:
    """nfdump on PATH (Linux/SIFT installs it)."""
    return shutil.which("nfdump") or shutil.which("nfdump.exe")


def looks_like_nfdump_csv_header(header: list[str]) -> bool:
    """True when a CSV header is an nfdump export (≥4 distinctive columns)."""
    low = {h.strip().lower().lstrip("\ufeff") for h in header}
    return len(low & _CSV_HINTS) >= 4 and "ts" in low and ("sa" in low or "da" in low)


def parse_nfdump_csv(text: str) -> list[dict[str, str]]:
    """Parse nfdump ``-o csv`` text into row dicts (no type coercion)."""
    if not text.strip():
        return []
    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        return []
    names = [h.strip().lower().lstrip("\ufeff") for h in header]
    rows: list[dict[str, str]] = []
    for raw in reader:
        if not raw or len(raw) < 2:
            continue
        rows.append({
            names[i] if i < len(names) else f"col{i}": (raw[i] or "").strip()
            for i in range(len(raw))
        })
    return rows


def _safe_int(value: str) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


class NfdumpImporter(Importer):
    """nfcapd / nfdump CSV flows → NETFLOW artifacts."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.NETFLOW

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        if not path.is_file():
            return False
        name = path.name.lower()
        suffix = path.suffix.lower()
        if suffix in _NFDUMP_SUFFIXES or name.startswith("nfcapd"):
            return True
        if suffix in {".csv", ".txt"}:
            try:
                with path.open("r", encoding="utf-8", errors="replace") as fh:
                    first = fh.readline()
            except OSError:
                return False
            reader = csv.reader(io.StringIO(first))
            header = next(reader, None) or []
            return looks_like_nfdump_csv_header(header)
        return False

    def _load_csv_text(self, path: Path) -> str:
        suffix = path.suffix.lower()
        name = path.name.lower()
        binary = suffix in _NFDUMP_SUFFIXES or (
            name.startswith("nfcapd") and suffix not in {".csv", ".txt"}
        )
        if binary:
            nfdump = find_nfdump()
            if not nfdump:
                raise ImporterError(
                    "nfdump not found on PATH — install nfdump (SIFT: apt install "
                    "nfdump) or export the file with 'nfdump -r <file> -o csv' and "
                    "register that CSV instead"
                )
            from nexus.config import settings

            try:
                proc = subprocess.run(
                    [nfdump, "-r", str(path), "-o", "csv"],
                    capture_output=True, timeout=settings.command_timeout,
                )
            except subprocess.TimeoutExpired as exc:
                raise ImporterError(
                    f"nfdump timed out on {path.name} — export a time-bounded CSV "
                    "('nfdump -r file -t <from>-<to> -o csv') and register it"
                ) from exc
            except OSError as exc:
                raise ImporterError(f"nfdump execution failed: {exc}") from exc
            if proc.returncode != 0:
                raise ImporterError(
                    f"nfdump failed: {proc.stderr.decode('utf-8', errors='replace')[:300]}"
                )
            return proc.stdout.decode("utf-8", errors="replace")
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ImporterError(f"cannot read {path.name}: {exc}") from exc

    def parse(self, path: Path) -> Iterator[Artifact]:
        rows = parse_nfdump_csv(self._load_csv_text(path))
        for row in rows:
            yield self._row_to_artifact(row)

    def _row_to_artifact(self, row: dict[str, str]) -> Artifact:
        raw_ts = row.get("ts") or row.get("t_first") or row.get("first")
        ts, _real = self.resolve_timestamp(raw_ts)
        ts_synthesized = _real is False
        if ts is None:
            from datetime import UTC, datetime

            ts = datetime.now(UTC)
            ts_synthesized = True
        src_ip = row.get("sa") or row.get("srcaddr") or row.get("src_ip") or ""
        dst_ip = row.get("da") or row.get("dstaddr") or row.get("dst_ip") or ""
        src_port = _safe_int(row.get("sp") or row.get("srcport") or "")
        dst_port = _safe_int(row.get("dp") or row.get("dstport") or "")
        proto_n = _safe_int(row.get("pr") or row.get("proto") or "")
        protocol = _PROTO_MAP.get(proto_n) if proto_n is not None else None
        pkts = _safe_int(row.get("ipkt") or row.get("packets") or "")
        byts = _safe_int(row.get("ibyt") or row.get("bytes") or "")
        volume = ""
        if pkts is not None or byts is not None:
            volume = f" ({pkts if pkts is not None else '?'} pkts / {byts if byts is not None else '?'} B)"
        proto_label = protocol.value if protocol else (str(proto_n) if proto_n is not None else "unknown")
        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.NETWORK,
            source=ArtifactSource.NETFLOW,
            timestamp=ts,
            ts_synthesized=ts_synthesized,
            severity=Severity.INFORMATIONAL,
            source_ip=src_ip or None,
            source_port=src_port,
            dest_ip=dst_ip or None,
            dest_port=dst_port,
            protocol=protocol,
            description=(
                f"Netflow {proto_label} {src_ip}:{src_port or ''} -> "
                f"{dst_ip}:{dst_port or ''}{volume}"
            ),
            raw=row,
            tags=["nfdump", "netflow", f"proto.{proto_label}"],
        )
