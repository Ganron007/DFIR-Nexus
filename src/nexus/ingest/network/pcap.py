"""Raw PCAP/PCAPNG import — tshark conversion, then Wireshark JSON parsing.

Raw captures are not parsed natively: tshark (Wireshark CLI) converts the
capture to its JSON export in a temp file, and the Wireshark importer maps
each packet to a normalized Artifact. Uses the shared WIRESHARK lane, so the
pipeline's automatic ingest, the ``ingest_auto`` MCP tool, and the CLI all
gain raw-pcap support through the same registry path.

Bounds: timeout via ``NEXUS_PCAP_TIMEOUT`` (default: settings.command_timeout);
optional packet cap via ``NEXUS_PCAP_MAX_PACKETS`` (default 0 = all). A
timeout is reported honestly — never silently truncated.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

from nexus.ingest.base import Importer, ImporterError
from nexus.ingest.schemas import Artifact, ArtifactSource

log = logging.getLogger(__name__)

_PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
# pcap (LE/BE), pcapng; classic pcap magic as used by Wireshark
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
    b"\x0a\x0d\x0d\x0a",
}


def find_tshark() -> str | None:
    """tshark on PATH (Windows: Wireshark install adds it)."""
    return shutil.which("tshark") or shutil.which("tshark.exe")


def convert_pcap_to_json(
    src: Path,
    out_path: Path,
    *,
    display_filter: str = "",
    max_packets: int = 0,
    timeout: int | None = None,
) -> None:
    """Run ``tshark -T json`` into ``out_path``; raise ImporterError on failure."""
    tshark = find_tshark()
    if not tshark:
        raise ImporterError(
            "tshark not found on PATH — install Wireshark (e.g. "
            "'choco install wireshark') and reopen the terminal"
        )
    from nexus.config import settings

    cmd = [tshark, "-r", str(src), "-T", "json"]
    if display_filter:
        cmd += ["-Y", display_filter]
    if max_packets and max_packets > 0:
        cmd += ["-c", str(int(max_packets))]
    limit = timeout or settings.command_timeout
    try:
        with open(out_path, "wb") as out_f:
            proc = subprocess.run(
                cmd, stdout=out_f, stderr=subprocess.PIPE, timeout=limit,
            )
    except subprocess.TimeoutExpired as exc:
        raise ImporterError(
            f"tshark timed out after {limit}s — convert with a display filter "
            "(convert_pcap tool) or raise NEXUS_PCAP_TIMEOUT"
        ) from exc
    except OSError as exc:
        raise ImporterError(f"tshark execution failed: {exc}") from exc
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace")[:300]
        raise ImporterError(f"tshark failed: {stderr}")


class PcapImporter(Importer):
    """Raw .pcap/.pcapng/.cap via tshark; yields Wireshark-shaped artifacts."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.WIRESHARK

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        if not path.is_file():
            return False
        if path.suffix.lower() in _PCAP_SUFFIXES:
            return True
        # Extension-less captures: sniff the magic bytes.
        try:
            with path.open("rb") as fh:
                magic = fh.read(4)
        except OSError:
            return False
        return magic in _PCAP_MAGIC

    def parse(self, path: Path) -> Iterator[Artifact]:
        try:
            max_packets = int(os.environ.get("NEXUS_PCAP_MAX_PACKETS", "0"))
        except ValueError:
            max_packets = 0
        try:
            timeout = int(os.environ.get("NEXUS_PCAP_TIMEOUT", "0")) or None
        except ValueError:
            timeout = None
        from nexus.ingest.network.wireshark import WiresharkImporter

        with tempfile.TemporaryDirectory(prefix="nexus-pcap-") as tmp:
            converted = Path(tmp) / f"{path.stem}.tshark.json"
            log.info("pcap: converting %s via tshark -> %s", path.name, converted.name)
            convert_pcap_to_json(
                path, converted, max_packets=max_packets, timeout=timeout,
            )
            yield from WiresharkImporter().parse(converted)
