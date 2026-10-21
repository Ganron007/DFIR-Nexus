"""A file saved as base64 text (a mail attachment, a pasted payload) is identified, not extracted.

Sample S06 keeps a mail attachment as ``attachment.txt``: one base64 run that decodes to a ZIP archive holding a
script, and no importer read it (2026-10-18). The lane reads records, not specimens, so the decoded file is not
written anywhere and no member's content is read. What is recorded is what identifies it: the decoded file's type by
its signature, its size, SHA-256 and MD5 (what a threat-intel lookup takes), and for a ZIP each member's name, size,
compressed size, CRC and time from the central directory. Only text that is base64 as a whole and decodes to a known
file signature is taken, so a key or a token is not mistaken for an attachment. A ZIP member's time is the DOS local
time ZIP stores, with no zone; by the index's policy a naive time is UTC.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import tempfile
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from nexus.ingest.base import Importer
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity

_MIN_CHARS = 64
_BASE64_CHARS = re.compile(rb"[A-Za-z0-9+/=]*")
_WHITESPACE = re.compile(rb"\s+")
_STREAM_CHUNK_BYTES = 1024 * 1024
_SPOOL_MEMORY_BYTES = 8 * 1024 * 1024
# File signatures (the first bytes of the decoded file) and the type each names.
_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "ZIP archive"), (b"PK\x05\x06", "ZIP archive (empty)"), (b"MZ", "Windows executable (PE)"),
    (b"%PDF", "PDF document"), (b"\x1f\x8b", "gzip data"), (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file (Office 97-2003)"),
    (b"\x7fELF", "ELF executable"), (b"{\\rtf", "RTF document"),
)


def _decoded(path: Path) -> tuple[BinaryIO, str, int, str, str] | None:
    """Stream a base64 file into a spillable temp file and identify its signature.

    The decoder validates the complete input and hashes the full decoded object.
    Its spool threshold controls memory use only: larger evidence spills to disk,
    never gets rejected or truncated because of an application size limit.
    """
    encoded = tempfile.SpooledTemporaryFile(  # noqa: SIM115
        max_size=_SPOOL_MEMORY_BYTES, mode="w+b"
    )
    decoded: BinaryIO | None = None
    try:
        if not path.is_file():
            encoded.close()
            return None
        with path.open("rb") as fh:
            pending = b""
            data_chars = 0
            padding_chars = 0
            padding_started = False
            for chunk in iter(lambda: fh.read(_STREAM_CHUNK_BYTES), b""):
                clean = _WHITESPACE.sub(b"", chunk)
                if not clean:
                    continue
                if not _BASE64_CHARS.fullmatch(clean):
                    encoded.close()
                    return None
                if padding_started:
                    if clean.strip(b"="):
                        encoded.close()
                        return None
                    padding_chars += len(clean)
                else:
                    pad_at = clean.find(b"=")
                    if pad_at >= 0:
                        if clean[pad_at:].strip(b"="):
                            encoded.close()
                            return None
                        padding_started = True
                        data_chars += pad_at
                        padding_chars += len(clean) - pad_at
                    else:
                        data_chars += len(clean)
                if padding_chars > 2:
                    encoded.close()
                    return None
                pending += clean
                while len(pending) >= 76:
                    encoded.write(pending[:76] + b"\n")
                    pending = pending[76:]
            total_chars = data_chars + padding_chars
            valid_padding = (
                (padding_chars == 0 and data_chars % 4 == 0)
                or (padding_chars == 1 and data_chars % 4 == 3)
                or (padding_chars == 2 and data_chars % 4 == 2)
            )
            if total_chars < _MIN_CHARS or total_chars % 4 or not valid_padding:
                encoded.close()
                return None
            if pending:
                encoded.write(pending + b"\n")
        encoded.seek(0)
        decoded = tempfile.SpooledTemporaryFile(max_size=_SPOOL_MEMORY_BYTES, mode="w+b")  # noqa: SIM115
        base64.decode(encoded, decoded)
        encoded.close()
        decoded.seek(0)
        signature = decoded.read(16)
        kind = next((name for magic, name in _SIGNATURES if signature.startswith(magic)), "")
        if not kind:
            decoded.close()
            return None
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        size = 0
        decoded.seek(0)
        for block in iter(lambda: decoded.read(_STREAM_CHUNK_BYTES), b""):
            size += len(block)
            sha256.update(block)
            md5.update(block)
        decoded.seek(0)
        return decoded, kind, size, sha256.hexdigest(), md5.hexdigest()
    except (OSError, binascii.Error, ValueError):
        encoded.close()
        if decoded is not None:
            decoded.close()
        return None


class Base64FileImporter(Importer):
    """Identifies a file saved as base64 text: its type, hashes and, for a ZIP, its members."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.ENCODED_FILE

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        result = _decoded(Path(path))
        if result is None:
            return False
        result[0].close()
        return True

    def parse(self, path: Path) -> Iterator[Artifact]:
        got = _decoded(Path(path))
        if got is None:
            return
        stream, kind, size, sha256, md5 = got
        identity = {"encoding": "base64", "decoded_type": kind, "decoded_size": size,
                    "decoded_sha256": sha256, "decoded_md5": md5}
        members: list[zipfile.ZipInfo] = []
        try:
            if kind.startswith("ZIP"):
                try:
                    with zipfile.ZipFile(stream) as archive:
                        members = archive.infolist()
                except zipfile.BadZipFile:
                    members = []
        finally:
            stream.close()
        names = ", ".join(m.filename for m in members[:10])
        yield Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.FILE,
            source=ArtifactSource.ENCODED_FILE,
            timestamp=datetime.now(UTC),
            ts_synthesized=True,
            severity=Severity.INFORMATIONAL,
            file_path=str(path),
            description=(f"{Path(path).name}: base64 of a {kind}, {size} bytes, SHA-256 {identity['decoded_sha256']}"
                         + (f", holding {len(members)} file(s): {names}" if members else "")),
            raw={**identity, "members": [m.filename for m in members]},
            iocs=[identity["decoded_sha256"]],
            tags=["encoded", "base64", *(["zip"] if members else [])],
        )
        for m in members:
            try:
                when, synthesized = datetime(*m.date_time, tzinfo=UTC), False
            except ValueError:
                when, synthesized = datetime.now(UTC), True
            yield Artifact(
                id=Artifact.new_id(),
                artifact_type=ArtifactType.FILE,
                source=ArtifactSource.ENCODED_FILE,
                timestamp=when,
                ts_synthesized=synthesized,
                severity=Severity.INFORMATIONAL,
                file_path=m.filename,
                description=(f"{m.filename} in the ZIP archive base64-encoded in {Path(path).name}: {m.file_size} bytes "
                             f"({m.compress_size} compressed), CRC {m.CRC:08x}"),
                raw={"container": str(path), "container_sha256": identity["decoded_sha256"], "member": m.filename,
                     "size": m.file_size, "compressed_size": m.compress_size, "crc32": f"{m.CRC:08x}",
                     "modified": when.isoformat() if not synthesized else ""},
                tags=["encoded", "base64", "zip-member"],
            )
