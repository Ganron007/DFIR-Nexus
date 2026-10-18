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
import io
import re
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from nexus.ingest.base import Importer
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity

_MAX_BYTES = 64 << 20
_MIN_CHARS = 64
_BASE64 = re.compile(rb"[A-Za-z0-9+/]+={0,2}")
_WHITESPACE = re.compile(rb"\s+")
# File signatures (the first bytes of the decoded file) and the type each names.
_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "ZIP archive"), (b"PK\x05\x06", "ZIP archive (empty)"), (b"MZ", "Windows executable (PE)"),
    (b"%PDF", "PDF document"), (b"\x1f\x8b", "gzip data"), (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file (Office 97-2003)"),
    (b"\x7fELF", "ELF executable"), (b"{\\rtf", "RTF document"),
)


def _decoded(path: Path) -> tuple[bytes, str] | None:
    """The decoded bytes and their type, when the whole file is base64 of a file with a known signature."""
    try:
        if not path.is_file() or path.stat().st_size > _MAX_BYTES:
            return None
        with path.open("rb") as fh:
            head = fh.read(4096)
            if not _BASE64.fullmatch(_WHITESPACE.sub(b"", head).rstrip(b"=") or b"-"):
                return None
            text = _WHITESPACE.sub(b"", head + fh.read())
    except OSError:
        return None
    if len(text) < _MIN_CHARS or len(text) % 4 or not _BASE64.fullmatch(text):
        return None
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    kind = next((name for magic, name in _SIGNATURES if data.startswith(magic)), "")
    return (data, kind) if kind else None


class Base64FileImporter(Importer):
    """Identifies a file saved as base64 text: its type, hashes and, for a ZIP, its members."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.ENCODED_FILE

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        return _decoded(Path(path)) is not None

    def parse(self, path: Path) -> Iterator[Artifact]:
        got = _decoded(Path(path))
        if got is None:
            return
        data, kind = got
        identity = {"encoding": "base64", "decoded_type": kind, "decoded_size": len(data),
                    "decoded_sha256": hashlib.sha256(data).hexdigest(), "decoded_md5": hashlib.md5(data).hexdigest()}
        members: list[zipfile.ZipInfo] = []
        if kind.startswith("ZIP"):
            try:
                members = zipfile.ZipFile(io.BytesIO(data)).infolist()
            except zipfile.BadZipFile:
                members = []
        names = ", ".join(m.filename for m in members[:10])
        yield Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.FILE,
            source=ArtifactSource.ENCODED_FILE,
            timestamp=datetime.now(UTC),
            ts_synthesized=True,
            severity=Severity.INFORMATIONAL,
            file_path=str(path),
            description=(f"{Path(path).name}: base64 of a {kind}, {len(data)} bytes, SHA-256 {identity['decoded_sha256']}"
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
