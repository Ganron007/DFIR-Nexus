"""Email (.eml / .msg) importer.

Parses RFC 2822 ``.eml`` files using Python's ``email`` standard library.
Extracts headers (From, To, Subject, Date), body text, and basic
attachments metadata. ``.msg`` (Outlook) files are flagged but require
optional ``olefile`` dependency for full parsing — plain-text fallback
attempts header extraction.
"""

from __future__ import annotations

import email
import email.policy
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
    Severity,
)

log = logging.getLogger(__name__)


class EmailImporter(Importer):
    """Parser for RFC 2822 .eml email files."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.GENERIC_JSONL

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: .eml extension, or content starts with 'From:' + 'Subject:'."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if name.endswith(".eml") or name.endswith(".msg"):
            return True
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(2048)
        except OSError:
            return False
        return ("From:" in head or "from:" in head) and (
            "Subject:" in head or "subject:" in head
        )

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per email message."""
        try:
            if path.suffix.lower() == ".msg":
                yield from self._parse_msg(path)
            else:
                yield from self._parse_eml(path)
        except Exception:
            log.warning("Failed to parse email file %s", path, exc_info=True)

    def _parse_eml(self, path: Path) -> Iterator[Artifact]:
        """Parse a RFC 2822 .eml file."""
        with path.open("rb") as f:
            msg = email.message_from_binary_file(f, policy=email.policy.default)
        artifact = self._message_to_artifact(msg, path)
        if artifact is not None:
            yield artifact

    def _parse_msg(self, path: Path) -> Iterator[Artifact]:
        """Parse an Outlook .msg file (requires olefile, falls back to header scan)."""
        try:
            import olefile  # type: ignore[import-untyped]

            ole = olefile.OleFileIO(str(path))
            try:
                # Try to extract stream data for headers
                header_bytes = b""
                for stream_path in ole.listdir():
                    name = "/".join(stream_path).lower()
                    if "transport" in name or "header" in name:
                        header_bytes = ole.openstream(stream_path).read()
                        break
                if header_bytes:
                    msg = email.message_from_bytes(
                        header_bytes, policy=email.policy.default
                    )
                    artifact = self._message_to_artifact(msg, path)
                    if artifact is not None:
                        yield artifact
                        return
            finally:
                ole.close()
        except ImportError:
            log.debug("olefile not installed; .msg parsing limited")
        except Exception:
            log.debug("olefile failed to parse %s", path, exc_info=True)

        # Fallback: raw text header scan
        yield from self._fallback_text_parse(path)

    def _fallback_text_parse(self, path: Path) -> Iterator[Artifact]:
        """Best-effort header extraction from raw bytes."""
        try:
            with path.open("rb") as f:
                raw = f.read(8192)
            text = raw.decode("utf-8", errors="replace")
            headers: dict[str, str] = {}
            for line in text.splitlines():
                if line.startswith("From:"):
                    headers["From"] = line[5:].strip()
                elif line.startswith("To:"):
                    headers["To"] = line[3:].strip()
                elif line.startswith("Subject:"):
                    headers["Subject"] = line[8:].strip()
                elif line.startswith("Date:"):
                    headers["Date"] = line[5:].strip()

            ts = self.normalize_timestamp(headers.get("Date"))
            if ts is None:
                ts = datetime.now(UTC)

            from_addr = headers.get("From", "")
            to_addr = headers.get("To", "")
            subject = headers.get("Subject", "(no subject)")

            yield Artifact(
                id=Artifact.new_id(),
                artifact_type=ArtifactType.SMTP,
                source=ArtifactSource.GENERIC_JSONL,
                timestamp=ts,
                severity=Severity.INFORMATIONAL,
                user=from_addr or None,
                description=f"Email: {subject} (from {from_addr} to {to_addr})",
                raw={"headers": headers, "source_file": str(path)},
                tags=["email", "msg", "fallback"],
            )
        except Exception:
            log.debug("Fallback .msg parse failed for %s", path, exc_info=True)

    def _message_to_artifact(
        self, msg: Any, path: Path
    ) -> Artifact | None:
        """Convert an email.message.Message to an Artifact."""
        try:
            from_addr = str(msg.get("From", ""))
            to_addr = str(msg.get("To", ""))
            subject = str(msg.get("Subject", "(no subject)"))
            date_str = str(msg.get("Date", ""))
            message_id = str(msg.get("Message-ID", ""))

            ts = self.normalize_timestamp(date_str)
            if ts is None:
                ts = datetime.now(UTC)

            # Extract body text
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    ct = part.get_content_type()
                    if ct == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode("utf-8", errors="replace")[:2000]
                            break
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="replace")[:2000]

            # Attachment names
            attachments: list[str] = []
            if msg.is_multipart():
                for part in msg.walk():
                    filename = part.get_filename()
                    if filename:
                        attachments.append(str(filename))

            # IOC extraction: pull URLs and IPs from body
            iocs = self._extract_iocs(body)

            tags = ["email", "eml"]
            if attachments:
                tags.append(f"attachments.{len(attachments)}")
            if message_id:
                tags.append(f"msgid.{message_id[:64]}")

            description = f"Email: {subject} (from {from_addr})"
            if attachments:
                description += f" [{len(attachments)} attachment(s)]"

            return Artifact(
                id=Artifact.new_id(),
                artifact_type=ArtifactType.SMTP,
                source=ArtifactSource.GENERIC_JSONL,
                timestamp=ts,
                severity=Severity.INFORMATIONAL,
                user=from_addr or None,
                description=description,
                raw={
                    "from": from_addr,
                    "to": to_addr,
                    "subject": subject,
                    "date": date_str,
                    "message_id": message_id,
                    "body_preview": body[:500],
                    "attachments": attachments,
                    "source_file": str(path),
                },
                iocs=iocs,
                tags=tags,
            )
        except Exception:
            log.debug("Failed to convert email message to artifact: %s", path, exc_info=True)
            return None

    @staticmethod
    def _extract_iocs(text: str) -> list[str]:
        """Extract potential IOC indicators (URLs, IPs) from text."""
        import re

        iocs: list[str] = []
        # URLs
        for match in re.findall(r"https?://[^\s<>\"']+", text):
            iocs.append(match[:256])
        # IPv4 addresses
        for match in re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text
        ):
            # Skip obvious non-IPs
            parts = match.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                iocs.append(match)
        return list(set(iocs))[:50]
