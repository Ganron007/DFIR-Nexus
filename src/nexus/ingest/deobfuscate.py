"""Payload deobfuscation — auto-decode obfuscated command lines.

Detects and decodes common obfuscation techniques in forensic artifacts:
- Base64-encoded PowerShell (-EncodedCommand / -enc)
- [Convert]::FromBase64String() calls
- Hex-encoded strings
- Reversed strings

Pure/deterministic — no AI, no network.
Inspired by DFIR-Companion's applyDeobfuscation.ts.
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

_ENCODED_CMD_RE = re.compile(
    r"(?:-EncodedCommand|-enc)\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE
)

_FROM_BASE64_RE = re.compile(
    r"\[Convert\]::FromBase64String\(\s*['\"]([A-Za-z0-9+/=]{16,})['\"]",
    re.IGNORECASE,
)

_HEX_STRING_RE = re.compile(
    r"(?:0x[0-9a-fA-F]{2}[\s,]*){8,}"
)

_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


@dataclass
class DeobfuscationResult:
    """Result of deobfuscating a command line or payload."""
    original: str
    decoded: str | None
    technique: str
    confidence: str
    artifact_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "original": self.original[:200],
            "decoded": self.decoded[:500] if self.decoded else None,
            "technique": self.technique,
            "confidence": self.confidence,
            "artifact_id": self.artifact_id,
        }


def _try_decode_base64(encoded: str, prefer_utf16: bool = False) -> str | None:
    """Attempt to decode a base64 string. Returns None on failure."""
    try:
        raw = base64.b64decode(encoded)
    except Exception:
        return None

    if prefer_utf16:
        try:
            decoded = raw.decode("utf-16-le", errors="replace")
            if decoded and sum(1 for c in decoded[:40] if c.isprintable()) > 10:
                return decoded.strip("\x00")
        except Exception:
            pass

    try:
        decoded = raw.decode("utf-8", errors="replace")
        if decoded and sum(1 for c in decoded[:40] if c.isprintable()) > 10:
            return decoded
    except Exception:
        pass

    if not prefer_utf16:
        try:
            decoded = raw.decode("utf-16-le", errors="replace")
            if decoded and sum(1 for c in decoded[:40] if c.isprintable()) > 10:
                return decoded.strip("\x00")
        except Exception:
            pass

    return None


def deobfuscate_command(command_line: str) -> list[DeobfuscationResult]:
    """Extract and decode obfuscated payloads from a command line.

    Returns a list of deobfuscation results (one per detected payload).
    """
    results: list[DeobfuscationResult] = []

    for match in _ENCODED_CMD_RE.finditer(command_line):
        encoded = match.group(1)
        decoded = _try_decode_base64(encoded, prefer_utf16=True)
        if decoded:
            results.append(DeobfuscationResult(
                original=match.group(0)[:200],
                decoded=decoded,
                technique="PowerShell -EncodedCommand (base64 UTF-16LE)",
                confidence="high",
            ))

    for match in _FROM_BASE64_RE.finditer(command_line):
        encoded = match.group(1)
        decoded = _try_decode_base64(encoded)
        if decoded:
            results.append(DeobfuscationResult(
                original=match.group(0)[:200],
                decoded=decoded,
                technique="[Convert]::FromBase64String",
                confidence="high",
            ))

    for match in _HEX_STRING_RE.finditer(command_line):
        hex_str = match.group(0)
        try:
            hex_bytes = bytes.fromhex(
                re.sub(r"[0x,\s]", "", hex_str)
            )
            decoded = hex_bytes.decode("utf-8", errors="replace")
            if decoded and any(c.isprintable() for c in decoded[:20]):
                results.append(DeobfuscationResult(
                    original=hex_str[:200],
                    decoded=decoded,
                    technique="Hex-encoded string",
                    confidence="medium",
                ))
        except Exception:
            pass

    return results


def deobfuscate_artifacts(artifacts: list[Any]) -> list[DeobfuscationResult]:
    """Scan a list of artifacts for obfuscated payloads.

    Checks command_line and description fields.
    """
    all_results: list[DeobfuscationResult] = []

    for artifact in artifacts:
        text_fields = []
        if hasattr(artifact, "command_line") and artifact.command_line:
            text_fields.append(artifact.command_line)
        if hasattr(artifact, "description") and artifact.description:
            text_fields.append(artifact.description)
        if hasattr(artifact, "raw") and isinstance(artifact.raw, dict):
            for key in ("CommandLine", "command_line", "ProcessCommandLine"):
                val = artifact.raw.get(key)
                if val and isinstance(val, str):
                    text_fields.append(val)

        for text in text_fields:
            results = deobfuscate_command(text)
            for r in results:
                r.artifact_id = getattr(artifact, "id", None)
            all_results.extend(results)

    return all_results
