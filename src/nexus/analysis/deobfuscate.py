"""Deterministic payload deobfuscation — PowerShell/base64 decode + IOC harvest."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any, Literal

DeobfuscationMethod = Literal["powershell-enc", "base64"]

PS_ENC_RE = re.compile(r"(?:-enc(?:odedcommand)?|-e\b)\s+([A-Za-z0-9+/]{20,}={0,2})", re.I)
FROM_B64_RE = re.compile(
    r"\[convert\]::frombase64string\(\s*[\"']([A-Za-z0-9+/]{20,}={0,2})[\"']\s*\)",
    re.I,
)
BASE64_BLOCK_RE = re.compile(r'(?:["\'`]|(?:=|:)\s*)([A-Za-z0-9+/]{40,}={0,2})(?:["\'`]|\s|$)')
EXEC_MARKER_RE = re.compile(r"iex\b|invoke-expression|certutil|frombase64string|downloadstring", re.I)

URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]{5,300}", re.I)
IPV4_RE = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b"
)
SHA256_RE = re.compile(r"\b([a-f0-9]{64})\b", re.I)
DOMAIN_RE = re.compile(
    r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|net|org|io|co|info|xyz|ru|cn|tk|top|pw|cc|biz|online|site|club|live|win|fun|space|tech|store|shop|link|click|download))\b",
    re.I,
)
NOISE_IPS = frozenset({"127.0.0.1", "0.0.0.0", "255.255.255.255", "8.8.8.8", "8.8.4.4"})


@dataclass
class RawIoc:
    type: str
    value: str


@dataclass
class DeobfuscationResult:
    decoded: str
    method: DeobfuscationMethod
    raw_iocs: list[RawIoc]

    def to_dict(self) -> dict[str, Any]:
        return {
            "decoded": self.decoded,
            "method": self.method,
            "raw_iocs": [{"type": i.type, "value": i.value} for i in self.raw_iocs],
        }


def _extract_iocs(text: str) -> list[RawIoc]:
    out: list[RawIoc] = []
    seen: set[str] = set()

    def add(ioc_type: str, value: str) -> None:
        key = f"{ioc_type}:{value.lower()}"
        if key not in seen:
            seen.add(key)
            out.append(RawIoc(ioc_type, value))

    for m in URL_RE.finditer(text):
        url = re.sub(r'[.,;:)\'">]+$', "", m.group(0))[:300]
        if len(url) > 10:
            add("url", url)
    for m in IPV4_RE.finditer(text):
        if m.group(1) not in NOISE_IPS:
            add("ip", m.group(1))
    for m in SHA256_RE.finditer(text):
        add("hash", m.group(1).lower())
    for m in DOMAIN_RE.finditer(text):
        d = m.group(1).lower()
        if not d[0].isdigit():
            add("domain", d)
    return out


def _safe_b64_decode(payload: str, encoding: str) -> str | None:
    try:
        raw = base64.b64decode(payload.strip().replace(" ", ""), validate=False)
        if len(raw) < 4:
            return None
        if encoding == "utf16le":
            text = raw.decode("utf-16-le", errors="replace")
        else:
            text = raw.decode("utf-8", errors="replace")
        printable = sum(1 for c in text if 0x20 <= ord(c) <= 0x7E)
        if printable < 4 or printable / max(len(text), 1) < 0.3:
            return None
        return text.replace("\0", "").strip()
    except (ValueError, UnicodeDecodeError):
        return None


def is_obfuscated(text: str) -> bool:
    return bool(
        PS_ENC_RE.search(text)
        or FROM_B64_RE.search(text)
        or (BASE64_BLOCK_RE.search(text) and EXEC_MARKER_RE.search(text))
    )


def deobfuscate_text(text: str) -> DeobfuscationResult | None:
    m = PS_ENC_RE.search(text)
    if m:
        decoded = _safe_b64_decode(m.group(1), "utf16le")
        if decoded and len(decoded) >= 5:
            return DeobfuscationResult(decoded, "powershell-enc", _extract_iocs(decoded))

    m = FROM_B64_RE.search(text)
    if m:
        decoded = _safe_b64_decode(m.group(1), "utf8")
        if decoded and len(decoded) >= 5:
            return DeobfuscationResult(decoded, "base64", _extract_iocs(decoded))

    if EXEC_MARKER_RE.search(text):
        m = BASE64_BLOCK_RE.search(text)
        if m:
            decoded = _safe_b64_decode(m.group(1), "utf16le") or _safe_b64_decode(m.group(1), "utf8")
            if decoded and len(decoded) >= 5:
                return DeobfuscationResult(decoded, "base64", _extract_iocs(decoded))
    return None
