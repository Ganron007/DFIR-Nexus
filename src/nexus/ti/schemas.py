"""Threat intelligence result schemas (D.0 Stellar)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class IOCType(StrEnum):
    """Supported indicator types for TI lookups."""

    HASH = "hash"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"


class TIProviderName(StrEnum):
    """Core TI provider names (optional providers use plain strings in router)."""

    THREATFOX = "threatfox"
    MALWARE_BAZAAR = "malware_bazaar"
    URLHAUS = "urlhaus"
    YARAIFY = "yaraify"
    MISP = "misp"


class ProviderMode(StrEnum):
    LIVE = "live"
    MOCK = "mock"
    UNCONFIGURED = "unconfigured"


@dataclass
class TIProviderInfo:
    """Provider availability for ti_list_providers."""

    name: str
    mode: ProviderMode
    tier: str  # "core" | "optional"
    ioc_types: list[str]
    env_keys: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "mode": self.mode.value,
            "tier": self.tier,
            "ioc_types": self.ioc_types,
            "env_keys": self.env_keys,
            "notes": self.notes,
        }


@dataclass
class TIResult:
    """Single-provider lookup response."""

    provider: str
    ioc_type: str
    value: str
    status: str
    malicious: bool | None = None
    confidence: float = 0.0
    summary: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "status": self.status,
            "malicious": self.malicious,
            "confidence": round(self.confidence, 3),
            "summary": self.summary,
            "raw": self.raw,
            "references": self.references,
            "tags": self.tags,
            "error": self.error,
        }


@dataclass
class TIFanoutResult:
    """Aggregated multi-provider response."""

    ioc_type: str
    value: str
    providers_queried: list[str]
    results: list[TIResult]
    malicious_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "providers_queried": self.providers_queried,
            "malicious_count": self.malicious_count,
            "results": [r.to_dict() for r in self.results],
        }
