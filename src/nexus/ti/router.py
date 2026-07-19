"""TI router — core default loop + optional providers on explicit request."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any

from nexus.ti.constants import (
    ALL_TI_PROVIDERS,
    ENV_ABUSECH_KEY,
    ENV_ABUSEIPDB_API_KEY,
    ENV_CROWDSTRIKE_CLIENT_ID,
    ENV_CROWDSTRIKE_CLIENT_SECRET,
    ENV_MISP_API_KEY,
    ENV_MISP_URL,
    ENV_OTX_API_KEY,
    ENV_SHODAN_API_KEY,
    ENV_VIRUSTOTAL_API_KEY,
    FANOUT_PROVIDERS,
    ti_mock_enabled,
)
from nexus.ti.providers import abuse_ch, misp, optional
from nexus.ti.schemas import IOCType, ProviderMode, TIFanoutResult, TIProviderInfo, TIResult

log = logging.getLogger(__name__)

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")
_URL_RE = re.compile(r"^https?://", re.I)


def infer_ioc_type(value: str) -> IOCType:
    v = value.strip()
    if _HASH_RE.match(v):
        return IOCType.HASH
    if _URL_RE.match(v):
        return IOCType.URL
    if "@" in v:
        return IOCType.EMAIL
    try:
        parts = v.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return IOCType.IP
    except ValueError:
        pass
    return IOCType.DOMAIN


class TIRouter:
    """Threat intelligence router — abuse.ch + MISP by default; optional APIs on demand."""

    def __init__(self, *, force_mock: bool | None = None) -> None:
        self._force_mock = force_mock

    @property
    def use_mock(self) -> bool:
        if self._force_mock is not None:
            return self._force_mock
        return ti_mock_enabled()

    def _abuse_key(self) -> str | None:
        return os.environ.get(ENV_ABUSECH_KEY)

    def _env_hint(self, provider: str) -> str:
        if provider in FANOUT_PROVIDERS:
            return f"Set {ENV_ABUSECH_KEY} (free abuse.ch Auth-Key)"
        hints: dict[str, str] = {
            "misp": f"Set {ENV_MISP_URL} and {ENV_MISP_API_KEY}",
            "otx": f"Set {ENV_OTX_API_KEY}",
            "shodan": f"Set {ENV_SHODAN_API_KEY}",
            "virustotal": f"Set {ENV_VIRUSTOTAL_API_KEY}",
            "abuseipdb": f"Set {ENV_ABUSEIPDB_API_KEY}",
            "crowdstrike": f"Set {ENV_CROWDSTRIKE_CLIENT_ID} and {ENV_CROWDSTRIKE_CLIENT_SECRET}",
        }
        return hints.get(provider, "Provider not configured")

    def _unconfigured_result(self, provider: str, value: str, ioc_type: str) -> TIResult:
        return TIResult(
            provider=provider,
            ioc_type=ioc_type,
            value=value,
            status="error",
            summary=f"{provider} not configured",
            error=self._env_hint(provider),
        )

    def _provider_mode(self, name: str) -> ProviderMode:
        if self.use_mock:
            return ProviderMode.MOCK
        if name in FANOUT_PROVIDERS:
            return ProviderMode.LIVE if self._abuse_key() else ProviderMode.UNCONFIGURED
        if name == "misp":
            url, key = os.environ.get(ENV_MISP_URL), os.environ.get(ENV_MISP_API_KEY)
            return ProviderMode.LIVE if (url and key) else ProviderMode.UNCONFIGURED
        optional_keys: dict[str, list[str | None]] = {
            "otx": [os.environ.get(ENV_OTX_API_KEY)],
            "shodan": [os.environ.get(ENV_SHODAN_API_KEY)],
            "virustotal": [os.environ.get(ENV_VIRUSTOTAL_API_KEY)],
            "abuseipdb": [os.environ.get(ENV_ABUSEIPDB_API_KEY)],
            "crowdstrike": [
                os.environ.get(ENV_CROWDSTRIKE_CLIENT_ID),
                os.environ.get(ENV_CROWDSTRIKE_CLIENT_SECRET),
            ],
        }
        req = optional_keys.get(name)
        if req is not None:
            return ProviderMode.LIVE if all(req) else ProviderMode.UNCONFIGURED
        return ProviderMode.UNCONFIGURED

    def list_providers(self) -> list[TIProviderInfo]:
        catalog: list[tuple[str, str, list[str], list[str], str]] = [
            ("threatfox", "core", ["hash", "domain", "ip", "url"], [ENV_ABUSECH_KEY], "abuse.ch ThreatFox"),
            ("malware_bazaar", "core", ["hash"], [ENV_ABUSECH_KEY], "abuse.ch Malware Bazaar"),
            ("urlhaus", "core", ["url"], [ENV_ABUSECH_KEY], "abuse.ch URLhaus"),
            ("yaraify", "core", ["hash"], [ENV_ABUSECH_KEY], "abuse.ch YARAify"),
            (
                "misp",
                "core",
                ["hash", "ip", "domain", "url", "email"],
                [ENV_MISP_URL, ENV_MISP_API_KEY],
                "Self-hosted MISP — attributes/restSearch",
            ),
            ("otx", "optional", ["hash", "ip", "domain", "url"], [ENV_OTX_API_KEY], "AlienVault OTX (free API key)"),
            ("shodan", "optional", ["ip"], [ENV_SHODAN_API_KEY], "Shodan host lookup (free tier)"),
            (
                "virustotal",
                "optional",
                ["hash", "ip", "domain", "url"],
                [ENV_VIRUSTOTAL_API_KEY],
                "VirusTotal v3 API (commercial/free tier)",
            ),
            ("abuseipdb", "optional", ["ip"], [ENV_ABUSEIPDB_API_KEY], "AbuseIPDB (commercial/free tier)"),
            (
                "crowdstrike",
                "optional",
                ["hash", "ip", "domain"],
                [ENV_CROWDSTRIKE_CLIENT_ID, ENV_CROWDSTRIKE_CLIENT_SECRET],
                "CrowdStrike Falcon Intel (commercial)",
            ),
        ]
        out: list[TIProviderInfo] = []
        for name, tier, iocs, envs, notes in catalog:
            mode = self._provider_mode(name)
            if self.use_mock:
                mode = ProviderMode.MOCK
            out.append(
                TIProviderInfo(name=name, mode=mode, tier=tier, ioc_types=iocs, env_keys=envs, notes=notes)
            )
        return out

    async def _dispatch(self, provider: str, value: str, ioc_type: IOCType) -> TIResult:
        if provider not in ALL_TI_PROVIDERS:
            return TIResult(
                provider=provider,
                ioc_type=ioc_type.value,
                value=value,
                status="error",
                summary="Unknown provider",
                error=f"Unknown provider: {provider}. See ti_list_providers.",
            )
        mock = self.use_mock
        it = ioc_type.value
        if not mock and self._provider_mode(provider) == ProviderMode.UNCONFIGURED:
            return self._unconfigured_result(provider, value, it)
        key = self._abuse_key()
        try:
            if provider == "threatfox":
                return await abuse_ch.query_threatfox(value, mock=mock, api_key=key, ioc_type=it)
            if provider == "malware_bazaar":
                return await abuse_ch.query_malware_bazaar(value, mock=mock, api_key=key)
            if provider == "urlhaus":
                return await abuse_ch.query_urlhaus(value, mock=mock, api_key=key)
            if provider == "yaraify":
                return await abuse_ch.query_yaraify(value, mock=mock, api_key=key)
            if provider == "misp":
                return await misp.query_misp(value, mock=mock, ioc_type=it)
            if provider == "otx":
                return await optional.query_otx(value, mock=mock, ioc_type=it)
            if provider == "shodan":
                return await optional.query_shodan(value, mock=mock)
            if provider == "virustotal":
                return await optional.query_virustotal(value, mock=mock, ioc_type=it)
            if provider == "abuseipdb":
                return await optional.query_abuseipdb(value, mock=mock)
            if provider == "crowdstrike":
                return await optional.query_crowdstrike(value, mock=mock, ioc_type=it)
        except Exception as exc:
            log.exception("TI provider %s failed", provider)
            error_msg = str(exc)
            for env_name, env_val in os.environ.items():
                if env_val and len(env_val) >= 8 and env_name.startswith("NEXUS_"):
                    error_msg = error_msg.replace(env_val, "***REDACTED***")
            return TIResult(
                provider=provider,
                ioc_type=it,
                value=value,
                status="error",
                summary=f"{provider} lookup failed",
                error=error_msg,
            )
        return TIResult(
            provider=provider,
            ioc_type=it,
            value=value,
            status="error",
            summary="Unknown provider",
            error=f"unknown provider: {provider}",
        )

    async def lookup(
        self,
        value: str,
        ioc_type: str | None = None,
        providers: list[str] | None = None,
    ) -> dict[str, Any]:
        it = IOCType(ioc_type) if ioc_type else infer_ioc_type(value)
        catalog = {p.name: p for p in self.list_providers()}
        if providers:
            names = providers
        else:
            # Default: core tier only (abuse.ch + MISP) — optional never auto-included.
            names = [
                p.name
                for p in self.list_providers()
                if p.tier == "core" and it.value in p.ioc_types
            ]
        unknown = [n for n in names if n not in catalog]
        if unknown:
            return {"error": f"Unknown providers: {unknown}", "known": list(catalog.keys())}
        results = await asyncio.gather(*[self._dispatch(n, value, it) for n in names])
        malicious = sum(1 for r in results if r.malicious is True)
        return {
            "ioc_type": it.value,
            "value": value,
            "tier": "explicit" if providers else "core",
            "providers_queried": names,
            "malicious_count": malicious,
            "results": [r.to_dict() for r in results],
        }

    async def fanout(self, value: str, ioc_type: str | None = None) -> dict[str, Any]:
        it = IOCType(ioc_type) if ioc_type else infer_ioc_type(value)
        names: list[str] = list(FANOUT_PROVIDERS)
        results = await asyncio.gather(*[self._dispatch(n, value, it) for n in names])
        malicious = sum(1 for r in results if r.malicious is True)
        return TIFanoutResult(
            ioc_type=it.value,
            value=value,
            providers_queried=names,
            results=list(results),
            malicious_count=malicious,
        ).to_dict()

    async def query_provider(self, provider: str, value: str, ioc_type: str | None = None) -> dict[str, Any]:
        it = IOCType(ioc_type) if ioc_type else infer_ioc_type(value)
        result = await self._dispatch(provider, value, it)
        return result.to_dict()


def create_default_router(*, force_mock: bool = False) -> TIRouter:
    return TIRouter(force_mock=force_mock)
