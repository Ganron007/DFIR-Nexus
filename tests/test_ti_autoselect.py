"""TI auto-select — configured providers join the default lookup.

Operator keyed set: virustotal / abuse.ch / otx / shodan (free tiers).
abuseipdb + crowdstrike remain support slots (no key required). With no
keys at all the default lookup falls back to the core set (env hints).
"""
from __future__ import annotations

from nexus.ti.schemas import TIResult

_ALL_TI_ENVS = (
    "NEXUS_TI_ABUSECH_API_KEY",
    "NEXUS_TI_VIRUSTOTAL_API_KEY",
    "NEXUS_TI_OTX_API_KEY",
    "NEXUS_TI_SHODAN_API_KEY",
    "NEXUS_TI_ABUSEIPDB_API_KEY",
    "NEXUS_TI_MISP_URL",
    "NEXUS_TI_MISP_API_KEY",
    "NEXUS_TI_CROWDSTRIKE_CLIENT_ID",
    "NEXUS_TI_CROWDSTRIKE_CLIENT_SECRET",
    "NEXUS_TI_MOCK",
)


def _router(monkeypatch, keys: dict[str, str]):
    for env_name in _ALL_TI_ENVS:
        monkeypatch.delenv(env_name, raising=False)
    for name, value in keys.items():
        monkeypatch.setenv(name, value)
    from nexus.ti.router import TIRouter

    return TIRouter(force_mock=False)


def _record_dispatch(router, monkeypatch) -> list[str]:
    seen: list[str] = []

    async def fake_dispatch(provider, value, ioc_type):
        seen.append(provider)
        return TIResult(provider=provider, ioc_type=ioc_type.value,
                        value=value, status="ok")

    monkeypatch.setattr(router, "_dispatch", fake_dispatch)
    return seen


async def test_configured_providers_auto_included(monkeypatch):
    router = _router(monkeypatch, keys={
        "NEXUS_TI_VIRUSTOTAL_API_KEY": "vt-test",
        "NEXUS_TI_OTX_API_KEY": "otx-test",
        "NEXUS_TI_ABUSECH_API_KEY": "abuse-test",
    })
    seen = _record_dispatch(router, monkeypatch)
    payload = await router.lookup("d41d8cd98f00b204e9800998ecf8427e")
    assert payload["tier"] == "configured"
    assert "virustotal" in seen
    assert "otx" in seen
    assert "malware_bazaar" in seen  # abuse.ch hash provider
    assert "shodan" not in seen  # shodan is ip-only


async def test_shodan_joins_ip_lookups(monkeypatch):
    router = _router(monkeypatch, keys={"NEXUS_TI_SHODAN_API_KEY": "sd-test"})
    seen = _record_dispatch(router, monkeypatch)
    payload = await router.lookup("203.0.113.10", ioc_type="ip")
    assert payload["tier"] == "configured"
    assert "shodan" in seen


async def test_no_keys_falls_back_to_core(monkeypatch):
    router = _router(monkeypatch, keys={})
    _record_dispatch(router, monkeypatch)
    payload = await router.lookup("evil.example")
    assert payload["tier"] == "core"
    assert "threatfox" in payload["providers_queried"]
    assert "virustotal" not in payload["providers_queried"]


async def test_explicit_providers_still_win(monkeypatch):
    router = _router(monkeypatch, keys={"NEXUS_TI_VIRUSTOTAL_API_KEY": "vt-test"})
    seen = _record_dispatch(router, monkeypatch)
    payload = await router.lookup("evil.example", providers=["otx"])
    assert payload["tier"] == "explicit"
    assert seen == ["otx"]
    assert "virustotal" not in payload["providers_queried"]
